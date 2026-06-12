from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field

from aicso.models.alert import Alert
from aicso.models.asset import Asset
from aicso.models.ioc import IoC


class CaseStatus(str, Enum):
    NEW = "new"
    ASSIGNED = "assigned"
    INVESTIGATING = "investigating"
    RESPONDING = "responding"
    RESOLVED = "resolved"
    CLOSED = "closed"


class CaseSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CasePriority(int, Enum):
    P1 = 1
    P2 = 2
    P3 = 3
    P4 = 4
    P5 = 5


# 严重级别到默认优先级的映射
SEVERITY_PRIORITY_MAP: dict[CaseSeverity, CasePriority] = {
    CaseSeverity.CRITICAL: CasePriority.P1,
    CaseSeverity.HIGH: CasePriority.P2,
    CaseSeverity.MEDIUM: CasePriority.P3,
    CaseSeverity.LOW: CasePriority.P4,
    CaseSeverity.INFO: CasePriority.P5,
}

# 各优先级的SLA（响应时间/处置时间，单位：分钟）
SLA_CONFIG: dict[CasePriority, tuple[int, int]] = {
    CasePriority.P1: (15, 60),
    CasePriority.P2: (30, 240),
    CasePriority.P3: (120, 1440),
    CasePriority.P4: (480, 4320),
    CasePriority.P5: (0, 0),
}

# 合法的状态转换
CASE_TRANSITIONS: dict[CaseStatus, list[CaseStatus]] = {
    CaseStatus.NEW: [CaseStatus.ASSIGNED],
    CaseStatus.ASSIGNED: [CaseStatus.INVESTIGATING, CaseStatus.NEW],
    CaseStatus.INVESTIGATING: [CaseStatus.RESPONDING, CaseStatus.RESOLVED, CaseStatus.ASSIGNED],
    CaseStatus.RESPONDING: [CaseStatus.RESOLVED, CaseStatus.INVESTIGATING],
    CaseStatus.RESOLVED: [CaseStatus.CLOSED, CaseStatus.INVESTIGATING],
    CaseStatus.CLOSED: [CaseStatus.NEW],
}


class CaseEvent(BaseModel):
    """Case事件/时间线条目"""
    event_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    event_type: str  # status_change, alert_added, action_executed, note_added, ai_analysis
    actor: str  # user_id 或 agent_name
    detail: dict = Field(default_factory=dict)


class Case(BaseModel):
    """Case（案件）- 安全事件的核心载体"""
    case_id: str
    title: str
    severity: CaseSeverity = CaseSeverity.MEDIUM
    status: CaseStatus = CaseStatus.NEW
    priority: CasePriority = CasePriority.P3
    assignee_id: Optional[str] = None
    tags: list[str] = Field(default_factory=list)
    ai_summary: Optional[str] = None
    ai_recommendation: Optional[str] = None
    resolution: Optional[str] = None

    # 关联实体
    alerts: list[Alert] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    iocs: list[IoC] = Field(default_factory=list)
    timeline: list[CaseEvent] = Field(default_factory=list)

    # 元数据
    metadata: dict = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    closed_at: Optional[datetime] = None
    sla_deadline: Optional[datetime] = None

    def transition_to(self, new_status: CaseStatus, actor: str, reason: str = "") -> CaseEvent:
        """执行状态转换，返回事件记录"""
        allowed = CASE_TRANSITIONS.get(self.status, [])
        if new_status not in allowed:
            raise ValueError(
                f"Invalid transition: {self.status.value} -> {new_status.value}. "
                f"Allowed: {[s.value for s in allowed]}"
            )
        old_status = self.status
        self.status = new_status
        self.updated_at = datetime.utcnow()
        if new_status == CaseStatus.CLOSED:
            self.closed_at = datetime.utcnow()

        event = CaseEvent(
            event_id=f"evt-{len(self.timeline) + 1:06d}",
            event_type="status_change",
            actor=actor,
            detail={
                "from": old_status.value,
                "to": new_status.value,
                "reason": reason,
            },
        )
        self.timeline.append(event)
        return event

    def add_alert(self, alert: Alert, reason: str = "") -> CaseEvent:
        """添加告警到Case"""
        self.alerts.append(alert)
        self.updated_at = datetime.utcnow()

        event = CaseEvent(
            event_id=f"evt-{len(self.timeline) + 1:06d}",
            event_type="alert_added",
            actor="system",
            detail={
                "alert_id": alert.alert_id,
                "source": alert.source,
                "reason": reason,
            },
        )
        self.timeline.append(event)
        return event
