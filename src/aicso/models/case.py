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


class CaseEventType(str, Enum):
    """Case事件类型"""
    # Case生命周期
    CASE_CREATED = "case_created"
    CASE_UPDATED = "case_updated"
    CASE_CLOSED = "case_closed"
    CASE_REOPENED = "case_reopened"

    # 状态变更
    STATUS_CHANGED = "status_changed"
    PRIORITY_CHANGED = "priority_changed"
    SEVERITY_CHANGED = "severity_changed"

    # 告警关联
    ALERT_ADDED = "alert_added"
    ALERT_REMOVED = "alert_removed"
    ALERT_FALSE_POSITIVE = "alert_false_positive"

    # 分配与指派
    ASSIGNED = "assigned"
    UNASSIGNED = "unassigned"

    # AI分析
    AI_TRIAGE_COMPLETED = "ai_triage_completed"
    AI_RULE_GENERATED = "ai_rule_generated"
    AI_INVESTIGATION_COMPLETED = "ai_investigation_completed"
    AI_REPORT_GENERATED = "ai_report_generated"

    # 聚合规则
    AGGREGATION_RULE_CREATED = "aggregation_rule_created"
    AGGREGATION_RULE_UPDATED = "aggregation_rule_updated"

    # 响应动作
    ACTION_EXECUTED = "action_executed"
    ACTION_APPROVED = "action_approved"
    ACTION_REJECTED = "action_rejected"

    # Playbook
    PLAYBOOK_STARTED = "playbook_started"
    PLAYBOOK_COMPLETED = "playbook_completed"
    PLAYBOOK_FAILED = "playbook_failed"

    # 备注
    NOTE_ADDED = "note_added"

    # 资产与IoC
    ASSET_LINKED = "asset_linked"
    IOC_ADDED = "ioc_added"


# 事件类型显示名称映射
EVENT_TYPE_LABELS: dict[str, str] = {
    "case_created": "Case创建",
    "case_updated": "Case更新",
    "case_closed": "Case关闭",
    "case_reopened": "Case重新打开",
    "status_changed": "状态变更",
    "priority_changed": "优先级变更",
    "severity_changed": "严重级别变更",
    "alert_added": "关联告警",
    "alert_removed": "移除告警",
    "alert_false_positive": "标记误报",
    "assigned": "分配负责人",
    "unassigned": "取消分配",
    "ai_triage_completed": "AI分诊完成",
    "ai_rule_generated": "AI聚合规则生成",
    "ai_investigation_completed": "AI调查完成",
    "ai_report_generated": "AI报告生成",
    "aggregation_rule_created": "聚合规则创建",
    "aggregation_rule_updated": "聚合规则更新",
    "action_executed": "执行响应动作",
    "action_approved": "动作审批通过",
    "action_rejected": "动作审批拒绝",
    "playbook_started": "Playbook启动",
    "playbook_completed": "Playbook完成",
    "playbook_failed": "Playbook失败",
    "note_added": "添加备注",
    "asset_linked": "关联资产",
    "ioc_added": "添加IoC",
}

# 事件类型图标映射
EVENT_TYPE_ICONS: dict[str, str] = {
    "case_created": "&#128196;",
    "case_updated": "&#128221;",
    "case_closed": "&#9989;",
    "case_reopened": "&#128260;",
    "status_changed": "&#128900;",
    "priority_changed": "&#128315;",
    "severity_changed": "&#9888;",
    "alert_added": "&#128276;",
    "alert_removed": "&#128263;",
    "alert_false_positive": "&#10060;",
    "assigned": "&#128100;",
    "unassigned": "&#128100;",
    "ai_triage_completed": "&#129302;",
    "ai_rule_generated": "&#129504;",
    "ai_investigation_completed": "&#128269;",
    "ai_report_generated": "&#128196;",
    "aggregation_rule_created": "&#9881;",
    "aggregation_rule_updated": "&#9881;",
    "action_executed": "&#9889;",
    "action_approved": "&#9989;",
    "action_rejected": "&#10060;",
    "playbook_started": "&#128203;",
    "playbook_completed": "&#9989;",
    "playbook_failed": "&#10060;",
    "note_added": "&#128221;",
    "asset_linked": "&#127970;",
    "ioc_added": "&#128274;",
}

# 事件类型颜色映射
EVENT_TYPE_COLORS: dict[str, str] = {
    "case_created": "#1565c0",
    "case_updated": "#1565c0",
    "case_closed": "#2e7d32",
    "case_reopened": "#ef6c00",
    "status_changed": "#7b1fa2",
    "priority_changed": "#e67e22",
    "severity_changed": "#c0392b",
    "alert_added": "#2980b9",
    "alert_removed": "#e67e22",
    "alert_false_positive": "#c0392b",
    "assigned": "#ef6c00",
    "unassigned": "#616161",
    "ai_triage_completed": "#00bcd4",
    "ai_rule_generated": "#00bcd4",
    "ai_investigation_completed": "#00bcd4",
    "ai_report_generated": "#00bcd4",
    "aggregation_rule_created": "#ff9800",
    "aggregation_rule_updated": "#ff9800",
    "action_executed": "#f44336",
    "action_approved": "#4caf50",
    "action_rejected": "#f44336",
    "playbook_started": "#9c27b0",
    "playbook_completed": "#4caf50",
    "playbook_failed": "#f44336",
    "note_added": "#607d8b",
    "asset_linked": "#795548",
    "ioc_added": "#ff5722",
}


class CaseEvent(BaseModel):
    """Case事件/时间线条目"""
    event_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    event_type: str  # CaseEventType value
    actor: str  # user_id 或 agent_name
    detail: dict = Field(default_factory=dict)

    @property
    def label(self) -> str:
        """获取事件类型的显示名称"""
        return EVENT_TYPE_LABELS.get(self.event_type, self.event_type)

    @property
    def icon(self) -> str:
        """获取事件类型的图标"""
        return EVENT_TYPE_ICONS.get(self.event_type, "&#128196;")

    @property
    def color(self) -> str:
        """获取事件类型的颜色"""
        return EVENT_TYPE_COLORS.get(self.event_type, "#666")


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

    def _create_event(self, event_type: str, actor: str, detail: dict) -> CaseEvent:
        """创建事件的内部方法"""
        event = CaseEvent(
            event_id=f"{self.case_id}-evt-{len(self.timeline) + 1:06d}",
            event_type=event_type,
            actor=actor,
            detail=detail,
        )
        self.timeline.append(event)
        self.updated_at = datetime.utcnow()
        return event

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
        if new_status == CaseStatus.CLOSED:
            self.closed_at = datetime.utcnow()
        elif old_status == CaseStatus.CLOSED and new_status == CaseStatus.NEW:
            self.closed_at = None
            event = self._create_event(
                CaseEventType.CASE_REOPENED, actor,
                {"reason": reason, "from": old_status.value, "to": new_status.value}
            )
            return event

        event = self._create_event(
            CaseEventType.STATUS_CHANGED, actor,
            {"from": old_status.value, "to": new_status.value, "reason": reason}
        )
        return event

    def add_alert(self, alert: Alert, reason: str = "") -> CaseEvent:
        """添加告警到Case"""
        self.alerts.append(alert)
        event = self._create_event(
            CaseEventType.ALERT_ADDED, "system",
            {
                "alert_id": alert.alert_id,
                "source": alert.source,
                "rule_name": alert.rule_name,
                "severity": alert.severity,
                "src_ip": alert.src_ip,
                "dst_ip": alert.dst_ip,
                "reason": reason,
            }
        )
        return event

    def remove_alert(self, alert_id: str, actor: str, reason: str = "") -> CaseEvent:
        """移除告警"""
        self.alerts = [a for a in self.alerts if a.alert_id != alert_id]
        event = self._create_event(
            CaseEventType.ALERT_REMOVED, actor,
            {"alert_id": alert_id, "reason": reason}
        )
        return event

    def mark_alert_false_positive(self, alert_id: str, actor: str, reason: str = "") -> CaseEvent:
        """标记告警为误报"""
        event = self._create_event(
            CaseEventType.ALERT_FALSE_POSITIVE, actor,
            {"alert_id": alert_id, "reason": reason}
        )
        return event

    def set_priority(self, new_priority: CasePriority, actor: str, reason: str = "") -> CaseEvent:
        """设置优先级"""
        old_priority = self.priority
        self.priority = new_priority
        event = self._create_event(
            CaseEventType.PRIORITY_CHANGED, actor,
            {"from": old_priority.value, "to": new_priority.value, "reason": reason}
        )
        return event

    def set_severity(self, new_severity: CaseSeverity, actor: str, reason: str = "") -> CaseEvent:
        """设置严重级别"""
        old_severity = self.severity
        self.severity = new_severity
        event = self._create_event(
            CaseEventType.SEVERITY_CHANGED, actor,
            {"from": old_severity.value, "to": new_severity.value, "reason": reason}
        )
        return event

    def assign(self, assignee_id: str, actor: str, reason: str = "") -> CaseEvent:
        """分配负责人"""
        old_assignee = self.assignee_id
        self.assignee_id = assignee_id
        event = self._create_event(
            CaseEventType.ASSIGNED, actor,
            {"from": old_assignee, "to": assignee_id, "reason": reason}
        )
        return event

    def unassign(self, actor: str, reason: str = "") -> CaseEvent:
        """取消分配"""
        old_assignee = self.assignee_id
        self.assignee_id = None
        event = self._create_event(
            CaseEventType.UNASSIGNED, actor,
            {"from": old_assignee, "reason": reason}
        )
        return event

    def add_note(self, note: str, actor: str) -> CaseEvent:
        """添加备注"""
        event = self._create_event(
            CaseEventType.NOTE_ADDED, actor,
            {"note": note}
        )
        return event

    def record_ai_triage(self, summary: str, recommendation: str, agent_name: str = "triage") -> CaseEvent:
        """记录AI分诊结果"""
        self.ai_summary = summary
        self.ai_recommendation = recommendation
        event = self._create_event(
            CaseEventType.AI_TRIAGE_COMPLETED, agent_name,
            {"summary": summary, "recommendation": recommendation}
        )
        return event

    def record_ai_rule_generated(self, rule_info: dict, agent_name: str = "triage") -> CaseEvent:
        """记录AI聚合规则生成"""
        event = self._create_event(
            CaseEventType.AI_RULE_GENERATED, agent_name,
            rule_info
        )
        return event

    def record_ai_investigation(self, result: dict, agent_name: str = "investigation") -> CaseEvent:
        """记录AI调查结果"""
        event = self._create_event(
            CaseEventType.AI_INVESTIGATION_COMPLETED, agent_name,
            {"result_keys": list(result.keys())}
        )
        return event

    def record_ai_report(self, report_summary: str, agent_name: str = "report") -> CaseEvent:
        """记录AI报告生成"""
        event = self._create_event(
            CaseEventType.AI_REPORT_GENERATED, agent_name,
            {"report_summary": report_summary[:500]}
        )
        return event

    def record_aggregation_rule_created(self, rule_info: dict) -> CaseEvent:
        """记录聚合规则创建"""
        event = self._create_event(
            CaseEventType.AGGREGATION_RULE_CREATED, "system",
            rule_info
        )
        return event

    def record_aggregation_rule_updated(self, rule_info: dict) -> CaseEvent:
        """记录聚合规则更新"""
        event = self._create_event(
            CaseEventType.AGGREGATION_RULE_UPDATED, "system",
            rule_info
        )
        return event

    def record_action_executed(self, action_type: str, target: str, result: str, actor: str) -> CaseEvent:
        """记录响应动作执行"""
        event = self._create_event(
            CaseEventType.ACTION_EXECUTED, actor,
            {"action_type": action_type, "target": target, "result": result}
        )
        return event

    def record_playbook_started(self, playbook_id: str, run_id: str) -> CaseEvent:
        """记录Playbook启动"""
        event = self._create_event(
            CaseEventType.PLAYBOOK_STARTED, "system",
            {"playbook_id": playbook_id, "run_id": run_id}
        )
        return event

    def record_playbook_completed(self, playbook_id: str, run_id: str, result: dict) -> CaseEvent:
        """记录Playbook完成"""
        event = self._create_event(
            CaseEventType.PLAYBOOK_COMPLETED, "system",
            {"playbook_id": playbook_id, "run_id": run_id, "result": result}
        )
        return event

    def record_playbook_failed(self, playbook_id: str, run_id: str, error: str) -> CaseEvent:
        """记录Playbook失败"""
        event = self._create_event(
            CaseEventType.PLAYBOOK_FAILED, "system",
            {"playbook_id": playbook_id, "run_id": run_id, "error": error}
        )
        return event

    def record_case_created(self, source: str = "manual") -> CaseEvent:
        """记录Case创建"""
        event = self._create_event(
            CaseEventType.CASE_CREATED, "system",
            {"source": source, "title": self.title}
        )
        return event
