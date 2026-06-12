"""审批引擎"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional

import structlog

from aicso.core.event_bus import EventBus, Event, EventType

logger = structlog.get_logger()


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class RiskConfig:
    auto_approve: bool = False
    approver_role: str = ""
    timeout_minutes: int = 30
    description: str = ""


# 风险级别配置
RISK_CONFIGS: dict[RiskLevel, RiskConfig] = {
    RiskLevel.LOW: RiskConfig(
        auto_approve=True,
        description="低风险：查询类操作、信息检索",
    ),
    RiskLevel.MEDIUM: RiskConfig(
        auto_approve=False,
        approver_role="analyst_l3",
        timeout_minutes=30,
        description="中风险：封禁类操作、邮件召回",
    ),
    RiskLevel.HIGH: RiskConfig(
        auto_approve=False,
        approver_role="soc_manager",
        timeout_minutes=15,
        description="高风险：隔离主机、修改防火墙规则",
    ),
}


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    TIMEOUT = "timeout"


@dataclass
class ApprovalRequest:
    """审批请求"""
    request_id: str
    action: str
    target: str
    case_id: str
    risk_level: RiskLevel
    reason: str = ""
    status: ApprovalStatus = ApprovalStatus.PENDING
    requested_at: datetime = field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = None
    approved_by: Optional[str] = None


@dataclass
class ApprovalResult:
    """审批结果"""
    approved: bool
    approver: str = ""
    reason: str = ""


class ApprovalEngine:
    """分级审批引擎"""

    def __init__(self, event_bus: Optional[EventBus] = None):
        self.event_bus = event_bus
        self._pending: dict[str, ApprovalRequest] = {}
        self._futures: dict[str, asyncio.Future] = {}

    async def request_approval(
        self,
        action: str,
        target: str,
        case_id: str,
        risk_level: RiskLevel,
        reason: str = "",
    ) -> ApprovalResult:
        """请求审批"""
        config = RISK_CONFIGS[risk_level]

        # 低风险自动审批
        if config.auto_approve:
            logger.info("approval.auto_approved", action=action, risk=risk_level.value)
            return ApprovalResult(approved=True, approver="system")

        # 创建审批请求
        import uuid
        request = ApprovalRequest(
            request_id=str(uuid.uuid4())[:8],
            action=action,
            target=target,
            case_id=case_id,
            risk_level=risk_level,
            reason=reason,
        )
        self._pending[request.request_id] = request

        # 创建Future用于等待审批结果
        future: asyncio.Future[ApprovalResult] = asyncio.get_event_loop().create_future()
        self._futures[request.request_id] = future

        # 发布审批请求事件
        if self.event_bus:
            await self.event_bus.publish(Event(
                event_type=EventType.APPROVAL_REQUESTED,
                source="approval_engine",
                data={
                    "request_id": request.request_id,
                    "action": action,
                    "target": target,
                    "case_id": case_id,
                    "risk_level": risk_level.value,
                    "required_role": config.approver_role,
                },
                correlation_id=case_id,
            ))

        logger.info(
            "approval.requested",
            request_id=request.request_id,
            action=action,
            risk=risk_level.value,
            required_role=config.approver_role,
        )

        # 等待审批结果（带超时）
        try:
            result = await asyncio.wait_for(future, timeout=config.timeout_minutes * 60)
            return result
        except asyncio.TimeoutError:
            request.status = ApprovalStatus.TIMEOUT
            logger.warning("approval.timeout", request_id=request.request_id)
            return ApprovalResult(approved=False, reason="审批超时")

    async def approve(self, request_id: str, approver: str, reason: str = "") -> bool:
        """批准审批请求"""
        request = self._pending.get(request_id)
        if not request:
            return False

        request.status = ApprovalStatus.APPROVED
        request.approved_by = approver
        request.resolved_at = datetime.utcnow()

        future = self._futures.pop(request_id, None)
        if future and not future.done():
            future.set_result(ApprovalResult(approved=True, approver=approver, reason=reason))

        if self.event_bus:
            await self.event_bus.publish(Event(
                event_type=EventType.APPROVAL_GRANTED,
                source="approval_engine",
                data={"request_id": request_id, "approver": approver},
                correlation_id=request.case_id,
            ))

        logger.info("approval.approved", request_id=request_id, approver=approver)
        return True

    async def reject(self, request_id: str, approver: str, reason: str = "") -> bool:
        """拒绝审批请求"""
        request = self._pending.get(request_id)
        if not request:
            return False

        request.status = ApprovalStatus.REJECTED
        request.approved_by = approver
        request.resolved_at = datetime.utcnow()

        future = self._futures.pop(request_id, None)
        if future and not future.done():
            future.set_result(ApprovalResult(approved=False, approver=approver, reason=reason))

        if self.event_bus:
            await self.event_bus.publish(Event(
                event_type=EventType.APPROVAL_REJECTED,
                source="approval_engine",
                data={"request_id": request_id, "approver": approver, "reason": reason},
                correlation_id=request.case_id,
            ))

        logger.info("approval.rejected", request_id=request_id, approver=approver)
        return True

    def get_pending(self) -> list[ApprovalRequest]:
        """获取所有待审批请求"""
        return [r for r in self._pending.values() if r.status == ApprovalStatus.PENDING]
