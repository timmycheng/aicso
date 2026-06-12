"""审批引擎测试"""
import pytest
import asyncio

from aicso.core.approval import ApprovalEngine, ApprovalResult, ApprovalStatus, RiskLevel
from aicso.core.event_bus import EventBus


class TestApprovalEngine:
    @pytest.mark.asyncio
    async def test_low_risk_auto_approve(self):
        engine = ApprovalEngine()
        result = await engine.request_approval(
            action="query_intel", target="1.2.3.4",
            case_id="CSO-001", risk_level=RiskLevel.LOW,
        )
        assert result.approved is True
        assert result.approver == "system"

    @pytest.mark.asyncio
    async def test_medium_risk_needs_approval(self):
        engine = ApprovalEngine()
        # 启动审批请求（不会自动通过）
        task = asyncio.create_task(engine.request_approval(
            action="block_ip", target="1.2.3.4",
            case_id="CSO-001", risk_level=RiskLevel.MEDIUM,
        ))
        await asyncio.sleep(0.1)

        # 模拟审批通过
        pending = engine.get_pending()
        assert len(pending) == 1
        await engine.approve(pending[0].request_id, approver="analyst_l3")

        result = await task
        assert result.approved is True
        assert result.approver == "analyst_l3"

    @pytest.mark.asyncio
    async def test_reject(self):
        engine = ApprovalEngine()
        task = asyncio.create_task(engine.request_approval(
            action="isolate_host", target="192.168.1.100",
            case_id="CSO-001", risk_level=RiskLevel.HIGH,
        ))
        await asyncio.sleep(0.1)

        pending = engine.get_pending()
        await engine.reject(pending[0].request_id, approver="manager", reason="业务高峰期")

        result = await task
        assert result.approved is False

    @pytest.mark.asyncio
    async def test_get_pending(self):
        engine = ApprovalEngine()
        task = asyncio.create_task(engine.request_approval(
            action="block_ip", target="1.2.3.4",
            case_id="CSO-001", risk_level=RiskLevel.MEDIUM,
        ))
        await asyncio.sleep(0.1)

        pending = engine.get_pending()
        assert len(pending) == 1
        assert pending[0].action == "block_ip"

        # 清理
        await engine.approve(pending[0].request_id, approver="test")
        await task
