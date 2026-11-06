"""编排引擎测试 — submit→flush 分流语义"""
import pytest
import pytest_asyncio

from aicso.agents.base import AgentResult, BaseAgent
from aicso.config import RoutingConfig, SystemOneConfig
from aicso.core.approval import ApprovalEngine
from aicso.core.context import ContextManager
from aicso.core.event_bus import EventBus
from aicso.core.orchestrator import Orchestrator
from aicso.models.alert import Alert
from aicso.router.engine import RouterEngine
from aicso.store.alert_store import AlertStore
from aicso.store.case_store import CaseStore
from aicso.store.database import Database
from aicso.store.routing_store import RoutingDecisionStore


class MockTriageAgent(BaseAgent):
    name = "triage"
    description = "Mock triage agent"

    async def run(self, task: dict, context: dict) -> AgentResult:
        return AgentResult.success(
            output={"summary": "Triage complete", "is_true_positive": True},
            confidence=0.85,
            reasoning="Mock triage reasoning",
        )


class MockAgent(BaseAgent):
    name = "mock"
    description = "Mock agent for testing"

    async def run(self, task: dict, context: dict) -> AgentResult:
        return AgentResult.success(
            output={"summary": "Mock analysis complete", "is_true_positive": True},
            confidence=0.9,
            reasoning="Mock reasoning",
            actions=["block_ip"],
        )


@pytest_asyncio.fixture
async def orchestrator():
    db = Database(":memory:")
    await db.connect()
    await db.init_tables()

    case_store = CaseStore(db)
    alert_store = AlertStore(db)
    event_bus = EventBus()
    context_manager = ContextManager(case_store, alert_store)
    approval_engine = ApprovalEngine(event_bus)

    # client=None → 纯本地兜底分流（pair规则），聚焦编排器语义
    router_engine = RouterEngine(
        case_store=case_store,
        alert_store=alert_store,
        routing_store=RoutingDecisionStore(db),
        system_one_config=SystemOneConfig(enabled=True),
        routing_config=RoutingConfig(),
        client=None,
    )
    orch = Orchestrator(
        case_store, alert_store, context_manager, event_bus, approval_engine,
        router=router_engine, llm_enabled=False,
    )
    router_engine.on_new_case = orch.handle_new_case
    orch.register_agent(MockTriageAgent())
    orch.register_agent(MockAgent())

    yield orch
    await router_engine.stop()
    await db.close()


def make_alert(alert_id, src="1.2.3.4", dst="10.0.0.1", rule_name="Rule"):
    return Alert(
        alert_id=alert_id, source="test", rule_name=rule_name,
        severity="high", src_ip=src, dst_ip=dst,
    )


class TestOrchestrator:
    @pytest.mark.asyncio
    async def test_handle_alert_creates_case(self, orchestrator):
        alert = make_alert("A-001", dst="192.168.1.100", rule_name="SQL Injection")
        await orchestrator.handle_alert(alert)
        decisions = await orchestrator.router.flush()
        assert len(decisions) == 1
        case_id = decisions[0].case_id
        assert case_id.startswith("CSO-")

        stored_alert = await orchestrator.alert_store.get("A-001")
        assert stored_alert is not None
        assert stored_alert["case_id"] == case_id

    @pytest.mark.asyncio
    async def test_handle_alert_aggregates_same_pair(self, orchestrator):
        """同src_ip+dst_ip的告警应分流到同一Case"""
        await orchestrator.handle_alert(make_alert("A-001", rule_name="Brute Force"))
        await orchestrator.handle_alert(make_alert("A-002", rule_name="Brute Force 2"))
        decisions = await orchestrator.router.flush()

        assert decisions[0].case_id == decisions[1].case_id
        assert decisions[1].decision == "route_to"

    @pytest.mark.asyncio
    async def test_handle_alert_no_aggregate_different_dst(self, orchestrator):
        """同src_ip但不同dst_ip不应分流到同一Case"""
        await orchestrator.handle_alert(make_alert("A-001", dst="10.0.0.1", rule_name="Rule 1"))
        await orchestrator.handle_alert(make_alert("A-002", dst="10.0.0.2", rule_name="Rule 2"))
        decisions = await orchestrator.router.flush()

        assert decisions[0].case_id != decisions[1].case_id

    @pytest.mark.asyncio
    async def test_handle_alert_different_ips(self, orchestrator):
        await orchestrator.handle_alert(make_alert("A-001", rule_name="Rule 1"))
        await orchestrator.handle_alert(make_alert("A-002", src="5.6.7.8", rule_name="Rule 2"))
        decisions = await orchestrator.router.flush()

        assert decisions[0].case_id != decisions[1].case_id

    @pytest.mark.asyncio
    async def test_routed_alert_has_case_id(self, orchestrator):
        await orchestrator.handle_alert(make_alert("A-001", rule_name="Rule 1"))
        await orchestrator.handle_alert(make_alert("A-002", rule_name="Rule 2"))
        decisions = await orchestrator.router.flush()
        case_id = decisions[0].case_id

        stored = await orchestrator.alert_store.get("A-002")
        assert stored["case_id"] == case_id
        assert stored["routed_at"] is not None
        assert stored["routing_source"] == "fallback"

    @pytest.mark.asyncio
    async def test_case_metadata_has_routing_info(self, orchestrator):
        await orchestrator.handle_alert(make_alert("A-001", rule_name="Test"))
        decisions = await orchestrator.router.flush()
        case_id = decisions[0].case_id

        case = await orchestrator.case_store.get(case_id)
        import json
        metadata = (
            json.loads(case["metadata"]) if isinstance(case["metadata"], str) else case["metadata"]
        )
        assert metadata["routing"]["created_by"] == "auto_from_alert"
        # Case时间线包含路由汇入事件
        events = await orchestrator.case_store.get_events(case_id)
        assert any(e["event_type"] == "alert_added" for e in events)

    @pytest.mark.asyncio
    async def test_agent_registered(self, orchestrator):
        agent = orchestrator.get_agent("mock")
        assert agent.name == "mock"

    @pytest.mark.asyncio
    async def test_agent_not_found(self, orchestrator):
        with pytest.raises(ValueError, match="Agent not found"):
            orchestrator.get_agent("nonexistent")
