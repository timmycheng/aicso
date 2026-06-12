"""编排引擎测试"""
import pytest
import pytest_asyncio

from aicso.agents.base import BaseAgent, AgentResult
from aicso.core.orchestrator import Orchestrator
from aicso.core.event_bus import EventBus
from aicso.core.context import ContextManager
from aicso.core.approval import ApprovalEngine
from aicso.aggregator.engine import AlertAggregator
from aicso.store.database import Database
from aicso.store.case_store import CaseStore
from aicso.store.alert_store import AlertStore
from aicso.models.alert import Alert


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
    aggregator = AlertAggregator()

    orch = Orchestrator(case_store, alert_store, context_manager, event_bus, approval_engine, aggregator)
    orch.register_agent(MockTriageAgent())
    orch.register_agent(MockAgent())

    yield orch
    await db.close()


class TestOrchestrator:
    @pytest.mark.asyncio
    async def test_handle_alert_creates_case(self, orchestrator):
        alert = Alert(
            alert_id="A-001", source="suricata",
            rule_name="SQL Injection", severity="high",
            src_ip="1.2.3.4", dst_ip="192.168.1.100",
        )
        case_id = await orchestrator.handle_alert(alert)
        assert case_id is not None
        assert case_id.startswith("CSO-")

    @pytest.mark.asyncio
    async def test_handle_alert_aggregates(self, orchestrator):
        alert1 = Alert(alert_id="A-001", source="test", src_ip="1.2.3.4", rule_name="Rule 1")
        case_id1 = await orchestrator.handle_alert(alert1)

        alert2 = Alert(alert_id="A-002", source="test", src_ip="1.2.3.4", rule_name="Rule 2")
        case_id2 = await orchestrator.handle_alert(alert2)

        assert case_id1 == case_id2

    @pytest.mark.asyncio
    async def test_handle_alert_different_ips(self, orchestrator):
        alert1 = Alert(alert_id="A-001", source="test", src_ip="1.2.3.4", rule_name="Rule 1")
        case_id1 = await orchestrator.handle_alert(alert1)

        alert2 = Alert(alert_id="A-002", source="test", src_ip="5.6.7.8", rule_name="Rule 2")
        case_id2 = await orchestrator.handle_alert(alert2)

        assert case_id1 != case_id2

    @pytest.mark.asyncio
    async def test_agent_registered(self, orchestrator):
        agent = orchestrator.get_agent("mock")
        assert agent.name == "mock"

    @pytest.mark.asyncio
    async def test_agent_not_found(self, orchestrator):
        with pytest.raises(ValueError, match="Agent not found"):
            orchestrator.get_agent("nonexistent")
