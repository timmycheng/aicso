"""OpsRecord 与上下文组装API测试（issue #9）"""
from __future__ import annotations

from aicso.agents.base import AgentResult, BaseAgent
from aicso.config import RoutingConfig, SystemOneConfig
from aicso.core.approval import ApprovalEngine
from aicso.core.context import ContextManager
from aicso.core.event_bus import EventBus
from aicso.core.ops import OpsAction, OpsService
from aicso.core.orchestrator import Orchestrator
from aicso.models.alert import Alert
from aicso.models.case import Case, CaseSeverity, CaseStatus
from aicso.models.ops import ActorType
from aicso.router.engine import RouterEngine
from aicso.store.alert_store import AlertStore
from aicso.store.case_store import CaseStore
from aicso.store.database import Database
from aicso.store.ops_store import OpsRecordStore
from aicso.store.routing_store import RoutingDecisionStore


async def make_setup():
    db = Database(":memory:")
    await db.connect()
    await db.init_tables()
    case_store = CaseStore(db)
    alert_store = AlertStore(db)
    ops_store = OpsRecordStore(db)
    ops_service = OpsService(case_store, ops_store)
    return db, case_store, alert_store, ops_store, ops_service


async def seed_case(db, case_id="CSO-OPS-1"):
    case_store = CaseStore(db)
    alert_store = AlertStore(db)
    case = Case(case_id=case_id, title="[t] 测试事件",
                severity=CaseSeverity.MEDIUM, status=CaseStatus.NEW)
    case.record_case_created()
    await case_store.create(case)
    for event in case.timeline:
        await case_store.add_event(case_id, event)
    await alert_store.create(Alert(
        alert_id="A-1", source="t", rule_name="sql injection", severity="high",
        src_ip="9.9.9.9", dst_ip="10.0.0.5", case_id=case_id,
    ))
    return case


class TestOpsService:
    async def test_record_op_writes_table_and_timeline(self):
        db, case_store, alert_store, ops_store, ops_service = await make_setup()
        await seed_case(db)

        record = await ops_service.record_op(
            "CSO-OPS-1", actor="analyst_zhang", actor_type=ActorType.HUMAN,
            action=OpsAction.ADD_CONTEXT,
            params={"log": "netflow snippet..."},
            result={"accepted": True},
            summary="补充流量日志上下文",
        )
        assert record.id

        rows = await ops_store.list_by_case("CSO-OPS-1")
        assert len(rows) == 1
        assert rows[0]["actor"] == "analyst_zhang"
        assert rows[0]["actor_type"] == "human"
        assert rows[0]["action"] == "add_context"

        # 时间线镜像
        events = await case_store.get_events("CSO-OPS-1")
        ops_events = [e for e in events if e["event_type"] == "ops_executed"]
        assert len(ops_events) == 1
        assert "补充流量日志上下文" in ops_events[0]["detail"]
        await db.close()

    async def test_multiple_ops_ordering(self):
        db, *_, ops_store, ops_service = await make_setup()
        await seed_case(db)
        await ops_service.record_op("CSO-OPS-1", "a1", ActorType.HUMAN, OpsAction.ASSIGN)
        await ops_service.record_op("CSO-OPS-1", "agent", ActorType.AGENT, OpsAction.INVESTIGATE)
        rows = await ops_store.list_by_case("CSO-OPS-1")
        assert len(rows) == 2
        assert {r["actor_type"] for r in rows} == {"human", "agent"}
        await db.close()


class TestBuildContext:
    async def test_full_context_contains_ops_entities_relations(self):
        db, case_store, alert_store, ops_store, ops_service = await make_setup()
        await seed_case(db)
        await ops_service.record_op("CSO-OPS-1", "a1", ActorType.HUMAN,
                                    OpsAction.MANUAL_HANDLE, summary="处置完成")

        cm = ContextManager(case_store, alert_store, ops_store=ops_store)
        context = await cm.build_full_context("CSO-OPS-1")

        assert context["case"]["case_id"] == "CSO-OPS-1"
        assert len(context["alerts"]) == 1
        assert len(context["ops_records"]) == 1
        assert context["entities"]["src_ips"] == ["9.9.9.9"]
        assert context["entities"]["dst_ips"] == ["10.0.0.5"]
        assert context["relations"] == {"merged_into": None, "split_from": None}
        await db.close()

    async def test_relations_reflect_merge(self):
        db, case_store, alert_store, ops_store, ops_service = await make_setup()
        await seed_case(db, "CSO-OPS-2")
        # 模拟合并重定向
        await case_store.update_relation("CSO-OPS-2", merged_into="CSO-MAIN")

        cm = ContextManager(case_store, alert_store, ops_store=ops_store)
        context = await cm.build_full_context("CSO-OPS-2")
        assert context["relations"]["merged_into"] == "CSO-MAIN"
        await db.close()


class MockAgent(BaseAgent):
    name = "investigation"
    description = "mock"

    async def run(self, task: dict, context: dict) -> AgentResult:
        return AgentResult.success(output={"attack_chain": "x"}, confidence=0.8)


class TestOrchestratorOps:
    async def test_investigate_records_ops(self):
        db, case_store, alert_store, ops_store, ops_service = await make_setup()
        await seed_case(db)
        orch = Orchestrator(
            case_store, alert_store,
            ContextManager(case_store, alert_store, ops_store=ops_store),
            EventBus(), ApprovalEngine(EventBus()),
            router=RouterEngine(
                case_store, alert_store, RoutingDecisionStore(db),
                SystemOneConfig(enabled=True), RoutingConfig(), client=None,
            ),
            ops_service=ops_service,
        )
        orch.register_agent(MockAgent())
        # intel agent未注册 → gather返回异常，不影响操作记录
        await orch.investigate_case("CSO-OPS-1")

        rows = await ops_store.list_by_case("CSO-OPS-1")
        assert len(rows) == 1
        assert rows[0]["action"] == "investigate"
        assert rows[0]["actor_type"] == "agent"
        await db.close()
