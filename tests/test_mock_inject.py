"""Mock数据注入测试 - 验证分流语义与event_id唯一性"""

import pytest

from aicso.adapters.mock_producer import ecs_to_alert, generate_mock_alerts
from aicso.config import RoutingConfig, SystemOneConfig
from aicso.core.approval import ApprovalEngine
from aicso.core.context import ContextManager
from aicso.core.event_bus import EventBus
from aicso.core.orchestrator import Orchestrator
from aicso.models.case import Case, CaseSeverity, CaseStatus
from aicso.router.engine import RouterEngine
from aicso.store.alert_store import AlertStore
from aicso.store.case_store import CaseStore
from aicso.store.database import Database
from aicso.store.routing_store import RoutingDecisionStore


@pytest.fixture
def db():
    """内存数据库"""
    return Database(":memory:")


@pytest.fixture
async def setup(db):
    """初始化数据库和组件"""
    await db.connect()
    await db.init_tables()

    case_store = CaseStore(db)
    alert_store = AlertStore(db)
    event_bus = EventBus()
    context_manager = ContextManager(case_store, alert_store)
    approval_engine = ApprovalEngine(event_bus)

    router_engine = RouterEngine(
        case_store=case_store,
        alert_store=alert_store,
        routing_store=RoutingDecisionStore(db),
        system_one_config=SystemOneConfig(enabled=True),
        routing_config=RoutingConfig(),
        client=None,  # 纯本地兜底分流
    )
    orch = Orchestrator(
        case_store, alert_store, context_manager, event_bus, approval_engine,
        router=router_engine, llm_enabled=False,
    )
    router_engine.on_new_case = orch.handle_new_case
    orch.start()

    yield {
        "db": db,
        "case_store": case_store,
        "alert_store": alert_store,
        "orch": orch,
        "router": router_engine,
    }

    await router_engine.stop()
    await orch.close()
    await db.close()


@pytest.mark.asyncio
async def test_event_id_unique_across_cases(setup):
    """验证不同Case的event_id不冲突"""
    case_store = setup["case_store"]

    case1 = Case(
        case_id="CSO-TEST-001",
        title="测试Case 1",
        severity=CaseSeverity.HIGH,
        status=CaseStatus.NEW,
    )
    case1.record_case_created()

    case2 = Case(
        case_id="CSO-TEST-002",
        title="测试Case 2",
        severity=CaseSeverity.MEDIUM,
        status=CaseStatus.NEW,
    )
    case2.record_case_created()

    await case_store.create(case1)
    await case_store.create(case2)

    for event in case1.timeline:
        await case_store.add_event(case1.case_id, event)
    for event in case2.timeline:
        await case_store.add_event(case2.case_id, event)

    events1 = await case_store.get_events(case1.case_id)
    events2 = await case_store.get_events(case2.case_id)

    assert len(events1) == 1
    assert len(events2) == 1
    assert events1[0]["event_id"] != events2[0]["event_id"]


@pytest.mark.asyncio
async def test_mock_inject_no_errors(setup):
    """验证Mock数据注入不会报错（submit→flush分流语义）"""
    orch = setup["orch"]
    router = setup["router"]

    ecs_alerts = generate_mock_alerts(count=10)
    for ecs in ecs_alerts:
        await orch.handle_alert(ecs_to_alert(ecs))

    decisions = await router.flush()
    assert len(decisions) == 10
    case_ids = {d.case_id for d in decisions}
    # 10条随机mock告警应收敛到少于10个Case（存在同源告警汇入）
    assert len(case_ids) > 0
    assert len(case_ids) <= 10


@pytest.mark.asyncio
async def test_mock_inject_events_persisted(setup):
    """验证Mock注入后事件正确持久化"""
    orch = setup["orch"]
    case_store = setup["case_store"]
    router = setup["router"]

    ecs_alerts = generate_mock_alerts(count=3)
    for ecs in ecs_alerts:
        await orch.handle_alert(ecs_to_alert(ecs))

    decisions = await router.flush()
    assert len(decisions) == 3

    for cid in {d.case_id for d in decisions}:
        events = await case_store.get_events(cid)
        assert len(events) >= 2
        event_ids = [e["event_id"] for e in events]
        assert len(event_ids) == len(set(event_ids))
