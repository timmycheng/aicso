"""Mock数据注入测试 - 验证event_id唯一性修复"""
import asyncio

import pytest

from aicso.adapters.mock_producer import ecs_to_alert, generate_mock_alerts
from aicso.aggregator.engine import AlertAggregator
from aicso.core.approval import ApprovalEngine
from aicso.core.context import ContextManager
from aicso.core.event_bus import EventBus
from aicso.core.orchestrator import Orchestrator
from aicso.models.case import Case, CaseEvent, CaseSeverity, CaseStatus
from aicso.store.alert_store import AlertStore
from aicso.store.case_store import CaseStore
from aicso.store.database import Database


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
    aggregator = AlertAggregator()

    orch = Orchestrator(
        case_store, alert_store, context_manager, event_bus, approval_engine,
        aggregator=aggregator, llm_enabled=False,
    )
    orch.start()

    yield {
        "db": db,
        "case_store": case_store,
        "alert_store": alert_store,
        "orch": orch,
    }

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
    """验证Mock数据注入不会报错"""
    orch = setup["orch"]

    ecs_alerts = generate_mock_alerts(count=10)
    cases = set()

    for ecs in ecs_alerts:
        alert = ecs_to_alert(ecs)
        case_id = await orch.handle_alert(alert)
        assert case_id is not None
        cases.add(case_id)

    assert len(cases) > 0


@pytest.mark.asyncio
async def test_mock_inject_events_persisted(setup):
    """验证Mock注入后事件正确持久化"""
    orch = setup["orch"]
    case_store = setup["case_store"]

    ecs_alerts = generate_mock_alerts(count=3)
    case_ids = []

    for ecs in ecs_alerts:
        alert = ecs_to_alert(ecs)
        case_id = await orch.handle_alert(alert)
        case_ids.append(case_id)

    for cid in case_ids:
        events = await case_store.get_events(cid)
        assert len(events) >= 2
        event_ids = [e["event_id"] for e in events]
        assert len(event_ids) == len(set(event_ids))