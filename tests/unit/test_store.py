"""存储层测试"""
import pytest
import pytest_asyncio
from datetime import datetime

from aicso.store.database import Database
from aicso.store.case_store import CaseStore
from aicso.store.alert_store import AlertStore
from aicso.models.case import Case, CaseStatus, CaseSeverity, CasePriority, CaseEvent
from aicso.models.alert import Alert


@pytest_asyncio.fixture
async def db():
    db = Database(":memory:")
    await db.connect()
    await db.init_tables()
    yield db
    await db.close()


@pytest_asyncio.fixture
async def case_store(db):
    return CaseStore(db)


@pytest_asyncio.fixture
async def alert_store(db):
    return AlertStore(db)


class TestCaseStore:
    @pytest.mark.asyncio
    async def test_create_and_get(self, case_store):
        case = Case(case_id="CSO-001", title="Test Case", severity=CaseSeverity.HIGH)
        await case_store.create(case)
        result = await case_store.get("CSO-001")
        assert result is not None
        assert result["case_id"] == "CSO-001"
        assert result["title"] == "Test Case"
        assert result["severity"] == "high"

    @pytest.mark.asyncio
    async def test_get_nonexistent(self, case_store):
        result = await case_store.get("NONEXISTENT")
        assert result is None

    @pytest.mark.asyncio
    async def test_update(self, case_store):
        case = Case(case_id="CSO-001", title="Original")
        await case_store.create(case)
        case.title = "Updated"
        case.status = CaseStatus.ASSIGNED
        await case_store.update(case)
        result = await case_store.get("CSO-001")
        assert result["title"] == "Updated"
        assert result["status"] == "assigned"

    @pytest.mark.asyncio
    async def test_list_cases(self, case_store):
        for i in range(5):
            await case_store.create(Case(case_id=f"CSO-{i:03d}", title=f"Case {i}"))
        cases = await case_store.list_cases(limit=10)
        assert len(cases) == 5

    @pytest.mark.asyncio
    async def test_list_cases_with_filter(self, case_store):
        await case_store.create(Case(case_id="CSO-001", title="A", severity=CaseSeverity.HIGH))
        await case_store.create(Case(case_id="CSO-002", title="B", severity=CaseSeverity.LOW))
        cases = await case_store.list_cases(severity="high")
        assert len(cases) == 1
        assert cases[0]["case_id"] == "CSO-001"

    @pytest.mark.asyncio
    async def test_add_event(self, case_store):
        case = Case(case_id="CSO-001", title="Test")
        await case_store.create(case)
        event = CaseEvent(
            event_id="EVT-001",
            event_type="status_change",
            actor="user",
            detail={"from": "new", "to": "assigned"},
        )
        await case_store.add_event("CSO-001", event)
        events = await case_store.get_events("CSO-001")
        assert len(events) == 1
        assert events[0]["event_type"] == "status_change"

    @pytest.mark.asyncio
    async def test_count(self, case_store):
        for i in range(3):
            await case_store.create(Case(case_id=f"CSO-{i:03d}", title=f"Case {i}"))
        count = await case_store.count()
        assert count == 3


class TestAlertStore:
    @pytest.mark.asyncio
    async def test_create_and_get(self, alert_store):
        alert = Alert(alert_id="A-001", source="suricata", rule_name="SQL Injection", severity="high")
        await alert_store.create(alert)
        result = await alert_store.get("A-001")
        assert result is not None
        assert result["alert_id"] == "A-001"
        assert result["source"] == "suricata"

    @pytest.mark.asyncio
    async def test_list_alerts(self, alert_store):
        for i in range(5):
            await alert_store.create(Alert(alert_id=f"A-{i:03d}", source="test"))
        alerts = await alert_store.list_alerts(limit=10)
        assert len(alerts) == 5

    @pytest.mark.asyncio
    async def test_list_alerts_by_source(self, alert_store):
        await alert_store.create(Alert(alert_id="A-001", source="suricata"))
        await alert_store.create(Alert(alert_id="A-002", source="edr"))
        alerts = await alert_store.list_alerts(source="suricata")
        assert len(alerts) == 1

    @pytest.mark.asyncio
    async def test_update_case_id(self, alert_store, case_store):
        await case_store.create(Case(case_id="CSO-001", title="Parent Case"))
        await alert_store.create(Alert(alert_id="A-001", source="test"))
        await alert_store.update_case_id("A-001", "CSO-001")
        result = await alert_store.get("A-001")
        assert result["case_id"] == "CSO-001"

    @pytest.mark.asyncio
    async def test_count(self, alert_store):
        for i in range(3):
            await alert_store.create(Alert(alert_id=f"A-{i:03d}", source="test"))
        count = await alert_store.count()
        assert count == 3
