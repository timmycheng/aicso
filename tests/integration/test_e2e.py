"""集成测试 - 端到端流程"""
import pytest
import pytest_asyncio
import json
import tempfile
import os

from aicso.store.database import Database
from aicso.store.case_store import CaseStore
from aicso.store.alert_store import AlertStore
from aicso.models.case import Case, CaseStatus, CaseSeverity
from aicso.models.alert import Alert
from aicso.adapters.base import JSONFileAdapter


@pytest_asyncio.fixture
async def db():
    db = Database(":memory:")
    await db.connect()
    await db.init_tables()
    yield db
    await db.close()


class TestEndToEnd:
    @pytest.mark.asyncio
    async def test_full_case_lifecycle(self, db):
        """测试Case完整生命周期"""
        case_store = CaseStore(db)
        alert_store = AlertStore(db)

        # 1. 创建Case
        case = Case(
            case_id="CSO-INT-001",
            title="Integration Test Case",
            severity=CaseSeverity.HIGH,
        )
        await case_store.create(case)

        # 2. 添加告警
        alert = Alert(
            alert_id="A-INT-001",
            source="suricata",
            rule_name="Brute Force",
            severity="high",
            src_ip="1.2.3.4",
            dst_ip="192.168.1.100",
        )
        await alert_store.create(alert)
        await alert_store.update_case_id("A-INT-001", "CSO-INT-001")

        # 3. 验证Case和告警关联
        case_data = await case_store.get("CSO-INT-001")
        assert case_data is not None

        alerts = await alert_store.list_alerts(case_id="CSO-INT-001")
        assert len(alerts) == 1
        assert alerts[0]["alert_id"] == "A-INT-001"

        # 4. 状态流转
        case_obj = Case(
            case_id=case_data["case_id"],
            title=case_data["title"],
            severity=CaseSeverity(case_data["severity"]),
            status=CaseStatus(case_data["status"]),
        )
        for target_status, reason in [
            (CaseStatus.ASSIGNED, ""),
            (CaseStatus.INVESTIGATING, ""),
            (CaseStatus.RESOLVED, "误报"),
        ]:
            event = case_obj.transition_to(target_status, actor="analyst_1", reason=reason)
            await case_store.add_event("CSO-INT-001", event)
        await case_store.update(case_obj)

        # 5. 验证最终状态
        final = await case_store.get("CSO-INT-001")
        assert final["status"] == "resolved"

        # 6. 验证事件时间线
        events = await case_store.get_events("CSO-INT-001")
        assert len(events) == 3  # assigned, investigating, resolved

    @pytest.mark.asyncio
    async def test_json_adapter_ingest(self, db):
        """测试JSON文件适配器批量导入告警"""
        alert_data = [
            {
                "alert_id": "JSON-001",
                "source": "waf",
                "rule_name": "SQL Injection",
                "severity": "high",
                "src_ip": "10.0.0.1",
                "dst_ip": "192.168.1.50",
                "timestamp": "2026-06-12T10:00:00",
            },
            {
                "alert_id": "JSON-002",
                "source": "edr",
                "rule_name": "Suspicious Process",
                "severity": "medium",
                "src_ip": "10.0.0.2",
                "dst_ip": "192.168.1.60",
                "timestamp": "2026-06-12T10:05:00",
            },
        ]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(alert_data, f)
            f.flush()

            adapter = JSONFileAdapter()
            await adapter.connect({"file_path": f.name})
            alerts = await adapter.poll(since=None)

            assert len(alerts) == 2
            assert alerts[0].alert_id == "JSON-001"
            assert alerts[1].source == "edr"

        os.unlink(f.name)
