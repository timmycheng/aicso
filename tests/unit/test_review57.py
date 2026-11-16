"""issue #57 分支1回归：degraded/local_mode拆分、指标补齐、复核开关、
merge/split落OpsRecord（Case搜索见test_store.py、Playbook执行见test_playbook.py）
"""
from __future__ import annotations

import json

from aicso.config import RoutingConfig, SystemOneConfig
from aicso.core.ops import OpsService
from aicso.models.alert import Alert
from aicso.models.case import Case, CaseSeverity, CaseStatus
from aicso.playbook.executor import ActionRegistry  # noqa: F401 (re-export便利)
from aicso.router.engine import RouterEngine
from aicso.router.fallback import LocalFallback
from aicso.router.index import CaseRoutingIndex
from aicso.router.merge import MergeSplitEngine
from aicso.router.metrics import RouterMetrics
from aicso.store.alert_store import AlertStore
from aicso.store.case_store import CaseStore
from aicso.store.database import Database
from aicso.store.ops_store import OpsRecordStore
from aicso.store.routing_store import RoutingDecisionStore


def make_alert(alert_id="A-001", src="1.2.3.4", dst="10.0.0.1", **kw):
    return Alert(
        alert_id=alert_id, source="test",
        rule_name=kw.pop("rule_name", "Test Rule"),
        severity=kw.pop("severity", "high"),
        src_ip=src, dst_ip=dst, **kw,
    )


async def make_engine(client=None, **scfg_overrides):
    db = Database(":memory:")
    await db.connect()
    await db.init_tables()
    scfg = SystemOneConfig(enabled=True, **scfg_overrides)
    engine = RouterEngine(
        case_store=CaseStore(db),
        alert_store=AlertStore(db),
        routing_store=RoutingDecisionStore(db),
        system_one_config=scfg,
        routing_config=RoutingConfig(),
        client=client,
    )
    return engine, db


class TestDegradedLocalModeSplit:
    async def test_local_mode_is_not_degraded(self):
        """local_mode（配置纯本地）不算故障降级（issue #57语义拆分）"""
        engine, db = await make_engine(client=None)
        st = engine.status()
        assert st["local_mode"] is True
        assert st["degraded"] is False
        await engine.submit(make_alert())
        decisions = await engine.flush()
        assert len(decisions) == 1
        assert decisions[0].degraded is False  # 决策不再被标degraded
        metrics = engine.metrics.to_dict()
        assert metrics["degraded_total"] == 0
        await db.close()

    async def test_status_fallback_active(self):
        engine, db = await make_engine(client=None)
        st = engine.status()
        assert st["fallback_active"] is True  # 纯本地=兜底路径接管中
        assert st["overload"] is False
        await db.close()

    async def test_s1_failure_marks_degraded(self):
        """S1故障降级仍如实标记degraded（与local_mode区别）"""
        from aicso.systemone.client import SystemOneUnavailableError
        from tests.unit.test_router import FakeSystemOneClient

        client = FakeSystemOneClient(error=SystemOneUnavailableError("x"))
        engine, db = await make_engine(client=client)
        case = Case(case_id="CSO-T1", title="T", severity=CaseSeverity.MEDIUM,
                    status=CaseStatus.NEW)
        case.record_case_created()
        await engine.case_store.create(case)
        for ev in case.timeline:
            await engine.case_store.add_event("CSO-T1", ev)
        engine.index.add_case("CSO-T1", "T", {"ip:1.2.3.4", "ip:10.0.0.1"})
        alert = make_alert("A-D")
        await engine.alert_store.create(alert)
        await engine.submit(alert)
        decisions = await engine.flush()
        assert len(decisions) == 1
        assert decisions[0].degraded is True  # 故障降级如实标记
        assert engine.status()["degraded"] is True
        assert engine.metrics.degraded_total == 1
        assert engine.status()["local_mode"] is False
        await db.close()


class TestConfidenceHistogram:
    def test_buckets(self):
        m = RouterMetrics()
        m.record_confidence(0.95)
        m.record_confidence(0.85)
        m.record_confidence(0.5)
        m.record_confidence(0.1)
        m.record_confidence(None)  # 不记录
        h = m.confidence_histogram()
        assert h == {"0.0-0.2": 1, "0.2-0.4": 0, "0.4-0.6": 1,
                     "0.6-0.8": 0, "0.8-1.0": 2}
        assert m.to_dict()["confidence_histogram"] == h

    async def test_fallback_new_case_no_confidence(self):
        engine, db = await make_engine(client=None)
        await engine.submit(make_alert())
        await engine.flush()
        h = engine.metrics.confidence_histogram()
        assert all(v == 0 for v in h.values())  # 兜底新建无置信度
        await db.close()


class TestReviewQueueDisabled:
    async def test_low_confidence_no_review_event(self):
        """review_queue_enabled=false：低置信新建不写复核事件（issue #57）"""
        from tests.unit.test_router import FakeSystemOneClient

        client = FakeSystemOneClient(
            answers_by_call=[{"alert_0": ("merge_into_a", 0.3)}])
        engine, db = await make_engine(client=client, review_queue_enabled=False)
        # 先建一个已有Case让告警有候选
        case = Case(case_id="CSO-T1", title="T", severity=CaseSeverity.MEDIUM,
                    status=CaseStatus.NEW)
        case.record_case_created()
        await engine.case_store.create(case)
        for ev in case.timeline:
            await engine.case_store.add_event("CSO-T1", ev)
        engine.index.add_case("CSO-T1", "T", {"ip:1.2.3.4", "ip:10.0.0.1"})
        await engine.alert_store.create(make_alert(case_id="CSO-T1"))
        # 同签名告警有候选：低置信 → 保守新建
        alert = make_alert("A-X")
        await engine.alert_store.create(alert)
        await engine.submit(alert)
        decisions = await engine.flush()
        assert any(d.detail.get("low_confidence") for d in decisions)
        new_case_id = next(d.case_id for d in decisions if d.decision == "new_case")
        events = await engine.case_store.get_events(new_case_id)
        assert "routing_review" not in [e["event_type"] for e in events]
        # 指标照记（观测不丢）
        assert engine.metrics.low_confidence_total >= 1
        await db.close()


class TestMergeSplitOpsRecord:
    """合并/拆分落OpsRecord（设计§7，OpsAction.MERGE/SPLIT此前无引用——issue #57）"""

    async def _make_merge_engine(self, db):
        ops_service = OpsService(CaseStore(db), OpsRecordStore(db))
        return MergeSplitEngine(
            case_store=CaseStore(db), alert_store=AlertStore(db),
            client=None, scfg=SystemOneConfig(enabled=True),
            index=CaseRoutingIndex(top_k=10), fallback=LocalFallback(),
            ops_service=ops_service,
        )

    async def test_merge_writes_ops_record(self):
        db = Database(":memory:")
        await db.connect()
        await db.init_tables()
        engine = await self._make_merge_engine(db)
        from tests.unit.test_merge_split import make_alert, seed_case
        await seed_case(db, "CSO-A", "A", [make_alert("A-1", "1.1.1.1", "2.2.2.2")])
        await seed_case(db, "CSO-B", "B", [make_alert("A-2", "1.1.1.1", "2.2.2.2")])

        result = await engine.merge("CSO-A", "CSO-B", reason="测试", actor="human")
        assert result.get("ok")
        records = await OpsRecordStore(db).list_by_case("CSO-A")
        assert len(records) == 1
        assert records[0]["action"] == "merge"
        assert json.loads(records[0]["params"])["absorbed"] == "CSO-B"
        assert records[0]["actor_type"] == "human"
        # 时间线镜像事件
        events = await CaseStore(db).get_events("CSO-A")
        assert any(e["event_type"] == "ops_executed" for e in events)
        await db.close()

    async def test_split_writes_ops_record(self):
        db = Database(":memory:")
        await db.connect()
        await db.init_tables()
        engine = await self._make_merge_engine(db)
        from tests.unit.test_merge_split import make_alert, seed_case
        await seed_case(db, "CSO-A", "A",
                        [make_alert("A-1", "1.1.1.1", "2.2.2.2"),
                         make_alert("A-2", "3.3.3.3", "4.4.4.4")])
        result = await engine.split("CSO-A", ["A-2"], reason="误并拆出")
        assert result.get("ok")
        records = await OpsRecordStore(db).list_by_case("CSO-A")
        assert len(records) == 1
        assert records[0]["action"] == "split"
        await db.close()
