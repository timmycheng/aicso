"""Case 合并/拆分引擎测试（issue #8）"""
from __future__ import annotations

from aicso.config import SystemOneConfig
from aicso.models.alert import Alert
from aicso.models.case import Case, CaseSeverity, CaseStatus
from aicso.router.fallback import LocalFallback
from aicso.router.index import CaseRoutingIndex
from aicso.router.merge import MergeSplitEngine
from aicso.store.alert_store import AlertStore
from aicso.store.case_store import CaseStore
from aicso.store.database import Database
from aicso.store.routing_store import RoutingDecisionStore
from aicso.systemone.client import SystemOneAnswer, SystemOneResponse


class FakeMergeClient:
    """脚本化System One替身（合并判定）"""

    def __init__(self, choice="merge_into_a", confidence=0.9, error=None):
        self.choice = choice
        self.confidence = confidence
        self.error = error
        self.calls: list[dict] = []

    async def system_one(self, state, questions):
        self.calls.append({"state": state, "questions": questions})
        if self.error:
            raise self.error
        answers = {
            name: SystemOneAnswer(
                qtype="choice", choice=self.choice, confidence=self.confidence,
                probabilities={self.choice: self.confidence},
            )
            for name in questions
        }
        return SystemOneResponse(model="fake", answers=answers, input_tokens=50)

    async def aclose(self):
        pass


async def make_engine(client=None):
    db = Database(":memory:")
    await db.connect()
    await db.init_tables()
    index = CaseRoutingIndex(top_k=10)
    engine = MergeSplitEngine(
        case_store=CaseStore(db),
        alert_store=AlertStore(db),
        client=client,
        scfg=SystemOneConfig(enabled=True, confidence_threshold=0.6),
        index=index,
        fallback=LocalFallback(),
    )
    return engine, db


async def seed_case(db, case_id, title, alerts: list[Alert]):
    case_store = CaseStore(db)
    alert_store = AlertStore(db)
    case = Case(case_id=case_id, title=title,
                severity=CaseSeverity.MEDIUM, status=CaseStatus.NEW)
    case.record_case_created()
    await case_store.create(case)
    for event in case.timeline:
        await case_store.add_event(case_id, event)
    for alert in alerts:
        alert.case_id = case_id
        await alert_store.create(alert)


def make_alert(alert_id, src, dst):
    return Alert(alert_id=alert_id, source="t", rule_name="R", severity="high",
                 src_ip=src, dst_ip=dst)


class TestFindCandidatePairs:
    async def test_shared_entity_pair(self):
        engine, db = await make_engine()
        await seed_case(db, "C1", "事件一", [make_alert("A-1", "1.1.1.1", "10.0.0.1")])
        await seed_case(db, "C2", "事件二", [make_alert("A-2", "1.1.1.1", "10.0.0.9")])
        await seed_case(db, "C3", "事件三", [make_alert("A-3", "9.9.9.9", "10.0.0.8")])
        engine.index.add_case("C1", "事件一", ["ip:1.1.1.1", "ip:10.0.0.1"])
        engine.index.add_case("C2", "事件二", ["ip:1.1.1.1", "ip:10.0.0.9"])
        engine.index.add_case("C3", "事件三", ["ip:9.9.9.9"])

        pairs = engine.find_candidate_pairs(min_shared=1)
        found = {(p.case_a, p.case_b) for p in pairs}
        assert ("C1", "C2") in found
        assert all("C3" not in p for p in found)  # C3无共享实体
        await db.close()


class TestMerge:
    async def test_merge_moves_alerts_and_redirects(self):
        engine, db = await make_engine()
        await seed_case(db, "C1", "事件一", [make_alert("A-1", "1.1.1.1", "10.0.0.1")])
        await seed_case(db, "C2", "事件二", [make_alert("A-2", "1.1.1.1", "10.0.0.2")])
        engine.index.add_case("C1", "事件一", ["ip:1.1.1.1"])
        engine.index.add_case("C2", "事件二", ["ip:1.1.1.1"])

        result = await engine.merge("C1", "C2", reason="测试合并")
        assert result["ok"] is True
        assert result["alerts_moved"] == 1

        # 告警迁移
        alerts = await AlertStore(db).list_alerts(case_id="C1")
        assert {a["alert_id"] for a in alerts} == {"A-1", "A-2"}
        # 重定向
        case2 = await CaseStore(db).get("C2")
        assert case2["merged_into"] == "C1"
        # 时间线审计
        events1 = await CaseStore(db).get_events("C1")
        assert any(e["event_type"] == "case_merged" for e in events1)
        events2 = await CaseStore(db).get_events("C2")
        assert any(e["event_type"] == "merged_into" for e in events2)
        # 索引退出候选
        assert engine.index.contains("C2") is False
        await db.close()

    async def test_merge_idempotent(self):
        engine, db = await make_engine()
        await seed_case(db, "C1", "事件一", [make_alert("A-1", "1.1.1.1", "10.0.0.1")])
        await seed_case(db, "C2", "事件二", [make_alert("A-2", "1.1.1.1", "10.0.0.2")])
        await engine.merge("C1", "C2")
        second = await engine.merge("C1", "C2")  # 重复执行
        assert second.get("skipped") == "already_merged"
        await db.close()

    async def test_merged_case_excluded_from_rebuild(self):
        engine, db = await make_engine()
        await seed_case(db, "C1", "事件一", [make_alert("A-1", "1.1.1.1", "10.0.0.1")])
        await seed_case(db, "C2", "事件二", [make_alert("A-2", "1.1.1.1", "10.0.0.2")])
        await engine.merge("C1", "C2")

        from aicso.config import RoutingConfig
        from aicso.router.engine import RouterEngine
        engine2 = RouterEngine(
            CaseStore(db), AlertStore(db), RoutingDecisionStore(db),
            SystemOneConfig(enabled=True), RoutingConfig(), client=None,
        )
        count = await engine2.rebuild_index_from_db()
        assert count == 1  # 已合并的C2不再进索引
        assert engine2.index.contains("C2") is False
        await db.close()


class TestEvaluateAndSweep:
    async def test_evaluate_returns_choice(self):
        client = FakeMergeClient(choice="merge_into_a", confidence=0.85)
        engine, db = await make_engine(client)
        await seed_case(db, "C1", "事件一", [make_alert("A-1", "1.1.1.1", "10.0.0.1")])
        await seed_case(db, "C2", "事件二", [make_alert("A-2", "1.1.1.1", "10.0.0.2")])

        evaluation = await engine.evaluate_pair("C1", "C2")
        assert evaluation is not None
        assert evaluation.choice == "merge_into_a"
        assert 0.8 <= evaluation.confidence <= 0.9
        # state包含两个Case的标题
        assert "事件一" in client.calls[0]["state"]
        assert "事件二" in client.calls[0]["state"]
        await db.close()

    async def test_sweep_executes_confident_merge(self):
        client = FakeMergeClient(choice="merge_into_b", confidence=0.9)
        engine, db = await make_engine(client)
        await seed_case(db, "C1", "事件一", [make_alert("A-1", "1.1.1.1", "10.0.0.1")])
        await seed_case(db, "C2", "事件二", [make_alert("A-2", "1.1.1.1", "10.0.0.2")])
        engine.index.add_case("C1", "事件一", ["ip:1.1.1.1"])
        engine.index.add_case("C2", "事件二", ["ip:1.1.1.1"])

        evaluations = await engine.sweep()
        assert len(evaluations) == 1
        assert evaluations[0].executed is True
        case1 = await CaseStore(db).get("C1")
        assert case1["merged_into"] == "C2"  # merge_into_b → C1被并入C2
        await db.close()

    async def test_sweep_low_confidence_no_execute(self):
        client = FakeMergeClient(choice="merge_into_a", confidence=0.4)
        engine, db = await make_engine(client)
        await seed_case(db, "C1", "事件一", [make_alert("A-1", "1.1.1.1", "10.0.0.1")])
        await seed_case(db, "C2", "事件二", [make_alert("A-2", "1.1.1.1", "10.0.0.2")])
        engine.index.add_case("C1", "事件一", ["ip:1.1.1.1"])
        engine.index.add_case("C2", "事件二", ["ip:1.1.1.1"])

        evaluations = await engine.sweep()
        assert evaluations[0].executed is False
        case2 = await CaseStore(db).get("C2")
        assert case2["merged_into"] is None
        await db.close()

    async def test_no_merge_choice(self):
        client = FakeMergeClient(choice="no_merge", confidence=0.95)
        engine, db = await make_engine(client)
        await seed_case(db, "C1", "事件一", [make_alert("A-1", "1.1.1.1", "10.0.0.1")])
        await seed_case(db, "C2", "事件二", [make_alert("A-2", "1.1.1.1", "10.0.0.2")])
        engine.index.add_case("C1", "事件一", ["ip:1.1.1.1"])
        engine.index.add_case("C2", "事件二", ["ip:1.1.1.1"])

        evaluations = await engine.sweep()
        assert evaluations[0].executed is False
        assert evaluations[0].choice == "no_merge"
        await db.close()


class TestSplit:
    async def test_split_moves_subset_and_backlinks(self):
        engine, db = await make_engine()
        await seed_case(db, "C1", "事件一", [
            make_alert("A-1", "1.1.1.1", "10.0.0.1"),
            make_alert("A-2", "1.1.1.1", "10.0.0.2"),
            make_alert("A-3", "1.1.1.1", "10.0.0.3"),
        ])

        result = await engine.split("C1", ["A-2"], reason="误报子集", new_title="拆分事件")
        assert result["ok"] is True
        assert result["alerts_moved"] == 1
        new_id = result["new_case_id"]

        alert_store = AlertStore(db)
        moved = await alert_store.get("A-2")
        assert moved["case_id"] == new_id
        stay = await alert_store.get("A-1")
        assert stay["case_id"] == "C1"

        new_case = await CaseStore(db).get(new_id)
        assert new_case["split_from"] == "C1"
        assert new_case["title"] == "拆分事件"
        # 双方时间线
        events_new = await CaseStore(db).get_events(new_id)
        assert any(e["event_type"] == "case_split_created" for e in events_new)
        events_origin = await CaseStore(db).get_events("C1")
        assert any(e["event_type"] == "case_split" for e in events_origin)
        # 新Case进索引可路由
        assert engine.index.contains(new_id) is True
        await db.close()

    async def test_split_empty_alerts_rejected(self):
        engine, db = await make_engine()
        await seed_case(db, "C1", "事件一", [make_alert("A-1", "1.1.1.1", "10.0.0.1")])
        result = await engine.split("C1", [], reason="x")
        assert result["ok"] is False
        await db.close()

    async def test_split_foreign_alerts_rejected(self):
        engine, db = await make_engine()
        await seed_case(db, "C1", "事件一", [make_alert("A-1", "1.1.1.1", "10.0.0.1")])
        await seed_case(db, "C9", "其他", [make_alert("A-9", "2.2.2.2", "10.0.0.9")])
        result = await engine.split("C1", ["A-9"], reason="x")  # A-9不属于C1
        assert result["ok"] is False
        await db.close()
