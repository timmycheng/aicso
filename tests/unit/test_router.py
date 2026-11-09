"""分流引擎测试：候选索引 / 本地兜底 / 缓存 / System One判定 / 降级 / 恢复

System One 全 mock（FakeSystemOneClient）；概率类断言用区间，禁止精确相等。
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta

import pytest

from aicso.config import RoutingConfig, SystemOneConfig
from aicso.models.alert import Alert
from aicso.router.batcher import RoutingBatcher
from aicso.router.decision import NEW_CASE, ROUTE_TO
from aicso.router.engine import RouterEngine
from aicso.router.fallback import LocalFallback
from aicso.router.index import CaseRoutingIndex, entity_keys_of, entity_signature
from aicso.router.metrics import RouterMetrics
from aicso.store.alert_store import AlertStore
from aicso.store.case_store import CaseStore
from aicso.store.database import Database
from aicso.store.routing_store import RoutingDecisionStore
from aicso.systemone.client import (
    Noul,
    RateLimitedError,
    SystemOneAnswer,
    SystemOneResponse,
)


def make_alert(alert_id="A-001", src="1.2.3.4", dst="10.0.0.1", rule_id=None, **kw):
    return Alert(
        alert_id=alert_id, source="test", rule_id=rule_id,
        rule_name=kw.pop("rule_name", "Test Rule"), severity=kw.pop("severity", "high"),
        src_ip=src, dst_ip=dst, **kw,
    )


class FakeSystemOneClient:
    """可编程的System One替身：按预设返回choice+confidence，或抛异常"""

    def __init__(self, answers_by_call: list | None = None, error: Exception | None = None):
        self.answers_by_call = answers_by_call or []  # 每次调用的 {name: (choice, confidence)}
        self.error = error
        self.calls: list[dict] = []

    async def system_one(self, state: str, questions: dict) -> SystemOneResponse:
        self.calls.append({"state": state, "questions": questions})
        if self.error:
            raise self.error
        script = (
            self.answers_by_call.pop(0)
            if self.answers_by_call else {}
        )
        answers = {}
        for name in questions:
            choice, confidence = script.get(name, ("__new__", 0.9))
            answers[name] = SystemOneAnswer(
                qtype="choice", choice=choice, confidence=confidence,
                probabilities={choice: confidence},
            )
        return SystemOneResponse(
            model="fake", answers=answers,
            input_tokens=100 * len(questions), output_tokens=0,
        )

    async def aclose(self) -> None:
        pass


async def make_engine(client=None, **scfg_overrides) -> tuple[RouterEngine, Database]:
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


async def submit_alert(engine: RouterEngine, alert: Alert) -> Alert:
    """测试助手：先持久化（生产路径由orchestrator.handle_alert负责），再入路由队列"""
    await engine.alert_store.create(alert)
    await engine.submit(alert)
    return alert


async def seed_case(engine: RouterEngine, case_id: str, title: str = "已有事件") -> None:
    """测试助手：在DB中真实创建Case（索引候选必须有对应DB行）"""
    from aicso.models.case import Case, CaseSeverity, CaseStatus
    case = Case(
        case_id=case_id, title=title,
        severity=CaseSeverity.MEDIUM, status=CaseStatus.NEW,
    )
    case.record_case_created()
    await engine.case_store.create(case)
    for event in case.timeline:
        await engine.case_store.add_event(case_id, event)


@pytest.fixture
def scfg() -> SystemOneConfig:
    return SystemOneConfig(enabled=True)


# ---------------- 候选索引 ----------------

class TestEntityExtraction:
    def test_full_entities(self):
        alert = make_alert(rule_id="rule-9")
        keys = entity_keys_of(alert)
        assert "ip:1.2.3.4" in keys
        assert "ip:10.0.0.1" in keys
        assert "pair:1.2.3.4>10.0.0.1" in keys
        # rule_id 不参与候选生成：同规则=同类攻击≠同一事件（issue #31）
        assert not any(k.startswith("rule:") for k in keys)

    def test_same_rule_disjoint_ips_no_candidates(self):
        """核心回归：仅同rule_id、IP不相交 → 不应产生候选（issue #31）"""
        index = CaseRoutingIndex()
        index.add_case("C1", "SQL注入事件", entity_keys_of(
            make_alert(alert_id="A-1", src="10.0.0.210", dst="10.0.1.203", rule_id="r-sqli")))
        # 同规则、IP完全不同的新告警
        keys = entity_keys_of(make_alert(
            alert_id="A-2", src="10.0.1.105", dst="172.16.1.187", rule_id="r-sqli"))
        assert index.candidates(keys) == []

    def test_partial(self):
        keys = entity_keys_of(make_alert(src="1.2.3.4", dst=None))
        assert "ip:1.2.3.4" in keys
        assert not any(k.startswith("pair:") for k in keys)

    def test_signature(self):
        a1 = make_alert(alert_id="A", rule_id="r1")
        a2 = make_alert(alert_id="B", rule_id="r1")
        assert entity_signature(a1) == entity_signature(a2)


class TestCaseRoutingIndex:
    def test_candidates_by_overlap(self):
        index = CaseRoutingIndex(top_k=5)
        index.add_case("C1", "Case One", ["ip:1.2.3.4", "ip:10.0.0.1", "pair:1.2.3.4>10.0.0.1"])
        index.add_case("C2", "Case Two", ["ip:9.9.9.9"])

        result = index.candidates(["ip:1.2.3.4", "ip:10.0.0.1", "pair:1.2.3.4>10.0.0.1"])
        assert [s.case_id for s in result] == ["C1"]  # C1重合度3

    def test_top_k_limit(self):
        index = CaseRoutingIndex(top_k=2)
        for i in range(5):
            index.add_case(f"C{i}", f"Case {i}", [f"ip:10.0.0.{i}"])
        result = index.candidates(["ip:10.0.0.0", "ip:10.0.0.1", "ip:10.0.0.2"])
        assert len(result) == 2

    def test_record_hit_grows_entities(self):
        index = CaseRoutingIndex()
        index.add_case("C1", "Case One", ["ip:1.2.3.4"])
        index.record_hit("C1", ["ip:1.2.3.4", "ip:7.7.7.7"])  # Case生长：吸收新实体
        result = index.candidates(["ip:7.7.7.7"])
        assert [s.case_id for s in result] == ["C1"]
        assert result[0].hits == 1

    def test_deactivate(self):
        index = CaseRoutingIndex()
        index.add_case("C1", "Case One", ["ip:1.2.3.4"])
        index.deactivate("C1")
        assert index.candidates(["ip:1.2.3.4"]) == []

    def test_rebuild(self):
        index = CaseRoutingIndex()
        count = index.rebuild([
            {"case_id": "C1", "summary": "T1", "src_ip": "1.2.3.4", "dst_ip": "10.0.0.1",
             "rule_id": None, "last_seen": datetime.utcnow(), "hits": 3},
            {"case_id": "C2", "summary": "T2", "src_ip": "5.6.7.8", "dst_ip": None,
             "rule_id": None, "last_seen": datetime.utcnow(), "hits": 1},
        ])
        assert count == 2
        assert len(index.candidates(["ip:1.2.3.4"])) == 1
        assert len(index.candidates(["ip:5.6.7.8"])) == 1


# ---------------- 本地兜底 ----------------

class TestLocalFallback:
    def test_no_match_first(self):
        fb = LocalFallback()
        assert fb.try_route(make_alert()) is None

    def test_pair_match_within_window(self):
        fb = LocalFallback()
        fb.register(make_alert(alert_id="A-001"), "CSO-001")
        match = fb.try_route(make_alert(alert_id="A-002"))
        assert match is not None
        assert match.case_id == "CSO-001"
        assert match.key == "1.2.3.4>10.0.0.1"

    def test_expired_after_window(self):
        fb = LocalFallback()
        fb.register(make_alert(), "CSO-001")
        # 手动把 last_seen 拨回窗口之前
        fb._pair_cache["1.2.3.4>10.0.0.1"] = (
            "CSO-001", datetime.utcnow() - timedelta(minutes=11)
        )
        assert fb.try_route(make_alert()) is None

    def test_missing_dst_no_match(self):
        fb = LocalFallback()
        fb.register(make_alert(), "CSO-001")
        assert fb.try_route(make_alert(alert_id="A-002", dst=None)) is None


# ---------------- 微批聚合器 ----------------

class TestRoutingBatcher:
    async def test_window_collects_multiple(self):
        batcher = RoutingBatcher(window_ms=50, max_batch=10)
        for i in range(3):
            batcher.put_nowait(i)
        batch = await batcher.collect()
        assert batch == [0, 1, 2]

    async def test_max_batch_trigger(self):
        batcher = RoutingBatcher(window_ms=5000, max_batch=3)  # 窗口拉长验证批上限先触发
        for i in range(5):
            batcher.try_put(i)
        batch = await batcher.collect()
        assert len(batch) == 3

    async def test_full_queue(self):
        batcher = RoutingBatcher(window_ms=10, max_batch=2, max_size=1)
        assert batcher.try_put(1) is True
        assert batcher.try_put(2) is False  # 满了


# ---------------- 路由指标 ----------------

class TestRouterMetrics:
    def test_percentiles_empty(self):
        assert RouterMetrics().latency_percentiles()["p50_ms"] is None

    def test_percentiles_and_backlog(self):
        m = RouterMetrics()
        for v in [10, 20, 30, 40, 50]:
            m.record_latency(float(v))
        p = m.latency_percentiles()
        assert p["p50_ms"] is not None
        assert p["p99_ms"] >= p["p95_ms"] >= p["p50_ms"]
        assert m.backlog_age_ms() is None
        m.oldest_pending_since = datetime.utcnow() - timedelta(milliseconds=1500)
        assert m.backlog_age_ms() >= 1500


# ---------------- 引擎：System One 路径 ----------------

class TestEngineSystemOne:
    async def test_first_alert_creates_case(self):
        client = FakeSystemOneClient()  # 无候选时不会调client
        engine, db = await make_engine(client)
        await submit_alert(engine, make_alert())
        decisions = await engine.flush()

        assert len(decisions) == 1
        assert decisions[0].decision == NEW_CASE
        assert decisions[0].case_id.startswith("CSO-")

        stored = await engine.alert_store.get("A-001")
        assert stored["case_id"] == decisions[0].case_id
        assert stored["routed_at"] is not None
        assert stored["routing_source"] == "fallback"  # 无候选直接新建，source=fallback
        await db.close()

    async def test_same_pair_routes_to_same_case(self):
        engine, db = await make_engine(None)  # 纯本地兜底模式
        await submit_alert(engine, make_alert(alert_id="A-001"))
        await submit_alert(engine, make_alert(alert_id="A-002"))
        decisions = await engine.flush()

        assert len(decisions) == 2
        assert decisions[0].case_id == decisions[1].case_id
        assert decisions[1].decision == ROUTE_TO

        stored = await engine.alert_store.get("A-002")
        assert stored["case_id"] == decisions[0].case_id
        await db.close()

    async def test_system_one_choice_route_to(self):
        client = FakeSystemOneClient(
            answers_by_call=[{"alert_0": ("CSO-TARGET", 0.85)}],
        )
        engine, db = await make_engine(client)
        # 候选Case：索引 + DB行
        await seed_case(engine, "CSO-TARGET", "疑似SSH暴破事件")
        engine.index.add_case("CSO-TARGET", "疑似SSH暴破事件", ["ip:1.2.3.4", "ip:10.0.0.1"])
        await submit_alert(engine, make_alert())
        decisions = await engine.flush()

        assert len(decisions) == 1
        assert decisions[0].decision == ROUTE_TO
        assert decisions[0].case_id == "CSO-TARGET"
        assert decisions[0].source == "system_one"
        assert 0.8 <= decisions[0].confidence <= 0.9
        assert len(client.calls) == 1

        # 候选项包含 __new__
        criteria = client.calls[0]["questions"]["alert_0"].criteria
        assert "__new__" in criteria
        assert "CSO-TARGET" in criteria
        await db.close()

    async def test_low_confidence_conservative_new_case(self):
        client = FakeSystemOneClient(
            answers_by_call=[{"alert_0": ("CSO-TARGET", 0.3)}],  # 低于阈值0.6
        )
        engine, db = await make_engine(client)
        await seed_case(engine, "CSO-TARGET")
        engine.index.add_case("CSO-TARGET", "已有事件", ["ip:1.2.3.4"])
        await submit_alert(engine, make_alert())
        decisions = await engine.flush()

        assert decisions[0].decision == NEW_CASE
        assert decisions[0].detail.get("low_confidence") is True
        assert engine.metrics.low_confidence_total == 1
        # 决策不应被缓存（保守新建不复用）
        assert len(engine._cache) == 0
        await db.close()

    async def test_decision_cache_reuse(self):
        client = FakeSystemOneClient(
            answers_by_call=[{"alert_0": ("CSO-TARGET", 0.9)}],
        )
        engine, db = await make_engine(client)
        await seed_case(engine, "CSO-TARGET")
        engine.index.add_case("CSO-TARGET", "已有事件", ["ip:1.2.3.4"])

        await submit_alert(engine, make_alert(alert_id="A-001", rule_id="r1"))
        await engine.flush()
        await submit_alert(engine, make_alert(alert_id="A-002", rule_id="r1"))  # 同签名
        decisions2 = await engine.flush()

        assert len(client.calls) == 1  # 第二次命中缓存，不再调用
        assert decisions2[0].source == "cache"
        assert decisions2[0].case_id == "CSO-TARGET"
        await db.close()

    async def test_batch_one_request_many_questions(self):
        # 预置多个候选Case，注入3条同实体不同签名的告警
        client = FakeSystemOneClient(
            answers_by_call=[{
                "alert_0": ("CSO-A", 0.9),
                "alert_1": ("CSO-B", 0.8),
                "alert_2": ("__new__", 0.9),
            }],
        )
        engine, db = await make_engine(client)
        await seed_case(engine, "CSO-A", "事件A")
        await seed_case(engine, "CSO-B", "事件B")
        engine.index.add_case("CSO-A", "事件A", ["ip:1.2.3.4"])
        engine.index.add_case("CSO-B", "事件B", ["ip:5.6.7.8"])

        await submit_alert(engine, make_alert(
            alert_id="A-001", src="1.2.3.4", dst="10.0.0.1", rule_id="r1"))
        await submit_alert(engine, make_alert(
            alert_id="A-002", src="5.6.7.8", dst="10.0.0.2", rule_id="r2"))
        # A-003 与 CSO-A 共享实体 ip:1.2.3.4（不同签名规则）→ 进批量判定后选新建
        await submit_alert(engine, make_alert(
            alert_id="A-003", src="1.2.3.4", dst="10.0.0.9", rule_id="r3"))
        decisions = await engine.flush()

        assert len(client.calls) == 1  # 3条告警合1次请求
        questions = client.calls[0]["questions"]
        assert set(questions.keys()) == {"alert_0", "alert_1", "alert_2"}
        assert decisions[0].case_id == "CSO-A"
        assert decisions[1].case_id == "CSO-B"
        assert decisions[2].decision == NEW_CASE
        await db.close()


# ---------------- 降级与恢复 ----------------

class TestDegradedMode:
    async def test_client_error_falls_back(self):
        client = FakeSystemOneClient(error=RateLimitedError("限流", 100))
        engine, db = await make_engine(client)
        await seed_case(engine, "CSO-TARGET")
        engine.index.add_case("CSO-TARGET", "已有事件", ["ip:1.2.3.4", "ip:10.0.0.1"])
        engine.fallback.register(make_alert(), "CSO-TARGET")

        await submit_alert(engine, make_alert(alert_id="A-001"))
        decisions = await engine.flush()

        assert engine._degraded is True  # 进入降级
        assert decisions[0].degraded is True
        assert decisions[0].case_id == "CSO-TARGET"  # pair兜底命中
        assert decisions[0].source == "fallback"
        assert engine.metrics.degraded_total >= 1
        await db.close()

    async def test_disabled_client_pure_local(self):
        engine, db = await make_engine(None)  # client=None
        assert engine._degraded is True
        assert engine.status()["system_one_enabled"] is False

        await submit_alert(engine, make_alert(alert_id="A-001"))
        decisions = await engine.flush()
        assert decisions[0].source == "fallback"
        await db.close()

    async def test_recovery_probe_flips_back(self):
        flaky = FakeSystemOneClient(error=RateLimitedError("x", 1))
        engine, db = await make_engine(flaky)
        await seed_case(engine, "CSO-TARGET")
        engine.index.add_case("CSO-TARGET", "已有事件", ["ip:1.2.3.4", "ip:10.0.0.1"])

        # 第一次失败 → 降级
        await submit_alert(engine, make_alert(alert_id="A-001"))
        await engine.flush()
        assert engine._degraded is True

        # 模拟探针成功 → 引擎恢复主路径
        flaky.error = None
        probe_result = await flaky.system_one(
            "probe", {"alive": Noul(instructions="探测可用性")}
        )
        assert probe_result.model == "fake"  # 探针请求恢复正常
        engine._degraded = False
        assert engine.status()["degraded"] is False
        await db.close()


# ---------------- 重启恢复 ----------------

class TestRecovery:
    async def test_rebuild_index_from_db(self):
        engine, db = await make_engine(None)
        # 第一轮：建Case并路由告警
        await submit_alert(engine, make_alert(alert_id="A-001"))
        await engine.flush()
        stored = await engine.alert_store.get("A-001")
        first_case_id = stored["case_id"]

        # 模拟重启：新引擎从DB重建索引
        engine2 = RouterEngine(
            case_store=engine.case_store,
            alert_store=engine.alert_store,
            routing_store=engine.routing_store,
            system_one_config=SystemOneConfig(enabled=True),
            routing_config=RoutingConfig(),
            client=None,
        )
        count = await engine2.rebuild_index_from_db()
        assert count == 1
        slots = engine2.index.slot_rows()
        assert slots[0]["case_id"] == first_case_id

        # 重建后同源告警仍可命中候选
        candidates = engine2.index.candidates(entity_keys_of(make_alert(alert_id="A-X")))
        assert len(candidates) == 1
        await db.close()

    async def test_backfill_unrouted(self):
        engine, db = await make_engine(None)
        # 直接插一条未路由告警（模拟重启前的积压）
        alert = make_alert(alert_id="A-BACKFILL")
        await engine.alert_store.create(alert)

        count = await engine.backfill_unrouted()
        assert count == 1
        decisions = await engine.flush()
        assert len(decisions) == 1
        stored = await engine.alert_store.get("A-BACKFILL")
        assert stored["case_id"] == decisions[0].case_id
        await db.close()

    async def test_decision_audit_persisted(self):
        engine, db = await make_engine(None)
        await submit_alert(engine, make_alert(alert_id="A-001"))
        await engine.flush()
        await asyncio.sleep(0.2)  # 审计写入是fire-and-forget，等一拍

        rows = await engine.routing_store.list_recent(limit=10)
        assert len(rows) == 1
        assert rows[0]["alert_id"] == "A-001"
        await db.close()
