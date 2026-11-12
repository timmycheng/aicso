"""处置反馈闭环测试（issue #51，Epic #47）

误报签名消费（标记后同签名免路由不建case，TTL过期恢复）/ 人工处置样本
沉淀进裁决上下文（few-shot）/ 实体类型存活率报告（报告only）。
"""
from __future__ import annotations

from datetime import datetime

from aicso.config import RoutingConfig, SystemOneConfig
from aicso.models.alert import Alert
from aicso.models.case import Case, CaseSeverity, CaseStatus
from aicso.models.routing import SRC_FALSE_POSITIVE
from aicso.router.engine import RouterEngine
from aicso.router.fallback import LocalFallback
from aicso.router.index import CaseRoutingIndex
from aicso.router.merge import MergeSplitEngine
from aicso.store.alert_store import AlertStore
from aicso.store.case_store import CaseStore
from aicso.store.database import Database
from aicso.store.routing_store import RoutingDecisionStore
from aicso.systemone.client import SystemOneAnswer, SystemOneResponse


def make_alert(alert_id, src, dst, entities=None, ts=None):
    return Alert(alert_id=alert_id, source="t", rule_id="r-1", rule_name="R",
                 severity="high", src_ip=src, dst_ip=dst,
                 entities=entities or {}, timestamp=ts or datetime.utcnow())


class ScriptedClient:
    def __init__(self, choice="C1", confidence=0.9):
        self.choice = choice
        self.confidence = confidence
        self.calls: list[dict] = []

    async def system_one(self, state, questions, timeout_ms=None):
        self.calls.append({"state": state, "questions": questions})
        answers = {}
        for name, q in questions.items():
            if q.qtype == "choice":
                answers[name] = SystemOneAnswer(
                    qtype="choice", choice=self.choice, confidence=self.confidence,
                    probabilities={self.choice: self.confidence})
            else:
                answers[name] = SystemOneAnswer(qtype="noul", noul=0.99)
        return SystemOneResponse(model="fake", answers=answers, input_tokens=50)

    async def aclose(self):
        pass


async def make_db():
    db = Database(":memory:")
    await db.connect()
    await db.init_tables()
    return db


async def seed_case(db, case_id, title="已有事件"):
    case_store = CaseStore(db)
    case = Case(case_id=case_id, title=title,
                severity=CaseSeverity.MEDIUM, status=CaseStatus.NEW)
    case.record_case_created()
    await case_store.create(case)
    for event in case.timeline:
        await case_store.add_event(case_id, event)


async def submit(engine: RouterEngine, alert: Alert) -> list:
    await engine.alert_store.create(alert)
    await engine.submit(alert)
    decisions = await engine.flush()
    await engine.alert_store.db.flush()
    return decisions


# ---------------- 误报签名消费 ----------------

class TestFalsePositive:
    async def test_marked_signature_skips_routing(self):
        """标记误报后同签名告警免路由不建case（#51核心路径）"""
        db = await make_db()
        engine = RouterEngine(
            case_store=CaseStore(db), alert_store=AlertStore(db),
            routing_store=RoutingDecisionStore(db),
            system_one_config=SystemOneConfig(enabled=True),
            routing_config=RoutingConfig(), client=None,
        )
        a1 = make_alert("A-1", "1.1.1.1", "10.0.0.1")
        await submit(engine, a1)
        first_case = (await engine.alert_store.get("A-1"))["case_id"]
        assert first_case, "首条正常路由建case"

        engine.record_false_positive(a1)
        a2 = make_alert("A-2", "1.1.1.1", "10.0.0.1")   # 同签名
        decisions = await submit(engine, a2)
        assert decisions[0].source == SRC_FALSE_POSITIVE
        assert decisions[0].case_id == ""
        row = await engine.alert_store.get("A-2")
        assert row["is_false_positive"], "误报标记应持久化"
        assert engine.metrics.fp_total == 1
        await db.close()

    async def test_different_signature_unaffected(self):
        db = await make_db()
        engine = RouterEngine(
            case_store=CaseStore(db), alert_store=AlertStore(db),
            routing_store=RoutingDecisionStore(db),
            system_one_config=SystemOneConfig(enabled=True),
            routing_config=RoutingConfig(), client=None,
        )
        a1 = make_alert("A-1", "1.1.1.1", "10.0.0.1")
        await submit(engine, a1)
        engine.record_false_positive(a1)
        b1 = make_alert("B-1", "2.2.2.2", "10.0.0.9")   # 不同签名
        decisions = await submit(engine, b1)
        assert decisions[0].source != SRC_FALSE_POSITIVE, "不同签名不受误报记忆影响"
        await db.close()

    async def test_ttl_expiry_resumes_routing(self):
        """TTL过期后同签名恢复正常路由"""
        db = await make_db()
        engine = RouterEngine(
            case_store=CaseStore(db), alert_store=AlertStore(db),
            routing_store=RoutingDecisionStore(db),
            system_one_config=SystemOneConfig(enabled=True),
            routing_config=RoutingConfig(fp_ttl_hours=0), client=None,
        )
        a1 = make_alert("A-1", "1.1.1.1", "10.0.0.1")
        await submit(engine, a1)
        engine.record_false_positive(a1)
        # 等待时钟前进使TTL(0)过期
        t0 = datetime.utcnow()
        while datetime.utcnow() == t0:
            import asyncio
            await asyncio.sleep(0.002)
        a2 = make_alert("A-2", "1.1.1.1", "10.0.0.1")
        decisions = await submit(engine, a2)
        assert decisions[0].source != SRC_FALSE_POSITIVE, "TTL过期后恢复正常路由"
        await db.close()


# ---------------- 人工处置样本进裁决 ----------------

class TestDispositionSamples:
    async def test_human_merge_records_sample(self):
        db = await make_db()
        client = ScriptedClient()
        engine = MergeSplitEngine(
            case_store=CaseStore(db), alert_store=AlertStore(db),
            client=client, scfg=SystemOneConfig(enabled=True),
            index=CaseRoutingIndex(top_k=10), fallback=LocalFallback(),
        )
        await seed_case(db, "C1", "事件一")
        await seed_case(db, "C2", "事件二")
        engine.index.add_case("C1", "事件一", ["ip:1.1.1.1"])
        engine.index.add_case("C2", "事件二", ["ip:1.1.1.1", "ip:10.0.0.9"])
        await engine.merge("C1", "C2", reason="同一攻击链", actor="human")
        assert len(engine.disposition_samples) == 1
        sample = engine.disposition_samples[0]
        assert "ip:1.1.1.1" in sample["shared"]
        assert sample["reason"] == "同一攻击链"

    async def test_system_merge_no_sample(self):
        """系统自动合并不沉淀样本（那是模型自己的结论，不是人的标注）"""
        db = await make_db()
        engine = MergeSplitEngine(
            case_store=CaseStore(db), alert_store=AlertStore(db),
            client=ScriptedClient(), scfg=SystemOneConfig(enabled=True),
            index=CaseRoutingIndex(top_k=10), fallback=LocalFallback(),
        )
        await seed_case(db, "C1", "事件一")
        await seed_case(db, "C2", "事件二")
        engine.index.add_case("C1", "事件一", ["ip:1.1.1.1"])
        engine.index.add_case("C2", "事件二", ["ip:1.1.1.1"])
        await engine.merge("C1", "C2", reason="自动", actor="system")
        assert engine.disposition_samples == []

    async def test_evaluation_injects_matching_sample(self):
        """裁决上下文注入相似实体的人工处置参考（few-shot）"""
        db = await make_db()
        client = ScriptedClient()
        engine = MergeSplitEngine(
            case_store=CaseStore(db), alert_store=AlertStore(db),
            client=client, scfg=SystemOneConfig(enabled=True),
            index=CaseRoutingIndex(top_k=10), fallback=LocalFallback(),
        )
        await seed_case(db, "C1", "事件一")
        await seed_case(db, "C2", "事件二")
        engine.index.add_case("C1", "事件一", ["ip:1.1.1.1"])
        engine.index.add_case("C2", "事件二", ["ip:1.1.1.1"])
        engine.disposition_samples.append({
            "ts": datetime.utcnow().isoformat(), "primary": "C1", "absorbed": "C2",
            "shared": ["ip:1.1.1.1"], "reason": "同一横向移动链",
        })
        await engine.evaluate_pair("C1", "C2")
        assert "历史人工处置参考" in client.calls[0]["state"]
        assert "同一横向移动链" in client.calls[0]["state"]


# ---------------- 实体类型存活率报告 ----------------

class TestEntitySurvival:
    async def test_survival_report(self):
        """合并证据的类型计数 + 事后拆分扣减（报告only，#51）"""
        db = await make_db()
        engine = MergeSplitEngine(
            case_store=CaseStore(db), alert_store=AlertStore(db),
            client=ScriptedClient(), scfg=SystemOneConfig(enabled=True),
            index=CaseRoutingIndex(top_k=10), fallback=LocalFallback(),
        )
        evidence = {"shared_entity_keys": ["host:web-01", "ip:1.1.1.1"]}
        await seed_case(db, "C1", "主事件")
        await seed_case(db, "C2", "被并事件")
        await engine.merge("C1", "C2", reason="r", evidence=evidence)
        # C1事后被拆分→host类型存活率下降
        await engine.alert_store.create(make_alert("A-9", "1.1.1.1", "10.0.0.1"))
        await engine.alert_store.update_case_id("A-9", "C1")
        await engine.case_store.db.flush()
        await engine.split("C1", ["A-9"], reason="误并修正")

        report = await engine.entity_survival_report()
        assert report["types"]["host"]["merged"] == 1
        assert report["types"]["host"]["split"] == 1
        assert report["types"]["host"]["survival"] == 0.0
        assert report["types"]["ip"]["merged"] == 1
        assert "报告only" in report["note"]
