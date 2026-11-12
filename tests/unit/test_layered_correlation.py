"""分层关联与合并兜底测试（issue #48）

pair窗只负责即时粗分；长期关联由合并层整体兜底：
冷Case发现（DB存量按共享IP）/ 整体化裁决上下文（时间跨度+实体分类）/
关联证据链（合并事件携带结构化说明）/ pair窗口可配置。
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta

from aicso.config import RoutingConfig, SystemOneConfig
from aicso.models.alert import Alert
from aicso.models.case import Case, CaseSeverity, CaseStatus
from aicso.router.engine import RouterEngine
from aicso.router.fallback import LocalFallback
from aicso.router.index import CaseRoutingIndex
from aicso.router.merge import MergeSplitEngine
from aicso.store.alert_store import AlertStore
from aicso.store.case_store import CaseStore
from aicso.store.database import Database
from aicso.store.routing_store import RoutingDecisionStore
from aicso.systemone.client import SystemOneAnswer, SystemOneResponse


def make_alert(alert_id, src, dst, ts=None, entities=None):
    return Alert(alert_id=alert_id, source="t", rule_name="R", severity="high",
                 src_ip=src, dst_ip=dst, timestamp=ts or datetime.utcnow(),
                 entities=entities or {})


class FakeMergeClient:
    def __init__(self, choice="merge_into_a", confidence=0.9):
        self.choice = choice
        self.confidence = confidence
        self.calls: list[dict] = []

    async def system_one(self, state, questions, timeout_ms=None):
        self.calls.append({"state": state, "questions": questions})
        answers = {name: SystemOneAnswer(
            qtype="choice", choice=self.choice, confidence=self.confidence,
            probabilities={self.choice: self.confidence}) for name in questions}
        return SystemOneResponse(model="fake", answers=answers, input_tokens=50)

    async def aclose(self):
        pass


async def make_merge_engine(client=None):
    db = Database(":memory:")
    await db.connect()
    await db.init_tables()
    engine = MergeSplitEngine(
        case_store=CaseStore(db), alert_store=AlertStore(db),
        client=client, scfg=SystemOneConfig(enabled=True, confidence_threshold=0.6),
        index=CaseRoutingIndex(top_k=10), fallback=LocalFallback(),
    )
    return engine, db


async def seed_case(db, case_id, title, alerts: list[Alert],
                    status=CaseStatus.NEW, merged_into=None):
    case_store = CaseStore(db)
    alert_store = AlertStore(db)
    case = Case(case_id=case_id, title=title,
                severity=CaseSeverity.MEDIUM, status=status)
    case.record_case_created()
    await case_store.create(case)
    for event in case.timeline:
        await case_store.add_event(case_id, event)
    if merged_into:
        await case_store.update_relation(case_id, merged_into=merged_into)
    for alert in alerts:
        alert.case_id = case_id
        await alert_store.create(alert)


# ---------------- 冷Case发现 ----------------

class TestColdDiscovery:
    async def test_cold_pair_found_without_index(self):
        """存量Case不在索引也能按共享IP发现（pair窗过期≠关联终点）"""
        engine, db = await make_merge_engine()
        await seed_case(db, "C1", "早期事件",
                        [make_alert("A-1", "1.1.1.1", "10.0.0.1")])
        await seed_case(db, "C2", "新事件",
                        [make_alert("A-2", "5.5.5.5", "1.1.1.1")])
        # 索引为空：模拟索引丢失/重启未覆盖的存量
        pairs = await engine.find_cold_candidate_pairs()
        found = {(p.case_a, p.case_b) for p in pairs}
        assert ("C1", "C2") in found
        assert all(p.source == "cold" for p in pairs)
        assert any("ip:1.1.1.1" in p.shared_entities for p in pairs)
        await db.close()

    async def test_cold_excludes_merged_and_closed(self):
        engine, db = await make_merge_engine()
        await seed_case(db, "C1", "主体",
                        [make_alert("A-1", "1.1.1.1", "10.0.0.1")])
        await seed_case(db, "C2", "已并", [make_alert("A-2", "5.5.5.5", "1.1.1.1")],
                        merged_into="C1")
        await seed_case(db, "C3", "已关", [make_alert("A-3", "5.5.5.5", "1.1.1.1")],
                        status=CaseStatus.CLOSED)
        pairs = await engine.find_cold_candidate_pairs()
        found = {(p.case_a, p.case_b) for p in pairs}
        assert ("C1", "C2") not in found, "已合并Case不参与冷发现"
        assert ("C1", "C3") not in found, "已关闭Case不参与冷发现"
        await db.close()

    async def test_sweep_includes_cold_and_executes(self):
        """sweep整体兜底：冷发现候选经裁决执行合并，事件带证据链"""
        client = FakeMergeClient(confidence=0.9)
        engine, db = await make_merge_engine(client)
        await seed_case(db, "C1", "早期事件",
                        [make_alert("A-1", "1.1.1.1", "10.0.0.1")])
        await seed_case(db, "C2", "迟到事件",
                        [make_alert("A-2", "5.5.5.5", "1.1.1.1")])
        evaluations = await engine.sweep(max_pairs=5, include_cold=True)
        assert any(e.executed for e in evaluations), "冷候选应被裁决并执行"
        events = await engine.case_store.get_events("C1")
        merged = [e for e in events if e["event_type"] == "case_merged"]
        assert merged, "合并应留时间线事件"
        detail = merged[-1]["detail"]
        if isinstance(detail, str):
            import json
            detail = json.loads(detail)
        assert detail.get("evidence"), "合并事件必须携带关联证据链"
        assert "shared_entities" in detail["evidence"]
        absorbed = await engine.case_store.get("C2")
        assert absorbed["merged_into"] == "C1"
        await db.close()


# ---------------- 整体化裁决上下文 ----------------

class TestHolisticContext:
    async def test_state_contains_spans_and_entities(self):
        """裁决上下文包含时间跨度/告警数/共享实体分类（#48整体视角）"""
        client = FakeMergeClient()
        engine, db = await make_merge_engine(client)
        old = datetime.utcnow() - timedelta(hours=8)
        await seed_case(db, "C1", "潜伏事件",
                        [make_alert("A-1", "1.1.1.1", "10.0.0.1", ts=old)])
        await seed_case(db, "C2", "后续事件",
                        [make_alert("A-2", "5.5.5.5", "1.1.1.1")])
        engine.index.add_case("C1", "潜伏事件", ["ip:1.1.1.1", "ip:10.0.0.1"])
        engine.index.add_case("C2", "后续事件", ["ip:5.5.5.5", "ip:1.1.1.1"])

        evaluation = await engine.evaluate_pair("C1", "C2")
        state = client.calls[0]["state"]
        assert "时间跨度" in state and "主要规则" in state
        assert "共享实体" in state
        assert evaluation.evidence["shared_entities"], "证据应含共享实体分类"
        assert evaluation.evidence["case_a"]["alerts"] == 1
        await db.close()

    async def test_instructions_tolerate_long_span(self):
        """问题文本明确：时间间隔本身不是否决理由（慢速渗透语义）"""
        client = FakeMergeClient()
        engine, db = await make_merge_engine(client)
        await seed_case(db, "C1", "A", [make_alert("A-1", "1.1.1.1", "10.0.0.1")])
        await seed_case(db, "C2", "B", [make_alert("A-2", "5.5.5.5", "1.1.1.1")])
        await engine.evaluate_pair("C1", "C2")
        question = client.calls[0]["questions"]["merge_decision"]
        assert "时间间隔本身不是否决理由" in question.instructions
        await db.close()


# ---------------- pair窗口可配置 ----------------

class TestPairWindowConfig:
    async def test_window_wiring(self):
        db = Database(":memory:")
        await db.connect()
        await db.init_tables()
        engine = RouterEngine(
            case_store=CaseStore(db), alert_store=AlertStore(db),
            routing_store=RoutingDecisionStore(db),
            system_one_config=SystemOneConfig(enabled=True),
            routing_config=RoutingConfig(pair_window_minutes=3), client=None,
        )
        assert engine.fallback.window_minutes == 3
        assert RoutingConfig().pair_window_minutes == 10, "默认值不变"
        await db.close()

    async def test_expired_window_creates_new_case(self):
        """窗口过期≠继续合并：过期后同pair走新建（后续由合并层兜底）"""
        fb = LocalFallback(window_minutes=0)
        a1 = make_alert("A-1", "1.1.1.1", "10.0.0.1")
        fb.register(a1, "C1")
        # 等待时钟前进（0分钟窗口即刻过期）
        t0 = datetime.utcnow()
        while datetime.utcnow() == t0:
            await asyncio.sleep(0.002)
        match = fb.try_route(make_alert("A-2", "1.1.1.1", "10.0.0.1"))
        assert match is None, "过期窗口不得继续pair合并"
