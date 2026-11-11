"""System One 微批 token 预算与 422 二分重试（issue #42）

真实数据回放暴露：batch_max_alerts 只限条数，真实SIEM候选上下文远大于合成告警，
30条批≈80k token超65536上限→整流静默降级。本组测试锁定修复行为：
预算切批 / 422二分重试 / 单条超限兜底不拖累全局降级。
"""
from __future__ import annotations

from aicso.config import RoutingConfig, SystemOneConfig
from aicso.models.alert import Alert
from aicso.router.engine import RouterEngine, estimate_tokens
from aicso.store.alert_store import AlertStore
from aicso.store.case_store import CaseStore
from aicso.store.database import Database
from aicso.store.routing_store import RoutingDecisionStore
from aicso.systemone.client import (
    InvalidRequestError,
    SystemOneAnswer,
    SystemOneResponse,
)


def make_alert(alert_id, src="9.9.9.9", dst="10.0.0.1", rule_id="r-1"):
    return Alert(alert_id=alert_id, source="test", rule_id=rule_id,
                 rule_name="Test Rule", severity="high", src_ip=src, dst_ip=dst)


class OverflowClient:
    """422替身：问题数>max_questions即抛上下文溢出；否则全部裁决汇入C1"""

    def __init__(self, max_questions: int | None = None):
        self.max_questions = max_questions   # None=永不422；0=总是422
        self.call_sizes: list[int] = []

    async def system_one(self, state: str, questions: dict) -> SystemOneResponse:
        self.call_sizes.append(len(questions))
        if self.max_questions is not None and len(questions) > self.max_questions:
            raise InvalidRequestError(
                "请求被拒绝(状态码422): the request has 80857 tokens, more than 65536", 422)
        answers = {}
        for name in questions:
            answers[name] = SystemOneAnswer(
                qtype="choice", choice="C1", confidence=0.9,
                probabilities={"C1": 0.9},
            )
        return SystemOneResponse(model="stub", answers=answers,
                                 input_tokens=50 * len(questions), output_tokens=0)

    async def aclose(self) -> None:
        pass


async def make_engine(client, **scfg_overrides) -> tuple[RouterEngine, Database]:
    db = Database(":memory:")
    await db.connect()
    await db.init_tables()
    engine = RouterEngine(
        case_store=CaseStore(db),
        alert_store=AlertStore(db),
        routing_store=RoutingDecisionStore(db),
        system_one_config=SystemOneConfig(enabled=True, **scfg_overrides),
        routing_config=RoutingConfig(),
        client=client,
    )
    return engine, db


async def seed_candidate(engine: RouterEngine) -> None:
    """建C1并进索引：后续同源告警有候选→走System One判定路径"""
    from aicso.models.case import Case, CaseSeverity, CaseStatus
    from aicso.router.index import entity_keys_of
    case = Case(case_id="C1", title="已有事件",
                severity=CaseSeverity.MEDIUM, status=CaseStatus.NEW)
    case.record_case_created()
    await engine.case_store.create(case)
    for event in case.timeline:
        await engine.case_store.add_event("C1", event)
    engine.index.add_case("C1", "已有事件",
                          entity_keys_of(make_alert("seed", src="9.9.9.9")))


async def submit_n(engine: RouterEngine, n: int) -> list:
    for i in range(n):
        alert = make_alert(f"B-{i}", dst=f"10.0.0.{i}", rule_id=f"r-{i}")
        await engine.alert_store.create(alert)
        await engine.submit(alert)
    decisions = await engine.flush()
    await engine.alert_store.db.flush()
    return decisions


def test_estimate_tokens_bounds():
    assert estimate_tokens("") >= 1
    ascii_text = "abcdefghij" * 10          # 纯ASCII ≈ len/3+8
    assert estimate_tokens(ascii_text) <= len(ascii_text) // 3 + 20
    cjk_text = "安全事件判定" * 20           # 纯CJK ≈ len+8（上界保守）
    assert estimate_tokens(cjk_text) >= len(cjk_text)


async def test_token_budget_splits_batch():
    """预算100：每条告警估算必超→每子批1条，逐条调用不422不降级"""
    client = OverflowClient()
    engine, db = await make_engine(client, token_budget=100)
    await seed_candidate(engine)
    decisions = await submit_n(engine, 6)

    assert len(client.call_sizes) == 6, f"应逐条调用,实际{client.call_sizes}"
    assert all(size == 1 for size in client.call_sizes)
    assert all(d.source == "system_one" for d in decisions)
    assert engine._degraded is False
    await db.close()


async def test_overflow_binary_split_recovers():
    """首批8条422→二分到≤2条成功：全部得到裁决，零降级"""
    client = OverflowClient(max_questions=2)
    engine, db = await make_engine(client)   # 默认预算,仅靠422触发二分
    await seed_candidate(engine)
    decisions = await submit_n(engine, 8)

    assert client.call_sizes[0] == 8, f"首批应整批{client.call_sizes}"
    assert max(client.call_sizes[1:]) <= 4, f"二分后批应≤4: {client.call_sizes}"
    assert len(decisions) == 8
    assert all(d.source == "system_one" for d in decisions)
    assert engine._degraded is False
    assert engine.metrics.systemone_split_total >= 1
    await db.close()


async def test_oversized_single_falls_back_without_global_degrade():
    """单条仍超限：该批兜底但全局不降级（不拖累其他告警的模型路径）"""
    client = OverflowClient(max_questions=0)   # 任何规模都422
    engine, db = await make_engine(client)
    await seed_candidate(engine)
    decisions = await submit_n(engine, 4)

    assert len(decisions) == 4
    assert all(d.source == "fallback" for d in decisions)
    assert engine._degraded is False, "单条超限不应触发全局降级"
    assert engine.metrics.systemone_oversized_total == 4
    await db.close()
