"""S2认知任务分发器测试（issue #7）

判定型→System One（FakeSystemOneClient脚本化应答）；生成型→LLM（Mock Agent）；
概率断言用区间。
"""
from __future__ import annotations

from aicso.agents.base import AgentResult, BaseAgent
from aicso.cognition.dispatcher import ATTACK_CATEGORIES, S2Dispatcher
from aicso.config import SystemOneConfig
from aicso.core.approval import ApprovalEngine
from aicso.core.context import ContextManager
from aicso.core.event_bus import EventBus
from aicso.core.orchestrator import Orchestrator
from aicso.models.alert import Alert
from aicso.store.alert_store import AlertStore
from aicso.store.case_store import CaseStore
from aicso.store.database import Database
from aicso.systemone.client import (
    SystemOneAnswer,
    SystemOneResponse,
)


class FakeS2Client:
    """脚本化System One替身"""

    def __init__(self, script: dict | None = None, error: Exception | None = None):
        self.script = script or {}
        self.error = error
        self.calls: list[dict] = []

    async def system_one(self, state: str, questions: dict) -> SystemOneResponse:
        self.calls.append({"state": state, "questions": questions})
        if self.error:
            raise self.error
        answers = {}
        for name in questions:
            kind = questions[name].qtype
            value = self.script.get(name)
            if kind == "noul":
                noul_val = value if value is not None else 0.9
                answers[name] = SystemOneAnswer(qtype="noul", noul=noul_val)
            elif kind == "choice":
                choice, confidence = value if isinstance(value, tuple) else (value, 0.9)
                answers[name] = SystemOneAnswer(
                    qtype="choice", choice=choice, confidence=confidence,
                    probabilities={choice: confidence},
                )
        return SystemOneResponse(model="fake", answers=answers,
                                 input_tokens=100, output_tokens=0)

    async def aclose(self):
        pass


class MockTriageAgent(BaseAgent):
    name = "triage"
    description = "Mock"

    async def run(self, task: dict, context: dict) -> AgentResult:
        return AgentResult.success(
            output={"summary": "摘要", "is_true_positive": True},
            confidence=0.8,
        )


def _dummy_alert() -> Alert:
    return Alert(alert_id="A-X", source="t", rule_name="R", severity="high",
                 src_ip="1.1.1.1", dst_ip="2.2.2.2")


class TestS2Dispatcher:
    async def test_judge_triage_parses_answers(self):
        client = FakeS2Client(script={
            "is_true_positive": 0.92,
            "attack_category": ("brute_force", 0.88),
            "severity": ("high", 0.85),
        })
        d = S2Dispatcher(client, SystemOneConfig(enabled=True))
        assert d.enabled

        judgment = await d.judge_triage(
            "C1", "SSH暴破", [Alert(alert_id="A-1", source="t", rule_name="ssh fail",
                                    severity="high", src_ip="1.1.1.1", dst_ip="2.2.2.2")],
        )
        assert judgment is not None
        assert judgment.true_positive is True
        assert judgment.category == "brute_force"
        assert 0.8 <= judgment.category_confidence <= 0.95
        assert judgment.severity == "high"
        assert judgment.needs_review is False  # 全部高于阈值0.6
        # 问题集包含三类判定
        assert set(client.calls[0]["questions"].keys()) == {
            "is_true_positive", "attack_category", "severity"}

    async def test_low_confidence_flags_review(self):
        client = FakeS2Client(script={
            "is_true_positive": 0.7,
            "attack_category": ("other", 0.4),  # 低于阈值
            "severity": ("high", 0.85),
        })
        d = S2Dispatcher(client, SystemOneConfig(enabled=True))
        judgment = await d.judge_triage("C1", "T", [_dummy_alert()])
        assert judgment.needs_review is True

    async def test_invalid_choice_flags_review(self):
        client = FakeS2Client(script={
            "attack_category": ("hacking_the_planet", 0.99),  # 不在合法选项
        })
        d = S2Dispatcher(client, SystemOneConfig(enabled=True))
        judgment = await d.judge_triage("C1", "T", [_dummy_alert()])
        assert judgment.needs_review is True

    async def test_system_one_error_returns_none(self):
        from aicso.systemone.client import SystemOneUnavailableError
        client = FakeS2Client(error=SystemOneUnavailableError("x"))
        d = S2Dispatcher(client, SystemOneConfig(enabled=True))
        assert await d.judge_triage("C1", "T", []) is None

    async def test_disabled_dispatcher(self):
        d = S2Dispatcher(None, SystemOneConfig(enabled=True))
        assert d.enabled is False
        assert await d.judge_triage("C1", "T", [Alert(alert_id="A", source="t")]) is None

    def test_categories_aligned_with_mock(self):
        # 与 mock_producer 8类攻击模板对齐（设计§6）
        assert {"brute_force", "phishing", "malware", "lateral_movement",
                "data_exfiltration", "privilege_escalation", "port_scan",
                "web_attack"} <= set(ATTACK_CATEGORIES)


async def make_orchestrator(s2_client, llm_enabled=True):
    db = Database(":memory:")
    await db.connect()
    await db.init_tables()
    case_store = CaseStore(db)
    alert_store = AlertStore(db)
    event_bus = EventBus()
    orch = Orchestrator(
        case_store, alert_store, ContextManager(case_store, alert_store),
        event_bus, ApprovalEngine(event_bus),
        router=None,
        dispatcher=S2Dispatcher(s2_client, SystemOneConfig(enabled=True)),
        llm_enabled=llm_enabled,
    )
    return orch, db, case_store, alert_store


async def seed_case_with_alert(case_store, alert_store):
    from aicso.models.case import Case, CaseSeverity, CaseStatus
    case = Case(case_id="CSO-T1", title="[test] Suspicious SSH",
                severity=CaseSeverity.MEDIUM, status=CaseStatus.NEW)
    case.record_case_created()
    await case_store.create(case)
    for event in case.timeline:
        await case_store.add_event(case.case_id, event)
    await alert_store.create(Alert(
        alert_id="A-1", source="t", rule_name="ssh fail", severity="medium",
        src_ip="1.1.1.1", dst_ip="2.2.2.2", case_id="CSO-T1",
    ))
    return case


class TestTriageDualTrack:
    async def test_judgment_event_and_auto_severity(self):
        client = FakeS2Client(script={
            "is_true_positive": 0.9,
            "attack_category": ("brute_force", 0.88),
            "severity": ("critical", 0.9),  # high置信度 → 自动从medium升到critical
        })
        orch, db, case_store, alert_store = await make_orchestrator(
            client, llm_enabled=False)
        await seed_case_with_alert(case_store, alert_store)

        await orch.run_initial_triage("CSO-T1", Alert(alert_id="A-1", source="t"))

        events = await case_store.get_events("CSO-T1")
        types = [e["event_type"] for e in events]
        assert "s2_judgment" in types
        assert "severity_changed" in types  # 自动修正
        case = await case_store.get("CSO-T1")
        assert case["severity"] == "critical"  # 修正生效
        # LLM关闭 → needs_review 事件
        assert "routing_review" in types
        await db.close()

    async def test_low_confidence_no_auto_correct(self):
        client = FakeS2Client(script={
            "is_true_positive": 0.7,
            "attack_category": ("phishing", 0.5),  # 低于阈值 → 不自动修正
            "severity": ("low", 0.5),
        })
        orch, db, case_store, alert_store = await make_orchestrator(
            client, llm_enabled=False)
        await seed_case_with_alert(case_store, alert_store)

        await orch.run_initial_triage("CSO-T1", Alert(alert_id="A-1", source="t"))
        case = await case_store.get("CSO-T1")
        assert case["severity"] == "medium"  # 保持原值
        events = await case_store.get_events("CSO-T1")
        reviews = [e for e in events if e["event_type"] == "routing_review"]
        # 双轨各记一条：S2判定复核 + LLM关闭的生成型复核
        assert len(reviews) == 2
        await db.close()

    async def test_llm_narrative_runs_when_enabled(self):
        client = FakeS2Client(script={
            "attack_category": ("brute_force", 0.9),
            "severity": ("high", 0.9),
        })
        orch, db, case_store, alert_store = await make_orchestrator(
            client, llm_enabled=True)
        orch.register_agent(MockTriageAgent())
        await seed_case_with_alert(case_store, alert_store)

        await orch.run_initial_triage("CSO-T1", Alert(alert_id="A-1", source="t"))
        case = await case_store.get("CSO-T1")
        assert case["ai_summary"] == "摘要"  # 生成型摘要落库
        await db.close()

    async def test_agent_missing_needs_review(self):
        client = FakeS2Client(script={
            "attack_category": ("brute_force", 0.9),
            "severity": ("high", 0.9),
        })
        orch, db, case_store, alert_store = await make_orchestrator(
            client, llm_enabled=True)  # 不注册triage agent
        await seed_case_with_alert(case_store, alert_store)

        await orch.run_initial_triage("CSO-T1", Alert(alert_id="A-1", source="t"))
        events = await case_store.get_events("CSO-T1")
        assert any(
            "TriageAgent未注册" in e["detail"]
            for e in events if e["event_type"] == "routing_review"
        )
        await db.close()

    async def test_disabled_dispatcher_skips_judgment(self):
        orch, db, case_store, alert_store = await make_orchestrator(
            None, llm_enabled=False)
        await seed_case_with_alert(case_store, alert_store)

        await orch.run_initial_triage("CSO-T1", Alert(alert_id="A-1", source="t"))
        events = await case_store.get_events("CSO-T1")
        assert "s2_judgment" not in [e["event_type"] for e in events]
        await db.close()
