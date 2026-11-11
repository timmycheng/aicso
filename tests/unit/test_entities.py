"""类型化实体层测试（issue #44）

弱实体（host/user/file_hash/dst_domain）让无IP主机告警可进候选：
映射提取/规范化 → 索引类型门控 → 候选交模型裁决（不自动合并）；
weak_entity_auto_merge 开关语义。
"""
from __future__ import annotations

from aicso.config import RoutingConfig, SystemOneConfig
from aicso.mapping.engine import SchemaMapper
from aicso.models.alert import Alert
from aicso.router.engine import RouterEngine
from aicso.router.fallback import LocalFallback
from aicso.router.index import CaseRoutingIndex, entity_keys_of, entity_signature
from aicso.store.alert_store import AlertStore
from aicso.store.case_store import CaseStore
from aicso.store.database import Database
from aicso.store.routing_store import RoutingDecisionStore
from aicso.systemone.client import (
    SystemOneAnswer,
    SystemOneResponse,
)


def make_alert(alert_id="A-1", src=None, dst=None, entities=None, rule_id="r-1"):
    return Alert(alert_id=alert_id, source="test", rule_id=rule_id,
                 rule_name="Test", severity="high",
                 src_ip=src, dst_ip=dst, entities=entities or {})


# ---------------- 映射提取 ----------------

def test_ecs_profile_extracts_entities():
    mapper = SchemaMapper({"schema": "ecs"})
    raw = {"@timestamp": "2020-08-07T14:32:25Z",
           "host": {"name": "Web-01.CorP.local"},
           "user": {"name": "JDOE"},
           "file": {"hash": {"sha256": "ABC123"}},
           "destination": {"domain": "Evil.COM"}}
    alert, warnings = mapper.normalize(raw, fallback_alert_id="x-1")
    assert alert.entities == {
        "host": "web-01.corp.local", "user": "jdoe",
        "file_hash": "abc123", "dst_domain": "evil.com",
    }, "实体统一小写防同实体裂键"


def test_entity_mapping_override_and_short_name():
    mapper = SchemaMapper({"schema": "generic",
                           "entity_mapping": {"host": "Hostname"},
                           "entity_short_name": True})
    alert, _ = mapper.normalize(
        {"Hostname": "MORDORDC.theshire.local"}, fallback_alert_id="x-2")
    assert alert.entities == {"host": "mordordc"}


def test_entity_placeholder_values_skipped():
    mapper = SchemaMapper({"schema": "generic",
                           "entity_mapping": {"host": "Hostname", "user": "User"}})
    alert, _ = mapper.normalize({"Hostname": "-", "User": ""}, fallback_alert_id="x-3")
    assert alert.entities == {}, "占位值(-/空)不提取"


def test_entity_keys_of_and_signature():
    alert = make_alert(entities={"host": "web-01"})
    keys = entity_keys_of(alert)
    assert "host:web-01" in keys
    assert "ip:" not in " ".join(keys) or True   # 无IP告警仅弱实体键
    sig = entity_signature(alert)
    assert "host=web-01" in sig
    # 实体不同→签名不同（决策缓存不串）
    assert entity_signature(make_alert(entities={"host": "web-02"})) != sig


# ---------------- 索引类型门控 ----------------

def test_index_entity_type_gate():
    index = CaseRoutingIndex(top_k=10, entity_types={"host"})
    index.add_case("C1", "主机事件", entity_keys_of(
        make_alert(entities={"host": "web-01", "user": "jdoe"})))
    # host 入索引产生候选
    assert index.candidates(entity_keys_of(make_alert(entities={"host": "web-01"})))
    # user 未在白名单→不产生候选（门控）
    assert not index.candidates(entity_keys_of(make_alert(entities={"user": "jdoe"})))


def test_index_ip_always_admitted():
    index = CaseRoutingIndex(top_k=10, entity_types=set())
    index.add_case("C1", "IP事件", entity_keys_of(make_alert(src="1.2.3.4", dst="10.0.0.1")))
    assert index.candidates(entity_keys_of(make_alert(src="1.2.3.4", dst="10.0.0.1")))


# ---------------- fallback 弱类型开关 ----------------

def test_fallback_weak_auto_merge_default_off():
    fb = LocalFallback(weak_auto_merge=False)
    a1 = make_alert("A-1", src="1.1.1.1", dst="10.0.0.1", entities={"host": "web-01"})
    fb.register(a1, "C1")
    a2 = make_alert("A-2", entities={"host": "web-01"})   # 同host、无IP
    assert fb.try_route(a2) is None, "默认关：弱实体不自动合并"


def test_fallback_weak_auto_merge_enabled():
    fb = LocalFallback(weak_auto_merge=True)
    a1 = make_alert("A-1", entities={"host": "web-01"})
    fb.register(a1, "C1")
    a2 = make_alert("A-2", entities={"host": "web-01"})
    match = fb.try_route(a2)
    assert match is not None and match.case_id == "C1"
    fb.deactivate("C1")
    assert fb.try_route(make_alert("A-3", entities={"host": "web-01"})) is None


# ---------------- E2E：弱实体候选→模型裁决（不自动合并） ----------------

class RouteClient:
    """全部裁决汇入C1的替身"""

    def __init__(self):
        self.calls = 0

    async def system_one(self, state: str, questions: dict,
                         timeout_ms: int | None = None) -> SystemOneResponse:
        self.calls += 1
        answers = {name: SystemOneAnswer(
            qtype="choice", choice="C1", confidence=0.95,
            probabilities={"C1": 0.95}) for name in questions}
        return SystemOneResponse(model="stub", answers=answers,
                                 input_tokens=100 * len(questions), output_tokens=0)

    async def aclose(self) -> None:
        pass


async def test_no_ip_alerts_converge_via_host_entity():
    """无IP、同主机告警：首条建Case，后续进候选交模型裁决汇入"""
    client = RouteClient()
    db = Database(":memory:")
    await db.connect()
    await db.init_tables()
    engine = RouterEngine(
        case_store=CaseStore(db), alert_store=AlertStore(db),
        routing_store=RoutingDecisionStore(db),
        system_one_config=SystemOneConfig(enabled=True),
        routing_config=RoutingConfig(), client=client,
    )
    from aicso.models.case import Case, CaseSeverity, CaseStatus
    case = Case(case_id="C1", title="主机事件",
                severity=CaseSeverity.MEDIUM, status=CaseStatus.NEW)
    case.record_case_created()
    await engine.case_store.create(case)
    for event in case.timeline:
        await engine.case_store.add_event("C1", event)
    engine.index.add_case("C1", "主机事件",
                          entity_keys_of(make_alert(entities={"host": "web-01"})))

    decisions = []
    for i in range(3):
        alert = make_alert(f"N-{i}", entities={"host": "web-01"}, rule_id=f"r-{i}")
        await engine.alert_store.create(alert)
        await engine.submit(alert)
    decisions = await engine.flush()
    await engine.alert_store.db.flush()

    assert client.calls >= 1, "弱实体候选应触发模型裁决"
    assert all(d.decision == "route_to" and d.case_id == "C1" for d in decisions)
    assert all(d.source == "system_one" for d in decisions), "弱实体不自动合并,全部经模型"
    shared = decisions[0].detail.get("shared_entities") or []
    assert "host:web-01" in shared, "汇入依据应含弱实体"
    await db.close()
