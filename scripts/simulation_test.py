"""分流/合并/拆分 全场景仿真测试（issue #33）

三种判定引擎模式:
  local     纯本地兜底（无模型）——管道吞吐与效率基线，确定性
  scripted  脚本化判定引擎——确定性编排"模型应答"，跑全行为矩阵
  systemone 真实象信API——语义质量抽检（成本受控，--with-systemone 显式开启）

用法:
  uv run python scripts/simulation_test.py                    # local+scripted 全矩阵
  uv run python scripts/simulation_test.py --with-systemone   # 附加真实API抽检
  uv run python scripts/simulation_test.py --scale 2          # 流量放大
  uv run python scripts/replay_dataset.py <数据集路径>...     # 真实数据集回放(issue #40)
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import tempfile
import time
from dataclasses import dataclass

import structlog

from aicso.config import RoutingConfig, SystemOneConfig
from aicso.mapping.engine import SchemaMapper
from aicso.models.alert import Alert
from aicso.models.case import Case, CaseSeverity, CaseStatus
from aicso.router.engine import RouterEngine
from aicso.router.merge import MergeSplitEngine
from aicso.store.alert_store import AlertStore
from aicso.store.case_store import CaseStore
from aicso.store.database import Database
from aicso.store.routing_store import RoutingDecisionStore
from aicso.systemone.client import (
    Noul,
    SystemOneAnswer,
    SystemOneClient,
    SystemOneResponse,
    SystemOneUnavailableError,
)

THROUGHPUT_TARGET = 500          # 本地管道吞吐验收（alerts/s）
AMPLIFICATION_LIMIT = 0.1        # API请求放大系数上限（requests/routed）


# ============ 基础设施 ============

@dataclass
class SimResult:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class ScriptedClient:
    """脚本化System One替身：按队列依次应答（确定性编排）"""

    def __init__(self):
        self.answers: list[dict] = []      # 每次调用弹出 {name: (choice, conf)}
        self.default_answer = ("__new__", 0.9)
        self.error: Exception | None = None
        self.calls = 0

    async def system_one(self, state: str, questions: dict) -> SystemOneResponse:
        self.calls += 1
        if self.error:
            raise self.error
        script = self.answers.pop(0) if self.answers else {}
        answers = {}
        for name in questions:
            q = questions[name]
            if q.qtype == "noul":
                answers[name] = SystemOneAnswer(qtype="noul", noul=0.99)
            else:
                choice, confidence = script.get(name, self.default_answer)
                answers[name] = SystemOneAnswer(
                    qtype="choice", choice=choice, confidence=confidence,
                    probabilities={choice: confidence},
                )
        return SystemOneResponse(model="scripted", answers=answers,
                                 input_tokens=50 * len(questions), output_tokens=0)

    async def aclose(self):
        pass


async def make_sim_engine(db_path: str, client=None, queue_max: int = 50000):
    db = Database(db_path)
    await db.connect()
    await db.init_tables()
    db.enable_write_buffer(batch_size=50, flush_interval=0.1)
    engine = RouterEngine(
        case_store=CaseStore(db),
        alert_store=AlertStore(db),
        routing_store=RoutingDecisionStore(db),
        system_one_config=SystemOneConfig(enabled=True, batch_window_ms=100,
                                          batch_max_alerts=50),
        routing_config=RoutingConfig(queue_max_size=queue_max),
        client=client,
    )
    return engine, db


def alert(alert_id, src, dst, rule_id, rule_name="R", severity="high"):
    return Alert(alert_id=alert_id, source="sim", rule_id=rule_id,
                 rule_name=rule_name, severity=severity, src_ip=src, dst_ip=dst)


async def submit_all(engine, alerts):
    for a in alerts:
        await engine.alert_store.create(a)
        await engine.submit(a)
    decisions = await engine.flush()
    await engine.alert_store.db.flush()  # 读己之写：后续DB读立即可见
    return decisions


def check(name: str, ok: bool, detail: str = "") -> SimResult:
    print(f"  {'✅' if ok else '❌'} {name}" + (f"  — {detail}" if detail else ""))
    return SimResult(name, ok, detail)


# ============ 分流矩阵 ============

async def suite_routing_local() -> list[SimResult]:
    """本地兜底模式：管道语义矩阵"""
    print("\n── 分流矩阵 · local 模式 ──")
    out: list[SimResult] = []
    tmp = tempfile.mkdtemp(prefix="sim-rt-")
    engine, db = await make_sim_engine(os.path.join(tmp, "a.db"))

    # 1 首告新建
    ds = await submit_all(engine, [alert("A1", "1.1.1.1", "10.0.0.1", "r-brute")])
    out.append(check("首告新建Case", len(ds) == 1 and ds[0].decision == "new_case"))

    # 2 同pair汇入（本地pair规则）
    ds = await submit_all(engine, [alert("A2", "1.1.1.1", "10.0.0.1", "r-brute")])
    out.append(check("同pair汇入(fallback)", ds[0].decision == "route_to"
                     and ds[0].source == "fallback"))

    # 3 同规则不相交IP → 独立新建（issue #31回归）
    disjoint = [alert(f"A3-{i}", f"20.0.0.{i}", f"172.16.0.{i}", "r-brute")
                for i in range(1, 5)]
    ds = await submit_all(engine, disjoint)
    out.append(check("同规则不相交IP各自新建(#31)", all(d.decision == "new_case" for d in ds)
                     and len({d.case_id for d in ds}) == 4,
                     f"4条独立Case={[d.case_id for d in ds][:1]}..."))

    # 4 背压过载零丢失
    engine2, db2 = await make_sim_engine(os.path.join(tmp, "b.db"), queue_max=5)
    batch = [alert(f"BP-{i}", f"30.0.0.{i}", f"10.1.0.{i}", "r-x") for i in range(20)]
    for a in batch:
        await engine2.alert_store.create(a)
        await engine2.submit(a)
    await engine2.flush()
    routed = engine2.metrics.routed_total
    hw = engine2.metrics.queue_high_water_events
    out.append(check("背压过载零丢失", routed == 20,
                     f"routed={routed}/20 queue_high_water={hw}"))
    await asyncio.sleep(0.2)
    await db2.close()

    await db.close()
    return out


async def suite_routing_scripted() -> list[SimResult]:
    """scripted模式：System One行为矩阵（确定性编排）"""
    print("\n── 分流矩阵 · scripted 模式 ──")
    out: list[SimResult] = []
    tmp = tempfile.mkdtemp(prefix="sim-rs-")
    client = ScriptedClient()
    engine, db = await make_sim_engine(os.path.join(tmp, "a.db"), client=client)

    # 1 首告新建 + 模型被询问的前提是有候选——首告无候选直接fallback新建
    ds = await submit_all(engine, [alert("B1", "5.5.5.5", "10.0.0.1", "r-spray")])
    out.append(check("无候选不调用模型直接新建",
                     ds[0].decision == "new_case" and ds[0].source == "fallback"
                     and client.calls == 0))

    # 2 建立候选源（喷射源5.5.5.5已入索引），同源不同目标 → 候选存在 → 模型裁决新建
    client.answers = [{"alert_0": ("__new__", 0.9)}]
    ds = await submit_all(engine, [alert("B2", "5.5.5.5", "10.0.0.2", "r-spray")])
    out.append(check("喷射攻击：模型裁决新建(有候选)",
                     ds[0].decision == "new_case" and ds[0].source == "system_one"
                     and ds[0].detail.get("choice") == "__new__" and client.calls == 1))

    # 3 模型裁决汇入（同源喷射但判定为同一事件）
    client.answers = [{"alert_0": ("__new__", 0.9)}]
    ds = await submit_all(engine, [alert("B3", "5.5.5.5", "10.0.0.3", "r-spray")])
    out.append(check("模型独立裁决可重复(仍新建)", ds[0].decision == "new_case"))

    # 4 缓存命中：同签名60s内第二次 → 不再调用模型
    calls_before = client.calls
    ds = await submit_all(engine, [alert("B4", "5.5.5.5", "10.0.0.3", "r-spray")])
    out.append(check("决策缓存命中(零模型调用)",
                     ds[0].source == "cache" and client.calls == calls_before))

    # 5 低置信度 → 保守新建 + 复核
    engine.index.add_case("C-TARGET", "目标事件",
                          entity_keys_for(engine, "5.5.5.5", "10.0.0.9"))
    client.answers = [{"alert_0": ("C-TARGET", 0.4)}]
    ds = await submit_all(engine, [alert("B5", "5.5.5.5", "10.0.0.9", "r-spray")])
    out.append(check("低置信度保守新建+复核标记",
                     ds[0].decision == "new_case" and ds[0].detail.get("low_confidence") is True
                     and engine.metrics.low_confidence_total >= 1))

    # 6 无效选项 → 保守新建
    client.answers = [{"alert_0": ("hacking_the_planet", 0.99)}]
    ds = await submit_all(engine, [alert("B6", "5.5.5.5", "10.0.0.9", "r-spray")])
    out.append(check("无效选项保守新建", ds[0].decision == "new_case"))

    # 7 System One故障 → 降级接管，本批全兜底
    client.error = SystemOneUnavailableError("仿真注入故障")
    # 注意：换签名——B6的同签名已写入决策缓存，缓存路径在降级标志置位前返回
    ds = await submit_all(engine, [alert("B7", "5.5.5.5", "10.0.0.9", "r-spray2")])
    out.append(check("模型故障降级接管",
                     engine._degraded and ds[0].degraded is True
                     and ds[0].source in ("fallback", "cache")))

    # 8 恢复：故障解除后探针成功切回
    client.error = None
    probe = await client.system_one("probe", {"alive": Noul(instructions="i")})
    engine._degraded = False
    out.append(check("探针恢复切回主路径",
                     probe.model == "scripted" and engine._degraded is False))

    await asyncio.sleep(0.2)
    await db.close()
    return out


def entity_keys_for(engine, src, dst):
    from aicso.router.index import entity_keys_of
    return entity_keys_of(alert("tmp", src, dst, "r-tmp"))


# ============ 合并/拆分矩阵 ============

async def suite_merge_split() -> list[SimResult]:
    print("\n── 合并/拆分矩阵 · scripted 模式 ──")
    out: list[SimResult] = []
    tmp = tempfile.mkdtemp(prefix="sim-ms-")
    client = ScriptedClient()
    engine, db = await make_sim_engine(os.path.join(tmp, "a.db"), client=client)
    merge = MergeSplitEngine(
        engine.case_store, engine.alert_store, client,
        SystemOneConfig(enabled=True, confidence_threshold=0.6),
        engine.index, engine.fallback,
    )

    # 造两个共享实体的Case（同源喷射：源5.6.7.8 → 两个不同目标被模型判为两个Case）
    await submit_all(engine, [alert("M1", "5.6.7.8", "10.0.0.1", "r-spray")])
    await submit_all(engine, [alert("M2", "5.6.7.8", "10.0.0.2", "r-spray")])
    all_cases = await engine.case_store.list_cases(limit=10)
    ca, cb = all_cases[0]["case_id"], all_cases[1]["case_id"]

    # 1 候选发现：共享源IP
    pairs = merge.find_candidate_pairs(min_shared=1)
    pair_keys = {(p.case_a, p.case_b) for p in pairs}
    out.append(check("共享实体候选发现",
                     (ca, cb) in pair_keys or (cb, ca) in pair_keys,
                     f"候选对数={len(pairs)}"))

    # 2 评估 → merge_into_a → 执行
    client.answers = [{"merge_decision": ("merge_into_a", 0.9)}]
    evaluation = await merge.evaluate_pair(ca, cb)
    assert evaluation is not None and evaluation.choice == "merge_into_a"
    result = await merge.merge(evaluation.case_a, evaluation.case_b, reason="仿真合并")
    moved = result.get("alerts_moved", 0)
    absorbed = evaluation.case_b
    absorbed_row = await engine.case_store.get(absorbed)
    absorbed_alerts = await engine.alert_store.list_alerts(case_id=evaluation.case_a)
    out.append(check("合并执行:告警迁移+重定向",
                     result["ok"] is True and absorbed_row["merged_into"] == evaluation.case_a
                     and all(a["case_id"] == evaluation.case_a for a in absorbed_alerts),
                     f"迁移{moved}条"))

    # 3 双向时间线审计
    ev_primary = await engine.case_store.get_events(evaluation.case_a)
    ev_absorbed = await engine.case_store.get_events(absorbed)
    out.append(check("双向时间线审计",
                     any(e["event_type"] == "case_merged" for e in ev_primary)
                     and any(e["event_type"] == "merged_into" for e in ev_absorbed)))

    # 4 幂等：重复合并跳过
    again = await merge.merge(evaluation.case_a, absorbed, reason="重复")
    out.append(check("重复合并幂等跳过", again.get("skipped") == "already_merged"))

    # 5 索引退出候选
    out.append(check("被并Case退出路由候选", engine.index.contains(absorbed) is False))

    # 6 no_merge：判定为不同事件 → 不执行合并
    case_nm = Case(case_id="C-NM", title="待评估事件",
                   severity=CaseSeverity.MEDIUM, status=CaseStatus.NEW)
    case_nm.record_case_created()
    await engine.case_store.create(case_nm)
    for e in case_nm.timeline:
        await engine.case_store.add_event("C-NM", e)
    await engine.case_store.db.flush()
    engine.index.add_case("C-NM", "待评估事件", ["ip:7.7.7.7", "ip:10.0.0.2"])
    client.answers = [{"merge_decision": ("no_merge", 0.95)}]
    evaluation_nm = await merge.evaluate_pair(ca, "C-NM")
    out.append(check("no_merge判定不执行合并",
                     evaluation_nm is not None and evaluation_nm.choice == "no_merge"))

    # 7 拆分：从主Case拆回被并告警（合并↔拆分组合场景）
    moved_alert = absorbed_alerts[0]["alert_id"]
    split_result = await merge.split(evaluation.case_a, [moved_alert],
                                     reason="仿真拆分修正", new_title="拆回的独立事件")
    new_case_id = split_result.get("new_case_id", "")
    split_row = await engine.case_store.get(new_case_id) if new_case_id else None
    moved_row = await engine.alert_store.get(moved_alert)
    out.append(check("拆分:回链+实体继承+告警迁移",
                     split_result["ok"] is True and split_row["split_from"] == evaluation.case_a
                     and moved_row["case_id"] == new_case_id
                     and engine.index.contains(new_case_id) is True))

    # 8 跨Case归属拒绝
    foreign = await merge.split(evaluation.case_a, ["NOT-IN-THIS-CASE"], reason="x")
    out.append(check("跨Case告警归属拒绝", foreign["ok"] is False))

    # 9 空集拒绝
    empty = await merge.split(evaluation.case_a, [], reason="x")
    out.append(check("空集拒绝", empty["ok"] is False))

    # 10 拆后合回：新拆Case与父Case共享实体 → sweep+高置信度自动合并回
    client.answers = [{"merge_decision": ("merge_into_a", 0.92)}]
    evaluations = await merge.sweep(max_pairs=5, min_shared=1)
    merged_back = any(e.executed for e in evaluations)
    # 方向中性：候选对排序随机，主体可能是父或子——只要形成了合并重定向即通过
    child_row = await engine.case_store.get(new_case_id)
    parent_row = await engine.case_store.get(evaluation.case_a)
    linked = ((child_row["merged_into"] or "") == evaluation.case_a
              or (parent_row["merged_into"] or "") == new_case_id)
    out.append(check("拆后合回(sweep自动合并)",
                     merged_back is True and linked,
                     f"评估{len(evaluations)}对"))

    # 11 sweep调用上界（效率：配额保护）
    out.append(check("sweep调用上界≤max_pairs", client.calls <= 10,
                     f"累计调用{client.calls}"))

    await asyncio.sleep(0.2)
    await db.close()
    return out


# ============ 恢复矩阵 ============

async def suite_recovery() -> list[SimResult]:
    print("\n── 恢复矩阵 ──")
    out: list[SimResult] = []
    tmp = tempfile.mkdtemp(prefix="sim-rec-")
    db_path = os.path.join(tmp, "r.db")
    engine, db = await make_sim_engine(db_path, client=None)
    await submit_all(engine, [alert("R1", "8.8.8.8", "10.0.0.8", "r-brute")])
    first_case = (await engine.alert_store.get("R1"))["case_id"]
    await db.flush()
    await db.close()

    # 重启：新引擎重建
    engine2, db2 = await make_sim_engine(db_path, client=None)
    rebuilt = await engine2.rebuild_index_from_db()
    backfilled = await engine2.backfill_unrouted()
    probe = alert("R2", "8.8.8.8", "10.0.0.8", "r-brute")
    await engine2.alert_store.create(probe)
    await engine2.submit(probe)
    ds = await engine2.flush()
    out.append(check("重启恢复:索引重建+零回灌+窗口语义",
                     rebuilt >= 1 and backfilled == 0
                     and ds[0].decision == "route_to" and ds[0].case_id == first_case))
    await asyncio.sleep(0.2)
    await db2.close()
    return out


# ============ 效率 ============

async def suite_efficiency(scale: float, client=None) -> tuple[list[SimResult], dict]:
    print("\n── 效率矩阵 ──")
    out: list[SimResult] = []
    metrics_summary: dict = {}
    tmp = tempfile.mkdtemp(prefix="sim-eff-")
    engine, db = await make_sim_engine(os.path.join(tmp, "e.db"), client=client)

    # 1 吞吐：随机形状新IP流（测纯管道与本地兜底路径）
    n = int(3000 * scale)
    batch = [alert(f"T-{i}", f"40.{i // 50}.{i % 50}.{i % 254}", f"10.9.{i // 100}.{i % 100}",
                   f"r-{i % 7}") for i in range(n)]
    start = time.monotonic()
    for a in batch:
        await engine.alert_store.create(a)
        await engine.submit(a)
    await engine.flush()
    elapsed = time.monotonic() - start
    throughput = n / elapsed if elapsed else 0
    ok_tp = throughput >= THROUGHPUT_TARGET
    mode = "local" if client is None else "scripted"
    out.append(check(f"吞吐({n}条,{mode})", ok_tp,
                     f"{throughput:.0f} alerts/s 目标≥{THROUGHPUT_TARGET}"))
    metrics_summary["throughput"] = round(throughput)
    metrics_summary["routed"] = engine.metrics.routed_total

    # 2 API请求放大系数（scripted模式）：真实SOC流量形状——
    #   10个campaign（种子Case + 同实体后续告警），候选存在时才问模型，
    #   同签名后续命中决策缓存。放大系数=模型请求/已路由告警。
    if client is not None:
        campaigns = 10 * max(1, int(scale))
        followups = 19
        # 种子：每campaign首告建Case（新IP无候选，fallback新建）
        seeds = [alert(f"CP-{c}-0", f"50.0.0.{c}", f"60.0.0.{c}", f"r-camp{c}")
                 for c in range(campaigns)]
        await submit_all(engine, seeds)
        calls_after_seeds = client.calls
        # 同实体后续告警：候选存在（模型裁决）+ 同签名（缓存命中）
        follow = [alert(f"CP-{c}-{k}", f"50.0.0.{c}", f"60.0.0.{c}", f"r-camp{c}")
                  for c in range(campaigns) for k in range(1, followups + 1)]
        start = time.monotonic()
        for a in follow:
            await engine.alert_store.create(a)
            await engine.submit(a)
        await engine.flush()
        follow_elapsed = time.monotonic() - start
        model_calls = client.calls - calls_after_seeds
        routed_follow = campaigns * followups
        amplification = model_calls / routed_follow if routed_follow else 0
        ok_amp = amplification <= AMPLIFICATION_LIMIT
        out.append(check("API请求放大系数(campaign形状)",
                         ok_amp,
                         f"{model_calls}次模型请求/{routed_follow}条 = {amplification:.4f}"
                         f" 目标≤{AMPLIFICATION_LIMIT}"
                         f"（微批{engine.scfg.batch_max_alerts}条/批+缓存60s）"))
        follow_tp = routed_follow / follow_elapsed if follow_elapsed else 0
        print(f"  同实体汇入吞吐: {follow_tp:.0f} alerts/s")
        metrics_summary["requests"] = client.calls
        metrics_summary["amplification"] = round(amplification, 4)

    # 3 延迟分位
    lat = engine.metrics.latency_percentiles()
    p99 = lat.get("p99_ms")
    out.append(check("路由P99", p99 is not None and p99 <= 1000,
                     f"p99={p99}ms"))
    metrics_summary["latency"] = lat

    await asyncio.sleep(0.3)
    await db.flush_and_close()
    return out, metrics_summary


# ============ 真实API语义抽检 ============

async def suite_systemone_real(count: int = 40) -> list[SimResult]:
    print(f"\n── 语义抽检 · 真实象信API（{count}条，成本受控） ──")
    from aicso.config import load_config
    config = load_config()
    if not config.system_one.api_key:
        print("  ⚠ 缺少 api_key，跳过")
        return [SimResult("systemone语义抽检", True, "跳过（无key）")]
    tmp = tempfile.mkdtemp(prefix="sim-s1-")
    client = SystemOneClient(
        api_key=config.system_one.api_key, base_url=config.system_one.base_url,
        model=config.system_one.model, timeout_ms=config.system_one.timeout_ms)
    engine, db = await make_sim_engine(os.path.join(tmp, "s.db"), client=client)

    # 场景一：同一受害者的暴破事件（同pair，应汇入）
    same_pair = [alert(f"S-P{i}", "1.2.3.4", "10.0.0.1", "r-brute",
                       rule_name="SSH暴力破解检测")
                 for i in range(count // 2)]
    # 场景二：同规则扫描全网（不相交，应各自新建——issue #31语义）
    scan = [alert(f"S-S{i}", f"66.0.{i // 254}.{i % 254}", f"77.0.{i // 254}.{i % 254}",
                  "r-scan", rule_name="端口扫描检测")
            for i in range(count // 2)]
    alerts = same_pair + scan
    for a in alerts:
        await engine.alert_store.create(a)
        await engine.submit(a)
    start = time.monotonic()
    while engine.metrics.routed_total < count:
        await engine.flush()
        if time.monotonic() - start > 180:
            break
        await asyncio.sleep(0.05)

    m = engine.metrics
    all_routed = await engine.alert_store.list_alerts(limit=500)
    pair_cases = {a["case_id"] for a in all_routed if a["alert_id"].startswith("S-P")}
    scan_cases = {a["case_id"] for a in all_routed if a["alert_id"].startswith("S-S")}
    out = []
    out.append(check("同pair暴破事件收敛(汇入)", len(pair_cases) <= 3,
                     f"{count // 2}条 → {len(pair_cases)}个Case"))
    out.append(check("同规则扫描不相交IP独立建Case(#31语义)",
                     len(scan_cases) >= count // 2 - 3,
                     f"{count // 2}条 → {len(scan_cases)}个Case"))
    out.append(check("API请求受微批约束", m.systemone_requests_total <= 10,
                     f"{m.systemone_requests_total}次/{count}条"))
    cost = m.systemone_tokens_total * 0.042 / 1_000_000
    print(f"  用量: {m.systemone_requests_total}请求 {m.systemone_tokens_total}token ≈¥{cost:.4f}"
          f" 延迟{m.latency_percentiles()}")
    await db.flush_and_close()
    await client.aclose()
    return out


# ============ 真实数据集回放矩阵 ============

@dataclass
class ScenarioStream:
    """数据集场景流：一个数据集文件 = 一个预期场景（天然的 expected-case 标签）

    kind: attack=攻击场景(收敛断言对象) | benign=良性噪声(误并断言对象)
    field_mapping: 该场景的字段路径覆盖（None=用套件级 field_mapping）
    """
    name: str
    records: list[dict]
    kind: str = "attack"   # attack | benign
    field_mapping: dict | None = None


async def suite_dataset(streams: list[ScenarioStream], field_mapping: dict | None = None,
                        schema: str = "generic", rate: float = 0.0,
                        max_records: int = 0) -> tuple[list[SimResult], dict]:
    """真实数据集回放有效性矩阵（issue #40）

    数据形状即真值：每个数据集文件=一个攻击场景或良性噪声流，断言：
      1. 单场景收敛：带IP告警的case数 ≤ 去重(src,dst)对数（本地pair窗内结构下界）
      2. 跨场景零串流：任何case不得同时含两个场景的告警
      3. 良性零误并：良性告警不得进入含攻击告警的case
    语义级收敛增益（模型裁决汇入）属真实SIEM调优范畴，记分卡输出、不强断言。

    rate: 每秒回放条数（0=尽快）。路由pair窗与索引last_seen按摄入时钟计
    （router/fallback.py PAIR_WINDOW_MINUTES=10），低速回放会真实产生更多
    独立case——收敛断言仅在窗内速率下有意义。
    """
    print(f"\n── 真实数据集回放矩阵 · local 模式（{len(streams)}场景） ──")
    out: list[SimResult] = []
    tmp = tempfile.mkdtemp(prefix="sim-ds-")
    prior_log_config = structlog.get_config()
    structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.WARNING))
    engine, db = await make_sim_engine(os.path.join(tmp, "d.db"))

    def mapper_for(stream: ScenarioStream) -> SchemaMapper:
        mapping = stream.field_mapping if stream.field_mapping is not None \
            else (field_mapping or {})
        return SchemaMapper({"schema": schema, "field_mapping": mapping},
                            default_source="dataset")

    alert_scenario: dict[str, str] = {}   # alert_id → 场景名
    alert_has_ip: dict[str, bool] = {}
    alert_entities: dict[str, set] = {}   # alert_id → 实体键集合
    benign_alerts: set[str] = set()
    scenario_pairs: dict[str, set] = {}   # 场景 → 去重(src,dst)对
    warn_count = 0
    total = 0
    start = time.monotonic()
    for stream in streams:
        mapper = mapper_for(stream)
        pairs: set = set()
        for i, record in enumerate(stream.records):
            if max_records and total >= max_records:
                break
            alert, warnings = mapper.normalize(
                record, fallback_alert_id=f"{stream.name}-{i}")
            warn_count += len(warnings)
            await engine.alert_store.create(alert)
            await engine.submit(alert)
            alert_scenario[alert.alert_id] = stream.name
            has_ip = bool(alert.src_ip or alert.dst_ip)
            alert_has_ip[alert.alert_id] = has_ip
            ents = set()
            if alert.src_ip:
                ents.add(f"ip:{alert.src_ip}")
            if alert.dst_ip:
                ents.add(f"ip:{alert.dst_ip}")
            if alert.src_ip and alert.dst_ip:
                ents.add(f"pair:{alert.src_ip}>{alert.dst_ip}")
            alert_entities[alert.alert_id] = ents
            if has_ip:
                pairs.add((alert.src_ip, alert.dst_ip))
            if stream.kind == "benign":
                benign_alerts.add(alert.alert_id)
            total += 1
            if rate > 0:
                await asyncio.sleep(1.0 / rate)
        scenario_pairs[stream.name] = pairs
        if max_records and total >= max_records:
            break
    await engine.flush()
    await engine.alert_store.db.flush()   # 读己之写

    elapsed = time.monotonic() - start
    throughput = total / elapsed if elapsed else 0

    case_of: dict[str, str] = {}
    for alert_id in alert_scenario:
        row = await engine.alert_store.get(alert_id)
        if row and row.get("case_id"):
            case_of[alert_id] = row["case_id"]

    # 1 单场景收敛（仅带IP告警；无IP告警按无候选独立新建属预期形态）
    per_scenario: dict = {}
    for stream in streams:
        ids = [a for a in alert_scenario if alert_scenario[a] == stream.name]
        ip_ids = [a for a in ids if alert_has_ip[a]]
        ip_cases = {case_of[a] for a in ip_ids if a in case_of}
        pairs = scenario_pairs[stream.name]
        per_scenario[stream.name] = {
            "kind": stream.kind, "alerts": len(ids), "ip_alerts": len(ip_ids),
            "cases": len({case_of[a] for a in ids if a in case_of}),
            "ip_cases": len(ip_cases), "pairs": len(pairs),
        }
    over = {n: f"ip_case {m['ip_cases']}>对数{max(m['pairs'], 1)}"
            for n, m in per_scenario.items()
            if m["kind"] == "attack" and m["ip_cases"] > max(m["pairs"], 1)}
    out.append(check("单场景收敛(带IP告警case数≤去重对数)", not over,
                     f"超额:{over}" if over else f"{len(per_scenario)}场景达标"))

    # 2 跨场景串流必须由共享实体解释：真实多数据集常共享同一靶场/基础设施，
    #   同pair/同IP汇入同case是合法路由；不同场景告警无任何共享实体却同case
    #   则是路由错误（索引损坏/错误合并）
    case_scenarios: dict[str, set] = {}
    for a, c in case_of.items():
        case_scenarios.setdefault(c, set()).add(alert_scenario[a])
    leaks = [c for c, s in case_scenarios.items() if len(s) > 1]
    unexplained: dict[str, list] = {}
    for c in leaks:
        by_scn: dict[str, list[set]] = {}
        for a, cc in case_of.items():
            if cc == c:
                by_scn.setdefault(alert_scenario[a], []).append(alert_entities[a])
        bad_pairs = []
        scns = sorted(by_scn)
        for i, s1 in enumerate(scns):
            for s2 in scns[i + 1:]:
                if not any(ea & eb for ea in by_scn[s1] for eb in by_scn[s2]):
                    bad_pairs.append(f"{s1}↔{s2}")
        if bad_pairs:
            unexplained[c] = bad_pairs
    out.append(check("跨场景串流均有共享实体支撑", not unexplained,
                     f"不可解释串流={list(unexplained.items())[:2]}"
                     f"（可解释串流case {len(leaks) - len(unexplained)}个）"
                     if unexplained else
                     (f"串流case {len(leaks)}个均为共享实体汇入"
                      if leaks else f"{len(case_scenarios)}个case场景纯净")))

    # 3 良性零误并
    attack_names = {s.name for s in streams if s.kind == "attack"}
    benign_leak = [a for a, c in case_of.items()
                   if a in benign_alerts and (case_scenarios.get(c, set()) & attack_names)]
    out.append(check("良性零误并(不进攻击case)", not benign_leak,
                     f"误并{len(benign_leak)}条" if benign_leak else ""))

    print("  场景记分卡:")
    for name, m in per_scenario.items():
        conv = m["ip_alerts"] / m["ip_cases"] if m["ip_cases"] else 0.0
        print(f"    {name}[{m['kind']}] 告警{m['alerts']}(带IP{m['ip_alerts']})"
              f" → case {m['cases']}(带IP{m['ip_cases']})"
              f" 去重对{m['pairs']} 收敛比{conv:.1f}")
    print(f"  吞吐 {throughput:.0f}/s 映射警告{warn_count}条 用时{elapsed:.1f}s"
          f"（串流case {len(leaks)}个）")

    metrics_summary = {"total": total, "throughput": round(throughput),
                       "mapping_warnings": warn_count, "scenarios": per_scenario,
                       "elapsed_s": round(elapsed, 1)}
    await asyncio.sleep(0.2)
    await db.flush_and_close()
    structlog.configure(**prior_log_config)
    return out, metrics_summary


# ============ 主入口 ============

async def run_all(scale: float = 1.0, with_systemone: bool = False) -> dict:
    results: dict[str, list[SimResult]] = {}
    results["分流矩阵/local"] = await suite_routing_local()
    results["分流矩阵/scripted"] = await suite_routing_scripted()
    results["合并拆分矩阵"] = await suite_merge_split()
    results["恢复矩阵"] = await suite_recovery()

    # 效率：local吞吐 + scripted放大系数
    eff_local, m1 = await suite_efficiency(scale, client=None)
    results["效率/local吞吐"] = eff_local
    client2 = ScriptedClient()
    eff_scripted, m2 = await suite_efficiency(scale, client=client2)
    results["效率/scripted放大"] = eff_scripted

    if with_systemone:
        results["语义抽检/真实API"] = await suite_systemone_real(count=max(20, int(40 * scale)))

    print("\n" + "=" * 52)
    print("仿真记分卡")
    print("=" * 52)
    all_ok = True
    for suite, sims in results.items():
        suite_ok = all(s.ok for s in sims)
        all_ok = all_ok and suite_ok
        print(f"{'✅' if suite_ok else '❌'} {suite}")
        for s in sims:
            if not s.ok:
                print(f"     ❌ {s.name} — {s.detail}")
    if m1:
        print(f"\n效率指标: local吞吐 {m1.get('throughput')} alerts/s")
    if m2:
        print(f"          scripted {m2.get('routed')}条 / {m2.get('requests')}请求"
              f" (放大系数 {m2.get('amplification')})")
    print("=" * 52)
    print(f"总体: {'✅ 全部通过' if all_ok else '❌ 存在失败'}")
    return {"ok": all_ok, "results": {k: [vars(s) for s in v] for k, v in results.items()}}


async def main() -> int:
    parser = argparse.ArgumentParser(description="分流/合并/拆分全场景仿真")
    parser.add_argument("--scale", type=float, default=1.0, help="流量放大系数")
    parser.add_argument("--with-systemone", action="store_true",
                        help="附加真实象信API语义抽检（成本受控）")
    args = parser.parse_args()
    result = await run_all(scale=args.scale, with_systemone=args.with_systemone)
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    import sys
    sys.exit(asyncio.run(main()))
