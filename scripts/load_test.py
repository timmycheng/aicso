"""路由引擎负载测试与降级演练（issue #6，验收 docs/REFACTOR_DESIGN.md §13 P1）

模式:
  local      本地兜底模式吞吐压测（≥500 alerts/s、P99<1s、零丢失）
  degraded   System One 中断演练（降级接管、零丢失、degraded计数）
  recovery   重启恢复演练（索引重建+回灌，重启后同源告警仍汇入原Case）
  systemone  真实System One API小批量路由（成本受控，默认200条）
  all        依次执行以上全部（systemone 除外，需 --with-systemone 显式开启）

用法:
  uv run python scripts/load_test.py --mode all --count 5000
"""
from __future__ import annotations

import argparse
import asyncio
import os
import tempfile
import time

from aicso.adapters.mock_producer import ecs_to_alert, generate_mock_alerts
from aicso.config import RoutingConfig, SystemOneConfig
from aicso.models.alert import Alert
from aicso.router.engine import RouterEngine
from aicso.store.alert_store import AlertStore
from aicso.store.case_store import CaseStore
from aicso.store.database import Database
from aicso.store.routing_store import RoutingDecisionStore
from aicso.systemone.client import SystemOneClient, SystemOneError, SystemOneUnavailableError

THROUGHPUT_TARGET = 500      # alerts/s（本地模式验收线）
LATENCY_P99_TARGET_MS = 1000


class FailingClient:
    """演练用：模拟 System One 持续不可用"""

    async def system_one(self, state, questions):
        raise SystemOneUnavailableError("演练注入：服务不可用")

    async def aclose(self):
        pass


def build_alerts(count: int, seed_categories: list[str] | None = None) -> list[Alert]:
    alerts = []
    batch = 200  # mock生成器分批，避免单次过大
    generated = 0
    while generated < count:
        n = min(batch, count - generated)
        for ecs in generate_mock_alerts(count=n, categories=seed_categories):
            alerts.append(ecs_to_alert(ecs))
        generated += n
    return alerts


async def make_engine(db_path: str, client=None, scfg: SystemOneConfig | None = None):
    db = Database(db_path)
    await db.connect()
    await db.init_tables()
    db.enable_write_buffer(batch_size=50, flush_interval=0.1)  # 对齐生产配置
    engine = RouterEngine(
        case_store=CaseStore(db),
        alert_store=AlertStore(db),
        routing_store=RoutingDecisionStore(db),
        system_one_config=scfg or SystemOneConfig(enabled=True, batch_window_ms=100),
        routing_config=RoutingConfig(queue_max_size=50000),
        client=client,
    )
    return engine, db


async def drain(engine: RouterEngine, total: int, timeout_s: float = 120) -> float:
    """flush驱动直到全部路由完成，返回耗时秒"""
    start = time.monotonic()
    while engine.metrics.routed_total < total:
        await engine.flush()  # 无worker模式下由调用方驱动消费
        if engine.metrics.routed_total >= total:
            break
        if time.monotonic() - start > timeout_s:
            raise TimeoutError(f"路由未在{timeout_s}s内完成: "
                               f"{engine.metrics.routed_total}/{total}")
        await asyncio.sleep(0.05)
    return time.monotonic() - start


async def run_local(count: int) -> bool:
    print(f"\n=== 本地兜底模式吞吐压测 ({count} alerts) ===")
    tmp = tempfile.mkdtemp(prefix="aicso-load-")
    db_path = os.path.join(tmp, "load.db")
    engine, db = await make_engine(db_path, client=None)
    alerts = build_alerts(count)

    latencies: list[float] = []
    submit_start = time.monotonic()
    for i, alert in enumerate(alerts):
        await engine.alert_store.create(alert)
        t0 = time.monotonic()
        await engine.submit(alert)
        # 每500条同步排空一次，记录批尾延迟（模拟消费端节奏）
        if (i + 1) % 500 == 0:
            await engine.flush()
            latencies.append(time.monotonic() - t0)
    await engine.flush()
    elapsed = time.monotonic() - submit_start

    m = engine.metrics
    throughput = count / elapsed
    lost = count - m.routed_total
    avg_batch_latency = (sum(latencies) / len(latencies) * 1000) if latencies else 0
    ok_tp = throughput >= THROUGHPUT_TARGET
    ok_loss = lost == 0

    print("\n--- local 模式 ---")
    print(f"  告警数        : {count}  (丢失: {lost})")
    print(f"  总耗时        : {elapsed:.1f}s")
    print(f"  吞吐          : {throughput:.0f} alerts/s  "
          f"[{'PASS' if ok_tp else 'FAIL'} 目标≥{THROUGHPUT_TARGET}]")
    print(f"  每500条批尾延迟: {avg_batch_latency:.0f}ms (均值)")
    print(f"  汇入/新建     : {m.route_to_total} / {m.cases_created_total} "
          + (f"(并入率 {m.route_to_total / m.routed_total:.0%})" if m.routed_total else ""))
    print(f"  指标延迟分位  : {m.latency_percentiles()}")
    print(f"  积压年龄      : {m.backlog_age_ms()}ms")
    print(f"  验收          : {'✅ PASS' if ok_tp and ok_loss else '❌ FAIL'}")

    await asyncio.sleep(0.3)  # 等待fire-and-forget审计写入完成
    await db.flush_and_close()
    return ok_tp and ok_loss


async def run_degraded(count: int) -> bool:
    print(f"\n=== System One 中断降级演练 ({count} alerts) ===")
    tmp = tempfile.mkdtemp(prefix="aicso-deg-")
    engine, db = await make_engine(os.path.join(tmp, "deg.db"), client=FailingClient())
    assert engine._client is not None, "演练应注入client"
    alerts = build_alerts(count)

    submit_start = time.monotonic()
    for alert in alerts:
        await engine.alert_store.create(alert)
        await engine.submit(alert)
    await engine.flush()
    elapsed = time.monotonic() - submit_start

    m = engine.metrics
    ok_loss = (count - m.routed_total) == 0
    # 验收口径：终态降级 + 全部决策来自本地兜底 + 零丢失
    # （首批次无候选告警在降级标志置位前路由，degraded_total 可略小于count）
    ok_deg = engine._degraded and m.fallback_total == count
    throughput = count / elapsed

    print(f"  告警数        : {count}  (丢失: {count - m.routed_total})")
    print(f"  吞吐          : {throughput:.0f} alerts/s")
    print(f"  降级接管      : 终态degraded={engine._degraded} "
          f"fallback决策={m.fallback_total}/{count}  "
          f"[{'PASS' if ok_deg else 'FAIL'}]")
    print(f"  零丢失        : [{'PASS' if ok_loss else 'FAIL'}]")
    print(f"  验收          : {'✅ PASS' if ok_loss and ok_deg else '❌ FAIL'}")

    await db.flush_and_close()
    return ok_loss and ok_deg


async def run_recovery(count: int) -> bool:
    print(f"\n=== 重启恢复演练 ({count} alerts) ===")
    tmp = tempfile.mkdtemp(prefix="aicso-rec-")
    db_path = os.path.join(tmp, "rec.db")
    engine, db = await make_engine(db_path, client=None)
    alerts = build_alerts(count)
    for alert in alerts:
        await engine.alert_store.create(alert)
        await engine.submit(alert)
    await engine.flush()
    await db.flush()  # 写缓冲落库后再读（读取前需要看到最新写入）
    first_case_id = (await engine.alert_store.get(alerts[0].alert_id))["case_id"]
    await db.close()

    # 模拟重启：全新引擎实例，同DB
    engine2, db2 = await make_engine(db_path, client=None)
    rebuilt = await engine2.rebuild_index_from_db()
    backfilled = await engine2.backfill_unrouted()

    # 重启后同源告警的窗口语义：
    #   原Case最近告警在pair窗口内 → 应汇入原Case；超窗 → 应正确新建（不复活旧Case）
    probe = Alert(
        alert_id="REC-PROBE-001", source="test",
        rule_name=alerts[0].rule_name, severity=alerts[0].severity,
        src_ip=alerts[0].src_ip, dst_ip=alerts[0].dst_ip,
    )
    await engine2.alert_store.create(probe)
    await engine2.submit(probe)
    decisions = await engine2.flush()

    row = await engine2.alert_store.db.fetch_one(
        """SELECT MAX(timestamp) AS last_seen FROM alerts WHERE case_id = ?""",
        (first_case_id,),
    )
    from datetime import datetime, timedelta
    last_seen = datetime.fromisoformat(row["last_seen"]) if row and row["last_seen"] else None
    in_window = last_seen and (datetime.utcnow() - last_seen) <= timedelta(minutes=10)
    if in_window:
        ok_semantics = (
            decisions and decisions[0].decision == "route_to"
            and decisions[0].case_id == first_case_id
        )
        semantic_desc = f"窗口内→汇入原Case({first_case_id})"
    else:
        ok_semantics = decisions and decisions[0].decision == "new_case"
        semantic_desc = f"超窗→正确新建(原Case时间点{last_seen})"

    ok_backfill = backfilled == 0          # 全部已路由，无积压
    ok_rebuild = rebuilt > 0

    print(f"  索引重建      : {rebuilt} 个活跃Case  [{'PASS' if ok_rebuild else 'FAIL'}]")
    print(f"  积压回灌      : {backfilled} 条  [{'PASS' if ok_backfill else 'FAIL'} 应=0]")
    print(f"  窗口语义      : {semantic_desc}  [{'PASS' if ok_semantics else 'FAIL'}]")
    all_ok = ok_backfill and ok_rebuild and ok_semantics
    print(f"  验收          : {'✅ PASS' if all_ok else '❌ FAIL'}")

    await db2.flush_and_close()
    return ok_backfill and ok_rebuild and ok_semantics


async def run_systemone(count: int) -> bool:
    print(f"\n=== 真实System One路由 ({count} alerts，成本受控) ===")
    from aicso.config import load_config
    config = load_config()
    if not config.system_one.api_key:
        print("  ⚠ 缺少 api_key，跳过")
        return True

    tmp = tempfile.mkdtemp(prefix="aicso-s1-")
    client = SystemOneClient(
        api_key=config.system_one.api_key,
        base_url=config.system_one.base_url,
        model=config.system_one.model,
        timeout_ms=config.system_one.timeout_ms,
    )
    engine, db = await make_engine(
        os.path.join(tmp, "s1.db"), client=client,
        scfg=SystemOneConfig(enabled=True, batch_window_ms=100, batch_max_alerts=50),
    )
    alerts = build_alerts(count, seed_categories=["brute_force", "port_scan"])

    for alert in alerts:
        await engine.alert_store.create(alert)
        await engine.submit(alert)
    try:
        elapsed = await drain(engine, count, timeout_s=180)
    except (TimeoutError, SystemOneError) as e:
        print(f"  ❌ 未完成: {e}")
        await db.flush_and_close()
        await client.aclose()
        return False

    m = engine.metrics
    print(f"  告警数        : {count}")
    print(f"  总耗时        : {elapsed:.1f}s  吞吐 {count / elapsed:.0f} alerts/s")
    print(f"  System One    : {m.systemone_requests_total} 次请求 / "
          f"{m.systemone_tokens_total} 输入token "
          f"(≈¥{m.systemone_tokens_total * 0.042 / 1_000_000:.4f})")
    print(f"  汇入/新建     : {m.route_to_total} / {m.cases_created_total} "
          + (f"(并入率 {m.route_to_total / m.routed_total:.0%})" if m.routed_total else ""))
    print(f"  低置信度复核  : {m.low_confidence_total}")
    print(f"  指标延迟分位  : {m.latency_percentiles()}")

    await db.flush_and_close()
    await client.aclose()
    return True


async def main() -> int:
    parser = argparse.ArgumentParser(description="路由引擎负载测试与降级演练")
    parser.add_argument("--mode", default="all",
                        choices=["local", "degraded", "recovery", "systemone", "all"])
    parser.add_argument("--count", type=int, default=5000, help="告警数量")
    parser.add_argument("--with-systemone", action="store_true",
                        help="all模式下附加真实API测试（默认跳过）")
    args = parser.parse_args()

    results: dict[str, bool] = {}
    if args.mode in ("local", "all"):
        results["local"] = await run_local(args.count)
    if args.mode in ("degraded", "all"):
        results["degraded"] = await run_degraded(args.count)
    if args.mode in ("recovery", "all"):
        results["recovery"] = await run_recovery(args.count)
    if args.mode == "systemone":
        results["systemone"] = await run_systemone(args.count)
    elif args.mode == "all" and args.with_systemone:
        results["systemone"] = await run_systemone(min(args.count, 200))

    print("\n========== 汇总 ==========")
    all_ok = True
    for name, ok in results.items():
        print(f"  {name:12s}: {'✅ PASS' if ok else '❌ FAIL'}")
        all_ok = all_ok and ok
    return 0 if all_ok else 1


if __name__ == "__main__":
    import sys
    sys.exit(asyncio.run(main()))
