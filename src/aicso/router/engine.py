"""分流引擎（RouterEngine）— Case-centric 流式路由核心

设计依据: docs/REFACTOR_DESIGN.md §5

热路径: submit(alert) 入有界队列 → worker按窗口微批 → 本地候选索引粗筛
       → System One 一次请求并行判定（Choice: 候选Case + __new__）
       → confidence≥阈值 自动路由，否则保守新建 + 复核
降级:  System One 不可用 → LocalFallback 接管（degraded标记）→ 探针自动恢复
恢复:  rebuild_index_from_db() 从活跃Case重建索引；backfill_unrouted() 回灌未路由告警
"""
from __future__ import annotations

import asyncio
import json
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

import structlog
from ulid import ULID

from aicso.config import RoutingConfig, SystemOneConfig
from aicso.models.alert import Alert
from aicso.models.case import (
    SEVERITY_PRIORITY_MAP,
    SLA_CONFIG,
    Case,
    CaseEvent,
    CaseEventType,
    CasePriority,
    CaseSeverity,
    CaseStatus,
)
from aicso.models.routing import (
    NEW_CASE,
    ROUTE_TO,
    SRC_CACHE,
    SRC_FALLBACK,
    SRC_SYSTEM_ONE,
    RoutingDecision,
)
from aicso.router.batcher import RoutingBatcher
from aicso.router.fallback import LocalFallback
from aicso.router.index import CaseRoutingIndex, entity_keys_of, entity_signature
from aicso.router.metrics import RouterMetrics
from aicso.store.alert_store import AlertStore
from aicso.store.case_store import CaseStore
from aicso.store.routing_store import RoutingDecisionStore
from aicso.systemone.client import (
    Choice,
    InvalidRequestError,
    Noul,
    SystemOneClient,
    SystemOneError,
    SystemOneResponse,
)

logger = structlog.get_logger()


def estimate_tokens(text: str) -> int:
    """粗估请求token数：CJK≈1/字符、ASCII≈1/3字符、+8余量（issue #42）

    上界偏保守——宁可切小批不可422。仅用于微批切分预算，非计费用。
    """
    if not text:
        return 8
    cjk = sum(1 for ch in text if "\u4e00" <= ch <= "\u9fff")
    return 8 + cjk + (len(text) - cjk) // 3


@dataclass
class _S1Item:
    """单条System One判定项：批内构建/token预算切分/422二分的单元（issue #42）"""
    name: str
    alert: Alert
    candidates: list
    question: Choice
    state: str
    criteria_keys: list
    est_tokens: int


class RouterEngine:
    """分流引擎：告警 → 已有Case 或 新建Case"""

    def __init__(
        self,
        case_store: CaseStore,
        alert_store: AlertStore,
        routing_store: RoutingDecisionStore,
        system_one_config: SystemOneConfig,
        routing_config: RoutingConfig,
        client: SystemOneClient | None = None,
        on_new_case: None | (object) = None,  # Callable[[str, Alert], Awaitable[None]]
    ):
        self.case_store = case_store
        self.alert_store = alert_store
        self.routing_store = routing_store
        self.scfg = system_one_config
        self.rcfg = routing_config
        # client=None 或 enabled=False → 纯本地兜底模式
        self._client = client if (client and system_one_config.enabled) else None
        self.on_new_case = on_new_case

        self.index = CaseRoutingIndex(
            top_k=system_one_config.candidate_top_k,
            entity_types=set(routing_config.entity_types),
        )
        self.fallback = LocalFallback(
            window_minutes=routing_config.pair_window_minutes,
            weak_auto_merge=routing_config.weak_entity_auto_merge)
        self.metrics = RouterMetrics()

        self._batcher = RoutingBatcher(
            window_ms=system_one_config.batch_window_ms,
            max_batch=system_one_config.batch_max_alerts,
            max_size=routing_config.queue_max_size,
        )
        self._degraded = self._client is None
        self._worker_task: asyncio.Task | None = None
        self._probe_task: asyncio.Task | None = None
        self._running = False
        # 决策缓存: signature -> (case_id, ts)
        self._cache: dict[str, tuple[str, datetime]] = {}

    # ---- 生命周期 ----

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._worker_task = asyncio.create_task(self._worker())
        logger.info(
            "router.started",
            system_one_enabled=self._client is not None,
            queue_max=self.rcfg.queue_max_size,
            batch_window_ms=self.scfg.batch_window_ms,
        )

    async def stop(self) -> None:
        self._running = False
        for task in (self._worker_task, self._probe_task):
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        self._worker_task = None
        self._probe_task = None
        logger.info("router.stopped")

    # ---- 入口 ----

    async def submit(self, alert: Alert) -> bool:
        """告警入路由队列；队列满时立即走本地兜底（不阻塞上游、不丢告警）"""
        self.metrics.submitted_total += 1
        if self.metrics.oldest_pending_since is None:
            self.metrics.oldest_pending_since = datetime.utcnow()
        if self._batcher.qsize() >= self.rcfg.queue_max_size * self.rcfg.high_water_mark:
            self.metrics.queue_high_water_events += 1
            logger.warning("router.queue_high_water", depth=self._batcher.qsize())
        if not self._batcher.try_put(alert):
            # 过载：兜底立即决策，绝不丢弃
            logger.warning("router.queue_full_fallback", alert_id=alert.alert_id)
            await self._route_fallback_batch([alert])
            return False
        return True

    async def flush(self) -> list[RoutingDecision]:
        """同步排空队列（测试/CLI/Mock注入用，保证确定性结果）"""
        decisions: list[RoutingDecision] = []
        while not self._batcher.empty():
            batch: list[Alert] = []
            while len(batch) < self.scfg.batch_max_alerts and not self._batcher.empty():
                batch.append(self._batcher.get_nowait())
            if batch:
                decisions.extend(await self._route_batch(batch))
        if self.metrics.routed_total:
            self.metrics.oldest_pending_since = None
        return decisions

    async def _worker(self) -> None:
        """流式worker：按窗口/批上限聚合后路由"""
        while self._running:
            try:
                batch = await self._batcher.collect()
                if batch:
                    await self._route_batch(batch)
            except asyncio.CancelledError:
                break
            except Exception:
                logger.error("router.worker_error", exc_info=True)
                await asyncio.sleep(0.5)

    # ---- 核心路由 ----

    async def _route_batch(self, batch: list[Alert]) -> list[RoutingDecision]:
        """一批告警的路由主流程：缓存 → 候选 → System One → 应用"""
        decisions: list[RoutingDecision] = []
        pending: list[tuple[Alert, list]] = []  # 需要System One判定的

        for alert in batch:
            started = time.monotonic()
            entity_keys = entity_keys_of(alert)

            # 1. 决策缓存
            cached = self._cache_lookup(alert)
            if cached:
                case_id = cached
                decisions.append(await self._apply_route(
                    alert, case_id, RoutingDecision(
                        alert_id=alert.alert_id, case_id=case_id,
                        decision=ROUTE_TO, source=SRC_CACHE,
                        degraded=self._degraded,
                        latency_ms=(time.monotonic() - started) * 1000,
                        detail={"cache": True},
                    ),
                ))
                continue

            # 2. 本地候选粗筛
            candidates = self.index.candidates(entity_keys)
            if not candidates or self._degraded:
                # 无候选必新建（无需问模型）；降级时走兜底
                if not candidates:
                    decisions.append(await self._apply_new_case(
                        alert, RoutingDecision(
                            alert_id=alert.alert_id, case_id="",
                            decision=NEW_CASE, source=SRC_FALLBACK,
                            degraded=self._degraded,
                            latency_ms=(time.monotonic() - started) * 1000,
                            candidates=0,
                        ),
                    ))
                else:
                    decisions.append(await self._route_fallback_one(
                        alert, started, candidates
                    ))
                continue

            pending.append((alert, candidates))

        # 3. System One 批量判定（一次请求，每告警一个Choice问题）
        if pending:
            decisions.extend(await self._route_system_one(pending))

        self.metrics.oldest_pending_since = None
        return decisions

    async def _route_system_one(
        self, pending: list[tuple[Alert, list]]
    ) -> list[RoutingDecision]:
        started_all = time.monotonic()
        decisions: list[RoutingDecision] = []
        for sub in self._split_by_token_budget(pending):
            decisions.extend(await self._route_system_one_sub(sub, started_all))
        return decisions

    def _split_by_token_budget(
        self, pending: list[tuple[Alert, list]]
    ) -> list[list[_S1Item]]:
        """按token预算切子批（issue #42）

        batch_max_alerts只限条数——真实SIEM告警的候选上下文远大于合成告警，
        固定条数批会超模型上下文（65536）触发422→整流静默降级（#42根因）。
        现以估算token为硬约束切批；单条估算即超预算的保持独立子批，
        由422二分与单条兜底接手。
        """
        items = [self._build_s1_item(f"alert_{i}", i, alert, candidates)
                 for i, (alert, candidates) in enumerate(pending)]
        subs: list[list[_S1Item]] = []
        cur: list[_S1Item] = []
        cur_tokens = 0
        for item in items:
            if cur and cur_tokens + item.est_tokens > self.scfg.token_budget:
                subs.append(cur)
                cur, cur_tokens = [], 0
            cur.append(item)
            cur_tokens += item.est_tokens
        if cur:
            subs.append(cur)
        return subs

    def _build_s1_item(self, name: str, idx: int, alert: Alert, candidates: list) -> _S1Item:
        # 判定证据：候选Case附实体摘要（源/目标IP），让模型有据可判
        # 而非仅凭同名标题（issue #31）
        criteria = {}
        for slot in candidates:
            evidence = _entity_evidence(slot.entity_keys)
            criteria[slot.case_id] = f"{slot.to_summary()}｜实体: {evidence}"
        criteria["__new__"] = "与现有事件均无实体关联，应新建独立事件"
        question = Choice(
            instructions=(
                f"这是第{idx + 1}条安全告警。判断它应汇入哪个已有的安全事件(Case)。"
                "判定依据：告警的实体（源/目标IP、主机、用户、域名、文件哈希等）"
                "与候选事件实体是否重叠、是否明显属于同一攻击链。"
                "注意：仅攻击类型或规则名相同不是合并理由——不同源不同目标的同类攻击应新建独立事件；"
                "共享主机/用户也需结合行为连贯性判断，不必然是同一事件。"
                "若所有候选均无实体关联，选 __new__。"
            ),
            criteria=criteria,
        )
        state = self._compact_state(alert)
        est_tokens = (estimate_tokens(question.instructions)
                      + estimate_tokens(json.dumps(criteria, ensure_ascii=False))
                      + estimate_tokens(state))
        return _S1Item(name=name, alert=alert, candidates=candidates,
                       question=question, state=state,
                       criteria_keys=list(criteria.keys()), est_tokens=est_tokens)

    async def _call_split_on_overflow(self, items: list[_S1Item]) -> SystemOneResponse:
        """422上下文溢出→二分切半重试（issue #42）；单条仍溢出交上层兜底"""
        assert self._client is not None
        state = "\n\n".join(it.state for it in items)
        questions = {it.name: it.question for it in items}
        # 大批推理时长随输入规模增长：2s基线+0.3ms/估算token（45k批≈15s）。
        # 固定2s会把正常大请求误判为网络错误→整流降级（#42/#44验收实测）
        est_tokens = sum(it.est_tokens for it in items)
        req_timeout = self.scfg.timeout_ms + int(est_tokens * 0.3)
        try:
            response = await self._client.system_one(state=state, questions=questions,
                                                     timeout_ms=req_timeout)
        except InvalidRequestError as e:
            if e.status_code != 422 or len(items) <= 1:
                raise
            self.metrics.systemone_split_total += 1
            logger.warning("router.systemone_overflow_split", questions=len(items))
            mid = len(items) // 2
            left = await self._call_split_on_overflow(items[:mid])
            right = await self._call_split_on_overflow(items[mid:])
            return SystemOneResponse(
                model=left.model, answers={**left.answers, **right.answers},
                input_tokens=left.input_tokens + right.input_tokens,
                output_tokens=left.output_tokens + right.output_tokens,
            )
        self.metrics.systemone_requests_total += 1
        self.metrics.systemone_tokens_total += response.input_tokens
        return response

    async def _route_system_one_sub(
        self, items: list[_S1Item], started_all: float
    ) -> list[RoutingDecision]:
        try:
            assert self._client is not None
            response = await self._call_split_on_overflow(items)
        except InvalidRequestError as e:
            if e.status_code == 422:
                # 单条上下文仍超限：该条走兜底，不拖累全局降级（issue #42）
                self.metrics.systemone_oversized_total += len(items)
                logger.warning("router.systemone_question_oversized",
                               batch_size=len(items), error=str(e))
                return [await self._route_fallback_one(it.alert, started_all, it.candidates)
                        for it in items]
            raise
        except SystemOneError as e:
            self.metrics.systemone_errors_total += 1
            logger.warning("router.systemone_failed_enter_degraded",
                           error=str(e), batch_size=len(items))
            self._enter_degraded()
            # 该批全部走兜底
            return [await self._route_fallback_one(it.alert, started_all, it.candidates)
                    for it in items]

        decisions: list[RoutingDecision] = []
        for item in items:
            name = item.name
            alert, candidates = item.alert, item.candidates
            answer = response.answers.get(name)
            started = time.monotonic()
            if answer is None:
                logger.warning("router.missing_answer", alert_id=alert.alert_id)
                decisions.append(await self._route_fallback_one(
                    alert, started, candidates
                ))
                continue

            confidence = answer.confidence or 0.0
            choice = answer.choice
            valid_keys = item.criteria_keys
            if choice not in valid_keys:
                # 模型给了无效选项，保守新建
                choice = "__new__"
                confidence = min(confidence, self.scfg.confidence_threshold)

            if choice == "__new__" or confidence < self.scfg.confidence_threshold:
                low_conf = confidence < self.scfg.confidence_threshold
                if low_conf and choice != "__new__":
                    self.metrics.low_confidence_total += 1
                decisions.append(await self._apply_new_case(
                    alert, RoutingDecision(
                        alert_id=alert.alert_id, case_id="",
                        decision=NEW_CASE, source=SRC_SYSTEM_ONE,
                        confidence=confidence,
                        latency_ms=(time.monotonic() - started_all) * 1000,
                        candidates=len(candidates),
                        detail={"choice": choice, "low_confidence": low_conf},
                    ),
                ))
            else:
                # 汇入依据：与所选Case重叠的实体（审计可见，回应"原因不足"）
                shared = sorted(
                    set(entity_keys_of(alert))
                    & next((s.entity_keys for s in candidates if s.case_id == choice), set())
                )
                decision = RoutingDecision(
                    alert_id=alert.alert_id, case_id=choice,
                    decision=ROUTE_TO, source=SRC_SYSTEM_ONE,
                    confidence=confidence,
                    latency_ms=(time.monotonic() - started_all) * 1000,
                    candidates=len(candidates),
                    detail={"shared_entities": shared},
                )
                self._cache_store(alert, choice)
                decisions.append(await self._apply_route(alert, choice, decision))

        return decisions

    async def _route_fallback_one(
        self, alert: Alert, started: float, candidates: list
    ) -> RoutingDecision:
        """单条兜底：优先 pair 规则，其次无候选新建"""
        match = self.fallback.try_route(alert)
        if match:
            decision = RoutingDecision(
                alert_id=alert.alert_id, case_id=match.case_id,
                decision=ROUTE_TO, source=SRC_FALLBACK,
                degraded=self._degraded,
                latency_ms=(time.monotonic() - started) * 1000,
                candidates=len(candidates),
                detail={"fallback_key": match.key},
            )
            return await self._apply_route(alert, match.case_id, decision)
        return await self._apply_new_case(
            alert, RoutingDecision(
                alert_id=alert.alert_id, case_id="",
                decision=NEW_CASE, source=SRC_FALLBACK,
                degraded=self._degraded,
                latency_ms=(time.monotonic() - started) * 1000,
                candidates=len(candidates),
            ),
        )

    async def _route_fallback_batch(self, alerts: list[Alert]) -> None:
        now = time.monotonic()
        for alert in alerts:
            await self._route_fallback_one(alert, now, [])

    # ---- 决策应用 ----

    async def _apply_route(
        self, alert: Alert, case_id: str, decision: RoutingDecision
    ) -> RoutingDecision:
        """汇入已有Case：更新告警行 + Case时间线 + 索引活跃度"""
        # 防御：索引不认识目标Case（外部清理/长期失联）→ 保守改走新建。
        # 索引成员判断即权威：新建Case先入索引后写库（写缓冲0.1s），避免
        # 缓冲窗口内同批告警路由到刚建的Case被误判不存在
        if not self.index.contains(case_id):
            case_row = await self.case_store.get(case_id)
            if case_row is None:
                logger.warning("router.target_case_missing", case_id=case_id,
                               alert_id=alert.alert_id)
                self.index.deactivate(case_id)
                self.fallback.deactivate(case_id)
                decision.detail["target_missing"] = case_id
                return await self._apply_new_case(alert, decision)
            # DB里有但索引没有（如外部恢复的Case）→ 补进索引
            self.index.add_case(case_id, case_row.get("title", case_id), entity_keys_of(alert))

        entity_keys = entity_keys_of(alert)
        await self.alert_store.mark_routed(
            alert.alert_id, case_id, decision.source
        )
        # 汇入依据统一在此计算：与目标Case重叠的实体（覆盖三种来源，
        # issue #31——让"为什么汇入"在时间线上可审计）
        shared = sorted(set(entity_keys) & self.index.case_entities(case_id))
        event = CaseEvent(
            event_id=f"{case_id}-evt-{str(ULID())}",
            event_type=CaseEventType.ALERT_ADDED,
            actor="router",
            detail={
                "alert_id": alert.alert_id,
                "source": alert.source,
                "rule_name": alert.rule_name,
                "severity": alert.severity,
                "src_ip": alert.src_ip,
                "dst_ip": alert.dst_ip,
                "reason": (
                    f"分流汇入: {decision.source}"
                    + (f" (confidence={decision.confidence:.2f})" if decision.confidence else "")
                ),
                "shared_entities": shared,
            },
        )
        await self.case_store.add_event(case_id, event)
        self.index.record_hit(case_id, entity_keys)
        self._finalize(decision)
        if decision.source == SRC_FALLBACK:
            self.metrics.fallback_total += 1
        elif decision.source == SRC_CACHE:
            self.metrics.cache_hit_total += 1
        logger.info(
            "router.routed",
            alert_id=alert.alert_id, case_id=case_id,
            source=decision.source, confidence=decision.confidence,
            degraded=decision.degraded,
        )
        return decision

    async def _apply_new_case(
        self, alert: Alert, decision: RoutingDecision
    ) -> RoutingDecision:
        """新建Case：建Case + 注册索引/兜底 + 触发S2初始研判"""
        case = await self._create_case(alert)
        decision.case_id = case.case_id
        await self.alert_store.mark_routed(
            alert.alert_id, case.case_id, decision.source
        )
        entity_keys = entity_keys_of(alert)
        self.index.add_case(case.case_id, case.title, entity_keys)
        self.fallback.register(alert, case.case_id)
        # 低置信度保守新建不写缓存（避免错误决策被复用）
        if decision.source == SRC_SYSTEM_ONE and not decision.detail.get("low_confidence"):
            self._cache_store(alert, case.case_id)
        if decision.source == SRC_FALLBACK:
            self.metrics.fallback_total += 1

        # 低置信度保守新建 → 记复核事件
        if decision.detail.get("low_confidence"):
            event = CaseEvent(
                event_id=f"{case.case_id}-evt-{str(ULID())}",
                event_type="routing_review",
                actor="router",
                detail={
                    "reason": "System One置信度低于阈值，保守新建",
                    "confidence": decision.confidence,
                    "suggested_case": decision.detail.get("choice"),
                },
            )
            await self.case_store.add_event(case.case_id, event)

        self._finalize(decision)
        logger.info(
            "router.new_case",
            alert_id=alert.alert_id, case_id=case.case_id,
            source=decision.source, confidence=decision.confidence,
            degraded=decision.degraded,
        )
        # 通知编排器启动S2初始研判
        if self.on_new_case is not None:
            try:
                await self.on_new_case(case.case_id, alert)
            except Exception:
                logger.error("router.on_new_case_failed",
                             case_id=case.case_id, exc_info=True)
        return decision

    async def _create_case(self, alert: Alert) -> Case:
        """从告警创建新Case（迁自 orchestrator._create_case_from_alert）"""
        severity = (
            CaseSeverity(alert.severity)
            if alert.severity in [s.value for s in CaseSeverity]
            else CaseSeverity.MEDIUM
        )
        case = Case(
            # 12位hex（48bit）：5000条/日规模下生日碰撞概率<1e-7
            case_id=f"CSO-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:12].upper()}",
            title=f"[{alert.source}] {alert.rule_name or 'Unknown Alert'}",
            severity=severity,
            status=CaseStatus.NEW,
            priority=SEVERITY_PRIORITY_MAP.get(severity, CasePriority.P3),
            metadata={"routing": {"source": "router", "created_by": "auto_from_alert"}},
        )
        case.record_case_created(source="auto_from_alert")
        case.add_alert(alert, reason="auto_created")
        sla_mins = SLA_CONFIG.get(case.priority, (0, 0))[0]
        if sla_mins > 0:
            case.sla_deadline = datetime.utcnow() + timedelta(minutes=sla_mins)

        await self.case_store.create(case)
        for event in case.timeline:
            await self.case_store.add_event(case.case_id, event)
        self.metrics.cases_created_total += 1
        return case

    def _finalize(self, decision: RoutingDecision) -> None:
        """持久化审计记录并更新指标"""
        decision.degraded = decision.degraded or self._degraded
        self.metrics.routed_total += 1
        if decision.decision == ROUTE_TO:
            self.metrics.route_to_total += 1
        if decision.degraded:
            self.metrics.degraded_total += 1
        self.metrics.record_latency(decision.latency_ms)
        # 审计落库（异步fire-and-forget，失败不阻塞热路径）
        task = asyncio.create_task(self.routing_store.create(decision))
        task.add_done_callback(_log_store_error)

    # ---- 缓存 ----

    def _cache_lookup(self, alert: Alert) -> str | None:
        sig = entity_signature(alert)
        cached = self._cache.get(sig)
        if cached is None:
            return None
        case_id, ts = cached
        if datetime.utcnow() - ts <= timedelta(seconds=self.scfg.cache_ttl_seconds):
            return case_id
        del self._cache[sig]
        return None

    def _cache_store(self, alert: Alert, case_id: str) -> None:
        self._cache[entity_signature(alert)] = (case_id, datetime.utcnow())

    # ---- 降级与恢复 ----

    def _enter_degraded(self) -> None:
        if self._client is None:
            return
        self._degraded = True
        logger.warning("router.degraded")
        if self._probe_task is None or self._probe_task.done():
            self._probe_task = asyncio.create_task(self._probe_loop())

    async def _probe_loop(self) -> None:
        """降级后每30s探针探测，成功即切回主路径"""
        while self._degraded and self._client is not None:
            await asyncio.sleep(30)
            try:
                await self._client.system_one(
                    state="probe",
                    questions={"alive": Noul(instructions="探测服务可用性，任意作答")},
                )
                self._degraded = False
                logger.info("router.recovered_from_degraded")
                return
            except SystemOneError:
                continue

    # ---- 恢复（重启） ----

    async def rebuild_index_from_db(self) -> int:
        """从DB活跃Case重建候选索引（§5.6：不依赖规则TTL语义，重建即正确）"""
        rows = await self.alert_store.db.fetch_all("""
            SELECT a.case_id, c.title AS summary,
                   a.src_ip, a.dst_ip, a.rule_id,
                   MAX(a.timestamp) AS last_seen, COUNT(*) AS hits
            FROM alerts a
            JOIN cases c ON c.case_id = a.case_id
            WHERE a.case_id IS NOT NULL
              AND c.status NOT IN ('resolved', 'closed')
              AND c.merged_into IS NULL
            GROUP BY a.case_id, c.title, a.src_ip, a.dst_ip, a.rule_id
        """)
        count = self.index.rebuild(rows)
        self.fallback.rebuild(rows)
        logger.info("router.index_rebuilt", active_cases=count)
        return count

    async def backfill_unrouted(self) -> int:
        """回灌未路由告警（routed_at IS NULL），重启零丢失"""
        rows = await self.alert_store.list_unrouted(limit=self.rcfg.queue_max_size)
        for row in rows:
            alert = Alert(
                alert_id=row["alert_id"], source=row["source"],
                rule_id=row.get("rule_id"), rule_name=row.get("rule_name"),
                severity=row.get("severity"), src_ip=row.get("src_ip"),
                dst_ip=row.get("dst_ip"), src_port=row.get("src_port"),
                dst_port=row.get("dst_port"), protocol=row.get("protocol"),
                raw_log=row.get("raw_log"),
            )
            await self.submit(alert)
        if rows:
            logger.info("router.backfilled", count=len(rows))
        return len(rows)

    # ---- 展示 ----

    def status(self) -> dict:
        return {
            "system_one_enabled": self._client is not None,
            "degraded": self._degraded,
            "queue_depth": self._batcher.qsize(),
            "queue_max": self.rcfg.queue_max_size,
            "cache_size": len(self._cache),
            "index": self.index.stats(),
            "fallback": self.fallback.stats(),
            "metrics": self.metrics.to_dict(
                queue_depth=self._batcher.qsize(),
                queue_max=self.rcfg.queue_max_size,
            ),
        }

    @staticmethod
    def _compact_state(alert: Alert) -> str:
        """告警紧凑摘要（state模板，控制token）"""
        parts = [
            f"告警[{alert.alert_id}] 来源{alert.source}",
            f"规则: {alert.rule_name or '-'}",
            f"源IP {alert.src_ip or '-'} → 目标IP {alert.dst_ip or '-'}",
            f"严重度 {alert.severity or '-'}",
        ]
        if alert.entities:
            parts.append("实体: " + _entity_evidence(
                {f"{k}:{v}" for k, v in alert.entities.items()}))
        return " | ".join(parts)


_ENTITY_LABELS = {
    "host": "主机",
    "user": "用户",
    "file_hash": "文件哈希",
    "dst_domain": "域名",
}


def _entity_evidence(entity_keys: set[str], limit: int = 6) -> str:
    """实体键转人读摘要（System One判定证据，issue #44支持弱实体类型）"""
    items = []
    for key in sorted(entity_keys)[:limit]:
        if key.startswith("pair:"):
            items.append(key[5:].replace(">", "→"))
        elif key.startswith("ip:"):
            items.append(key[3:])
        else:
            etype, _, value = key.partition(":")
            label = _ENTITY_LABELS.get(etype, etype)
            items.append(f"{label}{value}")
    return ", ".join(items) or "无记录"


def _log_store_error(task: asyncio.Task) -> None:
    if not task.cancelled() and task.exception() is not None:
        logger.error("router.decision_store_failed", error=str(task.exception()))
