"""编排引擎 — S2认知任务调度（分诊/调查/报告）

告警分流已移交 RouterEngine（src/aicso/router），编排器专注于
Case 之上的认知任务：新Case初始研判、调查、报告。
"""
from __future__ import annotations

import asyncio

import structlog
from ulid import ULID

from aicso.agents.base import AgentResult, AgentStatus, BaseAgent
from aicso.cognition.dispatcher import S2Dispatcher
from aicso.core.approval import ApprovalEngine
from aicso.core.context import ContextManager
from aicso.core.event_bus import Event, EventBus, EventType
from aicso.models.alert import Alert
from aicso.models.case import (
    SEVERITY_PRIORITY_MAP,
    Case,
    CaseEvent,
    CaseEventType,
    CaseSeverity,
)
from aicso.router.engine import RouterEngine
from aicso.store.alert_store import AlertStore
from aicso.store.case_store import CaseStore

logger = structlog.get_logger()


class Orchestrator:
    """核心编排引擎"""

    def __init__(
        self,
        case_store: CaseStore,
        alert_store: AlertStore,
        context_manager: ContextManager,
        event_bus: EventBus,
        approval_engine: ApprovalEngine,
        router: RouterEngine | None = None,
        dispatcher: S2Dispatcher | None = None,
        ops_service=None,
        max_concurrent_triage: int = 3,
        llm_enabled: bool = True,
    ):
        self.case_store = case_store
        self.alert_store = alert_store
        self.context_manager = context_manager
        self.event_bus = event_bus
        self.approval_engine = approval_engine
        self.router = router
        self.dispatcher = dispatcher
        self.ops_service = ops_service
        self._agents: dict[str, BaseAgent] = {}
        self._llm_enabled = llm_enabled

        # TriageAgent 并发控制
        self._max_concurrent_triage = max_concurrent_triage
        self._triage_semaphore: asyncio.Semaphore | None = None
        self._triage_queue: asyncio.Queue | None = None
        self._triage_worker_task: asyncio.Task | None = None
        # 后台任务跟踪（fire-and-forget不进黑洞、shutdown可取消）
        self._background: set[asyncio.Task] = set()

    def start(self) -> None:
        """启动编排引擎（后台 worker）"""
        self._triage_semaphore = asyncio.Semaphore(self._max_concurrent_triage)
        self._triage_queue = asyncio.Queue(maxsize=200)
        self._triage_worker_task = asyncio.create_task(self._triage_worker())
        logger.info("orchestrator.started", max_concurrent_triage=self._max_concurrent_triage)

    async def close(self) -> None:
        """停止编排引擎"""
        if self._triage_worker_task:
            self._triage_worker_task.cancel()
            try:
                await self._triage_worker_task
            except asyncio.CancelledError:
                pass
            self._triage_worker_task = None
        for task in list(self._background):  # 跟踪的后台任务一并取消
            task.cancel()
        if self._background:
            await asyncio.gather(*self._background, return_exceptions=True)
        self._background.clear()
        logger.info("orchestrator.stopped")

    async def _triage_worker(self) -> None:
        """后台 worker：从队列取任务，控制并发执行 TriageAgent"""
        while True:
            try:
                case_id, trigger_alert = await self._triage_queue.get()
            except asyncio.CancelledError:
                break

            try:
                async with self._triage_semaphore:
                    await self.run_initial_triage(case_id, trigger_alert)
            except Exception as e:
                logger.error("orchestrator.triage_worker_error", case_id=case_id, error=str(e))
            finally:
                self._triage_queue.task_done()

    def register_agent(self, agent: BaseAgent) -> None:
        self._agents[agent.name] = agent
        logger.info("orchestrator.agent_registered", agent=agent.name)

    def get_agent(self, name: str) -> BaseAgent:
        agent = self._agents.get(name)
        if not agent:
            raise ValueError(f"Agent not found: {name}")
        return agent

    async def handle_alert(self, alert: Alert) -> None:
        """告警入口：持久化 → 交分流引擎（微批异步路由）

        分流由 RouterEngine 承担（System One 判定/本地兜底），
        新Case的初始研判经 on_new_case 回调进入 S2 triage 队列。
        """
        logger.info("orchestrator.handle_alert", alert_id=alert.alert_id, source=alert.source)

        # 1. 存储告警（先持久化后路由，路由延迟不丢数据）
        inserted = await self.alert_store.create(alert)
        if not inserted:
            # at-least-once重放的重复告警：已有首次路由结果，不重复路由
            logger.debug("orchestrator.duplicate_alert_skipped", alert_id=alert.alert_id)
            return

        # 2. 交分流引擎（有界微批队列，过载走本地兜底，不丢告警）
        if self.router is None:
            logger.error("orchestrator.no_router", alert_id=alert.alert_id)
            return
        await self.router.submit(alert)

    async def handle_new_case(self, case_id: str, trigger_alert: Alert) -> None:
        """RouterEngine 回调：新Case进入 → 入队 S2 初始研判

        LLM关闭不影响判定型任务（System One），仅跳过生成型摘要。
        """
        if self._triage_queue is not None:
            try:
                self._triage_queue.put_nowait((case_id, trigger_alert))
                return
            except asyncio.QueueFull:
                # §5.7：triage满时延迟而非丢弃。此前落入裸create_task——
                # 绕过队列有界性与s2_concurrency信号量，过载风暴下每个
                # 新Case起无界任务（review #56发现14）。改为跟踪任务内
                # 等空位入队：不阻塞router worker，仍受队列+信号量约束。
                logger.warning("orchestrator.triage_queue_full_wait", case_id=case_id)
                self._spawn(self._enqueue_when_space(case_id, trigger_alert))
                return
        # 未启动worker（如测试环境）：直接异步执行（跟踪任务防孤儿协程）
        self._spawn(self.run_initial_triage(case_id, trigger_alert))

    async def _enqueue_when_space(self, case_id: str, trigger_alert: Alert) -> None:
        """队列满时等待空位入队（零丢失延迟语义，§5.7）"""
        assert self._triage_queue is not None
        await self._triage_queue.put((case_id, trigger_alert))

    def _spawn(self, coro) -> asyncio.Task:
        """跟踪的后台任务：异常进日志不进黑洞，shutdown时可取消（#56发现48）"""
        task = asyncio.create_task(coro)
        self._background.add(task)
        task.add_done_callback(self._on_background_done)
        return task

    def _on_background_done(self, task: asyncio.Task) -> None:
        self._background.discard(task)
        if not task.cancelled() and task.exception() is not None:
            logger.error("orchestrator.background_task_failed",
                         error=str(task.exception()))

    async def run_initial_triage(self, case_id: str, trigger_alert: Alert) -> None:
        """S2初始研判（任务→引擎映射，设计§6）：

        判定型 → S2Dispatcher/System One（真伪/攻击分类/严重度，低置信度转人工复核）
        生成型 → LLM TriageAgent 叙述摘要（llm关闭或Agent未注册时标 needs_review）
        """
        try:
            case_data = await self.case_store.get(case_id)
            if not case_data:
                return
            alerts_data = await self.alert_store.list_alerts(case_id=case_id, limit=20)
            alerts = [
                Alert(
                    alert_id=r["alert_id"], source=r["source"],
                    rule_id=r.get("rule_id"), rule_name=r.get("rule_name"),
                    severity=r.get("severity"), src_ip=r.get("src_ip"),
                    dst_ip=r.get("dst_ip"),
                )
                for r in alerts_data
            ]

            # ---- 判定型：System One ----
            judgment = None
            if self.dispatcher and self.dispatcher.enabled:
                judgment = await self.dispatcher.judge_triage(
                    case_id, case_data.get("title", ""), alerts,
                )
                if judgment is None:
                    # §6：失败重试一次，仍失败标needs_review——
                    # 此前静默跳过，判定维度缺失无人知晓（review #56发现15）
                    judgment = await self.dispatcher.judge_triage(
                        case_id, case_data.get("title", ""), alerts,
                    )
                    if judgment is None:
                        await self._record_needs_review(
                            case_id,
                            "判定型初始研判未完成：System One判定失败（重试后仍失败），需人工研判"
                        )
            else:
                # §6开关矩阵：system_one.enabled=false时判定型降级为人工
                await self._record_needs_review(
                    case_id,
                    "判定型初始研判未执行：System One未启用，需人工研判"
                )
            if judgment:
                await self._apply_triage_judgment(case_id, case_data, judgment)

            # ---- 生成型：LLM 叙述摘要 ----
            if not self._llm_enabled:
                await self._record_needs_review(
                    case_id, "生成型摘要未执行：LLM未启用，需人工补充研判叙述"
                )
                return
            if "triage" not in self._agents:
                await self._record_needs_review(
                    case_id, "生成型摘要未执行：TriageAgent未注册，需人工补充研判叙述"
                )
                return

            triage_agent = self.get_agent("triage")
            context = await self.context_manager.build_context(case_id)
            result = await self._run_agent_safe(
                triage_agent,
                task={"type": "initial_triage", "case_id": case_id},
                context=context.to_dict(),
            )

            if result and result.status == AgentStatus.COMPLETED:
                case_data = await self.case_store.get(case_id)
                if case_data:
                    case = self._rebuild_case(case_data)

                    # 记录AI分诊完成事件
                    summary = result.output.get("summary", "")
                    recommendation = ", ".join(result.recommended_actions)
                    triage_event = case.record_ai_triage(summary, recommendation)
                    await self.case_store.add_event(case_id, triage_event)

                    case.ai_summary = summary
                    case.ai_recommendation = recommendation
                    await self.case_store.update(case)

                logger.info("orchestrator.triage_completed", case_id=case_id)

        except Exception as e:
            logger.error("orchestrator.triage_failed", case_id=case_id, error=str(e))

    @staticmethod
    def _rebuild_case(case_data: dict, **overrides) -> Case:
        """从DB行重建Case模型——走 Case.from_row 带全部持久化字段。

        update() 是全列UPDATE：重建若漏字段（tags/metadata/sla_deadline等），
        会被模型默认值静默覆盖（review #56 发现1）。
        """
        fields = Case.from_row(case_data).model_dump()
        fields.update(overrides)
        return Case(**fields)

    async def _apply_triage_judgment(self, case_id: str, case_data: dict, judgment) -> None:
        """应用System One判定：记录事件 + 高置信度自动修正严重度（Case随生长被修正，§3.2）"""
        event = CaseEvent(
            event_id=f"{case_id}-evt-{str(ULID())}",
            event_type="s2_judgment",
            actor="s2_dispatcher",
            detail={
                "true_positive": judgment.true_positive,
                "tp_confidence": judgment.tp_confidence,
                "category": judgment.category,
                "category_confidence": judgment.category_confidence,
                "severity": judgment.severity,
                "severity_confidence": judgment.severity_confidence,
                "overall_confidence": round(judgment.overall_confidence, 3),
                "needs_review": judgment.needs_review,
            },
        )
        await self.case_store.add_event(case_id, event)

        if judgment.needs_review:
            await self._record_needs_review(
                case_id,
                f"S2判定置信度低于阈值，需人工复核"
                f"（分类={judgment.category}/{judgment.category_confidence}, "
                f"严重度={judgment.severity}/{judgment.severity_confidence}）",
            )
            return

        new_severity = judgment.severity
        old_severity = case_data.get("severity")
        if (
            new_severity
            and new_severity in [s.value for s in CaseSeverity]
            and new_severity != old_severity
        ):
            case = self._rebuild_case(
                case_data,
                severity=CaseSeverity(new_severity),
                priority=SEVERITY_PRIORITY_MAP.get(
                    CaseSeverity(new_severity), case_data.get("priority", 3)
                ),
            )
            change_event = CaseEvent(
                event_id=f"{case_id}-evt-{str(ULID())}",
                event_type=CaseEventType.SEVERITY_CHANGED.value,
                actor="s2_dispatcher",
                detail={
                    "from": old_severity,
                    "to": new_severity,
                    "confidence": judgment.severity_confidence,
                    "reason": "S2判定高置信度自动修正",
                },
            )
            await self.case_store.add_event(case_id, change_event)
            await self.case_store.update(case)
            logger.info(
                "orchestrator.severity_auto_corrected",
                case_id=case_id, from_severity=old_severity, to_severity=new_severity,
            )

    async def _record_needs_review(self, case_id: str, reason: str) -> None:
        """记录人工复核事件"""
        event = CaseEvent(
            event_id=f"{case_id}-evt-{str(ULID())}",
            event_type="routing_review",
            actor="s2_dispatcher",
            detail={"reason": reason},
        )
        await self.case_store.add_event(case_id, event)

    async def investigate_case(self, case_id: str) -> dict:
        """启动Case调查"""
        logger.info("orchestrator.investigate", case_id=case_id)
        context = await self.context_manager.build_context(case_id)
        ctx_dict = context.to_dict()

        # 防御式解析：LLM关闭等场景下Agent可能未注册，跳过并告警而非整体失败
        tasks = []
        for agent_name, task_type, timeout in (
            ("investigation", "deep_investigation", 60),
            ("intel", "ioc_lookup", 30),
        ):
            if agent_name in self._agents:
                tasks.append(self._run_agent_safe(
                    self._agents[agent_name],
                    task={"type": task_type, "case_id": case_id},
                    context=ctx_dict, timeout=timeout,
                ))
            else:
                logger.warning("orchestrator.agent_not_registered_skip",
                               agent=agent_name, case_id=case_id)
        if not tasks:
            await self._record_needs_review(
                case_id, "调查未执行：investigation/intel Agent均未注册（LLM未启用？）"
            )
            return {}

        results = await asyncio.gather(*tasks, return_exceptions=True)

        combined = {}
        for r in results:
            if isinstance(r, AgentResult) and r.status == AgentStatus.COMPLETED:
                combined.update(r.output)

        # 统一操作记录（设计§7：Agent调查也是Case上的操作）
        if self.ops_service:
            await self.ops_service.record_op(
                case_id, actor="investigation+intel", actor_type="agent",
                action="investigate", params={"agents": ["investigation", "intel"]},
                result={"sections": list(combined.keys())},
                summary="Agent调查完成",
            )
        return combined

    async def generate_report(self, case_id: str) -> str:
        """生成事件报告"""
        context = await self.context_manager.build_context(case_id)
        investigation_result = await self.investigate_case(case_id)

        report_agent = self.get_agent("report")
        ctx = context.to_dict()
        ctx["investigation_result"] = investigation_result
        result = await self._run_agent_safe(
            report_agent,
            task={"type": "generate_report", "case_id": case_id},
            context=ctx,
        )

        if result and result.status == AgentStatus.COMPLETED:
            report = result.output.get("report", "报告生成失败")
            if self.ops_service:
                await self.ops_service.record_op(
                    case_id, actor="report", actor_type="agent",
                    action="generate_report",
                    result={"length": len(report)},
                    summary="事件报告生成完成",
                )
            return report
        return "报告生成失败"

    async def _run_agent_safe(
        self,
        agent: BaseAgent,
        task: dict,
        context: dict,
        timeout: int = 60,
        max_retries: int = 1,
    ) -> AgentResult:
        """带重试和超时的Agent执行"""
        await self.event_bus.publish(Event(
            event_type=EventType.AGENT_STARTED,
            source=agent.name,
            data={"task_type": task.get("type"), "case_id": task.get("case_id")},
            correlation_id=task.get("case_id", ""),
        ))

        for attempt in range(max_retries + 1):
            try:
                result = await asyncio.wait_for(
                    agent.run(task=task, context=context),
                    timeout=timeout,
                )
                await self.event_bus.publish(Event(
                    event_type=EventType.AGENT_COMPLETED,
                    source=agent.name,
                    data={"confidence": result.confidence},
                    correlation_id=task.get("case_id", ""),
                ))
                return result
            except TimeoutError:
                logger.warning("orchestrator.agent_timeout", agent=agent.name, attempt=attempt)
                if attempt == max_retries:
                    return AgentResult.failure(f"Agent {agent.name} timed out after {timeout}s")
            except Exception as e:
                logger.error("orchestrator.agent_error", agent=agent.name, error=str(e))
                if attempt == max_retries:
                    return AgentResult.failure(str(e))

        return AgentResult.failure("Max retries exceeded")
