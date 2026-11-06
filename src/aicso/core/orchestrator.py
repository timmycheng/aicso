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
    CasePriority,
    CaseSeverity,
    CaseStatus,
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
        self._agents: dict[str, BaseAgent] = {}
        self._llm_enabled = llm_enabled

        # TriageAgent 并发控制
        self._max_concurrent_triage = max_concurrent_triage
        self._triage_semaphore: asyncio.Semaphore | None = None
        self._triage_queue: asyncio.Queue | None = None
        self._triage_worker_task: asyncio.Task | None = None

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
        await self.alert_store.create(alert)

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
                logger.warning("orchestrator.triage_queue_full", case_id=case_id)
        # 未启动worker（如测试环境）：直接异步执行
        asyncio.create_task(self.run_initial_triage(case_id, trigger_alert))

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
        """从DB行重建Case模型（metadata/tags是JSON字符串，需解析）"""
        import json

        metadata = case_data.get("metadata", "{}")
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except (json.JSONDecodeError, TypeError):
                metadata = {}
        fields = dict(
            case_id=case_data["case_id"],
            title=case_data["title"],
            severity=CaseSeverity(case_data["severity"]),
            status=CaseStatus(case_data["status"]),
            priority=CasePriority(case_data["priority"]),
            assignee_id=case_data.get("assignee_id"),
            resolution=case_data.get("resolution"),
            metadata=metadata,
            ai_summary=case_data.get("ai_summary"),
            ai_recommendation=case_data.get("ai_recommendation"),
        )
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

        investigation_agent = self.get_agent("investigation")
        intel_agent = self.get_agent("intel")

        results = await asyncio.gather(
            self._run_agent_safe(investigation_agent,
                                 task={"type": "deep_investigation", "case_id": case_id},
                                 context=ctx_dict, timeout=60),
            self._run_agent_safe(intel_agent,
                                 task={"type": "ioc_lookup", "case_id": case_id},
                                 context=ctx_dict, timeout=30),
            return_exceptions=True,
        )

        combined = {}
        for r in results:
            if isinstance(r, AgentResult) and r.status == AgentStatus.COMPLETED:
                combined.update(r.output)

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
            return result.output.get("report", "报告生成失败")
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
