"""编排引擎 - 系统大脑"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from typing import Optional

import structlog

from aicso.agents.base import BaseAgent, AgentResult, AgentStatus
from aicso.aggregator.engine import (
    AlertAggregator, CaseAggregationRule, IMMEDIATE_DIMENSION, _build_key,
)
from aicso.core.approval import ApprovalEngine
from aicso.core.context import ContextManager
from aicso.core.event_bus import EventBus, Event, EventType
from aicso.models.alert import Alert
from aicso.models.case import Case, CasePriority, CaseSeverity, CaseStatus, SEVERITY_PRIORITY_MAP, SLA_CONFIG
from aicso.store.case_store import CaseStore
from aicso.store.alert_store import AlertStore

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
        aggregator: Optional[AlertAggregator] = None,
        max_concurrent_triage: int = 3,
        llm_enabled: bool = True,
    ):
        self.case_store = case_store
        self.alert_store = alert_store
        self.context_manager = context_manager
        self.event_bus = event_bus
        self.approval_engine = approval_engine
        self.aggregator = aggregator or AlertAggregator()
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
                    await self._run_triage_with_ai_rule(case_id, trigger_alert)
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

    async def handle_alert(self, alert: Alert) -> Optional[str]:
        """两阶段告警处理

        阶段1: 告警进入 → 存储 → 尝试聚合（AI规则 → 即时规则）
        阶段2: 未命中 → 创建Case → 注册即时规则 → 入队Triage → AI生成专属聚合规则
        """
        logger.info("orchestrator.handle_alert", alert_id=alert.alert_id, source=alert.source)

        # 1. 存储告警
        await self.alert_store.create(alert)

        # 2. 两阶段聚合
        match = await self.aggregator.try_aggregate(alert)
        if match:
            await self.alert_store.update_case_id(alert.alert_id, match.case_id)
            logger.info(
                "orchestrator.alert_aggregated",
                alert_id=alert.alert_id,
                case_id=match.case_id,
                source=match.source,
                dimension=match.dimension,
            )
            return match.case_id

        # 3. 未命中 → 创建新Case + 注册即时规则
        case = await self._create_case_from_alert(alert)

        # 4. 入队 TriageAgent（由 worker 控制并发）
        if not self._llm_enabled:
            logger.debug("orchestrator.triage_skipped_llm_disabled", case_id=case.case_id)
        elif self._triage_queue is not None:
            try:
                self._triage_queue.put_nowait((case.case_id, alert))
            except asyncio.QueueFull:
                logger.warning("orchestrator.triage_queue_full", case_id=case.case_id)
        else:
            # fallback: 未启动 worker 时直接异步执行
            asyncio.create_task(self._run_triage_with_ai_rule(case.case_id, alert))

        return case.case_id

    async def _run_triage_with_ai_rule(self, case_id: str, trigger_alert: Alert) -> None:
        """运行TriageAgent并应用AI生成的聚合规则"""
        try:
            triage_agent = self.get_agent("triage")
            context = await self.context_manager.build_context(case_id)
            result = await self._run_agent_safe(
                triage_agent,
                task={"type": "initial_triage", "case_id": case_id},
                context=context.to_dict(),
            )

            if result and result.status == AgentStatus.COMPLETED:
                # 更新Case的AI分析结果
                case_data = await self.case_store.get(case_id)
                if case_data:
                    case = Case(
                        case_id=case_data["case_id"],
                        title=case_data["title"],
                        severity=CaseSeverity(case_data["severity"]),
                        status=CaseStatus(case_data["status"]),
                        priority=CasePriority(case_data["priority"]),
                        assignee_id=case_data.get("assignee_id"),
                        resolution=case_data.get("resolution"),
                        ai_summary=result.output.get("summary", ""),
                        ai_recommendation=", ".join(result.recommended_actions),
                    )
                    await self.case_store.update(case)

                # 应用AI生成的聚合规则
                ai_rule = result.output.get("aggregation_rule")
                if ai_rule and isinstance(ai_rule, dict):
                    dimensions = ai_rule.get("dimensions", [])
                    if dimensions:
                        rule = CaseAggregationRule(
                            case_id=case_id,
                            dimensions=dimensions,
                            window_minutes=ai_rule.get("window_minutes", 30),
                            label=ai_rule.get("label", "AI生成规则"),
                            generated_by="triage_agent",
                        )
                        self.aggregator.set_ai_rule(case_id, rule)

                        # 将触发告警注册到AI规则缓存
                        for dim in dimensions:
                            key = _build_key(trigger_alert, dim)
                            if key:
                                cache_key = f"{case_id}:{dim}:{key}"
                                self.aggregator._ai_cache[cache_key] = datetime.utcnow()

                        # 持久化到Case metadata
                        await self._persist_rule_to_case(case_id, rule)

                logger.info("orchestrator.triage_completed", case_id=case_id)

        except Exception as e:
            logger.error("orchestrator.triage_failed", case_id=case_id, error=str(e))

    async def _persist_rule_to_case(self, case_id: str, rule: CaseAggregationRule) -> None:
        """将AI规则持久化到Case metadata"""
        import json
        case_data = await self.case_store.get(case_id)
        if not case_data:
            return

        metadata = case_data.get("metadata", "{}")
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except (json.JSONDecodeError, TypeError):
                metadata = {}

        metadata["aggregation_rule"] = {
            "source": "ai_rule",
            "dimensions": rule.dimensions,
            "label": rule.label,
            "window_minutes": rule.window_minutes,
            "generated_by": rule.generated_by,
        }

        case = Case(
            case_id=case_data["case_id"],
            title=case_data["title"],
            severity=CaseSeverity(case_data["severity"]),
            status=CaseStatus(case_data["status"]),
            priority=CasePriority(case_data["priority"]),
            assignee_id=case_data.get("assignee_id"),
            resolution=case_data.get("resolution"),
            ai_summary=case_data.get("ai_summary"),
            ai_recommendation=case_data.get("ai_recommendation"),
            metadata=metadata,
        )
        await self.case_store.update(case)

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

    async def _create_case_from_alert(self, alert: Alert) -> Case:
        """从告警创建Case并注册即时聚合规则"""
        import uuid
        severity = (
            CaseSeverity(alert.severity)
            if alert.severity in [s.value for s in CaseSeverity]
            else CaseSeverity.MEDIUM
        )

        immediate_key = _build_key(alert, IMMEDIATE_DIMENSION) or ""
        metadata = {
            "aggregation_rule": {
                "source": "immediate",
                "dimensions": [IMMEDIATE_DIMENSION],
                "label": "同源IP+同目标IP(即时,10min)",
                "window_minutes": 10,
                "generated_by": "system",
                "key": immediate_key,
            },
        }

        case = Case(
            case_id=f"CSO-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}",
            title=f"[{alert.source}] {alert.rule_name or 'Unknown Alert'}",
            severity=severity,
            status=CaseStatus.NEW,
            priority=SEVERITY_PRIORITY_MAP.get(severity, 3),
            metadata=metadata,
        )
        case.add_alert(alert, reason="auto_created")

        sla_mins = SLA_CONFIG.get(case.priority, (0, 0))[0]
        if sla_mins > 0:
            case.sla_deadline = datetime.utcnow() + timedelta(minutes=sla_mins)

        await self.case_store.create(case)
        await self.alert_store.update_case_id(alert.alert_id, case.case_id)
        await self.event_bus.publish(Event(
            event_type=EventType.CASE_CREATED,
            source="orchestrator",
            data={"case_id": case.case_id, "title": case.title},
            correlation_id=case.case_id,
        ))

        logger.info("orchestrator.case_created", case_id=case.case_id, title=case.title)

        # 注册即时聚合规则
        self.aggregator.register_immediate(alert, case.case_id)

        return case

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
            except asyncio.TimeoutError:
                logger.warning("orchestrator.agent_timeout", agent=agent.name, attempt=attempt)
                if attempt == max_retries:
                    return AgentResult.failure(f"Agent {agent.name} timed out after {timeout}s")
            except Exception as e:
                logger.error("orchestrator.agent_error", agent=agent.name, error=str(e))
                if attempt == max_retries:
                    return AgentResult.failure(str(e))

        return AgentResult.failure("Max retries exceeded")
