"""编排引擎 - 系统大脑"""
from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Optional

import structlog

from aicso.agents.base import BaseAgent, AgentResult, AgentStatus
from aicso.aggregator.engine import AlertAggregator
from aicso.core.approval import ApprovalEngine
from aicso.core.context import ContextManager
from aicso.core.event_bus import EventBus, Event, EventType
from aicso.models.alert import Alert
from aicso.models.case import Case, CaseSeverity, CaseStatus, SEVERITY_PRIORITY_MAP, SLA_CONFIG
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
    ):
        self.case_store = case_store
        self.alert_store = alert_store
        self.context_manager = context_manager
        self.event_bus = event_bus
        self.approval_engine = approval_engine
        self.aggregator = aggregator or AlertAggregator()
        self._agents: dict[str, BaseAgent] = {}

    def register_agent(self, agent: BaseAgent) -> None:
        """注册Agent"""
        self._agents[agent.name] = agent
        logger.info("orchestrator.agent_registered", agent=agent.name)

    def get_agent(self, name: str) -> BaseAgent:
        """获取Agent"""
        agent = self._agents.get(name)
        if not agent:
            raise ValueError(f"Agent not found: {name}")
        return agent

    async def handle_alert(self, alert: Alert) -> Optional[str]:
        """处理新告警，返回Case ID"""
        logger.info("orchestrator.handle_alert", alert_id=alert.alert_id, source=alert.source)

        # 1. 存储告警
        await self.alert_store.create(alert)

        # 2. 尝试聚合到已有Case（简化版：按src_ip聚合）
        existing_case_id = await self._try_aggregate(alert)
        if existing_case_id:
            await self.alert_store.update_case_id(alert.alert_id, existing_case_id)
            case = await self.case_store.get(existing_case_id)
            if case:
                logger.info("orchestrator.alert_aggregated", alert_id=alert.alert_id, case_id=existing_case_id)
            return existing_case_id

        # 3. 创建新Case
        case = await self._create_case_from_alert(alert)

        # 4. 触发TriageAgent
        triage_agent = self.get_agent("triage")
        context = await self.context_manager.build_context(case.case_id)
        result = await self._run_agent_safe(
            triage_agent,
            task={"type": "initial_triage", "case_id": case.case_id},
            context=context.to_dict(),
        )

        # 5. 更新Case的AI分析结果
        if result and result.status == AgentStatus.COMPLETED:
            case.ai_summary = result.output.get("summary", "")
            case.ai_recommendation = ", ".join(result.recommended_actions)
            await self.case_store.update(case)

        return case.case_id

    async def investigate_case(self, case_id: str) -> dict:
        """启动Case调查"""
        logger.info("orchestrator.investigate", case_id=case_id)
        context = await self.context_manager.build_context(case_id)
        ctx_dict = context.to_dict()

        # 并行调用InvestigationAgent和IntelAgent
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

        # 先做调查
        investigation_result = await self.investigate_case(case_id)

        # 生成报告
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
        """从告警创建Case"""
        import uuid
        severity = CaseSeverity(alert.severity) if alert.severity in [s.value for s in CaseSeverity] else CaseSeverity.MEDIUM
        case = Case(
            case_id=f"CSO-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}",
            title=f"[{alert.source}] {alert.rule_name or 'Unknown Alert'}",
            severity=severity,
            status=CaseStatus.NEW,
            priority=SEVERITY_PRIORITY_MAP.get(severity, 3),
        )
        case.add_alert(alert, reason="auto_created")

        # 计算SLA
        from datetime import timedelta
        sla_mins = SLA_CONFIG.get(case.priority, (0, 0))[0]
        if sla_mins > 0:
            case.sla_deadline = datetime.utcnow() + timedelta(minutes=sla_mins)

        await self.case_store.create(case)
        await self.event_bus.publish(Event(
            event_type=EventType.CASE_CREATED,
            source="orchestrator",
            data={"case_id": case.case_id, "title": case.title},
            correlation_id=case.case_id,
        ))

        logger.info("orchestrator.case_created", case_id=case.case_id, title=case.title)

        # 注册聚合Key
        self.aggregator.register_case(alert, case.case_id)

        return case

    async def _try_aggregate(self, alert: Alert) -> Optional[str]:
        """尝试聚合告警到已有Case"""
        return await self.aggregator.try_aggregate(alert)

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
