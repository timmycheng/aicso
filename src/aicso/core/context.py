"""上下文管理器 - 构建和管理Case上下文"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import structlog

from aicso.models.case import Case
from aicso.models.alert import Alert
from aicso.models.asset import Asset
from aicso.models.ioc import IoC
from aicso.store.case_store import CaseStore
from aicso.store.alert_store import AlertStore
from aicso.store.vector_store import VectorStore

logger = structlog.get_logger()


@dataclass
class CaseContext:
    """Case上下文，Agent间共享"""
    case: dict
    alerts: list[dict] = field(default_factory=list)
    assets: list[dict] = field(default_factory=list)
    iocs: list[dict] = field(default_factory=list)
    timeline: list[dict] = field(default_factory=list)
    history_similar_cases: list[dict] = field(default_factory=list)
    threat_intel: dict = field(default_factory=dict)
    analyst_notes: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "case": self.case,
            "alerts": self.alerts,
            "assets": self.assets,
            "iocs": self.iocs,
            "timeline": self.timeline,
            "history_similar_cases": self.history_similar_cases,
            "threat_intel": self.threat_intel,
            "analyst_notes": self.analyst_notes,
        }


class ContextManager:
    """上下文管理器"""

    def __init__(
        self,
        case_store: CaseStore,
        alert_store: AlertStore,
        vector_store: Optional[VectorStore] = None,
    ):
        self.case_store = case_store
        self.alert_store = alert_store
        self.vector_store = vector_store

    async def build_context(self, case_id: str) -> CaseContext:
        """构建Case完整上下文"""
        # 获取Case基本信息
        case_data = await self.case_store.get(case_id)
        if not case_data:
            raise ValueError(f"Case not found: {case_id}")

        # 获取关联告警
        alerts = await self.alert_store.list_alerts(case_id=case_id, limit=100)

        # 获取Case事件时间线
        timeline = await self.case_store.get_events(case_id)

        # 从向量存储检索相似Case
        similar_cases = []
        if self.vector_store:
            query = f"{case_data.get('title', '')} {case_data.get('ai_summary', '')}"
            if query.strip():
                results = await self.vector_store.search(query, top_k=3, score_threshold=0.6)
                similar_cases = results

        context = CaseContext(
            case=case_data,
            alerts=alerts,
            timeline=timeline,
            history_similar_cases=similar_cases,
        )

        logger.info(
            "context.built",
            case_id=case_id,
            alert_count=len(alerts),
            timeline_events=len(timeline),
            similar_cases=len(similar_cases),
        )

        return context

    async def update_context_with_result(
        self, case_id: str, agent_name: str, result: dict
    ) -> None:
        """Agent执行结果更新上下文（通过事件）"""
        logger.info(
            "context.updated",
            case_id=case_id,
            agent_name=agent_name,
        )
