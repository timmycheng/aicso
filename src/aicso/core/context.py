"""上下文管理器 - 构建和管理Case上下文"""
from __future__ import annotations

from dataclasses import dataclass, field

import structlog

from aicso.store.alert_store import AlertStore
from aicso.store.case_store import CaseStore
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
        vector_store: VectorStore | None = None,
        ops_store=None,
    ):
        self.case_store = case_store
        self.alert_store = alert_store
        self.vector_store = vector_store
        self.ops_store = ops_store

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

    async def build_full_context(self, case_id: str) -> dict:
        """Case完整运营视图（设计§3.2上下文四维度）：case+告警+时间线
        +OpsRecord+实体摘要+合并/拆分关联"""

        ctx = await self.build_context(case_id)
        data = ctx.to_dict()

        # 操作记录
        if self.ops_store:
            data["ops_records"] = await self.ops_store.list_by_case(case_id)

        # 实体摘要（从告警提取，Case生长的实体维度）
        entities: dict[str, set] = {"src_ips": set(), "dst_ips": set(), "rules": set()}
        for a in ctx.alerts:
            if a.get("src_ip"):
                entities["src_ips"].add(a["src_ip"])
            if a.get("dst_ip"):
                entities["dst_ips"].add(a["dst_ip"])
            if a.get("rule_name"):
                entities["rules"].add(a["rule_name"])
        data["entities"] = {k: sorted(v) for k, v in entities.items()}

        # 合并/拆分关联
        case_row = await self.case_store.get(case_id)
        data["relations"] = {
            "merged_into": case_row.get("merged_into") if case_row else None,
            "split_from": case_row.get("split_from") if case_row else None,
        }
        return data
