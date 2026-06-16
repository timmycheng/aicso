"""FastAPI依赖注入"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional

from fastapi import Request

from aicso.config import AppConfig, load_config
from aicso.core.approval import ApprovalEngine
from aicso.core.context import ContextManager
from aicso.core.datasource_manager import DataSourceManager
from aicso.core.event_bus import EventBus
from aicso.core.orchestrator import Orchestrator
from aicso.store.alert_store import AlertStore
from aicso.store.case_store import CaseStore
from aicso.store.database import Database


@dataclass
class AppState:
    config: AppConfig
    db: Database
    case_store: CaseStore
    alert_store: AlertStore
    event_bus: EventBus
    context_manager: ContextManager
    approval_engine: ApprovalEngine
    orchestrator: Orchestrator
    datasource_manager: Optional[DataSourceManager] = None


async def _restore_aggregation_rules(state: AppState) -> None:
    """从数据库的Case metadata中恢复聚合规则到内存"""
    from aicso.aggregator.engine import CaseAggregationRule

    cases = await state.case_store.list_cases(limit=1000)
    restored = 0
    for case_data in cases:
        metadata = case_data.get("metadata", "{}")
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except (json.JSONDecodeError, TypeError):
                continue

        agg = metadata.get("aggregation_rule", {})
        if not isinstance(agg, dict):
            continue
        if agg.get("source") != "ai_rule":
            continue

        dimensions = agg.get("dimensions", [])
        if not dimensions:
            continue

        case_id = case_data["case_id"]
        rule = CaseAggregationRule(
            case_id=case_id,
            dimensions=dimensions,
            window_minutes=agg.get("window_minutes", 30),
            label=agg.get("label", ""),
            generated_by=agg.get("generated_by", "triage_agent"),
        )
        state.orchestrator.aggregator.set_ai_rule(case_id, rule)
        restored += 1

    if restored:
        import structlog
        structlog.get_logger().info("aggregator.rules_restored", count=restored)


async def init_app_state(config_path: str = "config.yaml") -> AppState:
    config = load_config(config_path)
    db = Database()
    await db.connect()
    await db.init_tables()
    db.enable_write_buffer(batch_size=50, flush_interval=0.1)

    case_store = CaseStore(db)
    alert_store = AlertStore(db)
    event_bus = EventBus()
    context_manager = ContextManager(case_store, alert_store)
    approval_engine = ApprovalEngine(event_bus)

    from aicso.aggregator.engine import AlertAggregator
    aggregator = AlertAggregator(auto_cleanup=True)

    orchestrator = Orchestrator(
        case_store, alert_store, context_manager, event_bus, approval_engine,
        aggregator=aggregator, max_concurrent_triage=3,
        llm_enabled=config.llm.enabled,
    )
    orchestrator.start()

    state = AppState(
        config=config,
        db=db,
        case_store=case_store,
        alert_store=alert_store,
        event_bus=event_bus,
        context_manager=context_manager,
        approval_engine=approval_engine,
        orchestrator=orchestrator,
    )

    # 从数据库恢复聚合规则到内存
    await _restore_aggregation_rules(state)

    # 启动数据源管理器（周期拉取告警）
    if config.datasources:
        datasource_manager = DataSourceManager(config, orchestrator)
        await datasource_manager.start()
        state.datasource_manager = datasource_manager

    return state


async def close_app_state(state: AppState) -> None:
    if state.datasource_manager:
        await state.datasource_manager.stop()
    await state.orchestrator.close()
    await state.orchestrator.aggregator.stop()
    await state.db.flush_and_close()


def get_state(request: Request) -> AppState:
    return request.app.state.aicso
