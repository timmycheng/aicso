"""FastAPI依赖注入"""
from __future__ import annotations

from dataclasses import dataclass

from fastapi import Request
from structlog import get_logger

from aicso.config import AppConfig, load_config
from aicso.core.approval import ApprovalEngine
from aicso.core.context import ContextManager
from aicso.core.datasource_manager import DataSourceManager
from aicso.core.event_bus import EventBus
from aicso.core.orchestrator import Orchestrator
from aicso.router.engine import RouterEngine
from aicso.store.alert_store import AlertStore
from aicso.store.case_store import CaseStore
from aicso.store.database import Database
from aicso.store.routing_store import RoutingDecisionStore
from aicso.systemone.client import SystemOneClient

logger = get_logger()


@dataclass
class AppState:
    config: AppConfig
    db: Database
    case_store: CaseStore
    alert_store: AlertStore
    routing_store: RoutingDecisionStore
    event_bus: EventBus
    context_manager: ContextManager
    approval_engine: ApprovalEngine
    orchestrator: Orchestrator
    router: RouterEngine
    systemone_client: SystemOneClient | None = None
    datasource_manager: DataSourceManager | None = None


async def _recover_routing(state: AppState) -> None:
    """重启恢复（§5.6）：从活跃Case重建候选索引 + 回灌未路由告警"""
    await state.router.rebuild_index_from_db()
    backfilled = await state.router.backfill_unrouted()
    if backfilled:
        await state.router.flush()


async def init_app_state(config_path: str = "config.yaml") -> AppState:
    config = load_config(config_path)
    db = Database()
    await db.connect()
    await db.init_tables()
    db.enable_write_buffer(batch_size=50, flush_interval=0.1)

    case_store = CaseStore(db)
    alert_store = AlertStore(db)
    routing_store = RoutingDecisionStore(db)
    event_bus = EventBus()
    context_manager = ContextManager(case_store, alert_store)
    approval_engine = ApprovalEngine(event_bus)

    # System One 客户端（enabled=False 或缺 key → None，引擎进入纯本地模式）
    systemone_client: SystemOneClient | None = None
    scfg = config.system_one
    if scfg.enabled and scfg.api_key:
        systemone_client = SystemOneClient(
            api_key=scfg.api_key,
            base_url=scfg.base_url,
            model=scfg.model,
            timeout_ms=scfg.timeout_ms,
        )
    elif scfg.enabled and not scfg.api_key:
        logger.warning("systemone.no_api_key_local_mode")

    router_engine = RouterEngine(
        case_store=case_store,
        alert_store=alert_store,
        routing_store=routing_store,
        system_one_config=scfg,
        routing_config=config.routing,
        client=systemone_client,
    )

    orchestrator = Orchestrator(
        case_store, alert_store, context_manager, event_bus, approval_engine,
        router=router_engine, max_concurrent_triage=config.routing.s2_concurrency,
        llm_enabled=config.llm.enabled,
    )
    router_engine.on_new_case = orchestrator.handle_new_case
    orchestrator.start()
    await router_engine.start()

    state = AppState(
        config=config,
        db=db,
        case_store=case_store,
        alert_store=alert_store,
        routing_store=routing_store,
        event_bus=event_bus,
        context_manager=context_manager,
        approval_engine=approval_engine,
        orchestrator=orchestrator,
        router=router_engine,
        systemone_client=systemone_client,
    )

    # 恢复路由状态（索引重建 + 未路由告警回灌）
    await _recover_routing(state)

    # 启动数据源管理器（周期拉取告警）
    if config.datasources:
        datasource_manager = DataSourceManager(config, orchestrator)
        await datasource_manager.start()
        state.datasource_manager = datasource_manager

    return state


async def close_app_state(state: AppState) -> None:
    if state.datasource_manager:
        await state.datasource_manager.stop()
    await state.router.stop()
    await state.orchestrator.close()
    if state.systemone_client:
        await state.systemone_client.aclose()
    await state.db.flush_and_close()


def get_state(request: Request) -> AppState:
    return request.app.state.aicso
