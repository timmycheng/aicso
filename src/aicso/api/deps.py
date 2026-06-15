"""FastAPI依赖注入"""
from __future__ import annotations

from dataclasses import dataclass

from fastapi import Request

from aicso.config import AppConfig, load_config
from aicso.core.approval import ApprovalEngine
from aicso.core.context import ContextManager
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


async def init_app_state(config_path: str = "config.yaml") -> AppState:
    config = load_config(config_path)
    db = Database()
    await db.connect()
    await db.init_tables()

    case_store = CaseStore(db)
    alert_store = AlertStore(db)
    event_bus = EventBus()
    context_manager = ContextManager(case_store, alert_store)
    approval_engine = ApprovalEngine(event_bus)
    orchestrator = Orchestrator(
        case_store, alert_store, context_manager, event_bus, approval_engine
    )

    return AppState(
        config=config,
        db=db,
        case_store=case_store,
        alert_store=alert_store,
        event_bus=event_bus,
        context_manager=context_manager,
        approval_engine=approval_engine,
        orchestrator=orchestrator,
    )


async def close_app_state(state: AppState) -> None:
    await state.db.close()


def get_state(request: Request) -> AppState:
    return request.app.state.aicso
