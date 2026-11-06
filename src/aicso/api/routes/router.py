"""分流路由管理页面 — 替代原 /aggregator（不再读私有属性，走引擎公开接口）"""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from aicso.api.deps import AppState, get_state

_TEMPLATES_DIR = str(Path(__file__).resolve().parent.parent / "templates")
router = APIRouter(prefix="/router", tags=["router"])
templates = Jinja2Templates(directory=_TEMPLATES_DIR)


@router.get("", response_class=HTMLResponse)
async def router_index(
    request: Request,
    state: AppState = Depends(get_state),
):
    engine = state.router
    status = engine.status()
    return templates.TemplateResponse(
        request,
        "router/index.html",
        {
            "status": status,
            "slots": engine.index.slot_rows(),
            "decisions": await state.routing_store.list_recent(limit=30),
            "source_stats": await state.routing_store.stats_by_source(),
        },
    )


# --- JSON API ---

@router.get("/api/status")
async def api_router_status(state: AppState = Depends(get_state)):
    """引擎状态：队列/降级/缓存/索引/指标"""
    engine = state.router
    return {
        **engine.status(),
        "index_slots": engine.index.slot_rows()[:50],
    }


@router.get("/api/decisions")
async def api_router_decisions(
    limit: int = 50,
    state: AppState = Depends(get_state),
):
    """最近路由决策审计"""
    rows = await state.routing_store.list_recent(limit=min(limit, 200))
    return {"decisions": rows, "stats_by_source": await state.routing_store.stats_by_source()}
