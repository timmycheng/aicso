"""数据源管理路由"""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from aicso.api.deps import AppState, get_state

_TEMPLATES_DIR = str(Path(__file__).resolve().parent.parent / "templates")
router = APIRouter(prefix="/datasources", tags=["datasources"])
templates = Jinja2Templates(directory=_TEMPLATES_DIR)


@router.get("", response_class=HTMLResponse)
async def datasource_list(request: Request, state: AppState = Depends(get_state)):
    datasources = []
    for name, ds in state.config.datasources.items():
        datasources.append({
            "name": name,
            "type": ds.type,
            "description": ds.description,
            "enabled": ds.enabled,
        })
    return templates.TemplateResponse(
        request,
        "datasources/list.html",
        {"datasources": datasources},
    )


# --- JSON API ---

@router.get("/api/list")
async def api_datasource_list(state: AppState = Depends(get_state)):
    datasources = []
    for name, ds in state.config.datasources.items():
        datasources.append({
            "name": name,
            "type": ds.type,
            "description": ds.description,
            "enabled": ds.enabled,
        })
    return {"datasources": datasources}


@router.get("/api/types")
async def api_datasource_types():
    from aicso.adapters.registry import datasource_registry
    return {"types": datasource_registry.list_types()}


@router.get("/api/status")
async def api_datasource_status(state: AppState = Depends(get_state)):
    """查看所有已连接数据源的运行状态"""
    if not state.datasource_manager:
        return {"datasources": [], "message": "数据源管理器未启动"}
    return {"datasources": state.datasource_manager.list_status()}
