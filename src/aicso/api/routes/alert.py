"""Alert管理路由"""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from aicso.api.deps import AppState, get_state

_TEMPLATES_DIR = str(Path(__file__).resolve().parent.parent / "templates")
router = APIRouter(prefix="/alerts", tags=["alerts"])
templates = Jinja2Templates(directory=_TEMPLATES_DIR)


@router.get("", response_class=HTMLResponse)
async def alert_list(
    request: Request,
    case_id: str | None = None,
    source: str | None = None,
    limit: int = 50,
    state: AppState = Depends(get_state),
):
    alerts = await state.alert_store.list_alerts(case_id=case_id, source=source, limit=limit)
    total = await state.alert_store.count(case_id=case_id)
    return templates.TemplateResponse(
        request,
        "alerts/list.html",
        {
            "alerts": alerts, "total": total,
            "filter_case_id": case_id, "filter_source": source,
        },
    )


@router.get("/{alert_id}", response_class=HTMLResponse)
async def alert_detail(
    request: Request,
    alert_id: str,
    state: AppState = Depends(get_state),
):
    alert = await state.alert_store.get(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="告警不存在")
    return templates.TemplateResponse(
        request,
        "alerts/detail.html",
        {"alert": alert},
    )


# --- JSON API ---

@router.get("/api/list")
async def api_alert_list(
    case_id: str | None = None,
    source: str | None = None,
    limit: int = 50,
    state: AppState = Depends(get_state),
):
    alerts = await state.alert_store.list_alerts(case_id=case_id, source=source, limit=limit)
    return {"alerts": alerts, "count": len(alerts)}


@router.get("/api/{alert_id}")
async def api_alert_detail(alert_id: str, state: AppState = Depends(get_state)):
    alert = await state.alert_store.get(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="告警不存在")
    return {"alert": alert}
