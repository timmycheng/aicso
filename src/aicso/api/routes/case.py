"""Case管理路由"""
from __future__ import annotations

import json
import uuid
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from aicso.api.deps import AppState, get_state
from aicso.models.case import SEVERITY_PRIORITY_MAP, Case, CasePriority, CaseSeverity, CaseStatus

_TEMPLATES_DIR = str(Path(__file__).resolve().parent.parent / "templates")
router = APIRouter(prefix="/cases", tags=["cases"])
templates = Jinja2Templates(directory=_TEMPLATES_DIR)


@router.get("", response_class=HTMLResponse)
async def case_list(
    request: Request,
    status: str | None = None,
    severity: str | None = None,
    limit: int = 50,
    state: AppState = Depends(get_state),
):
    cases = await state.case_store.list_cases(status=status, severity=severity, limit=limit)
    total = await state.case_store.count(status=status)
    return templates.TemplateResponse(
        request,
        "cases/list.html",
        {
            "cases": cases, "total": total,
            "filter_status": status, "filter_severity": severity,
        },
    )


@router.get("/new", response_class=HTMLResponse)
async def case_new_form(request: Request):
    return templates.TemplateResponse(request, "cases/new.html")


@router.post("/new", response_class=HTMLResponse)
async def case_create(
    request: Request,
    title: str = Form(...),
    severity: str = Form("medium"),
    state: AppState = Depends(get_state),
):
    sev = CaseSeverity(severity)
    case = Case(
        case_id=f"CSO-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}",
        title=title,
        severity=sev,
        status=CaseStatus.NEW,
        priority=SEVERITY_PRIORITY_MAP.get(sev, CasePriority.P3),
    )
    await state.case_store.create(case)
    return RedirectResponse(url=f"/cases/{case.case_id}", status_code=303)


@router.get("/{case_id}", response_class=HTMLResponse)
async def case_detail(
    request: Request,
    case_id: str,
    state: AppState = Depends(get_state),
):
    case = await state.case_store.get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case不存在")

    # 解析JSON字段
    if isinstance(case.get("metadata"), str):
        try:
            case["metadata"] = json.loads(case["metadata"])
        except (json.JSONDecodeError, TypeError):
            case["metadata"] = {}
    if isinstance(case.get("tags"), str):
        try:
            case["tags"] = json.loads(case["tags"])
        except (json.JSONDecodeError, TypeError):
            case["tags"] = []

    alerts = await state.alert_store.list_alerts(case_id=case_id, limit=50)
    events = await state.case_store.get_events(case_id)
    return templates.TemplateResponse(
        request,
        "cases/detail.html",
        {"case": case, "alerts": alerts, "events": events},
    )


@router.post("/{case_id}/update", response_class=HTMLResponse)
async def case_update(
    request: Request,
    case_id: str,
    status: str | None = Form(None),
    assignee: str | None = Form(None),
    resolution: str | None = Form(None),
    state: AppState = Depends(get_state),
):
    case_data = await state.case_store.get(case_id)
    if not case_data:
        raise HTTPException(status_code=404, detail="Case不存在")

    case = Case(
        case_id=case_data["case_id"],
        title=case_data["title"],
        severity=CaseSeverity(case_data["severity"]),
        status=CaseStatus(case_data["status"]),
        priority=CasePriority(case_data["priority"]),
        assignee_id=case_data.get("assignee_id"),
        resolution=case_data.get("resolution"),
    )

    if status:
        new_status = CaseStatus(status)
        event = case.transition_to(new_status, actor="web_user", reason="Web update")
        await state.case_store.add_event(case_id, event)

    if assignee is not None:
        case.assignee_id = assignee or None

    if resolution is not None:
        case.resolution = resolution or None

    await state.case_store.update(case)
    return RedirectResponse(url=f"/cases/{case_id}", status_code=303)


# --- JSON API ---

@router.get("/api/list")
async def api_case_list(
    status: str | None = None,
    severity: str | None = None,
    limit: int = 50,
    state: AppState = Depends(get_state),
):
    cases = await state.case_store.list_cases(status=status, severity=severity, limit=limit)
    return {"cases": cases, "count": len(cases)}


@router.get("/api/{case_id}")
async def api_case_detail(case_id: str, state: AppState = Depends(get_state)):
    case = await state.case_store.get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case不存在")
    alerts = await state.alert_store.list_alerts(case_id=case_id, limit=50)
    events = await state.case_store.get_events(case_id)
    return {"case": case, "alerts": alerts, "events": events}
