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
from aicso.models.case import (
    CASE_TRANSITIONS,
    EVENT_TYPE_COLORS,
    EVENT_TYPE_ICONS,
    EVENT_TYPE_LABELS,
    SEVERITY_PRIORITY_MAP,
    Case,
    CasePriority,
    CaseSeverity,
    CaseStatus,
)

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
    # 记录Case创建事件
    create_event = case.record_case_created(source="manual")
    await state.case_store.create(case)
    await state.case_store.add_event(case.case_id, create_event)
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

    # 解析事件detail字段
    for event in events:
        if isinstance(event.get("detail"), str):
            try:
                event["detail"] = json.loads(event["detail"])
            except (json.JSONDecodeError, TypeError):
                event["detail"] = {}

    # 状态机合法转换目标（表单下拉只渲染可达状态，防非法转换500）
    allowed_statuses = [
        s.value for s in CASE_TRANSITIONS.get(CaseStatus(case["status"]), [])
    ]
    # metadata从DB读回是JSON字符串，解析为dict供模板渲染路由信息
    meta = case.get("metadata", "{}")
    if isinstance(meta, str):
        try:
            meta = json.loads(meta)
        except (json.JSONDecodeError, TypeError):
            meta = {}

    return templates.TemplateResponse(
        request,
        "cases/detail.html",
        {
            "case": case, "alerts": alerts, "events": events,
            "meta": meta, "allowed_statuses": allowed_statuses,
            "error": request.query_params.get("error"),
            "event_labels": EVENT_TYPE_LABELS,
            "event_icons": EVENT_TYPE_ICONS,
            "event_colors": EVENT_TYPE_COLORS,
        },
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

    events_to_save = []

    if status:
        new_status = CaseStatus(status)
        try:
            event = case.transition_to(new_status, actor="web_user", reason="Web界面更新")
        except ValueError as e:
            # 非法状态转换：回详情页带错误提示，而非500
            from urllib.parse import quote
            return RedirectResponse(
                url=f"/cases/{case_id}?error={quote(str(e))}", status_code=303
            )
        events_to_save.append(event)

    if assignee is not None:
        old_assignee = case.assignee_id
        new_assignee = assignee or None
        if old_assignee != new_assignee:
            if new_assignee:
                event = case.assign(new_assignee, actor="web_user", reason="Web界面分配")
            else:
                event = case.unassign(actor="web_user", reason="Web界面取消分配")
            events_to_save.append(event)

    if resolution is not None:
        case.resolution = resolution or None

    await state.case_store.update(case)
    for event in events_to_save:
        await state.case_store.add_event(case_id, event)

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

    # 解析JSON字段
    if isinstance(case.get("metadata"), str):
        try:
            case["metadata"] = json.loads(case["metadata"])
        except (json.JSONDecodeError, TypeError):
            case["metadata"] = {}

    alerts = await state.alert_store.list_alerts(case_id=case_id, limit=50)
    events = await state.case_store.get_events(case_id)

    # 解析事件detail字段并添加显示元数据
    for event in events:
        if isinstance(event.get("detail"), str):
            try:
                event["detail"] = json.loads(event["detail"])
            except (json.JSONDecodeError, TypeError):
                event["detail"] = {}
        # 添加显示元数据
        event["label"] = EVENT_TYPE_LABELS.get(event["event_type"], event["event_type"])
        event["icon"] = EVENT_TYPE_ICONS.get(event["event_type"], "&#128196;")
        event["color"] = EVENT_TYPE_COLORS.get(event["event_type"], "#666")

    return {"case": case, "alerts": alerts, "events": events}


@router.get("/api/{case_id}/correlations")
async def api_case_correlations(case_id: str, state: AppState = Depends(get_state)):
    """关联链（issue #48）：合并/拆分关系与证据链的结构化视图

    "哪怕很久远的关联也必须有说明"——每条链路携带事件detail中的证据
    （共享实体分类/时间跨度/模型置信度理由），审计可回溯为什么关联。
    """
    case = await state.case_store.get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case不存在")
    events = await state.case_store.get_events(case_id)
    chain = []
    for event in events:
        if event.get("event_type") not in (
            "case_merged", "merged_into", "case_split", "case_split_created",
        ):
            continue
        detail = event.get("detail")
        if isinstance(detail, str):
            try:
                detail = json.loads(detail)
            except (json.JSONDecodeError, TypeError):
                detail = {}
        chain.append({
            "event_type": event["event_type"],
            "created_at": event.get("created_at"),
            "actor": event.get("actor"),
            "detail": detail,
        })
    return {
        "case_id": case_id,
        "relations": {
            "merged_into": case.get("merged_into"),
            "split_from": case.get("split_from"),
        },
        "chain": chain,
    }


# --- 运营操作API（设计§7 OpsRecord） ---

@router.get("/api/{case_id}/context")
async def api_case_context(case_id: str, state: AppState = Depends(get_state)):
    """Case完整运营视图：case+告警+时间线+操作记录+实体摘要+合并拆分关联"""
    context = await state.context_manager.build_full_context(case_id)
    if not context.get("case"):
        return {"error": f"Case not found: {case_id}"}
    return context


@router.post("/api/{case_id}/ops")
async def api_case_record_op(case_id: str, request: Request,
                             state: AppState = Depends(get_state)):
    """记录人工操作（补上下文/处置记录/拉人/升级等）"""
    body = await request.json()
    if await state.case_store.get(case_id) is None:
        return {"error": f"Case not found: {case_id}"}
    record = await state.ops_service.record_op(
        case_id=case_id,
        actor=body.get("actor", "analyst"),
        actor_type=body.get("actor_type", "human"),
        action=body.get("action", "manual_handle"),
        params=body.get("params", {}),
        result=body.get("result", {}),
        summary=body.get("summary", ""),
    )
    return {"ok": True, "ops_id": record.id}
