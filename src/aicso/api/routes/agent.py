"""Agent管理路由"""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from aicso.api.deps import AppState, get_state

_TEMPLATES_DIR = str(Path(__file__).resolve().parent.parent / "templates")
router = APIRouter(prefix="/agents", tags=["agents"])
templates = Jinja2Templates(directory=_TEMPLATES_DIR)

AGENT_INFO = [
    {
        "name": "triage",
        "description": "告警分诊Agent",
        "tools": ["search_alerts", "search_cases", "query_asset"],
    },
    {
        "name": "investigation",
        "description": "事件调查Agent",
        "tools": [
            "search_alerts", "query_asset", "lookup_threat_intel",
            "search_logs", "search_cases",
        ],
    },
    {
        "name": "intel",
        "description": "威胁情报Agent",
        "tools": ["lookup_threat_intel", "search_ioc"],
    },
    {
        "name": "response",
        "description": "响应执行Agent",
        "tools": ["execute_response_action"],
    },
    {
        "name": "report",
        "description": "报告生成Agent",
        "tools": [],
    },
]


@router.get("", response_class=HTMLResponse)
async def agent_index(request: Request):
    return templates.TemplateResponse(
        request,
        "agents/index.html",
        {"agents": AGENT_INFO},
    )


@router.post("/investigate", response_class=HTMLResponse)
async def agent_investigate(
    request: Request,
    case_id: str = Form(...),
    state: AppState = Depends(get_state),
):
    case = await state.case_store.get(case_id)
    if not case:
        return templates.TemplateResponse(
            request,
            "agents/index.html",
            {"agents": AGENT_INFO, "error": f"Case不存在: {case_id}"},
        )

    from aicso.agents.intel import IntelAgent
    from aicso.agents.investigation import InvestigationAgent

    state.orchestrator.register_agent(InvestigationAgent(llm_provider=state.config.llm.default_provider))
    state.orchestrator.register_agent(IntelAgent(llm_provider=state.config.llm.default_provider))

    try:
        result = await state.orchestrator.investigate_case(case_id)
        return templates.TemplateResponse(
            request,
            "agents/result.html",
            {"case_id": case_id, "action": "调查", "result": result},
        )
    except Exception as e:
        return templates.TemplateResponse(
            request,
            "agents/index.html",
            {"agents": AGENT_INFO, "error": f"调查失败: {e}"},
        )


@router.post("/report", response_class=HTMLResponse)
async def agent_report(
    request: Request,
    case_id: str = Form(...),
    state: AppState = Depends(get_state),
):
    case = await state.case_store.get(case_id)
    if not case:
        return templates.TemplateResponse(
            request,
            "agents/index.html",
            {"agents": AGENT_INFO, "error": f"Case不存在: {case_id}"},
        )

    from aicso.agents.intel import IntelAgent
    from aicso.agents.investigation import InvestigationAgent
    from aicso.agents.report import ReportAgent
    from aicso.agents.response import ResponseAgent
    from aicso.agents.triage import TriageAgent

    for agent_cls in [TriageAgent, InvestigationAgent, IntelAgent, ResponseAgent, ReportAgent]:
        state.orchestrator.register_agent(agent_cls(llm_provider=state.config.llm.default_provider))

    try:
        report = await state.orchestrator.generate_report(case_id)
        return templates.TemplateResponse(
            request,
            "agents/result.html",
            {"case_id": case_id, "action": "报告", "result": report},
        )
    except Exception as e:
        return templates.TemplateResponse(
            request,
            "agents/index.html",
            {"agents": AGENT_INFO, "error": f"报告生成失败: {e}"},
        )


# --- JSON API ---

@router.get("/api/status")
async def api_agent_status():
    return {"agents": AGENT_INFO}
