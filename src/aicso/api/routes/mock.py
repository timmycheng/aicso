"""Mock数据生成路由"""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from aicso.adapters.mock_producer import ecs_to_alert, generate_mock_alerts
from aicso.api.deps import AppState, get_state

_TEMPLATES_DIR = str(Path(__file__).resolve().parent.parent / "templates")
router = APIRouter(prefix="/mock", tags=["mock"])
templates = Jinja2Templates(directory=_TEMPLATES_DIR)

CATEGORIES = [
    "brute_force", "phishing", "malware", "lateral_movement",
    "data_exfiltration", "privilege_escalation", "port_scan", "web_attack",
]

CATEGORY_LABELS = {
    "brute_force": "暴力破解",
    "phishing": "钓鱼攻击",
    "malware": "恶意软件",
    "lateral_movement": "横向移动",
    "data_exfiltration": "数据外传",
    "privilege_escalation": "特权提升",
    "port_scan": "端口扫描",
    "web_attack": "Web攻击",
}


@router.get("", response_class=HTMLResponse)
async def mock_index(request: Request):
    return templates.TemplateResponse(
        request,
        "mock/index.html",
        {
            "categories": CATEGORIES,
            "category_labels": CATEGORY_LABELS,
            "result": None,
        },
    )


@router.post("/generate", response_class=HTMLResponse)
async def mock_generate(
    request: Request,
    count: int = Form(10),
    categories: list[str] = Form(default=[]),
    inject: bool = Form(default=False),
    state: AppState = Depends(get_state),
):
    # 类别健壮性：过滤非法值（透传未知类别会KeyError 500）
    valid_categories = [c for c in categories if c in CATEGORIES]
    ecs_alerts = generate_mock_alerts(
        count=count,
        categories=valid_categories or None,
    )

    injected = 0
    cases_created = 0
    if inject:
        from aicso.agents.triage import TriageAgent

        orch = state.orchestrator
        if "triage" not in orch._agents:
            orch.register_agent(TriageAgent(
                llm_provider=state.config.llm.default_provider,
            ))

        before = state.router.metrics.cases_created_total
        for ecs in ecs_alerts:
            await orch.handle_alert(ecs_to_alert(ecs))
            injected += 1
        # 同步排空路由队列+写缓冲，保证响应所报结果立即可查
        # （CI曾暴露：0.1s缓冲窗口内紧接的列表查询读到0行）
        await state.router.flush()
        cases_created = state.router.metrics.cases_created_total - before
        await state.db.flush()

    preview_alerts = []
    for ecs in ecs_alerts[:5]:
        a = ecs_to_alert(ecs)
        preview_alerts.append({
            "alert_id": a.alert_id,
            "rule_name": a.rule_name,
            "severity": a.severity,
            "src_ip": a.src_ip,
            "dst_ip": a.dst_ip,
            "host": ecs.get("host", {}).get("name", ""),
            "mitre": ecs.get("threat", {}).get("tactic", {}).get("name", ""),
        })

    return templates.TemplateResponse(
        request,
        "mock/index.html",
        {
            "categories": CATEGORIES,
            "category_labels": CATEGORY_LABELS,
            "result": {
                "total": len(ecs_alerts),
                "injected": injected,
                "cases_created": cases_created,
                "preview": preview_alerts,
            },
        },
    )


# --- JSON API ---

@router.post("/api/generate")
async def api_mock_generate(
    request: Request,
    state: AppState = Depends(get_state),
):
    body = await request.json()
    count = body.get("count", 10)
    categories = body.get("categories", [])
    inject = body.get("inject", False)

    # 类别健壮性：过滤非法值（透传未知类别会KeyError 500）
    valid_categories = [c for c in categories if c in CATEGORIES]
    ecs_alerts = generate_mock_alerts(
        count=count,
        categories=valid_categories or None,
    )

    injected = 0
    cases_created = 0
    if inject:
        from aicso.agents.triage import TriageAgent

        orch = state.orchestrator
        if "triage" not in orch._agents:
            orch.register_agent(TriageAgent(
                llm_provider=state.config.llm.default_provider,
            ))

        before = state.router.metrics.cases_created_total
        for ecs in ecs_alerts:
            await orch.handle_alert(ecs_to_alert(ecs))
            injected += 1
        # 同步排空路由队列+写缓冲，保证响应所报结果立即可查
        # （CI曾暴露：0.1s缓冲窗口内紧接的列表查询读到0行）
        await state.router.flush()
        cases_created = state.router.metrics.cases_created_total - before
        await state.db.flush()

    return {
        "generated": len(ecs_alerts),
        "injected": injected,
        "cases_created": cases_created,
        "alerts": [
            {
                "alert_id": ecs_to_alert(e).alert_id,
                "rule_name": e.get("rule", {}).get("name"),
                "severity": e.get("rule", {}).get("severity"),
                "src_ip": e.get("source", {}).get("ip"),
                "dst_ip": e.get("destination", {}).get("ip"),
            }
            for e in ecs_alerts[:20]
        ],
    }
