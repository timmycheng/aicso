"""聚合规则管理路由"""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from aicso.api.deps import AppState, get_state

_TEMPLATES_DIR = str(Path(__file__).resolve().parent.parent / "templates")
router = APIRouter(prefix="/aggregator", tags=["aggregator"])
templates = Jinja2Templates(directory=_TEMPLATES_DIR)


@router.get("", response_class=HTMLResponse)
async def aggregator_index(
    request: Request,
    state: AppState = Depends(get_state),
):
    aggregator = state.orchestrator.aggregator
    return templates.TemplateResponse(
        request,
        "aggregator/index.html",
        {
            "ai_rules": aggregator._ai_rules,
            "immediate_cache": aggregator._immediate_cache,
            "ai_cache": aggregator._ai_cache,
        },
    )


# --- JSON API ---

@router.get("/api/rules")
async def api_aggregation_rules(state: AppState = Depends(get_state)):
    aggregator = state.orchestrator.aggregator

    ai_rules = []
    for case_id, rule in aggregator._ai_rules.items():
        ai_rules.append({
            "case_id": case_id,
            "dimensions": rule.dimensions,
            "window_minutes": rule.window_minutes,
            "label": rule.label,
            "generated_by": rule.generated_by,
            "created_at": rule.created_at.isoformat(),
        })

    immediate = []
    from datetime import datetime
    for cache_key, (case_id, last_seen) in aggregator._immediate_cache.items():
        immediate.append({
            "cache_key": cache_key,
            "case_id": case_id,
            "last_seen": last_seen.isoformat(),
        })

    ai_cache = []
    for cache_key, last_seen in aggregator._ai_cache.items():
        ai_cache.append({
            "cache_key": cache_key,
            "last_seen": last_seen.isoformat(),
        })

    return {
        "ai_rules": ai_rules,
        "immediate_cache": immediate,
        "ai_cache": ai_cache,
    }
