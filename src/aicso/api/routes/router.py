"""分流路由管理页面 — 替代原 /aggregator（不再读私有属性，走引擎公开接口）"""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
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

@router.post("/api/merge/evaluate")
async def api_merge_evaluate(request: Request, state: AppState = Depends(get_state)):
    """评估两个Case是否应合并（System One判定，不执行）"""
    body = await request.json()
    case_a, case_b = body.get("case_a"), body.get("case_b")
    if not case_a or not case_b:
        return {"error": "case_a/case_b必填"}, 400
    evaluation = await state.merge_engine.evaluate_pair(case_a, case_b)
    if evaluation is None:
        return {"error": "评估不可用（System One不可用或Case不存在/已合并）"}
    return {
        "case_a": evaluation.case_a, "case_b": evaluation.case_b,
        "choice": evaluation.choice, "confidence": evaluation.confidence,
    }


@router.post("/api/merge/execute")
async def api_merge_execute(request: Request, state: AppState = Depends(get_state)):
    """执行合并（幂等）"""
    body = await request.json()
    primary, absorbed = body.get("primary"), body.get("absorbed")
    if not primary or not absorbed:
        return {"error": "primary/absorbed必填"}
    return await state.merge_engine.merge(
        primary, absorbed, reason=body.get("reason", "manual"))


@router.post("/api/split")
async def api_split(request: Request, state: AppState = Depends(get_state)):
    """拆分告警子集到新Case"""
    body = await request.json()
    result = await state.merge_engine.split(
        body.get("case_id"), body.get("alert_ids", []),
        reason=body.get("reason", "manual"),
        new_title=body.get("new_title", ""),
    )
    return result


@router.post("/api/merge-sweep")
async def api_merge_sweep(request: Request, state: AppState = Depends(get_state)):
    """扫描共享实体候选对并自动评估合并（System One判定+高置信度执行）"""
    evaluations = await state.merge_engine.sweep(max_pairs=5)
    return {
        "evaluated": len(evaluations),
        "results": [
            {
                "case_a": e.case_a, "case_b": e.case_b,
                "choice": e.choice, "confidence": e.confidence,
                "executed": e.executed,
            }
            for e in evaluations
        ],
    }



@router.get("/api/status")
async def api_router_status(state: AppState = Depends(get_state)):
    """引擎状态：队列/降级/缓存/索引/指标"""
    engine = state.router
    return {
        **engine.status(),
        "index_slots": engine.index.slot_rows()[:50],
    }


@router.get("/api/tuner")
async def api_tuner_status(state: AppState = Depends(get_state)):
    """参数微调器状态（issue #50）：当前值/初始值/调整历史"""
    tuner = getattr(state.router, "_tuner", None)
    if tuner is None:
        return {"enabled": False,
                "message": "未启用（auto_tune=false 或本地兜底模式）"}
    return {"enabled": True, **tuner.snapshot()}


@router.post("/api/tuner/rollback")
async def api_tuner_rollback(state: AppState = Depends(get_state)):
    """一键回滚微调器最近一次参数调整（issue #50）"""
    tuner = getattr(state.router, "_tuner", None)
    if tuner is None:
        raise HTTPException(status_code=404, detail="微调器未启用")
    decision = tuner.rollback()
    if decision is None:
        return {"ok": False, "message": "无可回滚的调整"}
    return {"ok": True, "decision": vars(decision)}


@router.get("/api/decisions")
async def api_router_decisions(
    limit: int = 50,
    state: AppState = Depends(get_state),
):
    """最近路由决策审计"""
    rows = await state.routing_store.list_recent(limit=min(limit, 200))
    return {"decisions": rows, "stats_by_source": await state.routing_store.stats_by_source()}
