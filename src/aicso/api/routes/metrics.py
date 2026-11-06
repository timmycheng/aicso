"""运行指标端点（docs/REFACTOR_DESIGN.md §11）"""
from __future__ import annotations

from fastapi import APIRouter, Depends

from aicso.api.deps import AppState, get_state

router = APIRouter(tags=["metrics"])


@router.get("/api/metrics")
async def api_metrics(state: AppState = Depends(get_state)):
    """路由引擎指标：延迟分位数/积压年龄/队列水位/降级计数/System One用量"""
    engine = state.router
    return engine.status()
