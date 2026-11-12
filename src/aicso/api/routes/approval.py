"""审批API（TECHNICAL_DESIGN §8.2）

高风险决策→人工（设计§6任务→引擎映射）。此前 approve/reject 全仓无调用方，
审批链路是死路：中/高风险步骤必然等满超时后失败（review #56发现16）。
"""
from __future__ import annotations

from dataclasses import asdict

from fastapi import APIRouter, Depends, HTTPException, Request

from aicso.api.deps import AppState, get_state

router = APIRouter(prefix="/approvals", tags=["approvals"])


def _serialize(req) -> dict:
    data = asdict(req)
    data["risk_level"] = req.risk_level.value
    data["status"] = req.status.value
    data["requested_at"] = req.requested_at.isoformat()
    data["resolved_at"] = req.resolved_at.isoformat() if req.resolved_at else None
    return data


@router.get("/api/pending")
async def api_pending_approvals(state: AppState = Depends(get_state)):
    """待审批列表（中/高风险操作等待人工决议）"""
    return {"approvals": [_serialize(r) for r in state.approval_engine.get_pending()]}


@router.post("/api/{request_id}/approve")
async def api_approve(request_id: str, request: Request,
                      state: AppState = Depends(get_state)):
    """批准（仅PENDING可决议）"""
    body = await request.json() if request.headers.get("content-length") else {}
    ok = await state.approval_engine.approve(
        request_id, approver=str(body.get("approver") or "analyst"),
        reason=str(body.get("reason") or ""),
    )
    if not ok:
        raise HTTPException(status_code=404, detail=f"审批请求不存在或已决议: {request_id}")
    return {"ok": True, "request_id": request_id}


@router.post("/api/{request_id}/reject")
async def api_reject(request_id: str, request: Request,
                     state: AppState = Depends(get_state)):
    """拒绝（仅PENDING可决议）"""
    body = await request.json() if request.headers.get("content-length") else {}
    ok = await state.approval_engine.reject(
        request_id, approver=str(body.get("approver") or "analyst"),
        reason=str(body.get("reason") or ""),
    )
    if not ok:
        raise HTTPException(status_code=404, detail=f"审批请求不存在或已决议: {request_id}")
    return {"ok": True, "request_id": request_id}
