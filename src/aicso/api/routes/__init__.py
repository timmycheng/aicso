"""路由注册"""
from __future__ import annotations

from fastapi import APIRouter

from aicso.api.routes.agent import router as agent_router
from aicso.api.routes.alert import router as alert_router
from aicso.api.routes.case import router as case_router
from aicso.api.routes.datasource import router as datasource_router
from aicso.api.routes.mock import router as mock_router

api_router = APIRouter()
api_router.include_router(case_router)
api_router.include_router(alert_router)
api_router.include_router(agent_router)
api_router.include_router(datasource_router)
api_router.include_router(mock_router)
