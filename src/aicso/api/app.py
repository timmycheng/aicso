"""FastAPI Web应用入口"""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from aicso.api.deps import AppState, close_app_state, init_app_state
from aicso.api.routes import api_router

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    state = await init_app_state()
    app.state.aicso = state
    yield
    await close_app_state(state)


app = FastAPI(
    title="AiCSO",
    description="AI Cyber Security Operations - Web Platform",
    version="0.1.0",
    lifespan=lifespan,
)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
app.include_router(api_router)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    state: AppState = request.app.state.aicso
    cases = await state.case_store.list_cases(limit=10)
    total_cases = await state.case_store.count()
    total_alerts = await state.alert_store.count()

    severity_counts = {}
    for c in cases:
        sev = c.get("severity", "unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "cases": cases,
            "total_cases": total_cases,
            "total_alerts": total_alerts,
            "severity_counts": severity_counts,
        },
    )


def main():
    """启动Web服务"""
    from aicso.config import load_config
    from aicso.logging import setup_logging
    config = load_config()
    setup_logging(level=config.logging.level)
    uvicorn.run(
        "aicso.api.app:app",
        host=config.server.host,
        port=config.server.port,
        reload=True,
        reload_dirs=[str(Path(__file__).resolve().parent.parent.parent / "src")],
    )


if __name__ == "__main__":
    main()
