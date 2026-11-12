"""数据源管理路由"""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from aicso.api.deps import AppState, get_state

_TEMPLATES_DIR = str(Path(__file__).resolve().parent.parent / "templates")
router = APIRouter(prefix="/datasources", tags=["datasources"])
templates = Jinja2Templates(directory=_TEMPLATES_DIR)


@router.get("", response_class=HTMLResponse)
async def datasource_list(request: Request, state: AppState = Depends(get_state)):
    datasources = []
    for name, ds in state.config.datasources.items():
        datasources.append({
            "name": name,
            "type": ds.type,
            "description": ds.description,
            "enabled": ds.enabled,
        })
    return templates.TemplateResponse(
        request,
        "datasources/list.html",
        {"datasources": datasources},
    )


# --- JSON API ---

@router.get("/api/list")
async def api_datasource_list(state: AppState = Depends(get_state)):
    datasources = []
    for name, ds in state.config.datasources.items():
        datasources.append({
            "name": name,
            "type": ds.type,
            "description": ds.description,
            "enabled": ds.enabled,
        })
    return {"datasources": datasources}


@router.get("/api/types")
async def api_datasource_types():
    from aicso.adapters.registry import datasource_registry
    return {"types": datasource_registry.list_types()}


@router.get("/api/status")
async def api_datasource_status(state: AppState = Depends(get_state)):
    """查看所有已连接数据源的运行状态"""
    if not state.datasource_manager:
        return {"datasources": [], "message": "数据源管理器未启动"}
    return {"datasources": state.datasource_manager.list_status()}


# --- 映射试算（issue #35 易用性：样例消息→归一化预览） ---

@router.post("/api/test-mapping")
async def api_test_mapping(request: Request):
    """schema映射试算：粘贴样例消息，预览归一化结果与警告清单"""
    from aicso.mapping.engine import SchemaMapper, generated_alert_id

    body = await request.json()
    sample = body.get("sample", "")
    mapper_config = body.get("config", {}) or {}
    if not sample.strip():
        return {"error": "sample必填：粘贴一条样例消息JSON"}

    mapper = SchemaMapper(mapper_config, default_source="preview")
    events = mapper.expand_message(sample)
    results = []
    for e in events:
        alert, warnings = mapper.normalize(e, fallback_alert_id=generated_alert_id("preview"))
        results.append({
            "alert": alert.model_dump(mode="json"),
            "warnings": warnings,
        })
    return {
        "events": len(events),
        "results": results,
        "detected_schema": mapper._detected or mapper.schema,
    }


# --- 映射自动建议（issue #49，Epic #47：采样→推断→试算验证→人工确认） ---

async def _infer_from_samples(samples: list) -> dict:
    """样本列表 → 推断草稿 + 试算验证结果（草稿不落盘，人工确认）"""

    from aicso.mapping.engine import SchemaMapper, generated_alert_id
    from aicso.mapping.suggest import suggest_mapping

    records: list[dict] = []
    expander = SchemaMapper({})
    for sample in samples[:50]:
        if isinstance(sample, dict):
            records.append(sample)
        elif isinstance(sample, str) and sample.strip():
            records.extend(expander.expand_message(sample))
    if not records:
        return {"error": "无有效样本：提供JSON对象或JSON消息串"}

    suggestion = suggest_mapping(records)
    # 试算验证：草稿配置跑全部样本，看警告与实体覆盖
    config = {"schema": "generic",
              "field_mapping": suggestion["fields"],
              "entity_mapping": suggestion["entity_mapping"]}
    mapper = SchemaMapper(config, default_source="suggest")
    warning_total = 0
    entity_hits = 0
    previews = []
    for record in records[:20]:
        alert, warnings = mapper.normalize(record,
                                           fallback_alert_id=generated_alert_id("suggest"))
        warning_total += len(warnings)
        if alert.src_ip or alert.dst_ip or alert.entities:
            entity_hits += 1
        previews.append({"alert_id": alert.alert_id,
                         "src_ip": alert.src_ip, "dst_ip": alert.dst_ip,
                         "entities": alert.entities,
                         "timestamp": str(alert.timestamp),
                         "warnings": warnings})
    suggestion["validation"] = {
        "records": len(records),
        "warning_total": warning_total,
        "entity_coverage": f"{entity_hits}/{min(len(records), 20)}",
        "previews": previews[:3],
    }
    return suggestion


@router.post("/api/suggest-mapping")
async def api_suggest_mapping(request: Request):
    """从粘贴样本推断映射草稿（系统提议，人工确认落盘）"""
    body = await request.json()
    samples = body.get("samples", [])
    if not samples:
        return {"error": "samples必填：JSON对象/消息串列表（≤50条）"}
    return await _infer_from_samples(samples)


@router.post("/api/{name}/suggest-mapping-live")
async def api_suggest_mapping_live(name: str, request: Request,
                                   state: AppState = Depends(get_state)):
    """从存量数据源活体采样推断映射（Kafka用独立临时消费组，主组位点零扰动）"""
    ds_config = state.config.datasources.get(name)
    if not ds_config:
        raise HTTPException(status_code=404, detail=f"数据源不存在: {name}")
    body = await request.json() if request.headers.get("content-length") else {}
    limit = int((body or {}).get("limit", 50))

    if ds_config.type == "kafka":
        from aicso.mapping.suggest import sample_kafka
        samples = await sample_kafka(ds_config.config, n=limit)
    else:
        from aicso.adapters.registry import datasource_registry
        adapter = datasource_registry.create(ds_config.type)
        if not await adapter.connect(dict(ds_config.config)):
            return {"error": f"数据源连接失败: {name}"}
        try:
            from datetime import datetime, timedelta
            samples = await adapter.fetch_alerts(datetime.utcnow() - timedelta(days=7))
        finally:
            await adapter.close()
    if not samples:
        return {"error": "采样为空：源无可用消息，稍后重试或直接粘贴样本"}
    result = await _infer_from_samples(samples[:50])
    result["sampled_from"] = name
    return result
