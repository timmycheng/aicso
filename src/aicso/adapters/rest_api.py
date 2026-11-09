"""REST API适配器 - 通用SIEM对接"""
from __future__ import annotations

from datetime import datetime

import httpx
import structlog

from aicso.adapters.base import DataSourceAdapter
from aicso.mapping.engine import SchemaMapper, generated_alert_id
from aicso.models.alert import Alert

logger = structlog.get_logger()


class RestApiAdapter(DataSourceAdapter):
    """通用REST API适配器 - 适用于大多数SIEM平台

    支持的认证方式：
    - bearer: Bearer Token (Authorization: Bearer <token>)
    - api_key: 自定义Header (X-API-Key: <key>)
    - basic: HTTP Basic Auth (username:password)

    通过 field_mapping 配置SIEM返回字段到AiCSO Alert字段的映射。
    """

    name = "rest_api"
    description = "通用REST API适配器（SIEM对接）"

    def __init__(self):
        self._client: httpx.AsyncClient | None = None
        self._config: dict = {}
        self._mapper = SchemaMapper({}, default_source="rest_api")
        self._last_fetch_time: datetime | None = None

    async def connect(self, config: dict) -> bool:
        """连接SIEM API"""
        self._config = config
        default_src = self._config.get("default_source", "rest_api")
        self._mapper = SchemaMapper(config, default_source=default_src)
        base_url = config.get("base_url", "")
        if not base_url:
            logger.error("rest_api.no_base_url")
            return False

        # 构建HTTP客户端
        headers = {}
        auth = None

        auth_type = config.get("auth_type", "bearer")
        if auth_type == "bearer":
            token = config.get("api_token", "")
            if token:
                headers["Authorization"] = f"Bearer {token}"
        elif auth_type == "api_key":
            header_name = config.get("api_key_header", "X-API-Key")
            api_key = config.get("api_key", config.get("api_token", ""))
            if api_key:
                headers[header_name] = api_key
        elif auth_type == "basic":
            username = config.get("username", "")
            password = config.get("password", "")
            if username:
                auth = httpx.BasicAuth(username, password)

        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            headers=headers,
            auth=auth,
            verify=config.get("verify_ssl", True),
            timeout=config.get("timeout", 30),
        )

        # 测试连接
        try:
            test_endpoint = config.get("alerts_endpoint", "/alerts")
            resp = await self._client.get(test_endpoint, params={"limit": 1})
            if resp.status_code in (200, 201, 401, 403):
                logger.info("rest_api.connected", base_url=base_url, status=resp.status_code)
                return resp.status_code == 200
            else:
                logger.warning("rest_api.connect_unexpected_status", status=resp.status_code)
                return False
        except Exception as e:
            logger.error("rest_api.connect_failed", error=str(e))
            return False

    async def fetch_alerts(self, since: datetime) -> list[dict]:
        """从SIEM API拉取告警"""
        if not self._client:
            return []

        endpoint = self._config.get("alerts_endpoint", "/alerts")
        params = {}

        # 时间过滤（大多数SIEM支持的参数格式）
        if since:
            time_format = self._config.get("time_format", "iso")
            if time_format == "iso":
                params["start_time"] = since.isoformat()
            elif time_format == "timestamp":
                params["start_time"] = int(since.timestamp() * 1000)
            elif time_format == "custom":
                time_param = self._config.get("time_param", "start_time")
                time_tpl = self._config.get("time_template", "{iso}")
                params[time_param] = time_tpl.format(
                    iso=since.isoformat(),
                    ts=int(since.timestamp() * 1000),
                )

        # 分页
        params["limit"] = self._config.get("page_size", 100)

        # 额外查询参数
        extra_params = self._config.get("extra_params", {})
        params.update(extra_params)

        try:
            resp = await self._client.get(endpoint, params=params)
            resp.raise_for_status()
            data = resp.json()

            # 适配不同的响应格式
            # 格式1: {"data": [...], "total": N}
            # 格式2: {"alerts": [...]}
            # 格式3: [...]
            if isinstance(data, list):
                return data
            elif isinstance(data, dict):
                # 尝试常见字段名
                for key in ["data", "alerts", "items", "results", "records", "list"]:
                    if key in data and isinstance(data[key], list):
                        return data[key]
                # 如果没有找到列表字段，返回整个响应（可能是单条）
                return [data]
            return []
        except Exception as e:
            logger.error("rest_api.fetch_failed", error=str(e))
            return []

    async def normalize(self, raw: dict) -> Alert:
        """统一映射引擎归一化（schema: auto|ecs|generic + field_mapping覆盖）"""
        alert, warnings = self._mapper.normalize(
            raw, fallback_alert_id=generated_alert_id("api")
        )
        for w in warnings:
            logger.warning("rest_api.normalize_warning", alert_id=alert.alert_id, warning=w)
        return alert

    async def close(self):
        if self._client:
            await self._client.aclose()
            self._client = None
