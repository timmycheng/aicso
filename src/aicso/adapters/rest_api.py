"""REST API适配器 - 通用SIEM对接"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

import httpx
import structlog

from aicso.adapters.base import DataSourceAdapter
from aicso.models.alert import Alert

logger = structlog.get_logger()


def _get_nested(data: dict, path: str, default=None):
    """从嵌套字典中按点号路径取值，如 'rule.name' -> data['rule']['name']"""
    keys = path.split(".")
    current = data
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key)
        else:
            return default
        if current is None:
            return default
    return current


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
        self._client: Optional[httpx.AsyncClient] = None
        self._config: dict = {}
        self._last_fetch_time: Optional[datetime] = None

    async def connect(self, config: dict) -> bool:
        """连接SIEM API"""
        self._config = config
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
        """根据field_mapping将SIEM原始数据映射为标准Alert"""
        mapping = self._config.get("field_mapping", {})
        severity_map = self._config.get("severity_mapping", {})

        # 提取字段
        alert_id = _get_nested(raw, mapping.get("alert_id", "alert_id"), f"api-{uuid.uuid4().hex[:8]}")
        source = _get_nested(raw, mapping.get("source", "source"), self._config.get("default_source", "siem"))
        rule_id = str(_get_nested(raw, mapping.get("rule_id", "rule_id"), ""))
        rule_name = _get_nested(raw, mapping.get("rule_name", "rule_name"), "")
        raw_severity = _get_nested(raw, mapping.get("severity", "severity"), "medium")
        src_ip = _get_nested(raw, mapping.get("src_ip", "src_ip"))
        dst_ip = _get_nested(raw, mapping.get("dst_ip", "dst_ip"))
        src_port = _get_nested(raw, mapping.get("src_port", "src_port"))
        dst_port = _get_nested(raw, mapping.get("dst_port", "dst_port"))
        protocol = _get_nested(raw, mapping.get("protocol", "protocol"))
        raw_log = _get_nested(raw, mapping.get("raw_log", "raw_log"))
        timestamp_raw = _get_nested(raw, mapping.get("timestamp", "timestamp"))

        # 严重级别映射
        severity = "medium"
        if isinstance(raw_severity, int) or (isinstance(raw_severity, str) and raw_severity.isdigit()):
            severity = severity_map.get(int(raw_severity), severity_map.get(str(raw_severity), "medium"))
        elif isinstance(raw_severity, str):
            severity = raw_severity.lower()
            if severity not in ("critical", "high", "medium", "low", "info"):
                severity = "medium"

        # 时间解析
        timestamp = datetime.utcnow()
        if timestamp_raw:
            try:
                if isinstance(timestamp_raw, (int, float)):
                    timestamp = datetime.fromtimestamp(timestamp_raw / 1000 if timestamp_raw > 1e12 else timestamp_raw)
                else:
                    timestamp = datetime.fromisoformat(str(timestamp_raw).replace("Z", "+00:00"))
            except (ValueError, OSError):
                pass

        # 端口类型转换
        try:
            src_port = int(src_port) if src_port else None
        except (ValueError, TypeError):
            src_port = None
        try:
            dst_port = int(dst_port) if dst_port else None
        except (ValueError, TypeError):
            dst_port = None

        return Alert(
            alert_id=str(alert_id),
            source=str(source),
            rule_id=str(rule_id) if rule_id else None,
            rule_name=str(rule_name) if rule_name else None,
            severity=severity,
            timestamp=timestamp,
            src_ip=str(src_ip) if src_ip else None,
            dst_ip=str(dst_ip) if dst_ip else None,
            src_port=src_port,
            dst_port=dst_port,
            protocol=str(protocol) if protocol else None,
            raw_log=str(raw_log) if raw_log else None,
            enriched_data=raw,
        )

    async def close(self):
        if self._client:
            await self._client.aclose()
            self._client = None
