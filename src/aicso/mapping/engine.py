"""统一Schema映射引擎（issue #35）

多数据源共用一套 normalize 逻辑：点号路径取值、静态默认、类型转换、
严重度双策略（文本枚举 + 数值阈值）、多格式时间解析、信封/批量数组
展开、警告收集。

配置形态（datasource config 段内）:
  schema: auto        # auto(默认,自动探测) | ecs | generic
  field_mapping: {}   # 自定义路径，覆盖profile默认（向后兼容存量配置）
  severity_mapping: {}# 自定义数值→级别映射（如 {1: critical, 2: high}）
  timestamp_format: "%Y-%m-%d %H:%M:%S"  # 自定义strptime模板（可选）
  events_path: events # 信封路径：消息内指向事件数组的点号路径（可选）
  entity_mapping: {}  # 类型化实体提取路径覆盖（issue #44）：{"host": "Hostname"}
  entity_short_name: false  # host实体FQDN→短名（引擎侧可选归一；归一责任默认数据源侧）
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any

import structlog

from aicso.mapping.profiles import BUILTIN_PROFILES, GENERIC_PROFILE
from aicso.models.alert import Alert

logger = structlog.get_logger()

SEVERITY_LEVELS = ("critical", "high", "medium", "low", "info")


def get_nested(data: Any, path: str, default: Any = None) -> Any:
    """点号路径取值（a.b.c），路径不存在返回default"""
    cur = data
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return default
    return cur


class SchemaMapper:
    """统一schema映射器：每个数据源适配器持有一个实例"""

    def __init__(self, config: dict, default_source: str = "unknown"):
        self.config = config
        self.default_source = default_source
        self.schema = config.get("schema", "auto")
        self.field_mapping: dict = config.get("field_mapping", {}) or {}
        self.entity_mapping: dict = config.get("entity_mapping", {}) or {}
        self.entity_short_name: bool = bool(config.get("entity_short_name", False))
        self.severity_mapping: dict = config.get("severity_mapping", {}) or {}
        self.timestamp_format: str | None = config.get("timestamp_format")
        self.events_path: str | None = config.get("events_path")
        self._detected: str | None = None  # auto模式下首条消息探测结果

    # ---- profile 解析 ----

    def resolve_profile(self, raw: dict | None = None) -> dict:
        """解析生效的profile：显式schema > auto探测 > generic+自定义覆盖"""
        schema = self.schema
        if schema == "auto":
            if self._detected:
                schema = self._detected
            else:
                schema = self._detect(raw or {})
                self._detected = schema
        profile = dict(BUILTIN_PROFILES.get(schema, GENERIC_PROFILE))
        fields = dict(profile.get("fields", {}))
        # 自定义路径覆盖profile默认（向后兼容存量field_mapping配置）
        fields.update(self.field_mapping)
        profile["fields"] = fields
        entities = dict(profile.get("entities", {}))
        entities.update(self.entity_mapping)
        profile["entities"] = entities
        return profile

    @staticmethod
    def _detect(raw: dict) -> str:
        """ECS签名探测：@timestamp + source/destination 结构"""
        if "@timestamp" in raw and ("source" in raw or "destination" in raw):
            return "ecs"
        return "generic"

    # ---- 信封/批量展开 ----

    def expand_message(self, raw_text: str) -> list[dict]:
        """单条消息 → 事件dict列表

        - 非JSON → 单个raw包装（由normalize包进raw_log）
        - 顶层JSON数组 → 每个元素一个事件
        - events_path 指向消息内数组 → 展开该数组
        - 其余 → 单事件
        """
        try:
            parsed = json.loads(raw_text)
        except (json.JSONDecodeError, TypeError):
            return [{"__raw__": raw_text}]

        if isinstance(parsed, list):
            return [p for p in parsed if isinstance(p, dict)] or [{"__raw__": raw_text}]
        if not isinstance(parsed, dict):
            return [{"__raw__": raw_text}]
        if self.events_path:
            events = get_nested(parsed, self.events_path)
            if isinstance(events, list) and events:
                return [e for e in events if isinstance(e, dict)]
        return [parsed]

    # ---- normalize ----

    def normalize(self, raw: dict, fallback_alert_id: str) -> tuple[Alert, list[str]]:
        """归一化：返回(Alert, 警告清单)"""
        warnings: list[str] = []
        profile = self.resolve_profile(raw)
        fields: dict = profile["fields"]

        if raw.get("__raw__") is not None and len(raw) == 1:
            # 非JSON消息：只保留原文（无实体 → 路由按无候选新建）
            warnings.append("消息非结构化JSON，仅保留raw_log，无实体可供分流")
            return self._build_alert(
                alert_id=fallback_alert_id, source=self.default_source,
                rule_name=None, severity="info", timestamp=datetime.utcnow(),
                raw_log=raw["__raw__"], extra={}, warnings=warnings,
            ), warnings

        def getf(key: str, default: Any = None) -> Any:
            path = fields.get(key, key)
            if path == "__json__":
                return json.dumps(raw, ensure_ascii=False)
            return get_nested(raw, path, default)

        # 缺少告警ID是常态（Elastic告警常无独立ID），自动生成不告警
        alert_id = getf("alert_id") or fallback_alert_id

        source = getf("source") or self.default_source
        rule_id = getf("rule_id")
        rule_name = getf("rule_name")

        severity, sev_warning = self._normalize_severity(raw, profile, getf)
        if sev_warning:
            warnings.append(sev_warning)

        timestamp = self._normalize_timestamp(getf("timestamp"))
        if timestamp is None:
            timestamp = datetime.utcnow()
            warnings.append("缺少/无法解析时间戳，已用当前时间")

        src_ip = getf("src_ip")
        dst_ip = getf("dst_ip")

        # 类型化实体提取（issue #44）：弱实体让无IP告警可进候选
        entities = self._extract_entities(raw, profile)
        if not src_ip and not dst_ip:
            if entities:
                evidence = ", ".join(f"{k}:{v}" for k, v in sorted(entities.items()))
                warnings.append(
                    f"无源/目标IP实体，弱实体({evidence})可进候选交模型裁决")
            else:
                warnings.append("无源/目标IP实体，该告警将独立建Case（无候选可汇入）")

        extra = {
            k: v for k, v in raw.items()
            if k not in ("__raw__",) and not isinstance(v, (dict, list))
        } or {"_raw_keys": list(raw.keys())}

        alert = self._build_alert(
            alert_id=str(alert_id), source=str(source),
            rule_id=str(rule_id) if rule_id else None,
            rule_name=str(rule_name) if rule_name else None,
            severity=severity, timestamp=timestamp,
            src_ip=str(src_ip) if src_ip else None,
            dst_ip=str(dst_ip) if dst_ip else None,
            src_port=self._to_int(getf("src_port")),
            dst_port=self._to_int(getf("dst_port")),
            protocol=str(getf("protocol")) if getf("protocol") else None,
            raw_log=str(getf("raw_log")) if getf("raw_log")
                    else json.dumps(raw, ensure_ascii=False),
            entities=entities,
            extra=extra, warnings=warnings,
        )
        return alert, warnings

    def _extract_entities(self, raw: dict, profile: dict) -> dict[str, str]:
        """按profile路径提取类型化实体并规范化（issue #44）

        归一责任默认数据源侧（日志中心）；引擎侧统一小写防同实体裂键，
        host 可选 entity_short_name 做 FQDN→短名。
        """
        entities: dict[str, str] = {}
        for etype, path in (profile.get("entities") or {}).items():
            if not path:
                continue
            value = get_nested(raw, str(path))
            if value in (None, "", "-"):
                continue
            value = str(value).strip().lower()
            if etype == "host" and self.entity_short_name:
                value = value.split(".", 1)[0]
            entities[etype] = value
        return entities

    @staticmethod
    def _build_alert(**kwargs) -> Alert:
        warnings = kwargs.pop("warnings", [])
        extra = kwargs.pop("extra", {})
        entities = kwargs.pop("entities", {}) or {}
        extra["_mapping_warnings"] = warnings
        return Alert(entities=entities, enriched_data=extra, **kwargs)

    # ---- 严重度：自定义映射 > 文本枚举 > 数值阈值 ----

    def _normalize_severity(self, raw: dict, profile: dict, getf) -> tuple[str, str | None]:
        severity_int_path = profile["fields"].get("severity_int")
        raw_text = getf("severity_text")
        raw_int = getf("severity_int") if severity_int_path else None

        # 1) 用户自定义数值映射（如 {1: critical, 2: high}）
        #    JSON配置的键必然是字符串，int/str双查都支持
        if self.severity_mapping and raw_int is not None:
            try:
                value = int(raw_int)
                mapped = (self.severity_mapping.get(value)
                          or self.severity_mapping.get(str(value)))
                if mapped:
                    return mapped, None
            except (ValueError, TypeError):
                pass

        # 2) 文本枚举
        if isinstance(raw_text, str) and raw_text.lower() in SEVERITY_LEVELS:
            return raw_text.lower(), None

        # 3) 数值阈值（ECS语义：数值越大越严重）
        if raw_int is not None:
            try:
                value = int(raw_int)
            except (ValueError, TypeError):
                value = None
            if value is not None:
                thresholds = profile.get("severity_int_thresholds") or \
                    [(80, "critical"), (60, "high"), (40, "medium"), (20, "low"), (0, "info")]
                for floor, level in thresholds:
                    if value >= floor:
                        return level, None

        if self.severity_mapping and isinstance(raw_text, str) and raw_text:
            mapped = self.severity_mapping.get(raw_text)
            if mapped:
                return mapped, None

        return "medium", f"无法识别严重度(text={raw_text!r}, int={raw_int!r})，已用medium"

    # ---- 时间：ISO / epoch ms / epoch s / 自定义模板 ----

    def _normalize_timestamp(self, raw_ts: Any) -> datetime | None:
        if raw_ts in (None, ""):
            return None
        if isinstance(raw_ts, (int, float)):
            try:
                value = raw_ts / 1000 if raw_ts > 1e12 else raw_ts
                return datetime.fromtimestamp(value)
            except (ValueError, OSError, OverflowError):
                return None
        text = str(raw_ts)
        if self.timestamp_format:
            try:
                return datetime.strptime(text, self.timestamp_format)
            except ValueError:
                pass
        try:
            return datetime.fromisoformat(text.replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            pass
        try:
            value = float(text)
            value = value / 1000 if value > 1e12 else value
            return datetime.fromtimestamp(value)
        except (ValueError, OverflowError):
            return None

    @staticmethod
    def _to_int(value: Any) -> int | None:
        if value in (None, ""):
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None


def generated_alert_id(prefix: str) -> str:
    """兜底告警ID"""
    return f"{prefix}-{uuid.uuid4().hex[:8]}"
