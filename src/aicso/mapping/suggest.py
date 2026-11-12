"""映射自动建议（issue #49，Epic #47）

采样消息 → 本地规则推断 field_mapping/entity_mapping 草稿 → 试算验证 →
人工确认落盘（系统提议、人拍板）。纯确定性启发式，无模型调用。

置信度 = 值形态命中率 × 名称信号加成；草稿必须经试算验证，
警告数高或覆盖率低的字段在 notes 中明示。
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import uuid
from collections.abc import Callable
from typing import Any

ISO_TS = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")
IPV4 = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
FQDN = re.compile(
    r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", re.I)
SHA256 = re.compile(r"^[0-9a-f]{64}$", re.I)

SEVERITY_LEVELS = ("critical", "high", "medium", "low", "info", "warn", "warning",
                   "error", "notice", "严重", "高", "中", "低")

# 目标字段 → 名称信号token（子串匹配，命中加分）+ 值形态校验
TARGETS: dict[str, dict] = {
    "timestamp": {"tokens": ("timestamp", "@timestamp", "occur_time", "eventtime")},
    "src_ip": {"tokens": ("src_ip", "sourceip", "source.ip", "srcaddr", "client_ip",
                          "sourceip", "s_ip", "sourceaddress")},
    "dst_ip": {"tokens": ("dst_ip", "destinationip", "destination.ip", "dstaddr",
                          "target_ip", "d_ip")},
    "src_port": {"tokens": ("src_port", "sourceport", "source.port")},
    "dst_port": {"tokens": ("dst_port", "destinationport", "destination.port")},
    "rule_id": {"tokens": ("rule_id", "eventid", "event_id", "ruleid", "signature_id")},
    "rule_name": {"tokens": ("rule_name", "rulename", "rule.name", "channel",
                             "check_name", "signature")},
    # severity_text/severity_int 不在此列：名称信号重叠，由下方按值形态专门消歧
    "source": {"tokens": ("sourcename", "source_name", "source.name", "dataset",
                          "provider", "agent.name")},
    "alert_id": {"tokens": ("alert_id", "recordnumber", "event.id", "request_id")},
}
ENTITY_TARGETS: dict[str, dict] = {
    "host": {"tokens": ("hostname", "host.name", "computer_name", "computername",
                        "host", "hostname")},
    "user": {"tokens": ("username", "user.name", "accountname", "user_id",
                        "account_name")},
    "file_hash": {"tokens": ("sha256", "hash", "filehash")},
    "dst_domain": {"tokens": ("domain", "destination.domain", "url.domain")},
}


def _is_ts(value: Any) -> bool:
    if isinstance(value, str):
        return bool(ISO_TS.match(value))
    if isinstance(value, (int, float)):
        return 1e9 <= value < 1e13
    return False


def _is_ip(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    m = IPV4.match(value)
    if m:
        return all(int(g) <= 255 for g in m.groups())
    # IPv6：原FQDN正则字符类不含冒号，含":"的字符串永远match不上（死代码）——
    # 改用标准库解析（review #56发现）
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_fqdn(value: Any) -> bool:
    return isinstance(value, str) and bool(FQDN.match(value)) and "." in value


def _is_port(value: Any) -> bool:
    try:
        return 0 <= int(value) <= 65535
    except (ValueError, TypeError):
        return False


SHAPES: dict[str, Callable[[Any], bool]] = {
    "timestamp": _is_ts,
    "src_ip": _is_ip,
    "dst_ip": _is_ip,
    "src_port": _is_port,
    "dst_port": _is_port,
    "file_hash": lambda v: isinstance(v, str) and bool(SHA256.match(v)),
}


def flatten_paths(record: dict, max_depth: int = 4) -> dict[str, list]:
    """样本展开为 点号路径 → 非空值列表"""
    out: dict[str, list] = {}

    def walk(obj: Any, prefix: str, depth: int) -> None:
        if depth > max_depth or not isinstance(obj, dict):
            return
        for key, value in obj.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(value, dict):
                walk(value, path, depth + 1)
            elif value not in (None, "", "-"):
                out.setdefault(path, []).append(value)

    walk(record, "", 0)
    return out


def suggest_mapping(samples: list[dict]) -> dict:
    """从样本推断映射草稿：fields/entity_mapping + 置信度 + notes

    纯本地确定性规则；草稿必须过试算验证并人工确认（#49系统提议、人拍板）。
    """
    if not samples:
        return {"fields": {}, "entity_mapping": {}, "coverage": {}, "notes": ["无样本"]}
    paths = flatten_paths(samples[0])
    for s in samples[1:]:
        for path, values in flatten_paths(s).items():
            paths.setdefault(path, []).extend(values)

    notes: list[str] = []
    fields: dict[str, str] = {}
    entities: dict[str, str] = {}
    coverage: dict[str, float] = {}
    used: set[str] = set()

    def shape_ok(target: str, values: list) -> float:
        check = SHAPES.get(target)
        if check is None:
            return 0.6   # 无形态校验的名称驱动目标（rule_id/channel等）给中性分
        hits = sum(1 for v in values if check(v))
        return hits / len(values)

    def pick(target: str, spec: dict, sink: dict) -> None:
        best_path, best_score = None, 0.0
        for path, values in paths.items():
            if path in used:
                continue
            name = path.lower()
            token_hit = max((name.find(tok) >= 0 for tok in spec["tokens"]),
                            default=False)
            if not token_hit:
                continue
            shape = shape_ok(target, values)
            score = shape * 0.8 + 0.2   # 名称命中保底，形态命中加权
            if score > best_score:
                best_path, best_score = path, score
        if best_path:
            sink[target] = best_path
            used.add(best_path)
            coverage[target] = round(min(best_score, 1.0), 2)

    for target, spec in TARGETS.items():
        pick(target, spec, fields)

    # severity 双字段消歧：text=字符串枚举路径，int=数值路径
    sev_paths = [p for p in paths if "severity" in p.lower() or p.lower().endswith("level")]
    for path in sev_paths:
        values = paths[path]
        if all(isinstance(v, (int, float)) for v in values):
            fields.setdefault("severity_int", path)
            coverage["severity_int"] = 0.8
        elif any(isinstance(v, str) and str(v).lower() in SEVERITY_LEVELS
                 for v in values):
            fields.setdefault("severity_text", path)
            coverage["severity_text"] = 0.8

    for target, spec in ENTITY_TARGETS.items():
        pick(target, spec, entities)

    # 时间戳兜底：名称未命中时按形态全局找（ISO键名任意）
    if "timestamp" not in fields:
        for path, values in paths.items():
            if sum(1 for v in values if _is_ts(v)) / len(values) >= 0.9:
                fields["timestamp"] = path
                coverage["timestamp"] = 0.6
                notes.append(f"时间戳按形态推断: {path}（名称无信号）")
                break

    if "timestamp" not in fields:
        notes.append("未找到时间戳字段——归一化将用摄入时间，可能影响时序审计")
    if "src_ip" not in fields and "dst_ip" not in fields:
        notes.append("未找到源/目标IP字段——弱实体或主机字段可补充候选来源")

    return {
        "fields": fields,
        "entity_mapping": entities,
        "coverage": coverage,
        "notes": notes,
        "sample_count": len(samples),
    }


def sample_group_id(datasource: str) -> str:
    """Kafka采样临时消费组：独立于主消费组（位点零扰动，#49）"""
    return f"aicso-sample-{datasource}-{uuid.uuid4().hex[:8]}"


async def sample_kafka(config: dict, n: int = 50, timeout_s: float = 8.0,
                       consumer_factory: Callable | None = None) -> list[dict]:
    """Kafka采样：临时消费组消费N条即停，不commit（主消费组位点零扰动）

    整体受 timeout_s 预算约束（此前该参数完全未使用，慢速topic下
    采样时长不可控，review #56发现）；超时返回已采到的部分。
    """
    from aicso.mapping.engine import SchemaMapper

    factory = consumer_factory or _default_kafka_factory
    group = sample_group_id(config.get("topic", "ds"))
    consumer = await factory(config, group)
    await consumer.start()
    samples: list[dict] = []
    try:
        mapper = SchemaMapper({})

        async def _consume() -> None:
            while len(samples) < n:
                data = await consumer.getmany(timeout_ms=1000, max_records=n - len(samples))
                got = False
                for _tp, messages in data.items():
                    for msg in messages:
                        got = True
                        samples.extend(mapper.expand_message(msg.value))
                if not got:
                    return

        try:
            await asyncio.wait_for(_consume(), timeout=timeout_s)
        except TimeoutError:
            pass  # 预算耗尽：返回已采样本
    finally:
        await consumer.stop()
    return samples[:n]


async def _default_kafka_factory(config: dict, group: str):
    """仅构造未启动的消费者；start/stop由sample_kafka统一管理"""
    from aiokafka import AIOKafkaConsumer

    return AIOKafkaConsumer(
        config.get("topic", "siem-alerts"),
        bootstrap_servers=config.get("bootstrap_servers", "localhost:9092"),
        group_id=group,
        auto_offset_reset="earliest",
        enable_auto_commit=False,
        value_deserializer=lambda m: m.decode("utf-8", errors="ignore"),
    )
