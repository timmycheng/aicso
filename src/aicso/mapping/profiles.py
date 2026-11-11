"""内置Schema Profile — 多数据源统一映射的预置方案（issue #35/#44）

ECS 8.x 为一等公民：schema: ecs 一行配置零映射接入 Elastic 系SIEM。
generic 为无profile时的默认路径集（向后兼容既有 field_mapping 行为）。

entities（issue #44）：类型化实体提取路径——位置型(ip/pair来自fields)外的
弱实体类型(host/user/file_hash/dst_domain)仅产生候选交模型裁决，
默认不自动合并。数据源可用 entity_mapping 覆盖路径（日志中心负责归一，
引擎侧只做小写统一 + entity_short_name 可选开关）。
"""
from __future__ import annotations

# ECS内置profile：内部Alert字段 → 源消息点号路径
# severity 双策略：优先 rule.severity 文本，回退 event.severity 数值阈值
ECS_PROFILE: dict = {
    "fields": {
        "alert_id": "event.id",          # 缺省时引擎自动生成并告警
        "source": "event.dataset",
        "rule_id": "rule.id",
        "rule_name": "rule.name",
        "severity_text": "rule.severity",
        "severity_int": "event.severity",
        "timestamp": "@timestamp",
        "src_ip": "source.ip",
        "dst_ip": "destination.ip",
        "src_port": "source.port",
        "dst_port": "destination.port",
        "protocol": "network.transport",
        "raw_log": "__json__",           # 整条消息JSON序列化
    },
    "entities": {                        # 弱实体类型→源路径（issue #44）
        "host": "host.name",
        "user": "user.name",
        "file_hash": "file.hash.sha256",
        "dst_domain": "destination.domain",
    },
    # 数值严重度阈值（Elastic语义：数值越大越严重）
    "severity_int_thresholds": [
        (80, "critical"), (60, "high"), (40, "medium"), (20, "low"), (0, "info"),
    ],
    "severity_levels": ("critical", "high", "medium", "low", "info"),
}

# generic默认路径：与历史kafka/rest_api适配器的默认行为一致
# 实体不预置：generic源字段各异，按需 entity_mapping 配置提取（issue #44）
GENERIC_PROFILE: dict = {
    "fields": {
        "alert_id": "alert_id",
        "source": "source",
        "rule_id": "rule_id",
        "rule_name": "rule_name",
        "severity_text": "severity",
        "timestamp": "timestamp",
        "src_ip": "src_ip",
        "dst_ip": "dst_ip",
        "src_port": "src_port",
        "dst_port": "dst_port",
        "protocol": "protocol",
        "raw_log": "raw_log",
    },
    "entities": {},
    "severity_levels": ("critical", "high", "medium", "low", "info"),
}

BUILTIN_PROFILES: dict[str, dict] = {"ecs": ECS_PROFILE, "generic": GENERIC_PROFILE}
