from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class AlertSource(BaseModel):
    """告警来源设备"""
    source_id: str
    name: str
    type: str  # siem, edr, ndr, waf, firewall, etc.


class Alert(BaseModel):
    """Alert（告警）- 安全设备的原始检测信号"""
    alert_id: str
    source: str  # 来源设备名称
    rule_id: str | None = None
    rule_name: str | None = None
    severity: str = "medium"  # critical, high, medium, low, info
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    # 网络五元组
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None

    # 类型化实体（issue #44）：{"host": "web-01", "user": "jdoe", ...}
    # 由SchemaMapper按profile/entity_mapping提取；ip/pair外的实体为弱类型，
    # 仅产生候选交模型裁决（弱类型自动合并默认关闭，见RoutingConfig）
    entities: dict = Field(default_factory=dict)

    # 原始数据
    raw_log: str | None = None
    enriched_data: dict = Field(default_factory=dict)

    # 聚合信息
    case_id: str | None = None
    is_false_positive: bool = False

    # 元数据
    created_at: datetime = Field(default_factory=datetime.utcnow)
