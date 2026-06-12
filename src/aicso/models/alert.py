from __future__ import annotations

from datetime import datetime
from typing import Optional

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
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    severity: str = "medium"  # critical, high, medium, low, info
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    # 网络五元组
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None

    # 原始数据
    raw_log: Optional[str] = None
    enriched_data: dict = Field(default_factory=dict)

    # 聚合信息
    case_id: Optional[str] = None
    is_false_positive: bool = False

    # 元数据
    created_at: datetime = Field(default_factory=datetime.utcnow)
