from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class AssetCriticality(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Asset(BaseModel):
    """Asset（资产）- 企业IT资产"""
    asset_id: str
    hostname: str | None = None
    ip_address: str | None = None
    mac_address: str | None = None
    os: str | None = None
    owner: str | None = None
    department: str | None = None
    criticality: AssetCriticality = AssetCriticality.MEDIUM
    tags: list[str] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
