from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class IoCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    URL = "url"
    EMAIL = "email"


class IoC(BaseModel):
    """IoC（Indicator of Compromise）- 失陷指标"""
    ioc_id: str
    type: IoCType
    value: str
    confidence: float = 0.5  # 0.0 - 1.0
    source: Optional[str] = None
    tags: list[str] = Field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
