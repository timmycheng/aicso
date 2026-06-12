from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class PlaybookStep(BaseModel):
    """Playbook步骤"""
    name: str
    action: str
    auto: bool = False
    approval_required: bool = False
    risk_level: RiskLevel = RiskLevel.LOW
    params: dict = Field(default_factory=dict)


class Playbook(BaseModel):
    """Playbook（剧本）- 标准化响应流程模板"""
    playbook_id: str
    name: str
    description: str = ""
    version: str = "1.0.0"
    trigger_tags: list[str] = Field(default_factory=list)
    steps: list[PlaybookStep] = Field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.LOW
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class RunStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    WAITING_APPROVAL = "waiting_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    TIMEOUT = "timeout"


class PlaybookRun(BaseModel):
    """Playbook运行记录"""
    run_id: str
    case_id: str
    playbook_id: str
    status: RunStatus = RunStatus.PENDING
    steps_status: dict = Field(default_factory=dict)
    approval_status: ApprovalStatus = ApprovalStatus.PENDING
    approved_by: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: dict = Field(default_factory=dict)
