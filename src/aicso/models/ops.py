"""OpsRecord 数据模型 — Case上的统一操作记录（设计§3.2 §7）"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from ulid import ULID


class ActorType(str, Enum):
    AGENT = "agent"    # AI Agent执行（调查/报告/判定）
    HUMAN = "human"    # 人工操作（处置记录/补上下文/拉人）
    SYSTEM = "system"  # 系统自动（playbook/合并拆分）


class OpsAction(str, Enum):
    """标准操作动作"""
    ADD_CONTEXT = "add_context"          # 补充日志/告警/资产上下文
    INVESTIGATE = "investigate"          # Agent调查
    GENERATE_REPORT = "generate_report"  # 生成报告
    ASSIGN = "assign"                    # 拉人/指派
    MANUAL_HANDLE = "manual_handle"      # 人工处置记录
    ESCALATE = "escalate"                # 升级
    PLAYBOOK_RUN = "playbook_run"        # playbook执行
    MERGE = "merge"                      # 合并
    SPLIT = "split"                      # 拆分
    CUSTOM = "custom"                    # 其他自定义动作


@dataclass
class OpsRecord:
    """Case上的单次操作记录"""
    case_id: str
    actor: str                      # 执行者标识（agent名/用户名/system）
    actor_type: str                 # agent | human | system
    action: str                     # OpsAction 或自定义动作名
    params: dict = field(default_factory=dict)   # 动作参数
    result: dict = field(default_factory=dict)   # 执行结果
    id: str = field(default_factory=lambda: str(ULID()))
    created_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "case_id": self.case_id,
            "actor": self.actor,
            "actor_type": self.actor_type,
            "action": self.action,
            "params": self.params,
            "result": self.result,
            "created_at": self.created_at.isoformat(),
        }
