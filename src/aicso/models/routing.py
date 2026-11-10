"""路由决策模型（中立模块：store与router共用，避免循环导入）"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

# decision 取值
ROUTE_TO = "route_to"      # 汇入已有Case
NEW_CASE = "new_case"      # 新建Case

# source 取值
SRC_SYSTEM_ONE = "system_one"  # System One 判定
SRC_CACHE = "cache"            # 决策缓存复用
SRC_FALLBACK = "fallback"      # 本地兜底规则


@dataclass
class RoutingDecision:
    """单条告警的路由决策（审计记录，落 routing_decisions 表）"""
    alert_id: str
    case_id: str                      # 决策目标（新建时为新case_id）
    decision: str                     # route_to | new_case
    source: str                       # system_one | cache | fallback
    confidence: float | None = None   # System One 置信度（fallback/cache为None）
    degraded: bool = False            # 是否降级状态下产生
    latency_ms: float = 0.0           # ingest→路由完成耗时
    candidates: int = 0               # 候选Case数（审计）
    detail: dict = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
