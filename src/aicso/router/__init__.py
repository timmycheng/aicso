"""路由分流引擎 — Case-centric 流式路由"""
from aicso.router.batcher import RoutingBatcher  # noqa: F401  (P1预留，微批聚合)
from aicso.router.decision import (
    NEW_CASE,
    ROUTE_TO,
    SRC_CACHE,
    SRC_FALLBACK,
    SRC_SYSTEM_ONE,
    RoutingDecision,
)
from aicso.router.engine import RouterEngine
from aicso.router.fallback import LocalFallback
from aicso.router.index import CaseRoutingIndex, CaseSlot, entity_keys_of
from aicso.router.metrics import RouterMetrics

__all__ = [
    "NEW_CASE",
    "ROUTE_TO",
    "RoutingBatcher",
    "RoutingDecision",
    "RouterEngine",
    "RouterMetrics",
    "SRC_CACHE",
    "SRC_FALLBACK",
    "SRC_SYSTEM_ONE",
    "CaseRoutingIndex",
    "CaseSlot",
    "LocalFallback",
    "entity_keys_of",
]
