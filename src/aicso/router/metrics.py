"""路由引擎指标

设计依据: docs/REFACTOR_DESIGN.md §11
进程内计数器+延迟采样，/api/metrics 暴露；Prometheus格式留P3。
"""
from __future__ import annotations

from collections import deque
from datetime import datetime


class RouterMetrics:
    """路由引擎运行指标（进程内单例，随AppState持有）"""

    def __init__(self, latency_samples: int = 2000):
        self.submitted_total = 0        # 进入路由队列的告警数
        self.routed_total = 0           # 完成路由决策的告警数
        self.route_to_total = 0         # 汇入已有Case
        self.cases_created_total = 0    # 新建Case
        self.cache_hit_total = 0        # 决策缓存命中
        self.fallback_total = 0         # 本地兜底决策
        self.degraded_total = 0         # 降级状态下完成的决策
        self.systemone_requests_total = 0
        self.systemone_tokens_total = 0
        self.systemone_errors_total = 0
        self.systemone_split_total = 0      # 422上下文溢出二分切批次数(#42)
        self.systemone_oversized_total = 0  # 单条上下文超限走兜底数(#42)
        self.queue_high_water_events = 0
        self.low_confidence_total = 0   # 低于阈值转复核
        self._latencies: deque[float] = deque(maxlen=latency_samples)
        self.oldest_pending_since: datetime | None = None  # 最老未路由告警入队时间

    def record_latency(self, latency_ms: float) -> None:
        self._latencies.append(latency_ms)

    def latency_percentiles(self) -> dict:
        if not self._latencies:
            return {"p50_ms": None, "p95_ms": None, "p99_ms": None}
        ordered = sorted(self._latencies)

        def pct(p: float) -> float:
            idx = min(int(len(ordered) * p), len(ordered) - 1)
            return round(ordered[idx], 1)

        return {"p50_ms": pct(0.50), "p95_ms": pct(0.95), "p99_ms": pct(0.99)}

    def backlog_age_ms(self) -> float | None:
        """积压年龄：最老未路由告警从入队至今的毫秒数"""
        if self.oldest_pending_since is None:
            return None
        delta = datetime.utcnow() - self.oldest_pending_since
        return round(delta.total_seconds() * 1000, 1)

    def to_dict(self, queue_depth: int = 0, queue_max: int = 0) -> dict:
        data = {
            "submitted_total": self.submitted_total,
            "routed_total": self.routed_total,
            "route_to_total": self.route_to_total,
            "cases_created_total": self.cases_created_total,
            "cache_hit_total": self.cache_hit_total,
            "fallback_total": self.fallback_total,
            "degraded_total": self.degraded_total,
            "low_confidence_total": self.low_confidence_total,
            "systemone_requests_total": self.systemone_requests_total,
            "systemone_tokens_total": self.systemone_tokens_total,
            "systemone_errors_total": self.systemone_errors_total,
            "systemone_split_total": self.systemone_split_total,
            "systemone_oversized_total": self.systemone_oversized_total,
            "queue_high_water_events": self.queue_high_water_events,
            "queue_depth": queue_depth,
            "queue_max": queue_max,
            "backlog_age_ms": self.backlog_age_ms(),
            "latency": self.latency_percentiles(),
        }
        # 并入率：汇入已有Case占已路由的比例
        if self.routed_total:
            data["route_to_ratio"] = round(self.route_to_total / self.routed_total, 3)
        return data
