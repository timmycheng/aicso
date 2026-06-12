"""告警聚合引擎"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional

import structlog

from aicso.models.alert import Alert

logger = structlog.get_logger()


class AggregationRule:
    """聚合规则"""

    def __init__(self, dimension: str, window_minutes: int):
        self.dimension = dimension
        self.window = timedelta(minutes=window_minutes)

    def get_key(self, alert: Alert) -> Optional[str]:
        """根据维度提取聚合Key"""
        if self.dimension == "src_ip":
            return alert.src_ip
        elif self.dimension == "dst_ip":
            return alert.dst_ip
        elif self.dimension == "dst_asset":
            return alert.dst_ip  # 简化：用dst_ip代表资产
        elif self.dimension == "rule_category":
            return alert.rule_id.split(".")[0] if alert.rule_id and "." in alert.rule_id else alert.rule_id
        return None


class AlertAggregator:
    """告警聚合引擎（规则引擎）"""

    def __init__(self):
        self.rules = [
            AggregationRule("src_ip", 5),
            AggregationRule("dst_asset", 30),
            AggregationRule("rule_category", 60),
        ]
        # 内存缓存：key -> (case_id, last_seen)
        self._cache: dict[str, tuple[str, datetime]] = {}

    async def try_aggregate(self, alert: Alert) -> Optional[str]:
        """尝试将告警聚合到已有Case，返回Case ID或None"""
        now = datetime.utcnow()

        for rule in self.rules:
            key = rule.get_key(alert)
            if not key:
                continue

            cache_key = f"{rule.dimension}:{key}"
            cached = self._cache.get(cache_key)

            if cached:
                case_id, last_seen = cached
                if now - last_seen <= rule.window:
                    self._cache[cache_key] = (case_id, now)
                    logger.info(
                        "aggregator.matched",
                        dimension=rule.dimension,
                        key=key,
                        case_id=case_id,
                    )
                    return case_id

        return None

    def register_case(self, alert: Alert, case_id: str) -> None:
        """将新告警的聚合Key注册到缓存"""
        now = datetime.utcnow()
        for rule in self.rules:
            key = rule.get_key(alert)
            if key:
                cache_key = f"{rule.dimension}:{key}"
                self._cache[cache_key] = (case_id, now)

    def cleanup(self, max_age_hours: int = 24) -> int:
        """清理过期缓存"""
        now = datetime.utcnow()
        cutoff = now - timedelta(hours=max_age_hours)
        expired = [k for k, (_, ts) in self._cache.items() if ts < cutoff]
        for k in expired:
            del self._cache[k]
        return len(expired)
