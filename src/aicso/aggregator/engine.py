"""告警聚合引擎 - 两阶段聚合"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

import structlog

from aicso.models.alert import Alert

logger = structlog.get_logger()


@dataclass
class CaseAggregationRule:
    """单个Case的AI生成聚合规则"""
    case_id: str
    dimensions: list[str]          # 匹配维度列表，如 ["src_ip+rule_id", "dst_ip+severity"]
    window_minutes: int = 30       # 聚合窗口
    label: str = ""                # 人类可读描述
    generated_by: str = "triage"   # 生成者
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class AggregationMatch:
    """聚合匹配结果"""
    case_id: str
    dimension: str
    key: str
    rule_label: str
    source: str  # "ai_rule" | "immediate"


# 即时兜底规则：无需AI，告警进入时立即执行
IMMEDIATE_DIMENSION = "src_ip+dst_ip"
IMMEDIATE_WINDOW_MINUTES = 10
IMMEDIATE_LABEL = "同源IP+同目标IP(即时,10min)"


def _build_key(alert: Alert, dimension: str) -> Optional[str]:
    """根据维度描述构建聚合Key"""
    if dimension == "src_ip":
        return alert.src_ip
    elif dimension == "dst_ip":
        return alert.dst_ip
    elif dimension == "src_ip+dst_ip":
        if alert.src_ip and alert.dst_ip:
            return f"{alert.src_ip}->{alert.dst_ip}"
        return None
    elif dimension == "src_ip+rule_id":
        if alert.src_ip and alert.rule_id:
            return f"{alert.src_ip}:{alert.rule_id}"
        return None
    elif dimension == "dst_ip+rule_id":
        if alert.dst_ip and alert.rule_id:
            return f"{alert.dst_ip}:{alert.rule_id}"
        return None
    elif dimension == "src_ip+severity":
        if alert.src_ip and alert.severity:
            return f"{alert.src_ip}:{alert.severity}"
        return None
    elif dimension == "rule_id":
        return alert.rule_id
    elif dimension == "dst_ip+rule_name":
        if alert.dst_ip and alert.rule_name:
            return f"{alert.dst_ip}:{alert.rule_name}"
        return None
    return None


class AlertAggregator:
    """两阶段告警聚合引擎

    阶段1（即时）：告警进入时，用 src_ip+dst_ip 兜底规则快速匹配
    阶段2（AI）：TriageAgent分析后，为每个Case生成专属聚合规则
    """

    def __init__(self, auto_cleanup: bool = False):
        # per-case AI规则: case_id -> CaseAggregationRule
        self._ai_rules: dict[str, CaseAggregationRule] = {}
        # 即时规则缓存: "src_ip+dst_ip:key" -> (case_id, last_seen)
        self._immediate_cache: dict[str, tuple[str, datetime]] = {}
        # AI规则缓存: "case_id:dimension:key" -> last_seen
        self._ai_cache: dict[str, datetime] = {}
        # 自动清理
        self._cleanup_task: asyncio.Task | None = None
        if auto_cleanup:
            self._cleanup_task = asyncio.create_task(self._auto_cleanup_loop())

    async def stop(self) -> None:
        """停止自动清理"""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            self._cleanup_task = None

    async def _auto_cleanup_loop(self) -> None:
        """每30分钟清理一次过期缓存"""
        while True:
            try:
                await asyncio.sleep(30 * 60)
                removed = self.cleanup(max_age_hours=2)
                if removed:
                    logger.info("aggregator.auto_cleanup", removed=removed)
            except asyncio.CancelledError:
                break
            except Exception:
                logger.error("aggregator.auto_cleanup_failed", exc_info=True)

    async def try_aggregate(self, alert: Alert) -> Optional[AggregationMatch]:
        """两阶段聚合：AI规则优先，即时规则兜底"""
        now = datetime.utcnow()

        # 阶段2：检查所有Case的AI生成规则
        for case_id, rule in self._ai_rules.items():
            if now - rule.created_at > timedelta(minutes=rule.window_minutes):
                continue
            for dimension in rule.dimensions:
                key = _build_key(alert, dimension)
                if not key:
                    continue
                cache_key = f"{case_id}:{dimension}:{key}"
                last_seen = self._ai_cache.get(cache_key)
                if last_seen and now - last_seen <= timedelta(minutes=rule.window_minutes):
                    self._ai_cache[cache_key] = now
                    logger.info(
                        "aggregator.ai_match",
                        case_id=case_id, dimension=dimension, key=key,
                    )
                    return AggregationMatch(
                        case_id=case_id,
                        dimension=dimension,
                        key=key,
                        rule_label=rule.label,
                        source="ai_rule",
                    )

        # 阶段1：即时兜底规则 src_ip+dst_ip
        key = _build_key(alert, IMMEDIATE_DIMENSION)
        if key:
            cache_key = f"{IMMEDIATE_DIMENSION}:{key}"
            cached = self._immediate_cache.get(cache_key)
            if cached:
                case_id, last_seen = cached
                if now - last_seen <= timedelta(minutes=IMMEDIATE_WINDOW_MINUTES):
                    self._immediate_cache[cache_key] = (case_id, now)
                    logger.info(
                        "aggregator.immediate_match",
                        case_id=case_id, key=key,
                    )
                    return AggregationMatch(
                        case_id=case_id,
                        dimension=IMMEDIATE_DIMENSION,
                        key=key,
                        rule_label=IMMEDIATE_LABEL,
                        source="immediate",
                    )

        return None

    def register_immediate(self, alert: Alert, case_id: str) -> None:
        """注册即时兜底规则（创建Case时立即调用）"""
        key = _build_key(alert, IMMEDIATE_DIMENSION)
        if key:
            cache_key = f"{IMMEDIATE_DIMENSION}:{key}"
            self._immediate_cache[cache_key] = (case_id, datetime.utcnow())
            logger.info(
                "aggregator.immediate_registered",
                case_id=case_id, key=key,
            )

    def set_ai_rule(self, case_id: str, rule: CaseAggregationRule) -> None:
        """为Case设置AI生成的聚合规则（TriageAgent异步调用）"""
        self._ai_rules[case_id] = rule
        logger.info(
            "aggregator.ai_rule_set",
            case_id=case_id,
            dimensions=rule.dimensions,
            label=rule.label,
        )

    def get_ai_rule(self, case_id: str) -> Optional[CaseAggregationRule]:
        """获取Case的AI规则"""
        return self._ai_rules.get(case_id)

    def get_rule_info(self, case_id: str) -> dict:
        """获取Case的聚合规则信息（用于UI展示）"""
        ai_rule = self._ai_rules.get(case_id)
        if ai_rule:
            return {
                "source": "ai_rule",
                "dimensions": ai_rule.dimensions,
                "label": ai_rule.label,
                "window_minutes": ai_rule.window_minutes,
                "generated_by": ai_rule.generated_by,
            }
        return {
            "source": "immediate",
            "dimensions": [IMMEDIATE_DIMENSION],
            "label": IMMEDIATE_LABEL,
            "window_minutes": IMMEDIATE_WINDOW_MINUTES,
            "generated_by": "system",
        }

    def cleanup(self, max_age_hours: int = 24) -> int:
        """清理过期缓存"""
        now = datetime.utcnow()
        cutoff = now - timedelta(hours=max_age_hours)
        removed = 0

        expired_imm = [
            k for k, (_, ts) in self._immediate_cache.items() if ts < cutoff
        ]
        for k in expired_imm:
            del self._immediate_cache[k]
            removed += 1

        expired_ai = [
            k for k, ts in self._ai_cache.items() if ts < cutoff
        ]
        for k in expired_ai:
            del self._ai_cache[k]
            removed += 1

        expired_rules = [
            cid for cid, r in self._ai_rules.items()
            if now - r.created_at > timedelta(hours=max_age_hours)
        ]
        for cid in expired_rules:
            del self._ai_rules[cid]
            removed += 1

        return removed
