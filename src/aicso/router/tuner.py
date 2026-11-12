"""参数自适应微调器（issue #50，Epic #47）

只调防御性参数（token_budget / timeout_scale），有界浮动+审计+可回滚：
- 422切批率高 → 收缩 token_budget（下限 8k）
- 超时错误占比高 → 放宽 timeout_scale（上限 1.0）
- 连续稳定周期 → 预算缓慢回升（不超过初始值）
- 每次调整冷却期防震荡；历史留痕，状态API可见、可一键回滚

语义类参数（confidence_threshold/entity_types/prompt）不在此列——
归处置反馈闭环，人工拍板。
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime

import structlog

from aicso.config import SystemOneConfig
from aicso.router.metrics import RouterMetrics

logger = structlog.get_logger()

BUDGET_FLOOR = 8000
SCALE_CEIL = 1.0
SCALE_FLOOR = 0.3
SPLIT_RATE_TRIGGER = 0.2
TIMEOUT_RATE_TRIGGER = 0.2
TIMEOUT_MIN_EVENTS = 3
COOLDOWN_CYCLES = 2
RECOVERY_CYCLES = 6
HISTORY_MAX = 50


@dataclass
class TunerDecision:
    param: str          # token_budget | timeout_scale
    old: float
    new: float
    reason: str
    ts: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class ParamTuner:
    """防御性参数有界自调：观测引擎metrics增量，按方向与边界调节"""

    def __init__(self, scfg: SystemOneConfig, metrics: RouterMetrics,
                 interval_s: int = 300):
        self.scfg = scfg
        self.metrics = metrics
        self.interval_s = interval_s
        self.initial_budget = scfg.token_budget
        self.initial_scale = scfg.timeout_scale
        self._last = self.sample()
        self._cooldown = 0
        self._stable = 0
        self.history: list[TunerDecision] = []

    # ---- 观测 ----

    def sample(self) -> dict:
        m = self.metrics
        return {"requests": m.systemone_requests_total,
                "splits": m.systemone_split_total,
                "timeouts": m.systemone_timeout_errors_total}

    # ---- 调节 ----

    def tick(self) -> TunerDecision | None:
        """一个调节周期：按增量观测决定是否调整（确定性，可单测）"""
        cur = self.sample()
        delta = {k: cur[k] - self._last[k] for k in cur}
        self._last = cur

        if self._cooldown > 0:
            self._cooldown -= 1
            return None

        decision = self._decide(delta)
        if decision is None:
            self._stable += 1
            return None
        self._stable = 0
        self.apply(decision)
        self._cooldown = COOLDOWN_CYCLES
        self.history.append(decision)
        del self.history[:-HISTORY_MAX]
        logger.info("tuner.adjusted", param=decision.param, old=decision.old,
                    new=decision.new, reason=decision.reason)
        return decision

    def _decide(self, delta: dict) -> TunerDecision | None:
        requests = delta["requests"]
        # 1) 422切批率高 → 收缩预算
        if (delta["splits"] >= 2 and requests >= 3
                and delta["splits"] / max(requests, 1) > SPLIT_RATE_TRIGGER):
            new = max(int(self.scfg.token_budget * 0.8), BUDGET_FLOOR)
            if new < self.scfg.token_budget:
                return TunerDecision(
                    "token_budget", self.scfg.token_budget, new,
                    f"422切批率{delta['splits']}/{requests}超阈值，收缩预算")
            return None
        # 2) 超时错误占比高 → 放宽超时系数
        if (delta["timeouts"] >= TIMEOUT_MIN_EVENTS and requests >= 3
                and delta["timeouts"] / max(requests, 1) > TIMEOUT_RATE_TRIGGER):
            new = min(self.scfg.timeout_scale + 0.2, SCALE_CEIL)
            if new > self.scfg.timeout_scale:
                return TunerDecision(
                    "timeout_scale", self.scfg.timeout_scale, new,
                    f"超时错误{delta['timeouts']}次占比高，放宽超时系数")
            return None
        # 3) 连续稳定 → 预算缓慢回升（不超过初始值）
        if (self._stable + 1 >= RECOVERY_CYCLES
                and delta["splits"] == 0 and delta["timeouts"] == 0
                and self.scfg.token_budget < self.initial_budget):
            new = min(int(self.scfg.token_budget * 1.1) + 1, self.initial_budget)
            if new > self.scfg.token_budget:
                return TunerDecision(
                    "token_budget", self.scfg.token_budget, new,
                    f"连续{self._stable + 1}周期稳定，预算回升")
        return None

    def apply(self, decision: TunerDecision) -> None:
        if decision.param == "token_budget":
            self.scfg.token_budget = int(decision.new)
        else:
            self.scfg.timeout_scale = float(decision.new)

    def rollback(self) -> TunerDecision | None:
        """一键回滚最近一次调整（审计可见，冷却期照常生效）

        回滚弹出该决策而非追加回滚记录——追加会让第二次回滚把第一次
        回滚反向撤销，在两值间震荡（review #56发现）。
        """
        if not self.history:
            return None
        last = self.history.pop()
        decision = TunerDecision(last.param, last.new, last.old, "人工回滚")
        self.apply(decision)
        self._cooldown = COOLDOWN_CYCLES
        logger.info("tuner.rolled_back", param=decision.param,
                    to=decision.new)
        return decision

    def snapshot(self) -> dict:
        return {
            "interval_s": self.interval_s,
            "current": {"token_budget": self.scfg.token_budget,
                        "timeout_scale": self.scfg.timeout_scale},
            "initial": {"token_budget": self.initial_budget,
                        "timeout_scale": self.initial_scale},
            "cooldown_cycles_left": self._cooldown,
            "stable_cycles": self._stable,
            "history": [vars(d) for d in self.history],
        }

    async def loop(self) -> None:
        while True:
            await asyncio.sleep(self.interval_s)
            try:
                self.tick()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.error("tuner.tick_failed", exc_info=True)
