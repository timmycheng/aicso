"""参数自适应微调器测试（issue #50，Epic #47）

有界自调语义：422率→收缩预算（下限）/超时占比→放宽timeout_scale（上限）/
稳定回升（不超过初始值）/冷却期防震荡/一键回滚。
"""
from __future__ import annotations

from aicso.config import SystemOneConfig
from aicso.router.metrics import RouterMetrics
from aicso.router.tuner import (
    BUDGET_FLOOR,
    SCALE_CEIL,
    ParamTuner,
)


def make_tuner(**scfg_overrides) -> tuple[ParamTuner, SystemOneConfig, RouterMetrics]:
    scfg = SystemOneConfig(token_budget=scfg_overrides.pop("token_budget", 32000),
                           **scfg_overrides)
    metrics = RouterMetrics()
    return ParamTuner(scfg, metrics, interval_s=300), scfg, metrics


def feed(tuner: ParamTuner, metrics: RouterMetrics,
         requests=0, splits=0, timeouts=0) -> None:
    metrics.systemone_requests_total += requests
    metrics.systemone_split_total += splits
    metrics.systemone_timeout_errors_total += timeouts


class TestShrinkOn422:
    async def test_high_split_rate_shrinks_budget(self):
        tuner, scfg, metrics = make_tuner()
        feed(tuner, metrics, requests=10, splits=5)   # 422率50%
        decision = tuner.tick()
        assert decision is not None and decision.param == "token_budget"
        assert decision.new == int(32000 * 0.8)
        assert scfg.token_budget == int(32000 * 0.8)
        assert "422切批率" in decision.reason

    async def test_budget_respects_floor(self):
        tuner, scfg, metrics = make_tuner(token_budget=9000)
        feed(tuner, metrics, requests=10, splits=5)
        tuner.tick()
        assert scfg.token_budget == BUDGET_FLOOR, "下限8k不得穿透"

    async def test_low_split_rate_no_shrink(self):
        tuner, scfg, metrics = make_tuner()
        feed(tuner, metrics, requests=10, splits=1)   # 10%低于阈值
        assert tuner.tick() is None
        assert scfg.token_budget == 32000

    async def test_tiny_sample_no_reaction(self):
        """样本过小不动作（requests<3防噪声）"""
        tuner, scfg, metrics = make_tuner()
        feed(tuner, metrics, requests=1, splits=1)
        assert tuner.tick() is None


class TestTimeoutScale:
    async def test_timeout_errors_raise_scale(self):
        tuner, scfg, metrics = make_tuner()
        feed(tuner, metrics, requests=10, timeouts=5)
        decision = tuner.tick()
        assert decision is not None and decision.param == "timeout_scale"
        assert scfg.timeout_scale == 0.5   # 0.3+0.2
        assert "超时" in decision.reason

    async def test_scale_respects_ceil(self):
        tuner, scfg, metrics = make_tuner(timeout_scale=0.95)
        feed(tuner, metrics, requests=10, timeouts=5)
        tuner.tick()
        assert scfg.timeout_scale == SCALE_CEIL


class TestRecoveryAndCooldown:
    async def test_recovery_raises_budget_toward_initial(self):
        tuner, scfg, metrics = make_tuner()
        feed(tuner, metrics, requests=10, splits=5)
        tuner.tick()                       # 收缩到25600
        shrunk = scfg.token_budget
        decision = None
        for _ in range(12):                # 2冷却 + 稳定满RECOVERY_CYCLES触发回升
            feed(tuner, metrics)
            decision = tuner.tick()
            if decision is not None:
                break
        assert decision is not None and decision.param == "token_budget", (
            "持续稳定后预算应回升")
        assert shrunk < scfg.token_budget <= tuner.initial_budget, "回升不超过初始值"

    async def test_cooldown_suppresses_immediate_reaction(self):
        tuner, scfg, metrics = make_tuner()
        feed(tuner, metrics, requests=10, splits=5)
        assert tuner.tick() is not None
        feed(tuner, metrics, requests=10, splits=5)   # 冷却期内再有422
        assert tuner.tick() is None, "冷却期不连续调节"

    async def test_stable_counter_resets_on_adjustment(self):
        tuner, scfg, metrics = make_tuner()
        feed(tuner, metrics, requests=10, timeouts=5)
        tuner.tick()                       # 放宽scale → cooldown=2
        feed(tuner, metrics, requests=10, splits=5)
        assert tuner.tick() is None        # 冷却
        assert tuner.tick() is None        # 冷却结束
        feed(tuner, metrics, requests=10, splits=5)
        decision = tuner.tick()
        assert decision is not None and decision.param == "token_budget"
        assert tuner._stable == 0, "调整后稳定计数应归零"


class TestRollback:
    async def test_rollback_restores_last_adjustment(self):
        tuner, scfg, metrics = make_tuner()
        feed(tuner, metrics, requests=10, splits=5)
        tuner.tick()
        assert scfg.token_budget == 25600
        decision = tuner.rollback()
        assert decision is not None and decision.param == "token_budget"
        assert scfg.token_budget == 32000, "回滚应恢复调整前值"

    async def test_rollback_empty_history(self):
        tuner, scfg, metrics = make_tuner()
        assert tuner.rollback() is None


class TestEngineWiring:
    async def test_auto_tune_creates_tuner_on_start(self):
        from aicso.config import RoutingConfig
        from aicso.router.engine import RouterEngine
        from aicso.store.alert_store import AlertStore
        from aicso.store.case_store import CaseStore
        from aicso.store.database import Database
        from aicso.store.routing_store import RoutingDecisionStore

        class _Ok:
            async def system_one(self, state, questions, timeout_ms=None):
                from aicso.systemone.client import SystemOneResponse
                return SystemOneResponse(model="t", answers={}, input_tokens=0)

            async def aclose(self):
                pass

        db = Database(":memory:")
        await db.connect()
        await db.init_tables()
        engine = RouterEngine(
            case_store=CaseStore(db), alert_store=AlertStore(db),
            routing_store=RoutingDecisionStore(db),
            system_one_config=SystemOneConfig(auto_tune=True),
            routing_config=RoutingConfig(), client=_Ok(),
        )
        await engine.start()
        assert engine._tuner is not None, "auto_tune开启应有微调器任务"
        await engine.stop()
        assert engine._tuner_task is None
        await db.close()

    async def test_auto_tune_off_no_tuner(self):
        from aicso.config import RoutingConfig
        from aicso.router.engine import RouterEngine
        from aicso.store.alert_store import AlertStore
        from aicso.store.case_store import CaseStore
        from aicso.store.database import Database
        from aicso.store.routing_store import RoutingDecisionStore

        db = Database(":memory:")
        await db.connect()
        await db.init_tables()
        engine = RouterEngine(
            case_store=CaseStore(db), alert_store=AlertStore(db),
            routing_store=RoutingDecisionStore(db),
            system_one_config=SystemOneConfig(auto_tune=False),
            routing_config=RoutingConfig(), client=None,
        )
        await engine.start()
        assert engine._tuner is None
        await engine.stop()
        await db.close()
