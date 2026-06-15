"""聚合引擎测试 - 两阶段聚合"""
import pytest
from datetime import datetime, timedelta

from aicso.aggregator.engine import (
    AlertAggregator, CaseAggregationRule, _build_key,
    IMMEDIATE_DIMENSION, IMMEDIATE_WINDOW_MINUTES,
)
from aicso.models.alert import Alert


class TestBuildKey:
    def test_src_ip_dst_ip(self):
        alert = Alert(
            alert_id="A-001", source="test",
            src_ip="1.2.3.4", dst_ip="10.0.0.1",
        )
        assert _build_key(alert, "src_ip+dst_ip") == "1.2.3.4->10.0.0.1"

    def test_src_ip_dst_ip_missing(self):
        alert = Alert(alert_id="A-001", source="test", src_ip="1.2.3.4")
        assert _build_key(alert, "src_ip+dst_ip") is None

    def test_src_ip(self):
        alert = Alert(alert_id="A-001", source="test", src_ip="1.2.3.4")
        assert _build_key(alert, "src_ip") == "1.2.3.4"

    def test_src_ip_rule_id(self):
        alert = Alert(
            alert_id="A-001", source="test",
            src_ip="1.2.3.4", rule_id="rule-001",
        )
        assert _build_key(alert, "src_ip+rule_id") == "1.2.3.4:rule-001"

    def test_unknown_dimension(self):
        alert = Alert(alert_id="A-001", source="test")
        assert _build_key(alert, "unknown") is None


class TestImmediateAggregation:
    @pytest.mark.asyncio
    async def test_no_match_first_alert(self):
        agg = AlertAggregator()
        alert = Alert(
            alert_id="A-001", source="test",
            src_ip="1.2.3.4", dst_ip="10.0.0.1",
        )
        result = await agg.try_aggregate(alert)
        assert result is None

    @pytest.mark.asyncio
    async def test_immediate_match(self):
        agg = AlertAggregator()
        alert1 = Alert(
            alert_id="A-001", source="test",
            src_ip="1.2.3.4", dst_ip="10.0.0.1",
        )
        agg.register_immediate(alert1, "CSO-001")

        alert2 = Alert(
            alert_id="A-002", source="test",
            src_ip="1.2.3.4", dst_ip="10.0.0.1",
        )
        result = await agg.try_aggregate(alert2)
        assert result is not None
        assert result.case_id == "CSO-001"
        assert result.source == "immediate"
        assert result.dimension == "src_ip+dst_ip"

    @pytest.mark.asyncio
    async def test_no_match_different_pair(self):
        agg = AlertAggregator()
        alert1 = Alert(
            alert_id="A-001", source="test",
            src_ip="1.2.3.4", dst_ip="10.0.0.1",
        )
        agg.register_immediate(alert1, "CSO-001")

        alert2 = Alert(
            alert_id="A-002", source="test",
            src_ip="1.2.3.4", dst_ip="10.0.0.2",
        )
        result = await agg.try_aggregate(alert2)
        assert result is None

    @pytest.mark.asyncio
    async def test_immediate_no_match_missing_dst(self):
        agg = AlertAggregator()
        alert1 = Alert(
            alert_id="A-001", source="test",
            src_ip="1.2.3.4", dst_ip="10.0.0.1",
        )
        agg.register_immediate(alert1, "CSO-001")

        alert2 = Alert(
            alert_id="A-002", source="test",
            src_ip="1.2.3.4",
        )
        result = await agg.try_aggregate(alert2)
        assert result is None


class TestAIAggregation:
    @pytest.mark.asyncio
    async def test_ai_rule_match(self):
        agg = AlertAggregator()
        rule = CaseAggregationRule(
            case_id="CSO-001",
            dimensions=["src_ip+rule_id"],
            window_minutes=30,
            label="SSH暴力破解",
        )
        agg.set_ai_rule("CSO-001", rule)

        # 模拟AI规则缓存
        alert = Alert(
            alert_id="A-001", source="test",
            src_ip="1.2.3.4", rule_id="rule-001",
        )
        key = _build_key(alert, "src_ip+rule_id")
        agg._ai_cache[f"CSO-001:src_ip+rule_id:{key}"] = datetime.utcnow()

        alert2 = Alert(
            alert_id="A-002", source="test",
            src_ip="1.2.3.4", rule_id="rule-001",
        )
        result = await agg.try_aggregate(alert2)
        assert result is not None
        assert result.case_id == "CSO-001"
        assert result.source == "ai_rule"

    @pytest.mark.asyncio
    async def test_ai_rule_no_match_different_rule(self):
        agg = AlertAggregator()
        rule = CaseAggregationRule(
            case_id="CSO-001",
            dimensions=["src_ip+rule_id"],
            window_minutes=30,
            label="SSH暴力破解",
        )
        agg.set_ai_rule("CSO-001", rule)

        alert = Alert(
            alert_id="A-001", source="test",
            src_ip="1.2.3.4", rule_id="rule-001",
        )
        key = _build_key(alert, "src_ip+rule_id")
        agg._ai_cache[f"CSO-001:src_ip+rule_id:{key}"] = datetime.utcnow()

        # 不同rule_id不应命中
        alert2 = Alert(
            alert_id="A-002", source="test",
            src_ip="1.2.3.4", rule_id="rule-002",
        )
        result = await agg.try_aggregate(alert2)
        assert result is None

    @pytest.mark.asyncio
    async def test_ai_rule_takes_priority(self):
        agg = AlertAggregator()

        # 注册即时规则
        alert1 = Alert(
            alert_id="A-001", source="test",
            src_ip="1.2.3.4", dst_ip="10.0.0.1",
        )
        agg.register_immediate(alert1, "CSO-001")

        # 注册AI规则（更精确）
        rule = CaseAggregationRule(
            case_id="CSO-002",
            dimensions=["src_ip+rule_id"],
            window_minutes=30,
            label="C2通信",
        )
        agg.set_ai_rule("CSO-002", rule)

        alert_c2 = Alert(
            alert_id="A-002", source="test",
            src_ip="1.2.3.4", dst_ip="10.0.0.1", rule_id="rule-c2",
        )
        key = _build_key(alert_c2, "src_ip+rule_id")
        agg._ai_cache[f"CSO-002:src_ip+rule_id:{key}"] = datetime.utcnow()

        # 应该命中AI规则（CSO-002），而非即时规则（CSO-001）
        result = await agg.try_aggregate(alert_c2)
        assert result is not None
        assert result.case_id == "CSO-002"
        assert result.source == "ai_rule"


class TestRuleInfo:
    def test_get_immediate_rule_info(self):
        agg = AlertAggregator()
        info = agg.get_rule_info("CSO-001")
        assert info["source"] == "immediate"
        assert info["dimensions"] == [IMMEDIATE_DIMENSION]

    def test_get_ai_rule_info(self):
        agg = AlertAggregator()
        rule = CaseAggregationRule(
            case_id="CSO-001",
            dimensions=["src_ip+rule_id", "dst_ip"],
            window_minutes=30,
            label="测试规则",
        )
        agg.set_ai_rule("CSO-001", rule)
        info = agg.get_rule_info("CSO-001")
        assert info["source"] == "ai_rule"
        assert info["dimensions"] == ["src_ip+rule_id", "dst_ip"]
        assert info["label"] == "测试规则"


class TestCleanup:
    @pytest.mark.asyncio
    async def test_cleanup_expired(self):
        agg = AlertAggregator()
        alert = Alert(
            alert_id="A-001", source="test",
            src_ip="1.2.3.4", dst_ip="10.0.0.1",
        )
        agg.register_immediate(alert, "CSO-001")

        agg._immediate_cache["src_ip+dst_ip:1.2.3.4->10.0.0.1"] = (
            "CSO-001", datetime.utcnow() - timedelta(hours=48),
        )
        removed = agg.cleanup(max_age_hours=24)
        assert removed >= 1
