"""聚合引擎测试"""
import pytest
from datetime import datetime, timedelta

from aicso.aggregator.engine import AlertAggregator, AggregationRule
from aicso.models.alert import Alert


class TestAggregationRule:
    def test_src_ip_key(self):
        rule = AggregationRule("src_ip", 5)
        alert = Alert(alert_id="A-001", source="test", src_ip="1.2.3.4")
        assert rule.get_key(alert) == "1.2.3.4"

    def test_dst_ip_key(self):
        rule = AggregationRule("dst_ip", 5)
        alert = Alert(alert_id="A-001", source="test", dst_ip="192.168.1.1")
        assert rule.get_key(alert) == "192.168.1.1"

    def test_rule_category_key(self):
        rule = AggregationRule("rule_category", 5)
        alert = Alert(alert_id="A-001", source="test", rule_id="suricata.http.001")
        assert rule.get_key(alert) == "suricata"

    def test_none_key(self):
        rule = AggregationRule("src_ip", 5)
        alert = Alert(alert_id="A-001", source="test", src_ip=None)
        assert rule.get_key(alert) is None


class TestAlertAggregator:
    @pytest.mark.asyncio
    async def test_no_match_first_alert(self):
        agg = AlertAggregator()
        alert = Alert(alert_id="A-001", source="test", src_ip="1.2.3.4")
        result = await agg.try_aggregate(alert)
        assert result is None

    @pytest.mark.asyncio
    async def test_match_same_src_ip(self):
        agg = AlertAggregator()
        alert1 = Alert(alert_id="A-001", source="test", src_ip="1.2.3.4")
        agg.register_case(alert1, "CSO-001")

        alert2 = Alert(alert_id="A-002", source="test", src_ip="1.2.3.4")
        result = await agg.try_aggregate(alert2)
        assert result == "CSO-001"

    @pytest.mark.asyncio
    async def test_no_match_different_ip(self):
        agg = AlertAggregator()
        alert1 = Alert(alert_id="A-001", source="test", src_ip="1.2.3.4")
        agg.register_case(alert1, "CSO-001")

        alert2 = Alert(alert_id="A-002", source="test", src_ip="5.6.7.8")
        result = await agg.try_aggregate(alert2)
        assert result is None

    @pytest.mark.asyncio
    async def test_cleanup(self):
        agg = AlertAggregator()
        alert = Alert(alert_id="A-001", source="test", src_ip="1.2.3.4")
        agg.register_case(alert, "CSO-001")

        # 手动设置过期时间
        agg._cache["src_ip:1.2.3.4"] = ("CSO-001", datetime.utcnow() - timedelta(hours=48))
        removed = agg.cleanup(max_age_hours=24)
        assert removed == 1
        assert "src_ip:1.2.3.4" not in agg._cache
