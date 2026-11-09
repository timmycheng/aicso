"""统一Schema映射引擎测试（issue #35）

fixture直接取自mock_producer的ECS 8.10输出——内置ECS profile与
mock格式的一致性自带验证。
"""
from __future__ import annotations

from aicso.adapters.mock_producer import generate_mock_alerts
from aicso.mapping.engine import SchemaMapper, get_nested
from aicso.mapping.profiles import ECS_PROFILE


def ecs_sample() -> dict:
    return generate_mock_alerts(count=1, categories=["brute_force"])[0]


class TestGetNested:
    def test_dotted_path(self):
        data = {"a": {"b": {"c": 1}}}
        assert get_nested(data, "a.b.c") == 1
        assert get_nested(data, "a.b.x", "dft") == "dft"

    def test_partial_path(self):
        assert get_nested({"a": 1}, "a.b", None) is None


class TestAutoDetect:
    def test_ecs_signature_detected(self):
        m = SchemaMapper({})
        assert m._detect(ecs_sample()) == "ecs"

    def test_generic_for_flat(self):
        m = SchemaMapper({})
        assert m._detect({"alert_id": "x", "severity": "high"}) == "generic"

    def test_auto_resolves_and_locks(self):
        m = SchemaMapper({})
        first = m.resolve_profile(ecs_sample())
        assert first["fields"]["src_ip"] == "source.ip"
        # 探测结果锁定，后续不抖动
        assert m.resolve_profile({})["fields"]["src_ip"] == "source.ip"


class TestECSNormalize:
    async def test_zero_config_full_fields(self):
        """ECS零配置：auto探测→全字段正确（mock样例即fixture）"""
        m = SchemaMapper({})
        sample = ecs_sample()
        alert, warnings = m.normalize(sample, fallback_alert_id="gen-1")

        assert alert.rule_id == sample["rule"]["id"]
        assert alert.rule_name == sample["rule"]["name"]
        assert alert.severity == sample["rule"]["severity"]  # 文本优先
        assert alert.src_ip == sample["source"]["ip"]
        assert alert.dst_ip == sample["destination"]["ip"]
        assert alert.src_port == sample["source"]["port"]
        assert alert.dst_port == sample["destination"]["port"]
        assert alert.protocol == sample["network"]["transport"]
        assert alert.timestamp.year == 2026
        # ECS零配置应无警告
        assert warnings == []

    def test_explicit_ecs_schema(self):
        m = SchemaMapper({"schema": "ecs"})
        profile = m.resolve_profile({})
        assert profile["fields"]["src_ip"] == "source.ip"
        assert profile["severity_int_thresholds"] == ECS_PROFILE["severity_int_thresholds"]

    async def test_severity_int_threshold(self):
        """rule.severity缺失时回退event.severity数值阈值"""
        sample = ecs_sample()
        del sample["rule"]["severity"]
        sample["event"]["severity"] = 90
        m = SchemaMapper({"schema": "ecs"})
        alert, warnings = m.normalize(sample, fallback_alert_id="g")
        assert alert.severity == "critical"
        assert warnings == []

    async def test_severity_unmappable_warns(self):
        sample = ecs_sample()
        del sample["rule"]["severity"]
        sample["event"]["severity"] = "weird"
        m = SchemaMapper({"schema": "ecs"})
        alert, warnings = m.normalize(sample, fallback_alert_id="g")
        assert alert.severity == "medium"
        assert any("无法识别严重度" in w for w in warnings)


class TestGenericAndCustom:
    async def test_generic_legacy_fields(self):
        """generic默认路径=历史kafka/rest_api行为（向后兼容）"""
        m = SchemaMapper({"schema": "generic"})
        raw = {"alert_id": "X-1", "severity": "high", "rule_name": "R",
               "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "timestamp": "2026-11-09T00:00:00"}
        alert, warnings = m.normalize(raw, fallback_alert_id="g")
        assert alert.alert_id == "X-1"
        assert alert.severity == "high"
        assert alert.src_ip == "1.1.1.1"
        assert warnings == []

    async def test_custom_field_mapping_overrides(self):
        """自定义field_mapping覆盖默认路径（存量配置兼容）"""
        m = SchemaMapper({
            "schema": "generic",
            "field_mapping": {"rule_name": "check.name", "src_ip": "attacker.addr"},
        })
        raw = {"check": {"name": "自定义规则"}, "attacker": {"addr": "3.3.3.3"}}
        alert, _ = m.normalize(raw, fallback_alert_id="g")
        assert alert.rule_name == "自定义规则"
        assert alert.src_ip == "3.3.3.3"

    async def test_custom_severity_mapping(self):
        """severity_mapping 经JSON配置读入时键是字符串——int/str双查都要生效"""
        m = SchemaMapper({
            "schema": "generic",
            "field_mapping": {"severity_int": "level"},
            "severity_mapping": {"1": "critical", "2": "high", "3": "medium"},
        })
        alert, _ = m.normalize({"level": 1}, fallback_alert_id="g")
        assert alert.severity == "critical"

    async def test_custom_severity_mapping_int_keys(self):
        m = SchemaMapper({
            "schema": "generic",
            "field_mapping": {"severity_int": "level"},
            "severity_mapping": {1: "critical"},
        })
        alert, _ = m.normalize({"level": 1}, fallback_alert_id="g")
        assert alert.severity == "critical"

    async def test_missing_fields_warn_and_fallback(self):
        m = SchemaMapper({"schema": "generic"})
        alert, warnings = m.normalize({}, fallback_alert_id="auto-99")
        assert alert.alert_id == "auto-99"  # 自动生成ID是标准行为，不告警
        assert any("时间戳" in w for w in warnings)
        assert any("无源/目标IP实体" in w for w in warnings)


class TestTimestamp:
    async def test_epoch_millis(self):
        m = SchemaMapper({"schema": "generic"})
        alert, _ = m.normalize({"timestamp": 1730000000000}, fallback_alert_id="g")
        assert alert.timestamp.year == 2024

    async def test_custom_strptime(self):
        m = SchemaMapper({"schema": "generic",
                          "timestamp_format": "%Y/%m/%d %H:%M:%S"})
        alert, _ = m.normalize({"timestamp": "2026/11/09 08:00:00"}, fallback_alert_id="g")
        assert (alert.timestamp.year, alert.timestamp.month) == (2026, 11)

    async def test_invalid_returns_none_then_now(self):
        m = SchemaMapper({"schema": "generic"})
        alert, warnings = m.normalize({"timestamp": "not-a-time"}, fallback_alert_id="g")
        assert warnings and alert.timestamp is not None


class TestEnvelope:
    async def test_top_level_array(self):
        m = SchemaMapper({"schema": "generic"})
        events = m.expand_message('[{"alert_id":"a"},{"alert_id":"b"}]')
        assert len(events) == 2

    async def test_events_path_envelope(self):
        m = SchemaMapper({"schema": "generic", "events_path": "data.items"})
        events = m.expand_message(
            '{"total":2,"data":{"items":[{"alert_id":"a"},{"alert_id":"b"}]}}'
        )
        assert len(events) == 2
        assert events[0]["alert_id"] == "a"

    async def test_non_json_raw(self):
        m = SchemaMapper({"schema": "generic"})
        events = m.expand_message("<134>Nov 09 sshd: failed password")
        assert events[0]["__raw__"].startswith("<134>")

    async def test_raw_normalize_keeps_log(self):
        m = SchemaMapper({"schema": "generic"})
        alert, warnings = m.normalize({"__raw__": "raw syslog line"}, fallback_alert_id="g")
        assert alert.raw_log == "raw syslog line"
        assert alert.src_ip is None
        assert any("非结构化" in w for w in warnings)


class TestAdapterDelegation:
    async def test_kafka_adapter_ecs_zero_config(self):
        """Kafka适配器经统一引擎零配置消费ECS消息"""
        from aicso.adapters.registry import datasource_registry
        adapter = datasource_registry.create("kafka")
        adapter._mapper = SchemaMapper({}, default_source="kafka")
        sample = ecs_sample()
        alert, warnings = adapter._mapper.normalize(sample, fallback_alert_id="k-1")
        assert alert.rule_name == sample["rule"]["name"]
        assert alert.src_ip == sample["source"]["ip"]
        assert warnings == []
