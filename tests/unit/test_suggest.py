"""映射自动建议测试（issue #49，Epic #47）

本地规则推断（确定性）/ 真实样本字段覆盖率 / Kafka采样临时消费组语义
（不移动主消费组位点、不commit）。
"""
from __future__ import annotations

import json

from aicso.mapping.suggest import sample_group_id, sample_kafka, suggest_mapping

# Security-Datasets Sysmon 记录的真实字段形态（脱敏子集）
SD_RECORDS = [
    {
        "@timestamp": "2020-08-07T14:32:25.358Z", "@version": "1",
        "EventTime": "2020-08-07 10:32:22", "Channel": "Microsoft-Windows-Sysmon/Operational",
        "EventID": 3, "Severity": "INFO", "SeverityValue": 2,
        "Hostname": "WORKSTATION5.theshire.local", "SourceName": "Microsoft-Windows-Sysmon",
        "RecordNumber": "1234", "SourceIp": "172.18.39.5", "DestinationIp": "10.10.10.5",
        "SourcePort": "65372", "DestinationPort": "80", "AccountName": "hacker",
        "Message": "Network connection detected",
    },
    {
        "@timestamp": "2020-08-07T14:33:01.100Z", "@version": "1",
        "EventTime": "2020-08-07 10:32:40", "Channel": "Microsoft-Windows-Sysmon/Operational",
        "EventID": 10, "Severity": "INFO", "SeverityValue": 2,
        "Hostname": "MORDORDC.theshire.local", "SourceName": "Microsoft-Windows-Sysmon",
        "RecordNumber": "1235", "SourceIp": "172.18.39.6", "DestinationIp": "10.10.10.5",
        "SourcePort": "65380", "DestinationPort": "445", "AccountName": "hacker",
        "Message": "Process accessed",
    },
]

SD_PRESET_FIELDS = ("src_ip", "dst_ip", "src_port", "dst_port", "rule_id",
                    "rule_name", "severity_text", "severity_int", "timestamp", "source")


def test_suggest_security_datasets_full_coverage():
    """真实Sysmon样本：preset关键字段推断覆盖率≥90%（#49验收）"""
    result = suggest_mapping(SD_RECORDS)
    hit = sum(1 for k in SD_PRESET_FIELDS if k in result["fields"])
    assert hit / len(SD_PRESET_FIELDS) >= 0.9, (
        f"覆盖率不足: {hit}/{len(SD_PRESET_FIELDS)} fields={result['fields']}")
    assert result["fields"]["src_ip"] == "SourceIp"
    assert result["fields"]["timestamp"] in ("@timestamp", "EventTime")
    assert result["fields"]["severity_int"] == "SeverityValue"
    assert result["fields"]["severity_text"] == "Severity"
    assert result["entity_mapping"]["host"] == "Hostname"


def test_suggest_ecs_records_detect_ecs_paths():
    """ECS形态样本：应推断出ECS路径（与内置profile一致）"""
    samples = [{
        "@timestamp": "2026-11-09T00:00:00Z", "event": {"dataset": "elastic.security",
                                                        "severity": 70, "id": "ev-1"},
        "rule": {"id": "r-1", "name": "SSH暴破", "severity": "high"},
        "source": {"ip": "1.2.3.4"}, "destination": {"ip": "10.0.0.1"},
        "host": {"name": "web-01.corp.local"},
    }]
    result = suggest_mapping(samples)
    assert result["fields"]["src_ip"] == "source.ip"
    assert result["fields"]["dst_ip"] == "destination.ip"
    assert result["fields"]["timestamp"] == "@timestamp"
    assert result["fields"]["severity_text"] == "rule.severity"
    assert result["entity_mapping"]["host"] == "host.name"


def test_suggest_empty_samples():
    result = suggest_mapping([])
    assert result["fields"] == {}
    assert "无样本" in result["notes"][0]


def test_sample_group_id_isolated():
    """采样临时消费组：独立命名，绝不等于主消费组"""
    group = sample_group_id("siem-alerts")
    assert group.startswith("aicso-sample-siem-alerts-")
    assert group != "aicso-consumer"
    assert sample_group_id("siem-alerts") != group, "每次采样独立组"


class _FakeKafkaConsumer:
    def __init__(self):
        self.started = False
        self.stopped = False
        self.commits = 0
        self._calls = 0

    async def start(self):
        self.started = True

    async def stop(self):
        self.stopped = True

    async def commit(self, *a, **kw):
        self.commits += 1

    async def getmany(self, timeout_ms=0, max_records=0):
        self._calls += 1
        if self._calls > 1:
            return {}   # 流耗尽：采样循环应退出
        msg = json.dumps(SD_RECORDS[0]).encode("utf-8")
        return {("t", 0): [type("M", (), {"value": msg})()]}


async def test_sample_kafka_temp_group_no_commit():
    """Kafka采样：临时组/不commit/消费即停（主组位点零扰动，#49验收）"""
    created = {}

    async def factory(config, group):
        created["group"] = group
        consumer = _FakeKafkaConsumer()
        created["consumer"] = consumer
        return consumer

    samples = await sample_kafka({"topic": "siem-alerts"}, n=5,
                                 consumer_factory=factory)
    assert created["group"].startswith("aicso-sample-"), "必须用独立临时消费组"
    assert len(samples) == 1
    assert samples[0]["SourceIp"] == "172.18.39.5", "原始消息应经expand_message展开"
    assert created["consumer"].started and created["consumer"].stopped
    assert created["consumer"].commits == 0, "采样绝不commit位点"
