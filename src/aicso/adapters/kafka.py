"""Kafka适配器 - 从Kafka Topic消费告警"""
from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Optional

import structlog

from aicso.adapters.base import DataSourceAdapter
from aicso.adapters.rest_api import _get_nested
from aicso.models.alert import Alert

logger = structlog.get_logger()


class KafkaAdapter(DataSourceAdapter):
    """Kafka数据源适配器 - 从Kafka Topic消费安全告警

    适用于：
    - SIEM平台通过Kafka输出告警（如态势感知平台的Kafka推送）
    - 日志平台（如ELK/Kafka）的告警Topic
    - 自建告警总线

    config示例：
        type: kafka
        config:
          bootstrap_servers: kafka-broker1:9092,kafka-broker2:9092
          topic: siem-alerts
          group_id: aicso-consumer
          # 认证（可选）
          sasl_mechanism: PLAIN    # PLAIN | SCRAM-SHA-256 | SCRAM-SHA-512
          sasl_username: ${KAFKA_USER}
          sasl_password: ${KAFKA_PASS}
          # 消费配置
          auto_offset_reset: latest    # earliest | latest
          max_batch_size: 100
          poll_timeout_ms: 5000
          # 消息格式
          message_format: json      # json | raw
          # 字段映射（同REST API适配器）
          field_mapping:
            alert_id: id
            rule_name: rule.name
            severity: level
            src_ip: src_addr
            dst_ip: dst_addr
            timestamp: occur_time
          severity_mapping:
            1: critical
            2: high
            3: medium
            4: low
            5: info
    """

    name = "kafka"
    description = "Kafka Topic告警消费适配器"

    def __init__(self):
        self._consumer = None
        self._config: dict = {}
        self._connected = False

    async def connect(self, config: dict) -> bool:
        """连接Kafka"""
        self._config = config
        try:
            from aiokafka import AIOKafkaConsumer

            servers = config.get("bootstrap_servers", "localhost:9092")
            topic = config.get("topic", "siem-alerts")
            group_id = config.get("group_id", "aicso-consumer")

            kwargs = {
                "bootstrap_servers": servers,
                "group_id": group_id,
                "auto_offset_reset": config.get("auto_offset_reset", "latest"),
                "enable_auto_commit": True,
                "value_deserializer": lambda m: m.decode("utf-8", errors="ignore"),
            }

            # SASL认证
            sasl_mechanism = config.get("sasl_mechanism")
            if sasl_mechanism:
                kwargs["security_protocol"] = "SASL_PLAINTEXT"
                kwargs["sasl_mechanism"] = sasl_mechanism
                kwargs["sasl_plain_username"] = config.get("sasl_username", "")
                kwargs["sasl_plain_password"] = config.get("sasl_password", "")

            # SSL
            if config.get("ssl", False):
                kwargs["security_protocol"] = "SASL_SSL" if sasl_mechanism else "SSL"
                if config.get("ssl_cafile"):
                    kwargs["ssl_cafile"] = config["ssl_cafile"]

            self._consumer = AIOKafkaConsumer(topic, **kwargs)
            await self._consumer.start()
            self._connected = True

            logger.info("kafka.connected", servers=servers, topic=topic, group_id=group_id)
            return True

        except ImportError:
            logger.error("kafka.missing_dependency", msg="pip install aiokafka")
            return False
        except Exception as e:
            logger.error("kafka.connect_failed", error=str(e))
            return False

    async def fetch_alerts(self, since: datetime) -> list[dict]:
        """从Kafka拉取一批告警"""
        if not self._connected or not self._consumer:
            return []

        max_batch = self._config.get("max_batch_size", 100)
        poll_timeout = self._config.get("poll_timeout_ms", 5000)
        message_format = self._config.get("message_format", "json")

        alerts = []
        try:
            # getmany批量消费
            data = await self._consumer.getmany(timeout_ms=poll_timeout, max_records=max_batch)

            for tp, messages in data.items():
                for msg in messages:
                    raw_text = msg.value
                    try:
                        if message_format == "json":
                            parsed = json.loads(raw_text)
                            alerts.append(parsed)
                        else:
                            alerts.append({"raw": raw_text})
                    except json.JSONDecodeError:
                        alerts.append({"raw": raw_text})

        except Exception as e:
            logger.error("kafka.poll_failed", error=str(e))

        return alerts

    async def normalize(self, raw: dict) -> Alert:
        """将Kafka消息映射为标准Alert"""
        # 如果是raw格式，直接包装
        if "raw" in raw and len(raw) == 1:
            return Alert(
                alert_id=f"kafka-{uuid.uuid4().hex[:8]}",
                source="kafka",
                raw_log=raw["raw"],
            )

        # 使用field_mapping映射（与REST API适配器逻辑一致）
        mapping = self._config.get("field_mapping", {})
        severity_map = self._config.get("severity_mapping", {})

        alert_id = _get_nested(raw, mapping.get("alert_id", "alert_id"), f"kafka-{uuid.uuid4().hex[:8]}")
        source = _get_nested(raw, mapping.get("source", "source"), "kafka")
        rule_id = str(_get_nested(raw, mapping.get("rule_id", "rule_id"), ""))
        rule_name = _get_nested(raw, mapping.get("rule_name", "rule_name"), "")
        raw_severity = _get_nested(raw, mapping.get("severity", "severity"), "medium")
        src_ip = _get_nested(raw, mapping.get("src_ip", "src_ip"))
        dst_ip = _get_nested(raw, mapping.get("dst_ip", "dst_ip"))
        src_port = _get_nested(raw, mapping.get("src_port", "src_port"))
        dst_port = _get_nested(raw, mapping.get("dst_port", "dst_port"))
        protocol = _get_nested(raw, mapping.get("protocol", "protocol"))
        raw_log = _get_nested(raw, mapping.get("raw_log", "raw_log"))
        timestamp_raw = _get_nested(raw, mapping.get("timestamp", "timestamp"))

        # 严重级别映射
        severity = "medium"
        if isinstance(raw_severity, int) or (isinstance(raw_severity, str) and str(raw_severity).isdigit()):
            severity = severity_map.get(int(raw_severity), severity_map.get(str(raw_severity), "medium"))
        elif isinstance(raw_severity, str):
            severity = raw_severity.lower()
            if severity not in ("critical", "high", "medium", "low", "info"):
                severity = "medium"

        # 时间解析
        timestamp = datetime.utcnow()
        if timestamp_raw:
            try:
                if isinstance(timestamp_raw, (int, float)):
                    timestamp = datetime.fromtimestamp(timestamp_raw / 1000 if timestamp_raw > 1e12 else timestamp_raw)
                else:
                    timestamp = datetime.fromisoformat(str(timestamp_raw).replace("Z", "+00:00"))
            except (ValueError, OSError):
                pass

        # 端口类型转换
        try:
            src_port = int(src_port) if src_port else None
        except (ValueError, TypeError):
            src_port = None
        try:
            dst_port = int(dst_port) if dst_port else None
        except (ValueError, TypeError):
            dst_port = None

        return Alert(
            alert_id=str(alert_id),
            source=str(source),
            rule_id=str(rule_id) if rule_id else None,
            rule_name=str(rule_name) if rule_name else None,
            severity=severity,
            timestamp=timestamp,
            src_ip=str(src_ip) if src_ip else None,
            dst_ip=str(dst_ip) if dst_ip else None,
            src_port=src_port,
            dst_port=dst_port,
            protocol=str(protocol) if protocol else None,
            raw_log=str(raw_log) if raw_log else None,
            enriched_data=raw,
        )

    async def close(self):
        """关闭消费者"""
        if self._consumer:
            await self._consumer.stop()
            self._consumer = None
            self._connected = False
