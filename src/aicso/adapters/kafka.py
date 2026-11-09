"""Kafka适配器 - 从Kafka Topic消费告警"""
from __future__ import annotations

from datetime import datetime

import structlog

from aicso.adapters.base import DataSourceAdapter
from aicso.mapping.engine import SchemaMapper, generated_alert_id
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
        self._mapper = SchemaMapper({}, default_source="kafka")

    async def connect(self, config: dict) -> bool:
        """连接Kafka"""
        self._config = config
        self._mapper = SchemaMapper(config, default_source="kafka")
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
            # getmany批量消费；单条消息经统一映射引擎展开（信封/数组）
            data = await self._consumer.getmany(timeout_ms=poll_timeout, max_records=max_batch)

            for tp, messages in data.items():
                for msg in messages:
                    raw_text = msg.value
                    if message_format == "json":
                        alerts.extend(self._mapper.expand_message(raw_text))
                    else:
                        alerts.append({"__raw__": raw_text})

        except Exception as e:
            logger.error("kafka.poll_failed", error=str(e))

        return alerts

    async def normalize(self, raw: dict) -> Alert:
        """统一映射引擎归一化（schema: auto|ecs|generic + field_mapping覆盖）"""
        alert, warnings = self._mapper.normalize(
            raw, fallback_alert_id=generated_alert_id("kafka")
        )
        for w in warnings:
            logger.warning("kafka.normalize_warning", alert_id=alert.alert_id, warning=w)
        return alert

    async def close(self):
        """关闭消费者"""
        if self._consumer:
            await self._consumer.stop()
            self._consumer = None
            self._connected = False
