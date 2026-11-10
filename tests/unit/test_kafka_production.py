"""Kafka 生产化测试（issue #37）：手动位点提交 / 幂等吸收 / lag 统计"""
from __future__ import annotations

from collections import namedtuple
from types import SimpleNamespace

from aicso.adapters.kafka import KafkaAdapter
from aicso.config import RoutingConfig, SystemOneConfig
from aicso.core.approval import ApprovalEngine
from aicso.core.context import ContextManager
from aicso.core.event_bus import EventBus
from aicso.core.orchestrator import Orchestrator
from aicso.models.alert import Alert
from aicso.router.engine import RouterEngine
from aicso.store.alert_store import AlertStore
from aicso.store.case_store import CaseStore
from aicso.store.database import Database
from aicso.store.routing_store import RoutingDecisionStore

FakeTopicPartition = namedtuple("FakeTopicPartition", ["topic", "partition"])


def make_tp(pid):
    return FakeTopicPartition(topic="siem-alerts", partition=pid)


class FakeMessage(SimpleNamespace):
    pass


class FakeConsumer:
    """可编程aiokafka替身：getmany返回预设消息，记录commit"""

    def __init__(self, batches: list[dict]):
        self.batches = list(batches)
        self.commits: list[dict] = []

    async def getmany(self, timeout_ms=None, max_records=None):
        if not self.batches:
            return {}
        batch = self.batches.pop(0)
        return {tp: msgs for tp, msgs in batch.items()}

    async def commit(self, offsets):
        self.commits.append(dict(offsets))

    def assignment(self):
        # 以最后一次commit/批次的分区为准（简化：静态返回）
        return {make_tp(0), make_tp(1)}

    def highwater(self, tp):
        return {0: 100, 1: 50}.get(tp.partition, 0)

    def position(self, tp):
        return {0: 90, 1: 50}.get(tp.partition, 0)


def make_adapter(consumer):
    adapter = KafkaAdapter()
    adapter._config = {"schema": "generic", "message_format": "json"}
    from aicso.mapping.engine import SchemaMapper
    adapter._mapper = SchemaMapper(adapter._config, default_source="kafka")
    adapter._consumer = consumer
    adapter._connected = True
    return adapter


def kafka_alert(i):
    return {"alert_id": f"K-{i}", "severity": "high", "rule_name": "R",
            "src_ip": f"1.1.1.{i}", "dst_ip": "10.0.0.1",
            "timestamp": "2026-11-10T00:00:00"}


class TestManualCommit:
    async def test_offset_tracked_and_committed(self):
        tp0 = make_tp(0)
        consumer = FakeConsumer([{tp0: [
            FakeMessage(offset=10, value='{"alert_id":"K-1"}'),
            FakeMessage(offset=11, value='{"alert_id":"K-2"}'),
        ]}])
        adapter = make_adapter(consumer)
        raws = await adapter.fetch_alerts(None)
        assert len(raws) == 2
        assert adapter._pending_offsets == {tp0: 12}  # 最高offset+1

        await adapter.commit()
        assert consumer.commits and list(consumer.commits[0].keys()) == [tp0]
        assert consumer.commits[0][tp0].offset == 12
        # 提交后清空待提交集
        assert adapter._pending_offsets == {}

    async def test_commit_noop_when_no_pending(self):
        consumer = FakeConsumer([])
        adapter = make_adapter(consumer)
        await adapter.commit()
        assert consumer.commits == []

    async def test_multi_partition_batch(self):
        tp0, tp1 = make_tp(0), make_tp(1)
        consumer = FakeConsumer([{tp0: [FakeMessage(offset=5, value='{"alert_id":"K-1"}')],
                                  tp1: [FakeMessage(offset=20, value='{"alert_id":"K-2"}')]}])
        adapter = make_adapter(consumer)
        await adapter.fetch_alerts(None)
        await adapter.commit()
        committed = consumer.commits[0]
        assert committed[tp0].offset == 6
        assert committed[tp1].offset == 21


class TestLagStats:
    async def test_lag_computed(self):
        consumer = FakeConsumer([])
        adapter = make_adapter(consumer)
        stats = adapter.stats()
        assert stats["total_lag"] == (100 - 90) + (50 - 50)
        assert stats["partitions"]["siem-alerts-0"] == 10
        assert stats["partitions"]["siem-alerts-1"] == 0

    async def test_stats_disconnected(self):
        adapter = KafkaAdapter()
        assert adapter.stats() == {"total_lag": None, "partitions": {}}


class TestIdempotentRedelivery:
    async def test_duplicate_alert_skips_routing(self):
        """at-least-once重放：同alert_id第二次入库被忽略且不重复路由"""
        db = Database(":memory:")
        await db.connect()
        await db.init_tables()
        case_store = CaseStore(db)
        alert_store = AlertStore(db)
        router = RouterEngine(
            case_store, alert_store, RoutingDecisionStore(db),
            SystemOneConfig(enabled=True), RoutingConfig(), client=None,
        )
        orch = Orchestrator(
            case_store, alert_store, ContextManager(case_store, alert_store),
            EventBus(), ApprovalEngine(EventBus()), router=router, llm_enabled=False,
        )
        router.on_new_case = orch.handle_new_case

        def a(alert_id):
            return Alert(alert_id=alert_id, source="kafka", rule_name="R",
                         severity="high", src_ip="1.1.1.1", dst_ip="10.0.0.1")

        # 首次投递：新建Case
        assert await alert_store.create(a("K-1")) is True
        await router.submit(a("K-1"))
        decisions = await router.flush()
        case_id = decisions[0].case_id

        # 重放：同alert_id经真实入口（handle_alert）再投递 → 幂等吸收
        assert await alert_store.create(a("K-1")) is False
        await orch.handle_alert(a("K-1"))

        events = await case_store.get_events(case_id)
        alert_added = [e for e in events if e["event_type"] == "alert_added"]
        assert len(alert_added) == 1  # 只有一次汇入事件
        assert await alert_store.count() == 1
        await db.close()
