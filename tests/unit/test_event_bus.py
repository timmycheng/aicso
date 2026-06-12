"""事件总线测试"""
import pytest
import asyncio

from aicso.core.event_bus import EventBus, Event, EventType


class TestEventBus:
    @pytest.mark.asyncio
    async def test_publish_subscribe(self):
        bus = EventBus()
        received = []

        async def handler(event: Event):
            received.append(event)

        bus.subscribe(EventType.CASE_CREATED, handler)
        await bus.publish(Event(
            event_type=EventType.CASE_CREATED,
            source="test",
            data={"case_id": "CSO-001"},
        ))
        assert len(received) == 1
        assert received[0].data["case_id"] == "CSO-001"

    @pytest.mark.asyncio
    async def test_multiple_handlers(self):
        bus = EventBus()
        count = {"a": 0, "b": 0}

        async def handler_a(event: Event):
            count["a"] += 1

        async def handler_b(event: Event):
            count["b"] += 1

        bus.subscribe(EventType.CASE_CREATED, handler_a)
        bus.subscribe(EventType.CASE_CREATED, handler_b)
        await bus.publish(Event(event_type=EventType.CASE_CREATED, source="test"))
        assert count["a"] == 1
        assert count["b"] == 1

    @pytest.mark.asyncio
    async def test_handler_error_isolation(self):
        bus = EventBus()
        received = []

        async def bad_handler(event: Event):
            raise RuntimeError("handler error")

        async def good_handler(event: Event):
            received.append(event)

        bus.subscribe(EventType.CASE_CREATED, bad_handler)
        bus.subscribe(EventType.CASE_CREATED, good_handler)
        await bus.publish(Event(event_type=EventType.CASE_CREATED, source="test"))
        assert len(received) == 1

    @pytest.mark.asyncio
    async def test_unsubscribe(self):
        bus = EventBus()
        received = []

        async def handler(event: Event):
            received.append(event)

        bus.subscribe(EventType.CASE_CREATED, handler)
        bus.unsubscribe(EventType.CASE_CREATED, handler)
        await bus.publish(Event(event_type=EventType.CASE_CREATED, source="test"))
        assert len(received) == 0
