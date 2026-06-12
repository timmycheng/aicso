"""事件总线 - Agent间通信"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Awaitable, Callable

import structlog

logger = structlog.get_logger()


class EventType(str, Enum):
    # Case事件
    CASE_CREATED = "case.created"
    CASE_UPDATED = "case.updated"
    CASE_STATUS_CHANGED = "case.status_changed"
    CASE_CLOSED = "case.closed"

    # 告警事件
    ALERT_RECEIVED = "alert.received"
    ALERT_AGGREGATED = "alert.aggregated"
    ALERT_FALSE_POSITIVE = "alert.false_positive"

    # Agent事件
    AGENT_STARTED = "agent.started"
    AGENT_COMPLETED = "agent.completed"
    AGENT_FAILED = "agent.failed"

    # 审批事件
    APPROVAL_REQUESTED = "approval.requested"
    APPROVAL_GRANTED = "approval.granted"
    APPROVAL_REJECTED = "approval.rejected"
    APPROVAL_TIMEOUT = "approval.timeout"

    # Playbook事件
    PLAYBOOK_STARTED = "playbook.started"
    PLAYBOOK_STEP_COMPLETED = "playbook.step_completed"
    PLAYBOOK_COMPLETED = "playbook.completed"
    PLAYBOOK_FAILED = "playbook.failed"


@dataclass
class Event:
    """事件"""
    event_type: EventType
    source: str
    data: dict = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    correlation_id: str = ""


EventHandler = Callable[[Event], Awaitable[None]]


class EventBus:
    """内存事件总线（MVP阶段），后续可替换为Redis Pub/Sub"""

    def __init__(self):
        self._handlers: dict[EventType, list[EventHandler]] = {}

    def subscribe(self, event_type: EventType, handler: EventHandler) -> None:
        """订阅事件"""
        self._handlers.setdefault(event_type, []).append(handler)
        logger.debug("event_bus.subscribed", event_type=event_type.value, handler=handler.__name__)

    def unsubscribe(self, event_type: EventType, handler: EventHandler) -> None:
        """取消订阅"""
        handlers = self._handlers.get(event_type, [])
        if handler in handlers:
            handlers.remove(handler)

    async def publish(self, event: Event) -> None:
        """发布事件"""
        handlers = self._handlers.get(event.event_type, [])
        if not handlers:
            return

        logger.debug(
            "event_bus.publishing",
            event_type=event.event_type.value,
            source=event.source,
            handler_count=len(handlers),
        )

        tasks = []
        for handler in handlers:
            tasks.append(self._safe_call_handler(handler, event))
        await asyncio.gather(*tasks)

    async def _safe_call_handler(self, handler: EventHandler, event: Event) -> None:
        """安全调用handler，捕获异常不影响其他handler"""
        try:
            await handler(event)
        except Exception as e:
            logger.error(
                "event_bus.handler_error",
                event_type=event.event_type.value,
                handler=handler.__name__,
                error=str(e),
            )
