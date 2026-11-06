"""微批聚合器 — 热路径批量化

设计依据: docs/REFACTOR_DESIGN.md §5.2
窗口(batch_window_ms)或批上限(batch_max_alerts)先到者触发一批，
以对齐 System One 的"一次请求并行多问题"能力与组织级速率配额。
"""
from __future__ import annotations

import asyncio
import time
from typing import Any


class RoutingBatcher:
    """有界微批队列：阻塞collect直到窗口闭合或批满"""

    def __init__(self, window_ms: int = 100, max_batch: int = 50, max_size: int = 10000):
        self.window_ms = window_ms
        self.max_batch = max_batch
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=max_size)

    def put_nowait(self, item: Any) -> None:
        self._queue.put_nowait(item)

    def try_put(self, item: Any) -> bool:
        try:
            self._queue.put_nowait(item)
            return True
        except asyncio.QueueFull:
            return False

    def qsize(self) -> int:
        return self._queue.qsize()

    def empty(self) -> bool:
        return self._queue.empty()

    def get_nowait(self) -> Any:
        return self._queue.get_nowait()

    async def collect(self) -> list[Any]:
        """阻塞取首条，窗口内继续聚合；窗口闭合或批满即返回"""
        first = await self._queue.get()
        batch = [first]
        end = time.monotonic() + self.window_ms / 1000
        while len(batch) < self.max_batch:
            remaining = end - time.monotonic()
            if remaining <= 0:
                break
            try:
                batch.append(await asyncio.wait_for(self._queue.get(), remaining))
            except TimeoutError:
                break
        return batch
