"""告警保留策略服务（P3，设计§12容量治理）

大量告警日志下的SQLite容量治理：按保留天数周期清理过期告警。
清理范围三档：
- orphan_only: 仅未关联Case的孤立告警
- closed_cases: 孤立告警 + 已关闭/已解决Case下的告警（默认）
- all: 所有过期告警（含活跃Case下的，慎用）
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta

import structlog

from aicso.config import RetentionConfig
from aicso.store.database import Database

logger = structlog.get_logger()

_SCOPE_SQL = {
    "orphan_only": "AND case_id IS NULL",
    "closed_cases": (
        "AND (case_id IS NULL OR case_id IN "
        "(SELECT case_id FROM cases WHERE status IN ('resolved', 'closed')))"
    ),
    "all": "",
}


class RetentionService:
    def __init__(self, db: Database, config: RetentionConfig):
        self.db = db
        self.config = config
        self._task: asyncio.Task | None = None
        self._running = False

    async def cleanup(self) -> int:
        """执行一次清理，返回删除的告警数"""
        if self.config.alert_days <= 0:
            return 0
        scope_sql = _SCOPE_SQL.get(self.config.scope)
        if scope_sql is None:
            logger.warning("retention.invalid_scope", scope=self.config.scope)
            return 0
        cutoff = (datetime.utcnow() - timedelta(days=self.config.alert_days)).isoformat()
        cursor = await self.db.execute(
            f"DELETE FROM alerts WHERE created_at < ? {scope_sql}",
            (cutoff,),
        )
        await self.db.commit()
        deleted = cursor.rowcount if cursor else 0
        if deleted:
            logger.info("retention.cleaned", deleted=deleted,
                        scope=self.config.scope, alert_days=self.config.alert_days)
        return deleted

    def start(self) -> None:
        """启动周期清理任务"""
        if self._running or self.config.alert_days <= 0:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())
        logger.info("retention.started", alert_days=self.config.alert_days,
                    interval_minutes=self.config.cleanup_interval_minutes)

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def _loop(self) -> None:
        interval_s = self.config.cleanup_interval_minutes * 60
        while self._running:
            try:
                await asyncio.sleep(interval_s)
                await self.cleanup()
            except asyncio.CancelledError:
                break
            except Exception:
                logger.error("retention.cleanup_failed", exc_info=True)
                await asyncio.sleep(interval_s)
