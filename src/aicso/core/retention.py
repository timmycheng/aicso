"""告警保留策略服务（P3，设计§12容量治理）

大量告警日志下的SQLite容量治理：按保留天数周期清理过期告警。
清理范围三档（均只删已路由告警——未路由=从未被处理，删除即永久丢失，
违背§2零丢弃与§5.6重启回灌前提，review #56发现3）：
- orphan_only: 仅已路由但未关联Case的过期告警
- closed_cases: 上述 + 已关闭/已解决Case下的过期告警（默认）
- all: 所有已路由的过期告警（含活跃Case下的，慎用）
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta

import structlog

from aicso.config import RetentionConfig
from aicso.store.database import Database

logger = structlog.get_logger()

# 三档范围均追加 routed_at IS NOT NULL：路由积压（routed_at IS NULL）
# 恰好落在 case_id IS NULL 的孤儿集合里，不排除会被当垃圾清掉
_SCOPE_SQL = {
    "orphan_only": "AND case_id IS NULL",
    "closed_cases": (
        "AND (case_id IS NULL OR case_id IN "
        "(SELECT case_id FROM cases WHERE status IN ('resolved', 'closed')))"
    ),
    "all": "",
}

# 单批删除行数：SQLite未编译ENABLE_UPDATE_DELETE_LIMIT时DELETE不支持LIMIT，
# 用 rowid IN (SELECT ... LIMIT ?) 分页，避免千万行级首跑形成长写事务
_DELETE_BATCH = 5000


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
        total = 0
        while True:
            cursor = await self.db.execute(
                f"""DELETE FROM alerts WHERE rowid IN (
                        SELECT rowid FROM alerts
                        WHERE created_at < ? {scope_sql}
                          AND routed_at IS NOT NULL
                        LIMIT {_DELETE_BATCH})""",
                (cutoff,),
            )
            deleted = cursor.rowcount if cursor else 0
            await self.db.commit()
            total += deleted
            if deleted < _DELETE_BATCH:
                break
            await asyncio.sleep(0)  # 批间让出事件循环，写事务不阻塞热路径
        if total:
            logger.info("retention.cleaned", deleted=total,
                        scope=self.config.scope, alert_days=self.config.alert_days)
        return total

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
