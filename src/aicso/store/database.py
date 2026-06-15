"""SQLite数据库连接管理"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Any

import aiosqlite
import structlog

logger = structlog.get_logger()


class WriteBuffer:
    """批量写入缓冲区，攒批后统一 commit

    每 flush_interval 秒或攒满 batch_size 条（先到者）flush 一次。
    """

    def __init__(
        self,
        db: aiosqlite.Connection,
        batch_size: int = 50,
        flush_interval: float = 0.1,
    ):
        self._db = db
        self._batch_size = batch_size
        self._flush_interval = flush_interval
        self._buffer: list[tuple[str, tuple]] = []
        self._lock = asyncio.Lock()
        self._flush_event = asyncio.Event()
        self._task: asyncio.Task | None = None
        self._running = False

    def start(self) -> None:
        if self._task is None:
            self._running = True
            self._task = asyncio.create_task(self._flush_loop())

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._flush_event.set()
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except asyncio.TimeoutError:
                self._task.cancel()
            self._task = None
        await self.flush()

    async def add(self, sql: str, params: tuple) -> None:
        async with self._lock:
            self._buffer.append((sql, params))
            if len(self._buffer) >= self._batch_size:
                self._flush_event.set()

    async def flush(self) -> int:
        async with self._lock:
            if not self._buffer:
                return 0
            batch = self._buffer
            self._buffer = []

        try:
            for sql, params in batch:
                await self._db.execute(sql, params)
            await self._db.commit()
            logger.debug("db.batch_flush", count=len(batch))
            return len(batch)
        except Exception:
            logger.error("db.batch_flush_failed", count=len(batch), exc_info=True)
            raise

    async def _flush_loop(self) -> None:
        while self._running:
            self._flush_event.clear()
            try:
                await asyncio.wait_for(
                    self._flush_event.wait(), timeout=self._flush_interval
                )
            except asyncio.TimeoutError:
                pass
            try:
                await self.flush()
            except Exception:
                pass


class Database:
    """SQLite异步数据库管理器"""

    def __init__(self, db_path: str = "aicso.db"):
        self.db_path = db_path
        self._db: aiosqlite.Connection | None = None
        self._write_buffer: WriteBuffer | None = None

    async def connect(self) -> None:
        self._db = await aiosqlite.connect(self.db_path)
        self._db.row_factory = aiosqlite.Row
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA foreign_keys=ON")

    def enable_write_buffer(
        self, batch_size: int = 50, flush_interval: float = 0.1
    ) -> None:
        """启用批量写入缓冲"""
        if self._db is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        self._write_buffer = WriteBuffer(self._db, batch_size, flush_interval)
        self._write_buffer.start()
        logger.info("db.write_buffer_enabled", batch_size=batch_size, flush_interval=flush_interval)

    async def flush_and_close(self) -> None:
        """flush 缓冲区并关闭数据库"""
        if self._write_buffer:
            await self._write_buffer.stop()
            self._write_buffer = None
        if self._db:
            await self._db.close()
            self._db = None

    async def close(self) -> None:
        if self._db:
            await self._db.close()
            self._db = None

    async def init_tables(self) -> None:
        """初始化数据库表"""
        await self._db.executescript("""
            CREATE TABLE IF NOT EXISTS cases (
                case_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'medium',
                status TEXT NOT NULL DEFAULT 'new',
                priority INTEGER DEFAULT 3,
                assignee_id TEXT,
                ai_summary TEXT,
                ai_recommendation TEXT,
                resolution TEXT,
                tags TEXT DEFAULT '[]',
                metadata TEXT DEFAULT '{}',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                closed_at TIMESTAMP,
                sla_deadline TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                rule_id TEXT,
                rule_name TEXT,
                severity TEXT,
                timestamp TIMESTAMP NOT NULL,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                raw_log TEXT,
                enriched_data TEXT DEFAULT '{}',
                case_id TEXT REFERENCES cases(case_id),
                is_false_positive BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS assets (
                asset_id TEXT PRIMARY KEY,
                hostname TEXT,
                ip_address TEXT,
                mac_address TEXT,
                os TEXT,
                owner TEXT,
                department TEXT,
                criticality TEXT DEFAULT 'medium',
                tags TEXT DEFAULT '[]',
                metadata TEXT DEFAULT '{}',
                first_seen TIMESTAMP,
                last_seen TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS iocs (
                ioc_id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                confidence REAL DEFAULT 0.5,
                source TEXT,
                tags TEXT DEFAULT '[]',
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                UNIQUE(type, value)
            );

            CREATE TABLE IF NOT EXISTS case_events (
                event_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL REFERENCES cases(case_id),
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                event_type TEXT NOT NULL,
                actor TEXT,
                detail TEXT DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS playbook_runs (
                run_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL REFERENCES cases(case_id),
                playbook_id TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                steps_status TEXT DEFAULT '{}',
                approval_status TEXT,
                approved_by TEXT,
                started_at TIMESTAMP,
                completed_at TIMESTAMP,
                result TEXT DEFAULT '{}'
            );

            CREATE INDEX IF NOT EXISTS idx_alerts_case_id ON alerts(case_id);
            CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip);
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_case_events_case_id ON case_events(case_id);
            CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
            CREATE INDEX IF NOT EXISTS idx_cases_severity ON cases(severity);
        """)
        await self._db.commit()

    @property
    def db(self) -> aiosqlite.Connection:
        if self._db is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        return self._db

    async def execute(self, sql: str, params: tuple = ()) -> aiosqlite.Cursor:
        return await self.db.execute(sql, params)

    async def buffered_execute(self, sql: str, params: tuple = ()) -> None:
        """通过缓冲区写入（批量 commit）"""
        if self._write_buffer:
            await self._write_buffer.add(sql, params)
        else:
            await self.db.execute(sql, params)
            await self.db.commit()

    async def fetch_one(self, sql: str, params: tuple = ()) -> dict | None:
        cursor = await self.db.execute(sql, params)
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def fetch_all(self, sql: str, params: tuple = ()) -> list[dict]:
        cursor = await self.db.execute(sql, params)
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def commit(self) -> None:
        await self.db.commit()
