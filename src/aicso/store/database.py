"""SQLite数据库连接管理"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import aiosqlite


class Database:
    """SQLite异步数据库管理器"""

    def __init__(self, db_path: str = "aicso.db"):
        self.db_path = db_path
        self._db: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        self._db = await aiosqlite.connect(self.db_path)
        self._db.row_factory = aiosqlite.Row
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA foreign_keys=ON")

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
