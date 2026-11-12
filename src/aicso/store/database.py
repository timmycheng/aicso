"""SQLite数据库连接管理"""
from __future__ import annotations

import asyncio

import aiosqlite
import structlog

logger = structlog.get_logger()


class WriteBuffer:
    """批量写入缓冲区，攒批后统一 commit

    每 flush_interval 秒或攒满 batch_size 条（先到者）flush 一次。
    flush 失败不丢批：回滚半执行状态后重试，整批重试超限则二分隔离
    毒语句（对齐 systemone client 422 二分惯例），单语句反复失败才
    落死信日志丢弃——路由热路径的 mark_routed/建Case/审计都走这里，
    静默丢批 = 静默丢告警（review #56 发现2）。
    """

    # 单语句最大重试次数；整批达到后二分
    MAX_BATCH_ATTEMPTS = 3

    def __init__(
        self,
        db: aiosqlite.Connection,
        batch_size: int = 50,
        flush_interval: float = 0.1,
    ):
        self._db = db
        self._batch_size = batch_size
        self._flush_interval = flush_interval
        self._buffer: list[tuple[str, tuple, int]] = []
        self._lock = asyncio.Lock()
        self._flush_event = asyncio.Event()
        self._task: asyncio.Task | None = None
        self._running = False
        self.flush_failures = 0
        self.dropped_total = 0

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
            except TimeoutError:
                self._task.cancel()
            self._task = None
        await self.flush()

    async def add(self, sql: str, params: tuple) -> None:
        async with self._lock:
            self._buffer.append((sql, params, 0))
            if len(self._buffer) >= self._batch_size:
                self._flush_event.set()

    async def flush(self) -> int:
        async with self._lock:
            if not self._buffer:
                return 0
            batch = self._buffer
            self._buffer = []
        return await self._execute_batch(batch)

    async def _execute_batch(self, batch: list[tuple[str, tuple, int]]) -> int:
        try:
            for sql, params, _attempt in batch:
                await self._db.execute(sql, params)
            await self._db.commit()
            return len(batch)
        except Exception:
            # 回滚半执行状态：不回滚的话下次flush会重执行已执行语句，
            # 对带主键的INSERT产生IntegrityError形成毒批
            # 注意：连接级rollback也会丢弃同时打开事务里的直写语句
            # （如AlertStore.create）——该窗口极小，且告警可由数据源重投兜底
            try:
                await self._db.rollback()
            except Exception:
                pass
            self.flush_failures += 1
            retried = [(sql, p, a + 1) for sql, p, a in batch]
            if len(retried) > 1 and all(a >= self.MAX_BATCH_ATTEMPTS for _, _, a in retried):
                # 整批反复失败：递归二分就地执行——不能只把两半塞回队列，
                # 下一次flush会把相邻的两半又合成一批整体执行，隔离永不生效
                mid = len(retried) // 2
                logger.error("db.batch_flush_split", count=len(retried))
                left = await self._execute_batch(retried[:mid])
                right = await self._execute_batch(retried[mid:])
                return left + right
            if len(retried) == 1 and retried[0][2] >= self.MAX_BATCH_ATTEMPTS:
                # 单语句隔离后仍失败：毒语句落死信日志丢弃，不阻塞后续写入
                self.dropped_total += 1
                logger.error(
                    "db.batch_dead_letter", sql=retried[0][0][:200], attempts=retried[0][2]
                )
                return 0
            await self._requeue(retried)
            logger.error("db.batch_flush_retry", count=len(retried), exc_info=True)
            return 0

    async def _requeue(self, items: list[tuple[str, tuple, int]]) -> None:
        async with self._lock:
            self._buffer[:0] = items

    async def _flush_loop(self) -> None:
        while self._running:
            self._flush_event.clear()
            try:
                await asyncio.wait_for(
                    self._flush_event.wait(), timeout=self._flush_interval
                )
            except TimeoutError:
                pass
            try:
                await self.flush()
            except Exception:
                pass


class Database:
    """SQLite异步数据库管理器"""

    def __init__(self, db_path: str = "aicso.db", profile: str = "sqlite",
                 url: str | None = None):
        # 存储profile缝（设计§12）：当前仅sqlite实现；
        # postgres/ClickHouse profile 接入时在此工厂分派（issue #10）
        if profile != "sqlite":
            raise NotImplementedError(
                f"存储profile '{profile}' 尚未实现：当前仅支持 sqlite。"
                "postgres/ClickHouse 接入见 docs/REFACTOR_DESIGN.md §12"
            )
        self.profile = profile
        # url 优先于 db_path（此前 config.database.url 是死配置：
        # config 写了 url 但装配只传 profile，路径硬编码 aicso.db，
        # review #56发现44）。兼容 sqlite:/// 与 sqlite+aiosqlite:/// 前缀
        if url:
            for prefix in ("sqlite+aiosqlite:///", "sqlite:///"):
                if url.startswith(prefix):
                    db_path = url[len(prefix):]
                    break
        self.db_path = db_path
        self._db: aiosqlite.Connection | None = None
        self._write_buffer: WriteBuffer | None = None

    async def connect(self) -> None:
        # url指向子目录（如./data/aicso.db）时自动创建，避免开箱连接失败
        import os

        parent = os.path.dirname(self.db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
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

    async def flush(self) -> int:
        """手动flush写缓冲（读取前需要看到最新写入时用）"""
        if self._write_buffer:
            return await self._write_buffer.flush()
        return 0

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
                merged_into TEXT,
                split_from TEXT,
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
                entities TEXT DEFAULT '{}',
                case_id TEXT REFERENCES cases(case_id),
                is_false_positive BOOLEAN DEFAULT FALSE,
                routed_at TIMESTAMP,
                routing_source TEXT,
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

            CREATE TABLE IF NOT EXISTS ops_records (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL REFERENCES cases(case_id),
                actor TEXT NOT NULL,
                actor_type TEXT NOT NULL DEFAULT 'human',
                action TEXT NOT NULL,
                params TEXT DEFAULT '{}',
                result TEXT DEFAULT '{}',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS routing_decisions (
                id TEXT PRIMARY KEY,
                alert_id TEXT NOT NULL,
                case_id TEXT,
                decision TEXT NOT NULL,
                source TEXT NOT NULL,
                confidence REAL,
                degraded BOOLEAN DEFAULT 0,
                latency_ms REAL,
                candidates INTEGER DEFAULT 0,
                detail TEXT DEFAULT '{}',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_alerts_case_id ON alerts(case_id);
            CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip);
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_alerts_routed_at ON alerts(routed_at);
            CREATE INDEX IF NOT EXISTS idx_case_events_case_id ON case_events(case_id);
            CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
            CREATE INDEX IF NOT EXISTS idx_cases_severity ON cases(severity);
            CREATE INDEX IF NOT EXISTS idx_routing_decisions_alert
                ON routing_decisions(alert_id);
            CREATE INDEX IF NOT EXISTS idx_routing_decisions_created
                ON routing_decisions(created_at);
            CREATE INDEX IF NOT EXISTS idx_ops_records_case ON ops_records(case_id);
        """)
        await self._db.commit()
        await self._migrate_columns()

    async def _migrate_columns(self) -> None:
        """存量库列迁移：CREATE TABLE IF NOT EXISTS 不会给旧表加新列"""
        migrations = {
            "alerts": ["routed_at TIMESTAMP", "routing_source TEXT",
                       "entities TEXT DEFAULT '{}'"],
            "cases": ["merged_into TEXT", "split_from TEXT"],
        }
        for table, columns in migrations.items():
            existing = {
                row["name"]
                for row in await self.fetch_all(f"PRAGMA table_info({table})")
            }
            if not existing:
                continue  # 表不存在（新建库已在上方建全）
            for col_def in columns:
                col_name = col_def.split()[0]
                if col_name not in existing:
                    await self._db.execute(
                        f"ALTER TABLE {table} ADD COLUMN {col_def}"
                    )
        await self._db.commit()

    @property
    def db(self) -> aiosqlite.Connection:
        if self._db is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        return self._db

    @property
    def buffering(self) -> bool:
        """是否启用了写缓冲（决定直写路径是否需要自行commit）"""
        return self._write_buffer is not None

    async def execute(self, sql: str, params: tuple = ()) -> aiosqlite.Cursor:
        return await self.db.execute(sql, params)

    async def buffered_execute(self, sql: str, params: tuple = ()) -> aiosqlite.Cursor | None:
        """通过缓冲区写入（批量 commit）；返回cursor（rowcount可用），缓冲模式下为None"""
        if self._write_buffer:
            await self._write_buffer.add(sql, params)
            return None
        cursor = await self.db.execute(sql, params)
        await self.db.commit()
        return cursor

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
