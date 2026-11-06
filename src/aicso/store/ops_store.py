"""OpsRecord 存储层"""
from __future__ import annotations

import json

from aicso.models.ops import OpsRecord
from aicso.store.database import Database


class OpsRecordStore:
    """ops_records 表读写"""

    def __init__(self, db: Database):
        self.db = db

    async def create(self, record: OpsRecord) -> None:
        await self.db.buffered_execute(
            """INSERT INTO ops_records (id, case_id, actor, actor_type,
               action, params, result, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                record.id, record.case_id, record.actor, record.actor_type,
                record.action,
                json.dumps(record.params, ensure_ascii=False),
                json.dumps(record.result, ensure_ascii=False),
                record.created_at.isoformat(),
            ),
        )

    async def list_by_case(self, case_id: str, limit: int = 100) -> list[dict]:
        return await self.db.fetch_all(
            """SELECT * FROM ops_records WHERE case_id = ?
               ORDER BY created_at DESC LIMIT ?""",
            (case_id, limit),
        )
