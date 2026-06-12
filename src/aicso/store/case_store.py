"""Case存储层"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Optional

from aicso.models.case import Case, CaseEvent, CaseSeverity, CaseStatus
from aicso.store.database import Database


class CaseStore:
    """Case持久化存储"""

    def __init__(self, db: Database):
        self.db = db

    async def create(self, case: Case) -> None:
        await self.db.execute(
            """INSERT INTO cases (case_id, title, severity, status, priority, assignee_id,
               ai_summary, ai_recommendation, resolution, tags, metadata,
               created_at, updated_at, closed_at, sla_deadline)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                case.case_id, case.title, case.severity.value, case.status.value,
                case.priority.value, case.assignee_id, case.ai_summary,
                case.ai_recommendation, case.resolution,
                json.dumps(case.tags), json.dumps(case.metadata),
                case.created_at.isoformat(), case.updated_at.isoformat(),
                case.closed_at.isoformat() if case.closed_at else None,
                case.sla_deadline.isoformat() if case.sla_deadline else None,
            ),
        )
        await self.db.commit()

    async def get(self, case_id: str) -> Optional[dict]:
        return await self.db.fetch_one(
            "SELECT * FROM cases WHERE case_id = ?", (case_id,)
        )

    async def update(self, case: Case) -> None:
        await self.db.execute(
            """UPDATE cases SET title=?, severity=?, status=?, priority=?,
               assignee_id=?, ai_summary=?, ai_recommendation=?, resolution=?,
               tags=?, metadata=?, updated_at=?, closed_at=?, sla_deadline=?
               WHERE case_id=?""",
            (
                case.title, case.severity.value, case.status.value,
                case.priority.value, case.assignee_id, case.ai_summary,
                case.ai_recommendation, case.resolution,
                json.dumps(case.tags), json.dumps(case.metadata),
                case.updated_at.isoformat(),
                case.closed_at.isoformat() if case.closed_at else None,
                case.sla_deadline.isoformat() if case.sla_deadline else None,
                case.case_id,
            ),
        )
        await self.db.commit()

    async def list_cases(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        assignee: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict]:
        sql = "SELECT * FROM cases WHERE 1=1"
        params: list = []
        if status:
            sql += " AND status = ?"
            params.append(status)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        if assignee:
            sql += " AND assignee_id = ?"
            params.append(assignee)
        sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        return await self.db.fetch_all(sql, tuple(params))

    async def add_event(self, case_id: str, event: CaseEvent) -> None:
        await self.db.execute(
            """INSERT INTO case_events (event_id, case_id, timestamp, event_type, actor, detail)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                event.event_id, case_id, event.timestamp.isoformat(),
                event.event_type, event.actor, json.dumps(event.detail),
            ),
        )
        await self.db.commit()

    async def get_events(self, case_id: str) -> list[dict]:
        return await self.db.fetch_all(
            "SELECT * FROM case_events WHERE case_id = ? ORDER BY timestamp ASC",
            (case_id,),
        )

    async def count(self, status: Optional[str] = None) -> int:
        sql = "SELECT COUNT(*) as cnt FROM cases"
        params: list = []
        if status:
            sql += " WHERE status = ?"
            params.append(status)
        row = await self.db.fetch_one(sql, tuple(params))
        return row["cnt"] if row else 0
