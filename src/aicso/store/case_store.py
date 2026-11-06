"""Case存储层"""
from __future__ import annotations

import json

from aicso.models.case import Case, CaseEvent
from aicso.store.database import Database


class CaseStore:
    """Case持久化存储"""

    def __init__(self, db: Database):
        self.db = db

    async def create(self, case: Case) -> None:
        # 走写缓冲（分流热路径高频建Case，直写commit是吞吐瓶颈）
        # 注意：缓冲0.1s内落库；索引成员判断已兜底缓冲窗口内的路由竞态
        await self.db.buffered_execute(
            """INSERT INTO cases (case_id, title, severity, status, priority, assignee_id,
               ai_summary, ai_recommendation, resolution, tags, metadata,
               merged_into, split_from,
               created_at, updated_at, closed_at, sla_deadline)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                case.case_id, case.title, case.severity.value, case.status.value,
                case.priority.value, case.assignee_id, case.ai_summary,
                case.ai_recommendation, case.resolution,
                json.dumps(case.tags), json.dumps(case.metadata),
                case.merged_into, case.split_from,
                case.created_at.isoformat(), case.updated_at.isoformat(),
                case.closed_at.isoformat() if case.closed_at else None,
                case.sla_deadline.isoformat() if case.sla_deadline else None,
            ),
        )

    async def get(self, case_id: str) -> dict | None:
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
        status: str | None = None,
        severity: str | None = None,
        assignee: str | None = None,
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
        await self.db.buffered_execute(
            """INSERT INTO case_events (event_id, case_id, timestamp, event_type, actor, detail)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                event.event_id, case_id, event.timestamp.isoformat(),
                event.event_type, event.actor,
                json.dumps(event.detail, ensure_ascii=False),
            ),
        )

    async def get_events(self, case_id: str) -> list[dict]:
        return await self.db.fetch_all(
            "SELECT * FROM case_events WHERE case_id = ? ORDER BY timestamp ASC",
            (case_id,),
        )

    async def count(self, status: str | None = None) -> int:
        sql = "SELECT COUNT(*) as cnt FROM cases"
        params: list = []
        if status:
            sql += " WHERE status = ?"
            params.append(status)
        row = await self.db.fetch_one(sql, tuple(params))
        return row["cnt"] if row else 0
