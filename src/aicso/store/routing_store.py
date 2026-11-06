"""路由决策审计存储"""
from __future__ import annotations

import json

from ulid import ULID

from aicso.router.decision import RoutingDecision
from aicso.store.database import Database


class RoutingDecisionStore:
    """routing_decisions 表的读写"""

    def __init__(self, db: Database):
        self.db = db

    async def create(self, decision: RoutingDecision) -> None:
        await self.db.buffered_execute(
            """INSERT INTO routing_decisions (id, alert_id, case_id, decision,
               source, confidence, degraded, latency_ms, candidates, detail, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                str(ULID()),
                decision.alert_id,
                decision.case_id,
                decision.decision,
                decision.source,
                decision.confidence,
                1 if decision.degraded else 0,
                decision.latency_ms,
                decision.candidates,
                json.dumps(decision.detail, ensure_ascii=False),
                decision.created_at.isoformat(),
            ),
        )

    async def list_recent(self, limit: int = 50) -> list[dict]:
        return await self.db.fetch_all(
            """SELECT * FROM routing_decisions
               ORDER BY created_at DESC LIMIT ?""",
            (limit,),
        )

    async def stats_by_source(self) -> dict:
        rows = await self.db.fetch_all(
            """SELECT source, decision, COUNT(*) AS cnt
               FROM routing_decisions GROUP BY source, decision"""
        )
        return {
            f"{r['source']}.{r['decision']}": r["cnt"] for r in rows
        }
