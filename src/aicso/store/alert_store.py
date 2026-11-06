"""Alert存储层"""
from __future__ import annotations

import json
from datetime import datetime

from aicso.models.alert import Alert
from aicso.store.database import Database


class AlertStore:
    """Alert持久化存储"""

    def __init__(self, db: Database):
        self.db = db

    async def create(self, alert: Alert) -> None:
        await self.db.buffered_execute(
            """INSERT INTO alerts (alert_id, source, rule_id, rule_name, severity,
               timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
               raw_log, enriched_data, case_id, is_false_positive, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                alert.alert_id, alert.source, alert.rule_id, alert.rule_name,
                alert.severity, alert.timestamp.isoformat(),
                alert.src_ip, alert.dst_ip, alert.src_port, alert.dst_port,
                alert.protocol, alert.raw_log, json.dumps(alert.enriched_data),
                alert.case_id, alert.is_false_positive,
                alert.created_at.isoformat(),
            ),
        )

    async def get(self, alert_id: str) -> dict | None:
        return await self.db.fetch_one(
            "SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)
        )

    async def update_case_id(self, alert_id: str, case_id: str) -> None:
        await self.db.buffered_execute(
            "UPDATE alerts SET case_id = ? WHERE alert_id = ?",
            (case_id, alert_id),
        )

    async def mark_routed(self, alert_id: str, case_id: str, source: str) -> None:
        """路由完成后更新：case关联 + 路由时间 + 决策来源"""
        await self.db.buffered_execute(
            "UPDATE alerts SET case_id = ?, routed_at = ?, routing_source = ? WHERE alert_id = ?",
            (case_id, datetime.utcnow().isoformat(), source, alert_id),
        )

    async def list_unrouted(self, limit: int = 10000) -> list[dict]:
        """未路由告警（重启回灌用，§5.6）"""
        return await self.db.fetch_all(
            """SELECT * FROM alerts
               WHERE routed_at IS NULL AND case_id IS NULL
               ORDER BY created_at ASC LIMIT ?""",
            (limit,),
        )

    async def list_alerts(
        self,
        case_id: str | None = None,
        source: str | None = None,
        src_ip: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        sql = "SELECT * FROM alerts WHERE 1=1"
        params: list = []
        if case_id:
            sql += " AND case_id = ?"
            params.append(case_id)
        if source:
            sql += " AND source = ?"
            params.append(source)
        if src_ip:
            sql += " AND src_ip = ?"
            params.append(src_ip)
        sql += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        return await self.db.fetch_all(sql, tuple(params))

    async def count(self, case_id: str | None = None) -> int:
        if case_id:
            row = await self.db.fetch_one(
                "SELECT COUNT(*) as cnt FROM alerts WHERE case_id = ?", (case_id,)
            )
        else:
            row = await self.db.fetch_one("SELECT COUNT(*) as cnt FROM alerts")
        return row["cnt"] if row else 0
