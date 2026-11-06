"""OpsService — Case操作的统一记录入口（设计§7）

所有对Case的操作（Agent调查/人工处置/补上下文/拉人/playbook/合并拆分）
统一经此落 OpsRecord，并镜像一条 ops_executed 时间线事件保证时间线完整性。
"""
from __future__ import annotations

import structlog
from ulid import ULID

from aicso.models.case import CaseEvent
from aicso.models.ops import ActorType, OpsAction, OpsRecord
from aicso.store.case_store import CaseStore
from aicso.store.ops_store import OpsRecordStore

logger = structlog.get_logger()


class OpsService:
    def __init__(self, case_store: CaseStore, ops_store: OpsRecordStore):
        self.case_store = case_store
        self.ops_store = ops_store

    async def record_op(
        self,
        case_id: str,
        actor: str,
        actor_type: ActorType | str,
        action: OpsAction | str,
        params: dict | None = None,
        result: dict | None = None,
        summary: str = "",
    ) -> OpsRecord:
        """记录一次操作：ops_records表 + ops_executed时间线事件"""
        record = OpsRecord(
            case_id=case_id,
            actor=actor,
            actor_type=actor_type.value if isinstance(actor_type, ActorType) else actor_type,
            action=action.value if isinstance(action, OpsAction) else action,
            params=params or {},
            result=result or {},
        )
        await self.ops_store.create(record)

        event = CaseEvent(
            event_id=f"{case_id}-evt-{str(ULID())}",
            event_type="ops_executed",
            actor=record.actor,
            detail={
                "ops_id": record.id,
                "action": record.action,
                "actor_type": record.actor_type,
                "summary": summary or f"{record.actor_type}:{record.actor} 执行 {record.action}",
                "params": record.params,
                "result": record.result,
            },
        )
        await self.case_store.add_event(case_id, event)
        # 交互频次操作：flush写缓冲保证读己之写（时间线/上下文立即可见）
        await self.case_store.db.flush()
        logger.info("ops.recorded", case_id=case_id, action=record.action,
                    actor=record.actor, actor_type=record.actor_type)
        return record
