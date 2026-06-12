"""Playbook执行器"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

import structlog

from aicso.models.playbook import Playbook, PlaybookRun, RunStatus, ApprovalStatus
from aicso.core.approval import ApprovalEngine, RiskLevel

logger = structlog.get_logger()


class PlaybookExecutor:
    """Playbook执行器"""

    def __init__(self, approval_engine: ApprovalEngine):
        self.approval_engine = approval_engine

    async def execute(self, playbook: Playbook, case_id: str) -> PlaybookRun:
        """执行Playbook"""
        import uuid
        run = PlaybookRun(
            run_id=f"run-{uuid.uuid4().hex[:8]}",
            case_id=case_id,
            playbook_id=playbook.playbook_id,
            status=RunStatus.RUNNING,
            started_at=datetime.utcnow(),
        )

        logger.info("playbook.started", run_id=run.run_id, playbook=playbook.name, case_id=case_id)

        for i, step in enumerate(playbook.steps):
            step_key = f"step_{i}"
            run.steps_status[step_key] = {"status": "pending", "step": step.name}

            if step.approval_required:
                risk = RiskLevel(step.risk_level.value)
                result = await self.approval_engine.request_approval(
                    action=step.action,
                    target=step.name,
                    case_id=case_id,
                    risk_level=risk,
                    reason=f"Playbook step: {step.name}",
                )
                if not result.approved:
                    run.steps_status[step_key]["status"] = "skipped"
                    run.steps_status[step_key]["reason"] = result.reason
                    logger.info("playbook.step_skipped", run_id=run.run_id, step=step.name)
                    continue

            run.steps_status[step_key]["status"] = "completed"
            logger.info("playbook.step_completed", run_id=run.run_id, step=step.name)

        run.status = RunStatus.COMPLETED
        run.completed_at = datetime.utcnow()
        run.approval_status = ApprovalStatus.APPROVED
        logger.info("playbook.completed", run_id=run.run_id)
        return run
