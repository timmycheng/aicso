"""Playbook执行器

issue #57：步骤动作经注册的处理器真实执行；未注册动作如实标记，
不再假装completed；支持引用前序步骤结果的条件分支。
"""
from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import Any

import structlog

from aicso.core.approval import ApprovalEngine, RiskLevel
from aicso.models.playbook import ApprovalStatus, Playbook, PlaybookRun, RunStatus

logger = structlog.get_logger()

# 步骤动作处理器：async (case_id, step) -> result dict
ActionHandler = Callable[[str, Any], Awaitable[dict]]


class ActionRegistry:
    """步骤动作处理器注册表

    部署侧按环境注册处理器（对接各环境的真实响应通道）；未注册的动作
    不再被静默标记completed——那会让审计记录说谎（issue #57）。
    """

    def __init__(self) -> None:
        self._handlers: dict[str, ActionHandler] = {}

    def register(self, action: str, handler: ActionHandler) -> None:
        self._handlers[action] = handler

    def get(self, action: str) -> ActionHandler | None:
        return self._handlers.get(action)

    def registered(self) -> list[str]:
        return sorted(self._handlers)


class PlaybookExecutor:
    """Playbook执行器：审批门控 + 动作真实执行 + 条件分支（issue #57）"""

    def __init__(self, approval_engine: ApprovalEngine,
                 registry: ActionRegistry | None = None):
        self.approval_engine = approval_engine
        self.registry = registry or ActionRegistry()

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

        rejected = False
        failed = False
        # 紧邻前序步骤的结果（条件分支引用它）
        last_result: dict = {}
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
                    rejected = True
                    run.steps_status[step_key]["status"] = "skipped"
                    run.steps_status[step_key]["reason"] = result.reason
                    logger.info("playbook.step_skipped", run_id=run.run_id, step=step.name)
                    continue

            # 条件分支（issue #57）：前序步骤字段与期望值不符则跳过本步骤
            condition = step.params.get("condition")
            if isinstance(condition, dict) and not self._condition_met(last_result, condition):
                run.steps_status[step_key]["status"] = "skipped"
                run.steps_status[step_key]["reason"] = "condition_not_met"
                logger.info("playbook.step_skipped", run_id=run.run_id,
                            step=step.name, reason="condition_not_met")
                continue

            handler = self.registry.get(step.action)
            if handler is None:
                # 动作无处理器：如实标记 no_handler，不再假装completed（issue #57）
                run.steps_status[step_key]["status"] = "no_handler"
                run.steps_status[step_key]["reason"] = f"动作 {step.action} 未注册处理器"
                logger.warning("playbook.step_no_handler", run_id=run.run_id,
                               step=step.name, action=step.action)
                continue
            try:
                output = await handler(case_id, step)
            except Exception as e:
                run.steps_status[step_key]["status"] = "failed"
                run.steps_status[step_key]["reason"] = str(e)
                failed = True
                logger.error("playbook.step_failed", run_id=run.run_id,
                             step=step.name, error=str(e))
                break
            run.steps_status[step_key]["status"] = "completed"
            run.steps_status[step_key]["result"] = output
            last_result = output if isinstance(output, dict) else {}
            # 步骤产出进运行记录（审计可见各步骤真实输出）
            run.result.setdefault("steps", {})[step_key] = {
                "name": step.name, "result": output,
            }
            logger.info("playbook.step_completed", run_id=run.run_id, step=step.name)

        run.status = RunStatus.FAILED if failed else RunStatus.COMPLETED
        run.completed_at = datetime.utcnow()
        # 审计语义：有被拒/超时步骤的run不得标APPROVED（此前无条件APPROVED，
        # 审计失真，review #56发现51）
        run.approval_status = ApprovalStatus.REJECTED if rejected else ApprovalStatus.APPROVED
        logger.info("playbook.finished", run_id=run.run_id, status=run.status.value)
        return run

    @staticmethod
    def _condition_met(previous_result: dict, cond: dict) -> bool:
        """条件分支求值：紧邻前序步骤结果字段与期望值等值比较

        形如 {"field": "blocked", "equals": true}。字段名只做遍历等值
        匹配（不用字段名按键取值）；前序步骤未产出结果 → 条件不成立。
        """
        field = cond.get("field")
        if not isinstance(field, str):
            return False
        expected = cond.get("equals")
        for key, value in previous_result.items():
            if key == field:
                return value == expected
        return False
