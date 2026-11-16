"""Playbook解析器测试"""
import os
import tempfile

from aicso.models.playbook import ApprovalStatus, Playbook, PlaybookStep, RiskLevel, RunStatus
from aicso.playbook.executor import ActionRegistry
from aicso.playbook.parser import PlaybookParser

SAMPLE_PLAYBOOK = """
name: test_playbook
version: 1.0.0
description: Test playbook
trigger:
  case_tags: ["test"]
steps:
  - name: Step 1
    action: query_intel
    auto: true
  - name: Step 2
    action: block_ip
    approval_required: true
    risk_level: medium
"""


class TestPlaybookParser:
    def test_parse_dict(self):
        import yaml
        data = yaml.safe_load(SAMPLE_PLAYBOOK)
        pb = PlaybookParser.parse_dict(data)
        assert pb.name == "test_playbook"
        assert len(pb.steps) == 2
        assert pb.steps[0].auto is True
        assert pb.steps[1].approval_required is True
        assert pb.steps[1].risk_level == RiskLevel.MEDIUM

    def test_parse_file(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, encoding="utf-8"
        ) as f:
            f.write(SAMPLE_PLAYBOOK)
            f.flush()
            pb = PlaybookParser.parse_file(f.name)
            assert pb.name == "test_playbook"
        os.unlink(f.name)

    def test_load_playbooks_directory(self):
        playbooks = PlaybookParser.load_playbooks("playbooks")
        assert len(playbooks) >= 1  # 至少有phishing.yaml


class TestPlaybookExecution:
    """issue #57：步骤动作真实执行/条件分支/no_handler如实标记"""

    def _executor(self, registry):
        from aicso.core.approval import ApprovalEngine
        from aicso.core.event_bus import EventBus
        from aicso.playbook.executor import PlaybookExecutor
        return PlaybookExecutor(ApprovalEngine(EventBus()), registry)

    async def test_action_executes_via_registry(self):
        calls = []

        async def handler(case_id, step):
            calls.append((case_id, step.action))
            return {"blocked": True}

        registry = ActionRegistry()
        registry.register("notify_owner", handler)
        executor = self._executor(registry)
        pb = Playbook(playbook_id="PB-1", name="t", steps=[
            PlaybookStep(name="通知", action="notify_owner"),
            PlaybookStep(name="记录", action="notify"),
        ])
        run = await executor.execute(pb, "CSO-1")
        assert calls == [("CSO-1", "notify_owner")]
        assert run.steps_status["step_0"]["status"] == "completed"
        assert run.steps_status["step_0"]["result"] == {"blocked": True}
        assert run.steps_status["step_1"]["status"] == "no_handler"  # 不再假装completed
        assert run.status == RunStatus.COMPLETED
        assert run.approval_status == ApprovalStatus.APPROVED

    async def test_condition_skips_step(self):
        """条件分支：引用前序步骤结果字段（issue #57）"""
        registry = ActionRegistry()

        async def detect(case_id, step):
            return {"confirmed": False}

        async def respond(case_id, step):
            return {"done": True}

        registry.register("detect", detect)
        registry.register("respond", respond)
        executor = self._executor(registry)
        pb = Playbook(playbook_id="PB-1", name="t", steps=[
            PlaybookStep(name="研判", action="detect"),
            PlaybookStep(name="处置", action="respond",
                         params={"condition": {"field": "confirmed", "equals": True}}),
            PlaybookStep(name="降级动作", action="respond",
                         params={"condition": {"field": "confirmed", "equals": False}}),
        ])
        run = await executor.execute(pb, "CSO-1")
        assert run.steps_status["step_1"]["status"] == "skipped"
        assert run.steps_status["step_1"]["reason"] == "condition_not_met"
        assert run.steps_status["step_2"]["status"] == "completed"  # 条件成立才执行
        assert run.status == RunStatus.COMPLETED

    async def test_handler_failure_fails_run(self):
        registry = ActionRegistry()

        async def boom(case_id, step):
            raise RuntimeError("外部系统不可达")

        registry.register("explode", boom)
        executor = self._executor(registry)
        pb = Playbook(playbook_id="PB-1", name="t", steps=[
            PlaybookStep(name="x", action="explode"),
        ])
        run = await executor.execute(pb, "CSO-1")
        assert run.steps_status["step_0"]["status"] == "failed"
        assert run.status == RunStatus.FAILED
