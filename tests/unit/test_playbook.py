"""Playbook解析器测试"""
import pytest
import tempfile
import os

from aicso.playbook.parser import PlaybookParser
from aicso.models.playbook import RiskLevel


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
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
            f.write(SAMPLE_PLAYBOOK)
            f.flush()
            pb = PlaybookParser.parse_file(f.name)
            assert pb.name == "test_playbook"
        os.unlink(f.name)

    def test_load_playbooks_directory(self):
        playbooks = PlaybookParser.load_playbooks("playbooks")
        assert len(playbooks) >= 1  # 至少有phishing.yaml
