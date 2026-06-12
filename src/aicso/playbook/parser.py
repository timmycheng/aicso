"""Playbook YAML解析器"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import yaml

from aicso.models.playbook import Playbook, PlaybookStep, RiskLevel


class PlaybookParser:
    """Playbook YAML解析器"""

    @staticmethod
    def parse_file(file_path: str) -> Playbook:
        """从YAML文件解析Playbook"""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Playbook file not found: {file_path}")
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return PlaybookParser.parse_dict(data)

    @staticmethod
    def parse_dict(data: dict) -> Playbook:
        """从字典解析Playbook"""
        steps = []
        for step_data in data.get("steps", []):
            steps.append(PlaybookStep(
                name=step_data["name"],
                action=step_data["action"],
                auto=step_data.get("auto", False),
                approval_required=step_data.get("approval_required", False),
                risk_level=RiskLevel(step_data.get("risk_level", "low")),
                params=step_data.get("params", {}),
            ))

        trigger = data.get("trigger", {})
        return Playbook(
            playbook_id=data.get("name", ""),
            name=data.get("name", ""),
            description=data.get("description", ""),
            version=data.get("version", "1.0.0"),
            trigger_tags=trigger.get("case_tags", []),
            steps=steps,
        )

    @staticmethod
    def load_playbooks(directory: str) -> list[Playbook]:
        """加载目录下所有Playbook"""
        playbooks = []
        path = Path(directory)
        if not path.exists():
            return playbooks
        for yaml_file in path.glob("*.yaml"):
            try:
                pb = PlaybookParser.parse_file(str(yaml_file))
                playbooks.append(pb)
            except Exception:
                pass
        for yml_file in path.glob("*.yml"):
            try:
                pb = PlaybookParser.parse_file(str(yml_file))
                playbooks.append(pb)
            except Exception:
                pass
        return playbooks
