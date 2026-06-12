"""TriageAgent - 告警分诊Agent"""
from __future__ import annotations

import json

from aicso.agents.base import BaseAgent, AgentResult


class TriageAgent(BaseAgent):
    """告警分诊Agent：负责告警分类、聚合判断、初步研判"""

    name = "triage"
    description = "负责告警分诊，判断告警真伪、严重级别，给出初步分析"
    tools = ["search_alerts", "search_cases", "query_asset"]

    def _build_system_prompt(self) -> str:
        return """你是一名资深SOC分诊分析师（Triage Agent）。

你的职责：
1. 分析告警信息，判断是否为真阳性（True Positive）
2. 评估告警的严重级别和优先级
3. 关联资产信息，判断影响范围
4. 给出初步处置建议

输出格式要求（JSON）：
{
    "is_true_positive": true/false,
    "confidence": 0.0-1.0,
    "severity_suggestion": "critical/high/medium/low/info",
    "category": "攻击类型分类",
    "summary": "简要分析摘要",
    "recommended_actions": ["建议的处置动作"],
    "reasoning": "详细推理过程"
}"""

    async def run(self, task: dict, context: dict) -> AgentResult:
        """执行分诊任务"""
        self._logger.info("triage.start", task_type=task.get("type"))

        alerts = context.get("alerts", [])
        assets = context.get("assets", [])

        if not alerts:
            return AgentResult.failure("No alerts provided for triage")

        # 构建分析上下文
        alert_summary = self._format_alerts(alerts)
        asset_summary = self._format_assets(assets)

        messages = [
            {"role": "system", "content": self._build_system_prompt()},
            {"role": "user", "content": f"""请对以下告警进行分诊分析：

## 告警信息
{alert_summary}

## 关联资产
{asset_summary}

请给出你的分析结果（JSON格式）。"""},
        ]

        try:
            response = await self._call_llm(messages)
            result = json.loads(response)
            return AgentResult.success(
                output=result,
                confidence=result.get("confidence", 0.5),
                reasoning=result.get("reasoning", ""),
                actions=result.get("recommended_actions", []),
            )
        except json.JSONDecodeError:
            return AgentResult.needs_review(
                output={"raw_response": response},
                reasoning="LLM返回格式不符合预期，需要人工审核",
            )
        except Exception as e:
            return AgentResult.failure(str(e))

    def _format_alerts(self, alerts: list) -> str:
        lines = []
        for a in alerts[:10]:  # 最多展示10条
            if isinstance(a, dict):
                lines.append(f"- [{a.get('severity', '?')}] {a.get('rule_name', 'N/A')} | "
                           f"src={a.get('src_ip', 'N/A')} dst={a.get('dst_ip', 'N/A')} | "
                           f"时间={a.get('timestamp', 'N/A')}")
            else:
                lines.append(f"- [{a.severity}] {a.rule_name or 'N/A'} | "
                           f"src={a.src_ip or 'N/A'} dst={a.dst_ip or 'N/A'} | "
                           f"时间={a.timestamp}")
        return "\n".join(lines)

    def _format_assets(self, assets: list) -> str:
        if not assets:
            return "暂无关联资产信息"
        lines = []
        for a in assets:
            if isinstance(a, dict):
                lines.append(f"- {a.get('hostname', 'N/A')} ({a.get('ip_address', 'N/A')}) "
                           f"[{a.get('criticality', 'medium')}] {a.get('department', '')}")
            else:
                lines.append(f"- {a.hostname or 'N/A'} ({a.ip_address or 'N/A'}) "
                           f"[{a.criticality.value}] {a.department or ''}")
        return "\n".join(lines)
