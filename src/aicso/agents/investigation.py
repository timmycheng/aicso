"""InvestigationAgent - 事件调查Agent"""
from __future__ import annotations

import json

from aicso.agents.base import BaseAgent, AgentResult


class InvestigationAgent(BaseAgent):
    """事件调查Agent：深入调查、攻击链还原、关联分析"""

    name = "investigation"
    description = "负责深入调查安全事件，还原攻击链，分析影响范围"
    tools = ["search_alerts", "query_asset", "lookup_threat_intel", "search_logs", "search_cases"]

    def _build_system_prompt(self) -> str:
        return """你是一名资深安全调查分析师（Investigation Agent）。

你的职责：
1. 深入分析安全事件的攻击手法和攻击链
2. 关联多维度数据（告警、资产、情报、日志）
3. 评估事件的影响范围和严重程度
4. 生成结构化的调查报告

输出格式要求（JSON）：
{
    "attack_chain": ["攻击步骤1", "攻击步骤2", ...],
    "tactics": ["ATT&CK战术ID"],
    "techniques": ["ATT&CK技术ID"],
    "affected_assets": ["受影响资产列表"],
    "iocs_extracted": ["提取的IoC列表"],
    "impact_assessment": "影响评估",
    "confidence": 0.0-1.0,
    "findings": "详细调查发现",
    "recommended_response": ["建议的响应措施"]
}"""

    async def run(self, task: dict, context: dict) -> AgentResult:
        self._logger.info("investigation.start", case_id=task.get("case_id"))

        case = context.get("case", {})
        alerts = context.get("alerts", [])
        intel = context.get("threat_intel", {})
        similar_cases = context.get("history_similar_cases", [])

        messages = [
            {"role": "system", "content": self._build_system_prompt()},
            {"role": "user", "content": f"""请对以下安全事件进行深入调查：

## Case信息
{json.dumps(case, ensure_ascii=False, default=str) if isinstance(case, dict) else str(case)}

## 关联告警（共{len(alerts)}条）
{json.dumps(alerts[:20], ensure_ascii=False, default=str) if alerts else '无'}

## 威胁情报
{json.dumps(intel, ensure_ascii=False, default=str) if intel else '暂无情报'}

## 历史相似Case
{json.dumps(similar_cases, ensure_ascii=False, default=str) if similar_cases else '无历史案例'}

请给出你的调查结果（JSON格式）。"""},
        ]

        try:
            response = await self._call_llm(messages)
            result = json.loads(response)
            return AgentResult.success(
                output=result,
                confidence=result.get("confidence", 0.5),
                reasoning=result.get("findings", ""),
                actions=result.get("recommended_response", []),
            )
        except json.JSONDecodeError:
            return AgentResult.needs_review(
                output={"raw_response": response},
                reasoning="LLM返回格式不符合预期，需要人工审核",
            )
        except Exception as e:
            return AgentResult.failure(str(e))
