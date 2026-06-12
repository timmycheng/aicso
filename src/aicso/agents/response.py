"""ResponseAgent - 响应执行Agent"""
from __future__ import annotations

import json

from aicso.agents.base import BaseAgent, AgentResult


class ResponseAgent(BaseAgent):
    """响应执行Agent：规划和执行安全响应动作"""

    name = "response"
    description = "负责制定响应方案，执行安全响应动作"
    tools = ["execute_response_action"]

    def _build_system_prompt(self) -> str:
        return """你是一名安全响应分析师（Response Agent）。

你的职责：
1. 根据调查结果制定响应方案
2. 评估每个响应动作的风险级别
3. 推荐执行顺序和审批要求

输出格式要求（JSON）：
{
    "response_plan": [
        {
            "action": "动作名称",
            "target": "目标对象",
            "risk_level": "low/medium/high",
            "approval_required": true/false,
            "reason": "执行原因",
            "priority": 1
        }
    ],
    "estimated_impact": "预期影响",
    "rollback_plan": "回滚方案",
    "confidence": 0.0-1.0,
    "summary": "响应方案摘要"
}"""

    async def run(self, task: dict, context: dict) -> AgentResult:
        self._logger.info("response.start", case_id=task.get("case_id"))

        investigation_result = context.get("investigation_result", {})
        case = context.get("case", {})

        messages = [
            {"role": "system", "content": self._build_system_prompt()},
            {"role": "user", "content": f"""请根据调查结果制定响应方案：

## Case信息
- 标题: {case.get('title', 'N/A') if isinstance(case, dict) else getattr(case, 'title', 'N/A')}
- 严重级别: {case.get('severity', 'N/A') if isinstance(case, dict) else getattr(case, 'severity', 'N/A')}

## 调查结果
{json.dumps(investigation_result, ensure_ascii=False, default=str) if investigation_result else '无调查结果'}

请给出响应方案（JSON格式）。"""},
        ]

        try:
            response = await self._call_llm(messages)
            result = json.loads(response)
            return AgentResult.success(
                output=result,
                confidence=result.get("confidence", 0.5),
                reasoning=result.get("summary", ""),
                actions=[r["action"] for r in result.get("response_plan", [])],
            )
        except json.JSONDecodeError:
            return AgentResult.needs_review(
                output={"raw_response": response},
                reasoning="LLM返回格式不符合预期",
            )
        except Exception as e:
            return AgentResult.failure(str(e))
