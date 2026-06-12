"""IntelAgent - 威胁情报Agent"""
from __future__ import annotations

import json

from aicso.agents.base import BaseAgent, AgentResult


class IntelAgent(BaseAgent):
    """威胁情报Agent：查询和分析威胁情报"""

    name = "intel"
    description = "负责威胁情报查询、IoC分析、ATT&CK映射"
    tools = ["lookup_threat_intel", "search_ioc"]

    def _build_system_prompt(self) -> str:
        return """你是一名威胁情报分析师（Intel Agent）。

你的职责：
1. 查询IoC（IP、域名、Hash、URL）的威胁情报
2. 分析IoC的关联威胁和攻击手法
3. 映射到MITRE ATT&CK框架
4. 评估威胁置信度

输出格式要求（JSON）：
{
    "ioc_results": [
        {"ioc": "1.2.3.4", "type": "ip", "malicious": true, "confidence": 0.9, "source": "...", "tags": ["botnet"]}
    ],
    "attack_context": "攻击背景分析",
    "attck_tactics": ["TA0001"],
    "attck_techniques": ["T1566"],
    "threat_actor": "关联威胁组织（如有）",
    "confidence": 0.0-1.0,
    "summary": "情报摘要"
}"""

    async def run(self, task: dict, context: dict) -> AgentResult:
        self._logger.info("intel.start", case_id=task.get("case_id"))

        iocs = context.get("iocs", [])
        alerts = context.get("alerts", [])

        # 从告警中提取IP作为IoC查询
        ips_to_check = set()
        for a in alerts:
            a_dict = a if isinstance(a, dict) else a.model_dump()
            if a_dict.get("src_ip"):
                ips_to_check.add(a_dict["src_ip"])
            if a_dict.get("dst_ip"):
                ips_to_check.add(a_dict["dst_ip"])

        messages = [
            {"role": "system", "content": self._build_system_prompt()},
            {"role": "user", "content": f"""请对以下IoC进行威胁情报分析：

## 已知IoC
{json.dumps([i if isinstance(i, dict) else i.model_dump() for i in iocs], ensure_ascii=False) if iocs else '无'}

## 从告警中提取的IP
{list(ips_to_check) if ips_to_check else '无'}

请给出情报分析结果（JSON格式）。"""},
        ]

        try:
            response = await self._call_llm(messages)
            result = json.loads(response)
            return AgentResult.success(
                output=result,
                confidence=result.get("confidence", 0.5),
                reasoning=result.get("summary", ""),
            )
        except json.JSONDecodeError:
            return AgentResult.needs_review(
                output={"raw_response": response},
                reasoning="LLM返回格式不符合预期",
            )
        except Exception as e:
            return AgentResult.failure(str(e))
