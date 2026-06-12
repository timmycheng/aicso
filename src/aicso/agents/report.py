"""ReportAgent - 报告生成Agent"""
from __future__ import annotations

from datetime import datetime

from aicso.agents.base import BaseAgent, AgentResult


class ReportAgent(BaseAgent):
    """报告生成Agent：生成事件报告和摘要"""

    name = "report"
    description = "负责生成安全事件报告、Case摘要"
    tools = []

    def _build_system_prompt(self) -> str:
        return """你是一名安全报告撰写专家（Report Agent）。

你的职责：
1. 汇总Case的所有调查结果和响应动作
2. 生成结构化的安全事件报告
3. 确保报告清晰、准确、可操作

报告格式要求（Markdown）：
# 事件报告

## 概述
（事件基本信息和摘要）

## 告警信息
（相关告警列表）

## 调查发现
（调查Agent的发现）

## 影响评估
（影响范围和严重程度）

## 响应措施
（已执行和待执行的响应动作）

## IoC列表
（相关失陷指标）

## 建议
（后续改进建议）"""

    async def run(self, task: dict, context: dict) -> AgentResult:
        self._logger.info("report.start", case_id=task.get("case_id"))

        case = context.get("case", {})
        triage_result = context.get("triage_result", {})
        investigation_result = context.get("investigation_result", {})
        response_result = context.get("response_result", {})
        intel_result = context.get("intel_result", {})

        messages = [
            {"role": "system", "content": self._build_system_prompt()},
            {"role": "user", "content": f"""请根据以下信息生成安全事件报告：

## Case信息
{self._format_case(case)}

## 分诊结果
{self._format_dict(triage_result)}

## 调查结果
{self._format_dict(investigation_result)}

## 威胁情报
{self._format_dict(intel_result)}

## 响应方案
{self._format_dict(response_result)}

请生成完整的事件报告（Markdown格式）。"""},
        ]

        try:
            report = await self._call_llm(messages)
            return AgentResult.success(
                output={"report": report, "generated_at": datetime.utcnow().isoformat()},
                confidence=0.8,
                reasoning="报告已生成",
            )
        except Exception as e:
            return AgentResult.failure(str(e))

    def _format_case(self, case) -> str:
        if isinstance(case, dict):
            return (f"- 标题: {case.get('title', 'N/A')}\n"
                    f"- ID: {case.get('case_id', 'N/A')}\n"
                    f"- 严重级别: {case.get('severity', 'N/A')}\n"
                    f"- 状态: {case.get('status', 'N/A')}")
        return (f"- 标题: {case.title}\n- ID: {case.case_id}\n"
                f"- 严重级别: {case.severity.value}\n- 状态: {case.status.value}")

    def _format_dict(self, d: dict) -> str:
        if not d:
            return "暂无数据"
        import json
        return json.dumps(d, ensure_ascii=False, indent=2, default=str)
