"""TriageAgent - 告警分诊Agent"""
from __future__ import annotations

import json
import re

from aicso.agents.base import BaseAgent, AgentResult

VALID_DIMENSIONS = {
    "src_ip+dst_ip", "src_ip+rule_id", "src_ip",
    "dst_ip", "dst_ip+rule_id", "src_ip+severity",
}

# 不同攻击类型的默认推荐维度
CATEGORY_DIMENSION_HINTS = {
    "brute_force": ["src_ip+dst_ip"],
    "暴力破解": ["src_ip+dst_ip"],
    "phishing": ["src_ip+rule_id"],
    "钓鱼": ["src_ip+rule_id"],
    "malware": ["src_ip+rule_id"],
    "恶意软件": ["src_ip+rule_id"],
    "c2": ["src_ip+rule_id"],
    "c2通信": ["src_ip+rule_id"],
    "lateral_movement": ["src_ip+dst_ip"],
    "横向移动": ["src_ip+dst_ip"],
    "data_exfiltration": ["dst_ip+rule_id"],
    "数据外传": ["dst_ip+rule_id"],
    "port_scan": ["src_ip"],
    "端口扫描": ["src_ip"],
    "web_attack": ["src_ip+dst_ip"],
    "sql_injection": ["src_ip+dst_ip"],
    "privilege_escalation": ["src_ip+rule_id"],
    "特权提升": ["src_ip+rule_id"],
}


def _extract_json(text: str) -> dict:
    """从LLM响应中提取JSON，兼容代码块和前后杂质文字"""
    # 尝试直接解析
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # 提取 ```json ... ``` 代码块
    m = re.search(r"```(?:json)?\s*\n?(.*?)\n?\s*```", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1).strip())
        except json.JSONDecodeError:
            pass

    # 提取第一个 { ... } 块
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            pass

    raise json.JSONDecodeError("No valid JSON found", text, 0)


def _validate_dimensions(dimensions: list, category: str = "") -> list[str]:
    """校验并修正dimensions，确保只含合法值"""
    valid = [d for d in dimensions if d in VALID_DIMENSIONS]
    if valid:
        return valid

    # 全部不合法时，根据category推断
    for key, dims in CATEGORY_DIMENSION_HINTS.items():
        if key in category.lower():
            return dims

    # 最终兜底
    return ["src_ip+dst_ip"]


class TriageAgent(BaseAgent):
    """告警分诊Agent：负责告警分类、聚合判断、初步研判"""

    name = "triage"
    description = "负责告警分诊，判断告警真伪、严重级别，给出初步分析"
    tools = ["search_alerts", "search_cases", "query_asset"]

    def _build_system_prompt(self) -> str:
        return """你是一名资深SOC分诊分析师。

职责：分析告警、判断真伪、评估严重级别、给出处置建议、生成聚合规则。

严格要求：只输出一个JSON对象，不要输出任何其他文字、解释或markdown标记。

JSON格式：
{
    "is_true_positive": true,
    "confidence": 0.85,
    "severity_suggestion": "high",
    "category": "暴力破解",
    "summary": "简要分析摘要",
    "recommended_actions": ["封禁源IP", "通知资产负责人"],
    "reasoning": "推理过程",
    "aggregation_rule": {
        "dimensions": ["src_ip+dst_ip"],
        "window_minutes": 30,
        "label": "规则描述"
    }
}

aggregation_rule.dimensions 从以下值中选择（可多选）：
- "src_ip+dst_ip": 同源IP+同目标IP（暴力破解、Web攻击、横向移动）
- "src_ip+rule_id": 同源IP+同规则（恶意软件、C2通信、钓鱼）
- "src_ip": 同源IP（端口扫描、同一攻击者的多目标活动）
- "dst_ip": 同目标IP（针对同一资产的多种攻击）
- "dst_ip+rule_id": 同目标IP+同规则（数据外传、特定目标的同类攻击）
- "src_ip+severity": 同源IP+同严重级别"""

    async def run(self, task: dict, context: dict) -> AgentResult:
        self._logger.info("triage.start", task_type=task.get("type"))

        alerts = context.get("alerts", [])
        assets = context.get("assets", [])

        if not alerts:
            return AgentResult.failure("No alerts provided for triage")

        alert_summary = self._format_alerts(alerts)
        asset_summary = self._format_assets(assets)
        category_hint = self._guess_category(alerts)

        messages = [
            {"role": "system", "content": self._build_system_prompt()},
            {"role": "user", "content": f"""分析以下告警并输出JSON：

## 告警
{alert_summary}

## 资产
{asset_summary}

只输出JSON。"""},
        ]

        response = ""
        try:
            response = await self._call_llm(messages)
            result = _extract_json(response)

            # 校验并修正聚合规则
            ai_rule = result.get("aggregation_rule", {})
            if not isinstance(ai_rule, dict):
                ai_rule = {}
            dimensions = ai_rule.get("dimensions", [])
            if not isinstance(dimensions, list):
                dimensions = []
            validated_dims = _validate_dimensions(dimensions, category_hint or result.get("category", ""))
            result["aggregation_rule"] = {
                "dimensions": validated_dims,
                "window_minutes": ai_rule.get("window_minutes", 30) if isinstance(ai_rule.get("window_minutes"), int) else 30,
                "label": ai_rule.get("label", "") if isinstance(ai_rule.get("label"), str) else "",
            }
            if not result["aggregation_rule"]["label"]:
                result["aggregation_rule"]["label"] = (
                    f"{result.get('category', '未知')}-"
                    f"{'+'.join(validated_dims)}"
                )

            # 校验confidence
            conf = result.get("confidence", 0.5)
            if not isinstance(conf, (int, float)) or not (0 <= conf <= 1):
                result["confidence"] = 0.5

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

    def _guess_category(self, alerts: list) -> str:
        """从告警内容猜测攻击类别"""
        for a in alerts[:3]:
            rule = ""
            if isinstance(a, dict):
                rule = (a.get("rule_name", "") or "").lower()
            else:
                rule = (a.rule_name or "").lower()
            for keyword in CATEGORY_DIMENSION_HINTS:
                if keyword in rule:
                    return keyword
        return ""

    def _format_alerts(self, alerts: list) -> str:
        lines = []
        for a in alerts[:10]:
            if isinstance(a, dict):
                lines.append(
                    f"- [{a.get('severity', '?')}] {a.get('rule_name', 'N/A')} | "
                    f"src={a.get('src_ip', 'N/A')} dst={a.get('dst_ip', 'N/A')} | "
                    f"rule_id={a.get('rule_id', 'N/A')} | "
                    f"时间={a.get('timestamp', 'N/A')}"
                )
            else:
                lines.append(
                    f"- [{a.severity}] {a.rule_name or 'N/A'} | "
                    f"src={a.src_ip or 'N/A'} dst={a.dst_ip or 'N/A'} | "
                    f"rule_id={a.rule_id or 'N/A'} | "
                    f"时间={a.timestamp}"
                )
        return "\n".join(lines)

    def _format_assets(self, assets: list) -> str:
        if not assets:
            return "暂无关联资产信息"
        lines = []
        for a in assets:
            if isinstance(a, dict):
                lines.append(
                    f"- {a.get('hostname', 'N/A')} ({a.get('ip_address', 'N/A')}) "
                    f"[{a.get('criticality', 'medium')}] {a.get('department', '')}"
                )
            else:
                lines.append(
                    f"- {a.hostname or 'N/A'} ({a.ip_address or 'N/A'}) "
                    f"[{a.criticality.value}] {a.department or ''}"
                )
        return "\n".join(lines)
