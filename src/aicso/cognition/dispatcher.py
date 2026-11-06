"""S2认知任务分发器 — 任务→引擎映射

设计依据: docs/REFACTOR_DESIGN.md §6
- 判定型任务 → System One（Noul/Choice/Score，校准置信度，低于阈值转人工复核）
- 生成型任务 → LLM（orchestrator既有Agent承担；llm.enabled=false时标needs_review）
- 高风险决策 → 人工（ApprovalEngine，既有）
- 检索型任务 → 本地实体索引（Router承担）
"""
from __future__ import annotations

from dataclasses import dataclass, field

import structlog

from aicso.config import SystemOneConfig
from aicso.models.alert import Alert
from aicso.systemone.client import (
    Choice,
    Noul,
    SystemOneClient,
    SystemOneError,
)

logger = structlog.get_logger()

# 攻击分类选项（与mock_producer 8类模板对齐）
ATTACK_CATEGORIES = {
    "brute_force": "暴力破解/口令爆破",
    "phishing": "钓鱼攻击/社工",
    "malware": "恶意软件/木马",
    "lateral_movement": "横向移动",
    "data_exfiltration": "数据外传",
    "privilege_escalation": "特权提升",
    "port_scan": "端口扫描/探测",
    "web_attack": "Web攻击(SQL注入等)",
    "other": "其他或无法判断",
}

SEVERITY_OPTIONS = {
    "critical": "危急：正在进行的重大入侵/数据泄露",
    "high": "高：确认的攻击行为，需尽快处置",
    "medium": "中：可疑行为，存在风险",
    "low": "低：轻微可疑，常规关注",
    "info": "信息：正常记录或误报",
}


@dataclass
class TriageJudgment:
    """初始研判的判定型结果"""
    true_positive: bool | None = None      # 是否真实事件
    tp_confidence: float | None = None
    category: str | None = None            # 攻击分类
    category_confidence: float | None = None
    severity: str | None = None            # 建议严重度
    severity_confidence: float | None = None
    needs_review: bool = False             # 任一判定低于阈值 → 人工复核
    overall_confidence: float = 0.0
    detail: dict = field(default_factory=dict)


class S2Dispatcher:
    """判定型认知任务经 System One 并行执行；不可用时优雅跳过（转人工）"""

    def __init__(self, client: SystemOneClient | None, scfg: SystemOneConfig):
        self._client = client
        self.scfg = scfg

    @property
    def enabled(self) -> bool:
        return self._client is not None

    async def judge_triage(
        self,
        case_id: str,
        case_title: str,
        alerts: list[Alert],
    ) -> TriageJudgment | None:
        """新Case初始研判的判定型任务集（一次请求并行多问题）

        System One不可用时返回None（调用方转人工复核）。
        """
        if not self._client or not alerts:
            return None

        alert_lines = [
            f"- [{a.severity}] {a.rule_name or '-'} "
            f"{a.src_ip or '-'}→{a.dst_ip or '-'}"
            for a in alerts[:10]  # 控制state规模
        ]
        state = (
            f"安全事件 {case_id}：{case_title}\n"
            f"关联告警{len(alerts)}条（前{len(alert_lines)}条）：\n" + "\n".join(alert_lines)
        )

        try:
            response = await self._client.system_one(
                state=state,
                questions={
                    "is_true_positive": Noul(
                        instructions=(
                            "综合这些告警，该事件是否为真实安全事件"
                            "（而非误报、测试流量或正常业务行为）？"
                        ),
                    ),
                    "attack_category": Choice(
                        instructions="该事件最主要的攻击类型是什么？",
                        criteria=ATTACK_CATEGORIES,
                    ),
                    "severity": Choice(
                        instructions="综合判断，该事件应定为什么严重级别？",
                        criteria=SEVERITY_OPTIONS,
                    ),
                },
            )
        except SystemOneError as e:
            logger.warning("s2.judge_triage_failed", case_id=case_id, error=str(e))
            return None

        answers = response.answers
        tp = answers.get("is_true_positive")
        cat = answers.get("attack_category")
        sev = answers.get("severity")

        threshold = self.scfg.confidence_threshold
        judgment = TriageJudgment(
            true_positive=(tp.value or 0) >= 0.5 if tp and tp.value is not None else None,
            tp_confidence=tp.value if tp else None,
            category=cat.choice if cat else None,
            category_confidence=cat.confidence if cat else None,
            severity=sev.choice if sev else None,
            severity_confidence=sev.confidence if sev else None,
            detail={"model": response.model, "input_tokens": response.input_tokens},
        )

        confidences = [
            c for c in (
                judgment.tp_confidence,
                judgment.category_confidence,
                judgment.severity_confidence,
            ) if c is not None
        ]
        judgment.overall_confidence = (
            sum(confidences) / len(confidences) if confidences else 0.0
        )
        judgment.needs_review = (
            not confidences
            or any(c < threshold for c in confidences)
            or judgment.category not in ATTACK_CATEGORIES
            or judgment.severity not in SEVERITY_OPTIONS
        )
        logger.info(
            "s2.judged",
            case_id=case_id,
            category=judgment.category,
            severity=judgment.severity,
            overall=round(judgment.overall_confidence, 2),
            needs_review=judgment.needs_review,
        )
        return judgment
