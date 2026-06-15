"""Agent基类定义"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class AgentStatus(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    WAITING_APPROVAL = "waiting_approval"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class AgentResult:
    """Agent执行结果"""
    status: AgentStatus
    output: dict = field(default_factory=dict)
    confidence: float = 0.0  # 0.0 - 1.0
    needs_human_review: bool = False
    recommended_actions: list[str] = field(default_factory=list)
    reasoning: str = ""

    @classmethod
    def success(cls, output: dict, confidence: float, reasoning: str = "",
                actions: list[str] | None = None) -> AgentResult:
        return cls(
            status=AgentStatus.COMPLETED,
            output=output,
            confidence=confidence,
            reasoning=reasoning,
            recommended_actions=actions or [],
        )

    @classmethod
    def failure(cls, error: str) -> AgentResult:
        return cls(
            status=AgentStatus.FAILED,
            output={"error": error},
            confidence=0.0,
            needs_human_review=True,
            reasoning=f"Agent execution failed: {error}",
        )

    @classmethod
    def needs_review(cls, output: dict, reasoning: str) -> AgentResult:
        return cls(
            status=AgentStatus.COMPLETED,
            output=output,
            confidence=0.0,
            needs_human_review=True,
            reasoning=reasoning,
        )


class BaseAgent(ABC):
    """所有Agent的基类"""

    name: str = "base"
    description: str = ""
    tools: list[str] = []

    def __init__(self, llm_provider: str = "deepseek", llm_model: str | None = None):
        self.llm_provider = llm_provider
        self.llm_model = llm_model
        self._logger = structlog.get_logger().bind(agent=self.name)

    @abstractmethod
    async def run(self, task: dict, context: dict) -> AgentResult:
        """执行任务"""
        ...

    async def plan(self, task: dict, context: dict) -> list[dict]:
        """规划执行步骤（Plan-and-Execute模式），子类可覆写"""
        return [{"step": 1, "action": "execute", "description": task.get("type", "unknown")}]

    async def _call_llm(self, messages: list[dict], tools: list[dict] | None = None) -> str:
        """调用LLM"""
        try:
            from litellm import acompletion
            from aicso.config import load_config

            config = load_config()
            provider_cfg = config.llm.providers.get(self.llm_provider, {})

            model_name = self.llm_model or provider_cfg.model if hasattr(provider_cfg, 'model') else self.llm_model or "deepseek-chat"

            kwargs = {
                "model": model_name,
                "messages": messages,
                "temperature": 0.1,
                "max_tokens": 4096,
            }

            if hasattr(provider_cfg, 'api_key') and provider_cfg.api_key:
                kwargs["api_key"] = provider_cfg.api_key
            if hasattr(provider_cfg, 'base_url') and provider_cfg.base_url:
                kwargs["api_base"] = provider_cfg.base_url
                kwargs["model"] = f"openai/{model_name}"

            if tools:
                kwargs["tools"] = tools
            response = await acompletion(**kwargs)
            return response.choices[0].message.content or ""
        except Exception as e:
            self._logger.error("llm_call_failed", error=str(e))
            raise

    def _build_system_prompt(self) -> str:
        """构建系统提示词，子类应覆写"""
        return f"You are {self.name}, a security operations AI agent. {self.description}"
