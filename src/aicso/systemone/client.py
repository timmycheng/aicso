"""象信AI System One 判定模型异步客户端

设计依据: docs/REFACTOR_DESIGN.md §5 §15
API: POST {base_url}/systemone，Bearer 认证
重试策略: 429/529 按 retry-after 等待；其他5xx/网络错误指数退避+抖动；
         422/401/402/404 等 4xx 不重试（请求构造或账号问题，重试无意义）
"""
from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field
from typing import Union

import httpx
import structlog

logger = structlog.get_logger()

# 按 retry-after 等待的限流/过载状态码
RETRY_AFTER_CODES = {429, 529}
# 不重试的客户端错误（请求构造/账号问题）
NO_RETRY_CODES = {400, 401, 402, 404, 413, 422}

Question = Union["Choice", "Score", "Noul"]


class SystemOneError(Exception):
    """System One 调用异常基类"""

    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class RateLimitedError(SystemOneError):
    """429/529 限流或过载（重试耗尽后抛出，携带建议等待时间）"""

    def __init__(self, message: str, retry_after_ms: int | None = None):
        super().__init__(message)
        self.retry_after_ms = retry_after_ms


class InvalidRequestError(SystemOneError):
    """422/400/413/404 请求构造或模型名问题，重试无意义"""


class AuthError(SystemOneError):
    """401 key 无效 / 402 余额不足，需人工介入"""


class SystemOneUnavailableError(SystemOneError):
    """网络错误或5xx重试耗尽后仍不可用"""


@dataclass
class Choice:
    """选择题：criteria 为 {选项key: 选项描述}，最多255个选项"""
    instructions: str
    criteria: dict[str, str]

    @property
    def qtype(self) -> str:
        return "choice"

    def to_dict(self) -> dict:
        return {
            "type": self.qtype,
            "instructions": self.instructions,
            "criteria": self.criteria,
        }


@dataclass
class Score:
    """评分题：criteria 为有序程度描述列表"""
    instructions: str
    criteria: list[str]

    @property
    def qtype(self) -> str:
        return "score"

    def to_dict(self) -> dict:
        return {
            "type": self.qtype,
            "instructions": self.instructions,
            "criteria": self.criteria,
        }


@dataclass
class Noul:
    """真假/置信题：无 criteria"""
    instructions: str

    @property
    def qtype(self) -> str:
        return "noul"

    def to_dict(self) -> dict:
        return {"type": self.qtype, "instructions": self.instructions}


@dataclass
class SystemOneAnswer:
    """单个问题的答案"""
    qtype: str
    choice: str | None = None
    score: float | None = None
    noul: float | None = None
    confidence: float | None = None
    probabilities: dict[str, float] = field(default_factory=dict)
    legend: dict[str, str] = field(default_factory=dict)

    @property
    def value(self) -> str | float | None:
        if self.qtype == "choice":
            return self.choice
        if self.qtype == "score":
            return self.score
        return self.noul


@dataclass
class SystemOneResponse:
    """一次 System One 调用的完整响应"""
    model: str
    answers: dict[str, SystemOneAnswer]
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: float = 0.0


class SystemOneClient:
    """异步 httpx 薄客户端

    项目为全 asyncio 栈，官方 xiangxin-sdk 是同步接口，故自实现；
    请求/响应结构以 docs/REFACTOR_DESIGN.md §15 为准。
    transport 参数仅供测试注入 httpx.MockTransport。
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.xiangxinai.cn/v1",
        model: str = "xiangxin-latest",
        timeout_ms: int = 2000,
        max_retries: int = 3,
        backoff_base: float = 0.5,     # 5xx指数退避基数（秒）
        backoff_cap: float = 5.0,
        retry_after_cap: float = 30.0,  # retry-after 等待上限（秒）
        transport: httpx.AsyncTransport | None = None,
    ):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout_ms = timeout_ms
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self.backoff_cap = backoff_cap
        self.retry_after_cap = retry_after_cap
        self._transport = transport
        self._client: httpx.AsyncClient | None = None

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=self.timeout_ms / 1000,
                transport=self._transport,
            )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> SystemOneClient:
        await self._ensure_client()
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.aclose()

    async def system_one(
        self, state: str, questions: dict[str, Question],
        timeout_ms: int | None = None,
    ) -> SystemOneResponse:
        """一次请求并行多个类型化问题，返回带校准置信度的答案

        timeout_ms: 本次请求覆盖构造超时（issue #42/#44）——大token批的
        推理时长随输入规模增长，固定2s会把正常大请求误判为网络错误降级。
        """
        payload = {
            "state": state,
            "model": self.model,
            "questions": {name: q.to_dict() for name, q in questions.items()},
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        client = await self._ensure_client()
        start = time.monotonic()
        attempt = 0
        req_timeout = (timeout_ms or self.timeout_ms) / 1000
        while True:
            attempt += 1
            try:
                resp = await client.post("/systemone", json=payload, headers=headers,
                                         timeout=req_timeout)
            except (httpx.TimeoutException, httpx.TransportError) as e:
                if attempt > self.max_retries:
                    raise SystemOneUnavailableError(
                        f"网络错误重试{self.max_retries}次后仍失败: {e}"
                    ) from e
                await self._backoff_sleep(attempt)
                continue

            if resp.status_code == 200:
                latency_ms = (time.monotonic() - start) * 1000
                return self._parse_response(resp, latency_ms)

            if resp.status_code in RETRY_AFTER_CODES:
                if attempt > self.max_retries:
                    raise RateLimitedError(
                        f"限流(状态码{resp.status_code})重试{self.max_retries}次后仍失败",
                        retry_after_ms=self._retry_after_ms(resp),
                    )
                wait_s = min((self._retry_after_ms(resp) or 0) / 1000, self.retry_after_cap)
                if wait_s <= 0:
                    await self._backoff_sleep(attempt)
                else:
                    logger.info("systemone.rate_limited", status=resp.status_code,
                                wait_s=round(wait_s, 2), attempt=attempt)
                    await asyncio.sleep(wait_s)
                continue

            if resp.status_code in NO_RETRY_CODES:
                self._raise_client_error(resp)

            # 其他5xx: 指数退避重试
            if attempt > self.max_retries:
                raise SystemOneUnavailableError(
                    f"服务错误(状态码{resp.status_code})重试{self.max_retries}次后仍失败"
                )
            await self._backoff_sleep(attempt)

    async def _backoff_sleep(self, attempt: int) -> None:
        """指数退避 + 随机抖动"""
        delay = min(
            self.backoff_base * (2 ** (attempt - 1)) + random.uniform(0, 0.25),
            self.backoff_cap,
        )
        logger.info("systemone.backoff", attempt=attempt, delay_s=round(delay, 2))
        await asyncio.sleep(delay)

    @staticmethod
    def _retry_after_ms(resp: httpx.Response) -> int | None:
        """优先 retry-after-ms（毫秒），回退 retry-after（秒）"""
        raw_ms = resp.headers.get("retry-after-ms")
        if raw_ms is not None:
            try:
                return int(float(raw_ms))
            except ValueError:
                pass
        raw_s = resp.headers.get("retry-after")
        if raw_s is not None:
            try:
                return int(float(raw_s) * 1000)
            except ValueError:
                pass
        return None

    @staticmethod
    def _raise_client_error(resp: httpx.Response) -> None:
        detail = ""
        try:
            detail = resp.json().get("detail", "")
        except Exception:
            detail = resp.text[:200]
        if resp.status_code == 401:
            raise AuthError(f"API key无效(401): {detail}", 401)
        if resp.status_code == 402:
            raise AuthError(f"余额不足(402): {detail}", 402)
        raise InvalidRequestError(
            f"请求被拒绝(状态码{resp.status_code}): {detail}", resp.status_code
        )

    @staticmethod
    def _parse_response(resp: httpx.Response, latency_ms: float) -> SystemOneResponse:
        try:
            body = resp.json()
        except Exception as e:
            raise SystemOneError(f"响应不是合法JSON: {e}") from e

        answers: dict[str, SystemOneAnswer] = {}
        for name, raw in (body.get("answers") or {}).items():
            qtype = raw.get("type", "")
            answer = SystemOneAnswer(
                qtype=qtype,
                choice=raw.get("choice"),
                score=raw.get("score"),
                noul=raw.get("noul"),
                confidence=raw.get("confidence"),
                probabilities={
                    k: float(v) for k, v in (raw.get("probabilities") or {}).items()
                },
                legend={str(k): v for k, v in (raw.get("legend") or {}).items()},
            )
            answers[name] = answer

        usage = body.get("usage") or {}
        return SystemOneResponse(
            model=body.get("model", ""),
            answers=answers,
            input_tokens=int(usage.get("input_tokens", 0)),
            output_tokens=int(usage.get("output_tokens", 0)),
            latency_ms=latency_ms,
        )

    @staticmethod
    def estimate_tokens(text: str) -> int:
        """粗估 token 数：CJK字符≈1 token/字，其他≈4字符/token（保守偏高估）

        用于批量裁剪（64k 单请求预算），误差可接受；实际用量以响应 usage 为准。
        """
        if not text:
            return 0
        cjk = sum(1 for ch in text if "\u4e00" <= ch <= "\u9fff")
        other = len(text) - cjk
        return cjk + (other + 3) // 4

    @classmethod
    def estimate_request_tokens(cls, state: str, questions: dict[str, Question]) -> int:
        """估算整个请求（state+questions）的 token 量"""
        total = cls.estimate_tokens(state)
        for q in questions.values():
            qd = q.to_dict()
            total += cls.estimate_tokens(qd.get("instructions", ""))
            criteria = qd.get("criteria")
            if isinstance(criteria, dict):
                total += sum(cls.estimate_tokens(f"{k}{v}") for k, v in criteria.items())
            elif isinstance(criteria, list):
                total += sum(cls.estimate_tokens(c) for c in criteria)
        return total
