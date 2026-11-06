"""SystemOneClient 与 .env 加载测试

注意：象信文档说明重复调用概率值有小幅浮点抖动，
因此涉及 probabilities 的断言一律使用区间断言，禁止精确相等。
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import httpx
import pytest

from aicso.config import load_config, load_dotenv
from aicso.systemone.client import (
    AuthError,
    Choice,
    InvalidRequestError,
    Noul,
    RateLimitedError,
    Score,
    SystemOneClient,
    SystemOneUnavailableError,
)


def _mock_client(handler, **kwargs) -> SystemOneClient:
    return SystemOneClient(
        api_key="test-key",
        backoff_base=0.01,      # 测试用极短退避
        retry_after_cap=0.05,
        transport=httpx.MockTransport(handler),
        **kwargs,
    )


def _ok_response(payload: dict) -> httpx.Response:
    return httpx.Response(200, json=payload)


def _sample_success() -> dict:
    return {
        "model": "xiangxin-3.0.0",
        "answers": {
            "category": {
                "type": "choice",
                "choice": "brute_force",
                "confidence": 0.86,
                "probabilities": {"brute_force": 0.91, "scan": 0.07, "other": 0.02},
            },
            "urgency": {"type": "noul", "noul": 0.91},
            "severity": {
                "type": "score",
                "score": 0.72,
                "confidence": 0.65,
                "legend": {"0": "低", "1": "中", "2": "高"},
                "probabilities": {"0": 0.15, "1": 0.7, "2": 0.15},
            },
        },
        "usage": {"input_tokens": 195, "output_tokens": 240},
    }


class TestRequestConstruction:
    async def test_choice_score_noul_payload(self):
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            captured["auth"] = request.headers.get("authorization")
            captured["body"] = json.loads(request.content)
            return _ok_response(_sample_success())

        client = _mock_client(handler)
        await client.system_one(
            state="测试状态文本",
            questions={
                "category": Choice(instructions="属于哪类？",
                                   criteria={"a": "选项A", "b": "选项B"}),
                "urgency": Noul(instructions="是否紧急？"),
                "level": Score(instructions="严重程度？", criteria=["低", "中", "高"]),
            },
        )
        await client.aclose()

        assert captured["url"].endswith("/systemone")
        assert captured["auth"] == "Bearer test-key"
        body = captured["body"]
        assert body["state"] == "测试状态文本"
        assert body["model"] == "xiangxin-latest"
        assert body["questions"]["category"] == {
            "type": "choice", "instructions": "属于哪类？",
            "criteria": {"a": "选项A", "b": "选项B"},
        }
        assert body["questions"]["urgency"] == {"type": "noul", "instructions": "是否紧急？"}
        assert body["questions"]["level"]["criteria"] == ["低", "中", "高"]

    async def test_response_parsing(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return _ok_response(_sample_success())

        client = _mock_client(handler)
        resp = await client.system_one(
            state="s", questions={"category": Choice(instructions="i", criteria={"a": "A"})}
        )
        await client.aclose()

        assert resp.model == "xiangxin-3.0.0"
        assert resp.input_tokens == 195
        assert resp.latency_ms >= 0

        cat = resp.answers["category"]
        assert cat.qtype == "choice"
        assert cat.value == "brute_force"
        assert 0.0 <= cat.confidence <= 1.0

        urg = resp.answers["urgency"]
        assert urg.qtype == "noul"
        assert 0.0 <= urg.value <= 1.0

        sev = resp.answers["severity"]
        assert sev.qtype == "score"
        assert 0.0 <= sev.value <= 1.0
        assert sev.legend == {"0": "低", "1": "中", "2": "高"}
        # 概率区间断言：全部落在[0,1]且总和接近1（容忍浮点抖动）
        total = sum(sev.probabilities.values())
        assert all(0.0 <= p <= 1.0 for p in sev.probabilities.values())
        assert 0.9 <= total <= 1.1


class TestRetryPolicy:
    async def test_429_retry_after_then_success(self):
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            if calls["n"] == 1:
                return httpx.Response(429, json={"detail": "rate limited"},
                                      headers={"retry-after-ms": "10"})
            return _ok_response({"model": "xiangxin-3.0.0",
                                 "answers": {"q": {"type": "noul", "noul": 0.9}},
                                 "usage": {"input_tokens": 10, "output_tokens": 5}})

        client = _mock_client(handler)
        resp = await client.system_one(
            state="s", questions={"q": Noul(instructions="i")}
        )
        await client.aclose()

        assert calls["n"] == 2
        assert resp.answers["q"].value is not None

    async def test_529_uses_retry_after_seconds_header(self):
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            if calls["n"] == 1:
                return httpx.Response(529, json={"detail": "overloaded"},
                                      headers={"retry-after": "0.01"})
            return _ok_response(_sample_success())

        client = _mock_client(handler)
        await client.system_one(state="s", questions={"q": Noul(instructions="i")})
        await client.aclose()
        assert calls["n"] == 2

    async def test_500_backoff_then_success(self):
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            if calls["n"] <= 2:
                return httpx.Response(500, json={"detail": "oops"})
            return _ok_response(_sample_success())

        client = _mock_client(handler)
        await client.system_one(state="s", questions={"q": Noul(instructions="i")})
        await client.aclose()
        assert calls["n"] == 3

    async def test_retries_exhausted_rate_limited(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(429, json={"detail": "rate limited"},
                                  headers={"retry-after-ms": "5"})

        client = _mock_client(handler)
        with pytest.raises(RateLimitedError) as exc_info:
            await client.system_one(state="s", questions={"q": Noul(instructions="i")})
        await client.aclose()
        assert exc_info.value.retry_after_ms == 5

    async def test_network_error_exhausted_unavailable(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused")

        client = _mock_client(handler)
        with pytest.raises(SystemOneUnavailableError):
            await client.system_one(state="s", questions={"q": Noul(instructions="i")})
        await client.aclose()

    async def test_422_no_retry(self):
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            return httpx.Response(
                422, json={"detail": "Too many choices. Must have at most 255 choices."}
            )

        client = _mock_client(handler)
        with pytest.raises(InvalidRequestError):
            await client.system_one(state="s", questions={"q": Noul(instructions="i")})
        await client.aclose()
        assert calls["n"] == 1  # 不重试

    async def test_401_auth_error_no_retry(self):
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            return httpx.Response(401, json={"detail": "invalid_api_key"})

        client = _mock_client(handler)
        with pytest.raises(AuthError):
            await client.system_one(state="s", questions={"q": Noul(instructions="i")})
        await client.aclose()
        assert calls["n"] == 1

    async def test_402_balance_error(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(402, json={"detail": "insufficient_balance"})

        client = _mock_client(handler)
        with pytest.raises(AuthError):
            await client.system_one(state="s", questions={"q": Noul(instructions="i")})
        await client.aclose()


class TestTokenEstimate:
    def test_cjk_vs_ascii(self):
        cjk_text = "告警分诊判定" * 10  # 60个汉字
        cjk_tokens = SystemOneClient.estimate_tokens(cjk_text)
        ascii_text = "alert triage decision " * 10  # 220字符
        ascii_tokens = SystemOneClient.estimate_tokens(ascii_text)
        # CJK ≈ 1 token/字, ASCII ≈ 4字符/token
        assert 55 <= cjk_tokens <= 65
        assert 50 <= ascii_tokens <= 65

    def test_empty(self):
        assert SystemOneClient.estimate_tokens("") == 0

    def test_request_estimate_includes_questions(self):
        q = Choice(instructions="属于哪类攻击？", criteria={"a": "暴力破解", "b": "扫描"})
        est = SystemOneClient.estimate_request_tokens("状态文本", {"q": q})
        assert est > SystemOneClient.estimate_tokens("状态文本")


class TestDotenvAndConfig:
    def test_load_dotenv_injects_and_not_overrides(self, tmp_path: Path, monkeypatch):
        env_file = tmp_path / ".env"
        env_file.write_text(
            "# 注释行\n"
            "XX-AI-KEY=sk-xx-from-file\n"
            "EXISTING_VAR=from-file\n"
            "MALFORMED_LINE_NO_EQUALS\n"
            "\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("EXISTING_VAR", "from-env")
        monkeypatch.delenv("XX-AI-KEY", raising=False)

        loaded = load_dotenv(str(env_file))

        assert os.environ["XX-AI-KEY"] == "sk-xx-from-file"
        # 已有环境变量不被覆盖
        assert os.environ["EXISTING_VAR"] == "from-env"
        assert "XX-AI-KEY" in loaded and "EXISTING_VAR" not in loaded
        assert "MALFORMED_LINE_NO_EQUALS" not in os.environ

    def test_load_dotenv_missing_file(self, tmp_path: Path):
        assert load_dotenv(str(tmp_path / "nonexistent")) == {}

    def test_load_config_resolves_env_in_system_one(self, tmp_path: Path, monkeypatch):
        (tmp_path / ".env").write_text("XX-AI-KEY=sk-xx-test-123\n", encoding="utf-8")
        (tmp_path / "config.yaml").write_text(
            "system_one:\n"
            "  enabled: true\n"
            "  api_key: ${XX-AI-KEY}\n"
            "  confidence_threshold: 0.7\n",
            encoding="utf-8",
        )
        monkeypatch.delenv("XX-AI-KEY", raising=False)
        monkeypatch.chdir(tmp_path)

        config = load_config(str(tmp_path / "config.yaml"))

        assert config.system_one.api_key == "sk-xx-test-123"
        assert config.system_one.confidence_threshold == 0.7
        # 默认值生效
        assert config.system_one.model == "xiangxin-latest"
        assert config.routing.queue_max_size == 10000

    def test_defaults_without_config(self, tmp_path: Path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        config = load_config(str(tmp_path / "no-such.yaml"))
        assert config.system_one.enabled is True
        assert config.system_one.base_url == "https://api.xiangxinai.cn/v1"
