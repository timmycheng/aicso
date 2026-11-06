"""象信 System One 连通性冒烟脚本

用真实 key 发一个单请求（state + Choice + Noul），验证连通性、响应结构与计费。
成本分级：输入 <100 token，按 ¥0.042/百万token 计 <1 分钱。

用法: uv run python scripts/systemone_smoke.py
前置: .env 含 XX-AI-KEY，config.yaml 含 system_one 段
"""
from __future__ import annotations

import asyncio
import sys

from aicso.config import load_config
from aicso.systemone.client import Choice, Noul, SystemOneClient

STATE = (
    "主机 10.0.0.8 在5分钟内出现12次SSH登录失败，来源IP 203.0.113.66，"
    "涉及账户 root、admin，失败后有一次成功登录。"
)


async def main() -> int:
    config = load_config()
    sc = config.system_one
    if not sc.api_key:
        print("缺少 api_key：检查 .env 的 XX-AI-KEY 与 config.yaml 中 ${XX-AI-KEY} 的展开")
        return 1

    print(f"endpoint={sc.base_url} model={sc.model}")
    async with SystemOneClient(
        api_key=sc.api_key,
        base_url=sc.base_url,
        model=sc.model,
        timeout_ms=sc.timeout_ms,
    ) as client:
        resp = await client.system_one(
            state=STATE,
            questions={
                "category": Choice(
                    instructions="这条告警最可能属于哪类攻击行为？",
                    criteria={
                        "brute_force": "暴力破解/口令爆破",
                        "scan": "端口或服务扫描",
                        "compromise": "已成功入侵/账户失陷",
                        "other": "其他或无法判断",
                    },
                ),
                "is_urgent": Noul(instructions="该告警是否需要立即关注？"),
            },
        )

    print("---answers---")
    for name, ans in resp.answers.items():
        # 概率在重复调用间有小幅抖动，仅做区间展示，不做精确断言
        print(f"{name}: value={ans.value} confidence={ans.confidence} "
              f"probs={ans.probabilities}")
    print(f"model={resp.model} latency={resp.latency_ms:.0f}ms "
          f"tokens_in={resp.input_tokens} tokens_out={resp.output_tokens}")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
