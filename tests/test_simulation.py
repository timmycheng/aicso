"""仿真套件 CI 包装（issue #33）——快速规模跑核心矩阵，纳入回归门禁"""
from __future__ import annotations

import pytest

from scripts.simulation_test import (
    run_all,
)


@pytest.mark.timeout(300)
async def test_simulation_core_matrix():
    """local+scripted 核心矩阵（分流13项/合并拆分11项/恢复/效率）"""
    result = await run_all(scale=0.3, with_systemone=False)
    assert result["ok"] is True, (
        "仿真矩阵存在失败: "
        + "; ".join(
            f"[{suite}] {s['name']} — {s['detail']}"
            for suite, sims in result["results"].items()
            for s in sims if not s["ok"]
        )
    )
