"""测试全局配置：密闭性保障

此前 test_pages.py 经 app lifespan 加载开发者本地 config.yaml（llm/system_one
全开 + .env 真key）→ 本地跑 pytest 会打真实LLM/System One API、写仓库根
aicso.db（review #56发现43）。此 fixture 强制全部走 app 生命周期的测试使用
密闭配置：LLM/System One 关闭、DB 指向临时目录，离线确定性。
"""
from __future__ import annotations

import json
from functools import partial
from pathlib import Path

import pytest

_HERMETIC_CONFIG = {
    "llm": {"enabled": False},
    "system_one": {"enabled": False},
    "database": {
        # from_row 接线后 Database 从 url 解析路径（此前url是死配置）
        "url": "sqlite+aiosqlite:///{db_path}",
        "profile": "sqlite",
    },
    "retention": {"alert_days": 0},
    "datasources": {},
}


@pytest.fixture(scope="session", autouse=True)
def hermetic_app_config(tmp_path_factory):
    """让 aicso.api.app.lifespan 用密闭配置初始化（不影响自建组件的单元测试）"""
    import aicso.api.app as app_mod

    db_dir = tmp_path_factory.mktemp("aicso-db")
    db_path = db_dir / "test.db"
    cfg_path = Path(tmp_path_factory.mktemp("aicso-cfg")) / "config.yaml"
    cfg_path.write_text(
        json.dumps(_HERMETIC_CONFIG).replace("{db_path}", str(db_path).replace("\\", "/")),
        encoding="utf-8",
    )

    real_init = app_mod.init_app_state
    app_mod.init_app_state = partial(real_init, config_path=str(cfg_path))
    yield
    app_mod.init_app_state = real_init
