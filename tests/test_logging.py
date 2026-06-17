"""日志模块测试"""
from __future__ import annotations

import gc
import logging
from pathlib import Path

import structlog

from aicso.logging import setup_logging


def _reset_logging():
    """重置logging状态，关闭所有handler释放文件句柄"""
    import aicso.logging
    aicso.logging._LOG_INITIALIZED = False

    # 清除structlog缓存
    structlog.reset_defaults()

    for name in ("", "uvicorn", "uvicorn.access", "uvicorn.error"):
        logger = logging.getLogger(name)
        for h in logger.handlers[:]:
            h.close()
            logger.removeHandler(h)

    gc.collect()


def test_setup_logging_creates_files(tmp_path):
    """setup_logging应创建日志文件并输出到控制台"""
    _reset_logging()
    setup_logging(level="DEBUG", log_dir=str(tmp_path))

    logger = structlog.get_logger("test")
    logger.info("hello_test", key="value")

    log_file = tmp_path / "aicso.log"
    assert log_file.exists(), "aicso.log should be created"

    content = log_file.read_text(encoding="utf-8")
    assert "hello_test" in content
    assert "key" in content

    _reset_logging()


def test_setup_logging_idempotent(tmp_path):
    """重复调用setup_logging不应添加重复handler"""
    _reset_logging()
    setup_logging(level="INFO", log_dir=str(tmp_path))
    handler_count = len(logging.getLogger().handlers)
    setup_logging(level="INFO", log_dir=str(tmp_path))
    assert len(logging.getLogger().handlers) == handler_count

    _reset_logging()


def test_error_log_only_captures_errors(tmp_path):
    """错误日志文件只记录ERROR及以上级别"""
    _reset_logging()
    setup_logging(level="DEBUG", log_dir=str(tmp_path))

    logger = structlog.get_logger("test")
    logger.info("info_msg")
    logger.error("error_msg")

    log_file = tmp_path / "aicso.log"
    error_file = tmp_path / "aicso_error.log"

    assert log_file.exists()
    assert error_file.exists(), "error file created after error log"

    error_content = error_file.read_text(encoding="utf-8")
    log_content = log_file.read_text(encoding="utf-8")
    assert "error_msg" in error_content
    assert "info_msg" not in error_content
    assert "info_msg" in log_content

    _reset_logging()
