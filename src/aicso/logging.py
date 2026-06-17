"""日志配置模块"""
from __future__ import annotations

import logging
import sys
from pathlib import Path

import structlog

_LOG_INITIALIZED = False


def setup_logging(level: str = "INFO", log_dir: str = "logs") -> None:
    """初始化structlog和标准logging，同时输出到控制台和文件"""
    global _LOG_INITIALIZED
    if _LOG_INITIALIZED:
        return
    _LOG_INITIALIZED = True

    log_path = Path(log_dir)
    log_path.mkdir(exist_ok=True)

    log_level = getattr(logging, level.upper(), logging.INFO)

    # structlog处理器链
    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    # 控制台用彩色key-value输出
    console_renderer = structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty())
    # 文件用JSON输出
    file_renderer = structlog.processors.JSONRenderer()

    # 配置structlog
    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # 控制台handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(
        structlog.stdlib.ProcessorFormatter(
            processor=console_renderer,
            foreign_pre_chain=shared_processors,
        )
    )

    # 文件handler - 常规日志
    file_handler = logging.FileHandler(
        log_path / "aicso.log", encoding="utf-8", delay=True
    )
    file_handler.setLevel(log_level)
    file_handler.setFormatter(
        structlog.stdlib.ProcessorFormatter(
            processor=file_renderer,
            foreign_pre_chain=shared_processors,
        )
    )

    # 文件handler - 错误日志
    error_handler = logging.FileHandler(
        log_path / "aicso_error.log", encoding="utf-8", delay=True
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(
        structlog.stdlib.ProcessorFormatter(
            processor=file_renderer,
            foreign_pre_chain=shared_processors,
        )
    )

    # 配置root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.handlers.clear()
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(error_handler)

    # uvicorn的logger也挂上去
    for name in ("uvicorn", "uvicorn.access", "uvicorn.error"):
        uv_logger = logging.getLogger(name)
        uv_logger.handlers.clear()
        uv_logger.addHandler(console_handler)
        uv_logger.addHandler(file_handler)
        uv_logger.addHandler(error_handler)

    structlog.get_logger("logging").info(
        "logging.initialized", level=level, log_dir=str(log_path.resolve())
    )
