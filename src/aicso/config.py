"""AiCSO全局配置"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field


class LLMProviderConfig(BaseModel):
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    model: str = "deepseek-chat"
    max_tokens: int = 4096
    temperature: float = 0.1


class LLMBudgetConfig(BaseModel):
    daily_limit: int = 1_000_000
    monthly_limit: int = 20_000_000
    alert_on_percent: int = 80


class LLMContextConfig(BaseModel):
    max_context_tokens: int = 120_000
    summary_threshold: int = 80_000
    truncation_strategy: str = "smart"


class LLMConfig(BaseModel):
    enabled: bool = True
    default_provider: str = "deepseek"
    providers: dict[str, LLMProviderConfig] = Field(default_factory=dict)
    budget: LLMBudgetConfig = Field(default_factory=LLMBudgetConfig)
    context: LLMContextConfig = Field(default_factory=LLMContextConfig)


class DatabaseConfig(BaseModel):
    url: str = "sqlite+aiosqlite:///./aicso.db"


class VectorStoreConfig(BaseModel):
    provider: str = "chromadb"
    path: str = "./data/chromadb"
    embedding_model: str = "BAAI/bge-small-zh-v1.5"
    similarity_threshold: float = 0.7


class ServerConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8000


class LoggingConfig(BaseModel):
    level: str = "INFO"
    format: str = "json"


class DataSourceConfig(BaseModel):
    type: str  # rest_api, syslog, json_file, webhook
    enabled: bool = True
    description: str = ""
    config: dict = Field(default_factory=dict)
    poll_interval: int = 60  # 周期拉取间隔（秒），0=不轮询


class AppConfig(BaseModel):
    llm: LLMConfig = Field(default_factory=LLMConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    vector_store: VectorStoreConfig = Field(default_factory=VectorStoreConfig)
    server: ServerConfig = Field(default_factory=ServerConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    datasources: dict[str, DataSourceConfig] = Field(default_factory=dict)


def _resolve_env_vars(obj):
    """递归解析 ${ENV_VAR} 格式的环境变量"""
    if isinstance(obj, str) and obj.startswith("${") and obj.endswith("}"):
        env_name = obj[2:-1]
        return os.environ.get(env_name, obj)
    elif isinstance(obj, dict):
        return {k: _resolve_env_vars(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_resolve_env_vars(i) for i in obj]
    return obj


def load_config(config_path: str = "config.yaml") -> AppConfig:
    """加载配置文件"""
    path = Path(config_path)
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        raw = _resolve_env_vars(raw)
        # Ensure dict fields are not None
        for key in ("datasources",):
            if key in raw and raw[key] is None:
                raw[key] = {}
        return AppConfig(**raw)
    return AppConfig()
