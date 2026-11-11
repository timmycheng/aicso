"""AiCSO全局配置"""
from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class LLMProviderConfig(BaseModel):
    api_key: str | None = None
    base_url: str | None = None
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
    # 存储profile缝（设计§12）：默认sqlite（内网单机）；
    # postgres等后续profile接入时替换实现，配置先行
    profile: str = "sqlite"


class RetentionConfig(BaseModel):
    """告警保留策略（设计§12容量治理）：0天=不清理"""
    alert_days: int = 0
    cleanup_interval_minutes: int = 60
    # 清理范围: orphan_only(仅未关联Case) | closed_cases(含已关闭Case的) | all
    scope: str = "closed_cases"


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


class SystemOneConfig(BaseModel):
    """象信AI System One 判定模型（分流引擎，见 docs/REFACTOR_DESIGN.md §5）"""
    enabled: bool = True
    base_url: str = "https://api.xiangxinai.cn/v1"
    api_key: str | None = None  # 支持 ${XX-AI-KEY} 环境变量展开
    model: str = "xiangxin-latest"
    batch_window_ms: int = 100   # 微批聚合窗口
    batch_max_alerts: int = 50   # 单批条数上限（token预算另约束，见 token_budget）
    token_budget: int = 32000    # 单请求token估算预算——象信上下文65536；真实数据实测
                                 # ~50k token请求有连接中断风险(#42/#44验收)，留2倍余量
    timeout_ms: int = 2000
    confidence_threshold: float = 0.6  # 低于阈值 → 保守新建Case + 人工复核
    cache_ttl_seconds: int = 60  # 同实体签名决策缓存
    fallback: str = "local_rules"  # API不可用时的降级方式
    candidate_top_k: int = 10    # 候选Case数量上限（Choice ≤255 约束内）
    review_queue_enabled: bool = True  # 低置信度进人工复核


class RoutingConfig(BaseModel):
    """路由队列与背压（见 docs/REFACTOR_DESIGN.md §5.7）"""
    # 类型化实体白名单：进候选索引的弱实体类型（issue #44）。
    # 默认四类起步；后续可由回放审计/人工处置/LLM建议机制动态调整
    entity_types: list[str] = Field(
        default_factory=lambda: ["host", "user", "file_hash", "dst_domain"])
    # 弱实体类型自动合并开关：默认关——弱实体仅产生候选交模型裁决。
    # 开启后共享弱实体的告警在pair窗内直接汇入（有误并风险，如共享服务账号）
    weak_entity_auto_merge: bool = False
    queue_max_size: int = 10000
    high_water_mark: float = 0.8   # 水位≥80%: 告警+指标
    overload_mark: float = 0.95    # 水位≥95%: 过载模式，本地兜底接管
    s2_concurrency: int = 3        # 冷路径任务并发上限


class AppConfig(BaseModel):
    llm: LLMConfig = Field(default_factory=LLMConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    vector_store: VectorStoreConfig = Field(default_factory=VectorStoreConfig)
    server: ServerConfig = Field(default_factory=ServerConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    datasources: dict[str, DataSourceConfig] = Field(default_factory=dict)
    system_one: SystemOneConfig = Field(default_factory=SystemOneConfig)
    routing: RoutingConfig = Field(default_factory=RoutingConfig)
    retention: RetentionConfig = Field(default_factory=RetentionConfig)


def load_dotenv(path: str = ".env") -> dict[str, str]:
    """轻量 .env 加载：KEY=VALUE 行注入 os.environ，不覆盖已有环境变量"""
    loaded: dict[str, str] = {}
    p = Path(path)
    if not p.exists():
        return loaded
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip("'\"")
        if key and key not in os.environ:
            os.environ[key] = value
            loaded[key] = value
    return loaded


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
    """加载配置文件（先加载同目录 .env，再展开 ${ENV} 引用）"""
    load_dotenv()
    path = Path(config_path)
    if path.exists():
        with open(path, encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        raw = _resolve_env_vars(raw)
        # Ensure dict fields are not None
        for key in ("datasources",):
            if key in raw and raw[key] is None:
                raw[key] = {}
        return AppConfig(**raw)
    return AppConfig()
