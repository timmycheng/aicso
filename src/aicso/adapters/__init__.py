"""数据源适配器"""
from aicso.adapters.base import DataSourceAdapter, JSONFileAdapter, SyslogAdapter
from aicso.adapters.kafka import KafkaAdapter
from aicso.adapters.registry import AdapterRegistry, datasource_registry
from aicso.adapters.rest_api import RestApiAdapter

__all__ = [
    "DataSourceAdapter", "SyslogAdapter", "JSONFileAdapter",
    "RestApiAdapter", "KafkaAdapter",
    "AdapterRegistry", "datasource_registry",
]
