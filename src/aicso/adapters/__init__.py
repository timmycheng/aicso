"""数据源适配器"""
from aicso.adapters.base import DataSourceAdapter, SyslogAdapter, JSONFileAdapter
from aicso.adapters.rest_api import RestApiAdapter
from aicso.adapters.kafka import KafkaAdapter
from aicso.adapters.registry import AdapterRegistry, datasource_registry

__all__ = [
    "DataSourceAdapter", "SyslogAdapter", "JSONFileAdapter",
    "RestApiAdapter", "KafkaAdapter",
    "AdapterRegistry", "datasource_registry",
]
