"""数据源适配器注册中心"""
from __future__ import annotations

from typing import Type

import structlog

from aicso.adapters.base import DataSourceAdapter, SyslogAdapter, JSONFileAdapter
from aicso.adapters.rest_api import RestApiAdapter
from aicso.adapters.kafka import KafkaAdapter

logger = structlog.get_logger()


class AdapterRegistry:
    """数据源适配器注册中心"""

    def __init__(self):
        self._adapters: dict[str, Type[DataSourceAdapter]] = {}
        # 注册内置适配器
        self.register(SyslogAdapter)
        self.register(JSONFileAdapter)
        self.register(RestApiAdapter)
        self.register(KafkaAdapter)

    def register(self, adapter_class: Type[DataSourceAdapter]) -> None:
        """注册适配器"""
        self._adapters[adapter_class.name] = adapter_class

    def get(self, adapter_type: str) -> Type[DataSourceAdapter] | None:
        """获取适配器类"""
        return self._adapters.get(adapter_type)

    def list_types(self) -> list[str]:
        """列出所有已注册的适配器类型"""
        return list(self._adapters.keys())

    def create(self, adapter_type: str) -> DataSourceAdapter | None:
        """创建适配器实例"""
        cls = self._adapters.get(adapter_type)
        if cls:
            return cls()
        return None


# 全局注册中心
datasource_registry = AdapterRegistry()
