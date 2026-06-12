"""数据源适配器基类"""
from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional

from aicso.models.alert import Alert


class DataSourceAdapter(ABC):
    """数据源适配器基类"""

    name: str = "base"
    description: str = ""

    @abstractmethod
    async def connect(self, config: dict) -> bool:
        """连接数据源"""
        ...

    @abstractmethod
    async def fetch_alerts(self, since: datetime) -> list[dict]:
        """拉取原始告警数据"""
        ...

    @abstractmethod
    async def normalize(self, raw: dict) -> Alert:
        """标准化为统一Alert格式"""
        ...

    async def poll(self, since: datetime) -> list[Alert]:
        """拉取并标准化告警"""
        raw_alerts = await self.fetch_alerts(since)
        results = []
        for raw in raw_alerts:
            try:
                alert = await self.normalize(raw)
                results.append(alert)
            except Exception:
                pass
        return results


class SyslogAdapter(DataSourceAdapter):
    """Syslog通用适配器（基于文件监听）"""

    name = "syslog"
    description = "Syslog日志文件适配器"

    def __init__(self, log_path: str = "/var/log/syslog"):
        self.log_path = log_path
        self._last_position = 0

    async def connect(self, config: dict) -> bool:
        from pathlib import Path
        self.log_path = config.get("log_path", self.log_path)
        return Path(self.log_path).exists()

    async def fetch_alerts(self, since: datetime) -> list[dict]:
        alerts = []
        try:
            with open(self.log_path, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(self._last_position)
                for line in f:
                    line = line.strip()
                    if line:
                        alerts.append({"raw": line, "timestamp": since.isoformat()})
                self._last_position = f.tell()
        except FileNotFoundError:
            pass
        return alerts

    async def normalize(self, raw: dict) -> Alert:
        import uuid
        return Alert(
            alert_id=f"syslog-{uuid.uuid4().hex[:8]}",
            source="syslog",
            raw_log=raw.get("raw", ""),
        )


class JSONFileAdapter(DataSourceAdapter):
    """JSON文件适配器（用于测试和批量导入）"""

    name = "json_file"
    description = "JSON文件告警适配器"

    def __init__(self, file_path: str = ""):
        self.file_path = file_path

    async def connect(self, config: dict) -> bool:
        from pathlib import Path
        self.file_path = config.get("file_path", self.file_path)
        return Path(self.file_path).exists()

    async def fetch_alerts(self, since: datetime) -> list[dict]:
        import json
        with open(self.file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else [data]

    async def normalize(self, raw: dict) -> Alert:
        import uuid
        from datetime import datetime as dt
        return Alert(
            alert_id=raw.get("alert_id", f"json-{uuid.uuid4().hex[:8]}"),
            source=raw.get("source", "json_file"),
            rule_id=raw.get("rule_id"),
            rule_name=raw.get("rule_name"),
            severity=raw.get("severity", "medium"),
            timestamp=dt.fromisoformat(raw["timestamp"]) if raw.get("timestamp") else dt.utcnow(),
            src_ip=raw.get("src_ip"),
            dst_ip=raw.get("dst_ip"),
            src_port=raw.get("src_port"),
            dst_port=raw.get("dst_port"),
            protocol=raw.get("protocol"),
            raw_log=raw.get("raw_log"),
        )
