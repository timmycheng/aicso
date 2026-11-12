"""数据源管理器 - 周期性拉取告警"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta

import structlog

from aicso.adapters.base import DataSourceAdapter
from aicso.adapters.registry import datasource_registry
from aicso.config import AppConfig, DataSourceConfig
from aicso.core.orchestrator import Orchestrator

logger = structlog.get_logger()


class DataSourceHandle:
    """单个数据源的运行时状态"""

    # 失败批连续rewind上限：防个别毒消息把分区卡死；触顶后放行commit
    # 并落死信告警（正常系统级失败如DB不可用在此前早已恢复）
    MAX_REWIND_ATTEMPTS = 10

    def __init__(self, name: str, ds_config: DataSourceConfig, adapter: DataSourceAdapter):
        self.name = name
        self.ds_config = ds_config
        self.adapter = adapter
        self.connected: bool = False
        self.last_poll: datetime | None = None
        self.last_error: str | None = None
        self.total_fetched: int = 0
        self.poll_count: int = 0
        self.rewind_attempts: int = 0
        self.task: asyncio.Task | None = None

    def status_dict(self, stats: dict | None = None) -> dict:
        data = {
            "name": self.name,
            "type": self.ds_config.type,
            "enabled": self.ds_config.enabled,
            "connected": self.connected,
            "poll_interval": self.ds_config.poll_interval,
            "last_poll": self.last_poll.isoformat() if self.last_poll else None,
            "last_error": self.last_error,
            "total_fetched": self.total_fetched,
            "poll_count": self.poll_count,
            "lag": None,
        }
        if stats:
            data["lag"] = stats.get("total_lag")
            data["lag_partitions"] = stats.get("partitions", {})
        return data


class DataSourceManager:
    """管理所有数据源的连接与周期拉取"""

    def __init__(self, config: AppConfig, orchestrator: Orchestrator):
        self._config = config
        self._orchestrator = orchestrator
        self._handles: dict[str, DataSourceHandle] = {}
        self._running = False

    async def start(self) -> None:
        """连接所有 enabled 数据源并启动轮询"""
        self._running = True

        for name, ds_config in self._config.datasources.items():
            if not ds_config.enabled:
                logger.info("datasource_manager.skip_disabled", name=name)
                continue

            adapter = datasource_registry.create(ds_config.type)
            if not adapter:
                logger.error("datasource_manager.unknown_type", name=name, type=ds_config.type)
                continue

            handle = DataSourceHandle(name, ds_config, adapter)

            # 连接
            try:
                ok = await adapter.connect(ds_config.config)
                handle.connected = ok
                if not ok:
                    handle.last_error = "connect returned False"
                    logger.warning("datasource_manager.connect_failed", name=name)
            except Exception as e:
                handle.last_error = str(e)
                logger.error("datasource_manager.connect_error", name=name, error=str(e))

            self._handles[name] = handle

            # 启动轮询任务
            if ds_config.poll_interval > 0:
                handle.task = asyncio.create_task(self._poll_loop(name))
                logger.info(
                    "datasource_manager.poll_started",
                    name=name,
                    type=ds_config.type,
                    interval=ds_config.poll_interval,
                )
            else:
                logger.info(
                    "datasource_manager.no_poll", name=name, poll_interval=ds_config.poll_interval
                )

    async def stop(self) -> None:
        """停止所有轮询任务并关闭连接"""
        self._running = False

        for name, handle in self._handles.items():
            if handle.task and not handle.task.done():
                handle.task.cancel()
                try:
                    await handle.task
                except asyncio.CancelledError:
                    pass
            try:
                await handle.adapter.close()
            except Exception as e:
                logger.error("datasource_manager.close_error", name=name, error=str(e))

        self._handles.clear()
        logger.info("datasource_manager.stopped")

    async def _poll_loop(self, name: str) -> None:
        """单个数据源的轮询循环"""
        handle = self._handles.get(name)
        if not handle:
            return

        interval = handle.ds_config.poll_interval
        since = datetime.utcnow() - timedelta(minutes=5)  # 首次拉取近5分钟

        while self._running:
            try:
                # 如果之前连接失败，尝试重连
                if not handle.connected:
                    try:
                        ok = await handle.adapter.connect(handle.ds_config.config)
                        handle.connected = ok
                        if ok:
                            handle.last_error = None
                            logger.info("datasource_manager.reconnected", name=name)
                    except Exception as e:
                        handle.last_error = str(e)
                        logger.warning(
                            "datasource_manager.reconnect_failed", name=name, error=str(e)
                        )

                if handle.connected:
                    alerts = await handle.adapter.poll(since)
                    handle.poll_count += 1
                    handle.last_poll = datetime.utcnow()

                    if alerts:
                        handle.total_fetched += len(alerts)
                        logger.info(
                            "datasource_manager.fetched",
                            name=name,
                            count=len(alerts),
                            total=handle.total_fetched,
                        )

                    # 批次处理：系统级失败计数>0则不提交位点且不推进since——
                    # 重复投递由 alert_id 主键幂等吸收（INSERT OR IGNORE）
                    failures = 0
                    for alert in alerts:
                        try:
                            await self._orchestrator.handle_alert(alert)
                        except Exception as e:
                            failures += 1
                            logger.error(
                                "datasource_manager.handle_alert_error",
                                name=name,
                                alert_id=alert.alert_id,
                                error=str(e),
                            )

                    if failures:
                        #位点与since都不动（重投）。Kafka还需显式seek回批首：
                        # getmany单调前进内存位点，仅不commit挡不住前进，
                        # 下一成功批的commit会永久跳过失败消息（#56发现17/22）
                        handle.rewind_attempts += 1
                        rewound = False
                        if hasattr(handle.adapter, "rewind"):
                            if handle.rewind_attempts <= DataSourceHandle.MAX_REWIND_ATTEMPTS:
                                try:
                                    rewound = await handle.adapter.rewind()
                                except Exception as e:
                                    logger.error("datasource_manager.rewind_error",
                                                 name=name, error=str(e))
                            else:
                                logger.error(
                                    "datasource_manager.dead_letter_advance",
                                    name=name, attempts=handle.rewind_attempts,
                                    msg="失败批连续回退超限：放行commit跳过毒批",
                                )
                        logger.warning(
                            "datasource_manager.skip_commit",
                            name=name, failures=failures, batch=len(alerts),
                            rewound=rewound, attempts=handle.rewind_attempts,
                        )
                        continue  # since不推进：REST路径下轮重拉同窗口（幂等吸收）

                    handle.rewind_attempts = 0
                    if hasattr(handle.adapter, "commit"):
                        await handle.adapter.commit()
                    # 全部处理成功才推进 since（失败窗口告警不漏采，#56发现22）
                    since = datetime.utcnow()

            except asyncio.CancelledError:
                break
            except Exception as e:
                handle.last_error = str(e)
                logger.error("datasource_manager.poll_error", name=name, error=str(e))

            await asyncio.sleep(interval)

    def get_handle(self, name: str) -> DataSourceHandle | None:
        return self._handles.get(name)

    async def list_status(self) -> list[dict]:
        rows = []
        for h in self._handles.values():
            stats = None
            if hasattr(h.adapter, "stats"):
                try:
                    result = h.adapter.stats()
                    # kafka适配器stats为协程（position()需await）
                    if asyncio.iscoroutine(result):
                        result = await result
                    stats = result
                except Exception as e:
                    logger.warning("datasource_manager.stats_error",
                                   name=h.name, error=str(e))
            rows.append(h.status_dict(stats))
        return rows
