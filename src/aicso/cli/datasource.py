"""数据源管理CLI命令"""
from __future__ import annotations

import asyncio
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

ds_app = typer.Typer(help="DataSource（数据源）管理")
console = Console()


@ds_app.command("list")
def ds_list():
    """列出已配置的数据源"""
    from aicso.config import load_config
    config = load_config()

    if not config.datasources:
        console.print("[yellow]No datasources configured[/]")
        console.print("Edit config.yaml to add datasources. See config.yaml for examples.")
        return

    table = Table(title="Configured Datasources")
    table.add_column("Name", style="cyan")
    table.add_column("Type")
    table.add_column("Description")
    table.add_column("Enabled")
    table.add_column("Status")

    for name, ds in config.datasources.items():
        table.add_row(
            name,
            ds.type,
            ds.description or "-",
            "[green]Yes[/]" if ds.enabled else "[red]No[/]",
            "configured",
        )
    console.print(table)


@ds_app.command("types")
def ds_types():
    """列出支持的数据源类型"""
    from aicso.adapters.registry import datasource_registry

    table = Table(title="Supported Datasource Types")
    table.add_column("Type", style="cyan")
    table.add_column("Description")

    descriptions = {
        "rest_api": "通用REST API适配（SIEM、态势感知平台）",
        "kafka": "Kafka Topic告警消费（内网SIEM常用）",
        "syslog": "Syslog日志文件监听",
        "json_file": "JSON文件批量导入",
    }
    for t in datasource_registry.list_types():
        table.add_row(t, descriptions.get(t, ""))
    console.print(table)


@ds_app.command("test")
def ds_test(name: str = typer.Argument(help="数据源名称（config.yaml中的key）")):
    """测试数据源连接"""
    asyncio.run(_ds_test(name))


async def _ds_test(name: str):
    from aicso.config import load_config
    from aicso.adapters.registry import datasource_registry

    config = load_config()
    ds_config = config.datasources.get(name)
    if not ds_config:
        console.print(f"[red]Datasource not found: {name}[/]")
        return

    adapter = datasource_registry.create(ds_config.type)
    if not adapter:
        console.print(f"[red]Unknown adapter type: {ds_config.type}[/]")
        return

    console.print(f"Testing datasource [cyan]{name}[/] (type={ds_config.type})...")
    try:
        ok = await adapter.connect(ds_config.config)
        if ok:
            console.print("[green]Connection OK[/]")
            # 尝试拉取一条告警
            from datetime import datetime, timedelta
            since = datetime.utcnow() - timedelta(hours=1)
            alerts = await adapter.fetch_alerts(since)
            console.print(f"Fetched [bold]{len(alerts)}[/] alerts (last 1h)")
            if alerts:
                console.print(f"Sample: {alerts[0]}")
        else:
            console.print("[red]Connection FAILED[/]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/]")
    finally:
        if hasattr(adapter, "close"):
            await adapter.close()


@ds_app.command("pull")
def ds_pull(
    name: str = typer.Argument(help="数据源名称"),
    hours: int = typer.Option(1, help="拉取最近N小时的告警"),
    dry_run: bool = typer.Option(False, "--dry-run", help="仅展示不入库"),
):
    """从数据源拉取告警"""
    asyncio.run(_ds_pull(name, hours, dry_run))


async def _ds_pull(name: str, hours: int, dry_run: bool):
    from datetime import datetime, timedelta
    from aicso.config import load_config
    from aicso.adapters.registry import datasource_registry
    from aicso.store.database import Database
    from aicso.store.alert_store import AlertStore
    from aicso.core.orchestrator import Orchestrator
    from aicso.core.event_bus import EventBus
    from aicso.core.context import ContextManager
    from aicso.core.approval import ApprovalEngine
    from aicso.aggregator.engine import AlertAggregator
    from aicso.store.case_store import CaseStore

    config = load_config()
    ds_config = config.datasources.get(name)
    if not ds_config:
        console.print(f"[red]Datasource not found: {name}[/]")
        return

    adapter = datasource_registry.create(ds_config.type)
    if not adapter:
        console.print(f"[red]Unknown adapter type: {ds_config.type}[/]")
        return

    try:
        ok = await adapter.connect(ds_config.config)
        if not ok:
            console.print("[red]Connection failed[/]")
            return

        since = datetime.utcnow() - timedelta(hours=hours)
        console.print(f"Pulling alerts from [cyan]{name}[/] since {since.isoformat()}...")

        raw_alerts = await adapter.fetch_alerts(since)
        console.print(f"Fetched [bold]{len(raw_alerts)}[/] raw alerts")

        if not raw_alerts:
            return

        # 标准化
        alerts = []
        for raw in raw_alerts:
            try:
                alert = await adapter.normalize(raw)
                alerts.append(alert)
            except Exception as e:
                console.print(f"[yellow]Skip alert: {e}[/]")

        console.print(f"Normalized [bold]{len(alerts)}[/] alerts")

        if dry_run:
            console.print("\n[bold]Dry run - showing first 5 alerts:[/]")
            for a in alerts[:5]:
                console.print(f"  [{a.severity}] {a.rule_name or 'N/A'} | "
                            f"src={a.src_ip or '-'} dst={a.dst_ip or '-'}")
            return

        # 入库并触发编排
        db = Database()
        await db.connect()
        try:
            case_store = CaseStore(db)
            alert_store = AlertStore(db)
            event_bus = EventBus()
            context_manager = ContextManager(case_store, alert_store)
            approval_engine = ApprovalEngine(event_bus)
            aggregator = AlertAggregator()

            orch = Orchestrator(case_store, alert_store, context_manager, event_bus, approval_engine, aggregator)

            created_cases = 0
            for alert in alerts:
                case_id = await orch.handle_alert(alert)
                if case_id:
                    created_cases += 1

            console.print(f"[green]Done![/] Processed {len(alerts)} alerts, {created_cases} cases affected")
        finally:
            await db.close()
    finally:
        if hasattr(adapter, "close"):
            await adapter.close()
