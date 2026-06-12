"""Alert管理CLI命令"""
from __future__ import annotations

import asyncio
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

alert_app = typer.Typer(help="Alert（告警）管理")
console = Console()


@alert_app.command("list")
def alert_list(
    case_id: Optional[str] = typer.Option(None, help="按Case ID筛选"),
    source: Optional[str] = typer.Option(None, help="按来源筛选"),
    limit: int = typer.Option(20, help="显示数量"),
):
    """列出告警"""
    asyncio.run(_alert_list(case_id, source, limit))


async def _alert_list(case_id: Optional[str], source: Optional[str], limit: int):
    from aicso.store.database import Database
    from aicso.store.alert_store import AlertStore

    db = Database()
    await db.connect()
    try:
        store = AlertStore(db)
        alerts = await store.list_alerts(case_id=case_id, source=source, limit=limit)
        if not alerts:
            console.print("[yellow]没有找到告警[/]")
            return

        table = Table(title=f"告警列表 (共 {len(alerts)} 条)")
        table.add_column("Alert ID", style="cyan")
        table.add_column("来源")
        table.add_column("规则名称", max_width=30)
        table.add_column("严重级别", style="bold")
        table.add_column("源IP")
        table.add_column("目标IP")
        table.add_column("Case ID")
        table.add_column("时间")

        severity_colors = {
            "critical": "red", "high": "yellow", "medium": "blue", "low": "green", "info": "white"
        }
        for a in alerts:
            sev = a.get("severity", "medium")
            color = severity_colors.get(sev, "white")
            table.add_row(
                a["alert_id"][:20],
                a.get("source", ""),
                (a.get("rule_name") or "N/A")[:30],
                f"[{color}]{sev}[/]",
                a.get("src_ip", "-"),
                a.get("dst_ip", "-"),
                a.get("case_id", "-"),
                str(a.get("timestamp", ""))[:19],
            )
        console.print(table)
    finally:
        await db.close()


@alert_app.command("show")
def alert_show(alert_id: str = typer.Argument(help="Alert ID")):
    """查看告警详情"""
    asyncio.run(_alert_show(alert_id))


async def _alert_show(alert_id: str):
    from aicso.store.database import Database
    from aicso.store.alert_store import AlertStore

    db = Database()
    await db.connect()
    try:
        store = AlertStore(db)
        alert = await store.get(alert_id)
        if not alert:
            console.print(f"[red]告警不存在: {alert_id}[/]")
            return

        console.print(f"\n[bold cyan]告警: {alert['alert_id']}[/]")
        console.print(f"  来源:     {alert.get('source', '')}")
        console.print(f"  规则ID:   {alert.get('rule_id', '-')}")
        console.print(f"  规则名称: {alert.get('rule_name', '-')}")
        console.print(f"  严重级别: {alert.get('severity', '')}")
        console.print(f"  时间:     {alert.get('timestamp', '')}")
        console.print(f"  源IP:     {alert.get('src_ip', '-')}")
        console.print(f"  目标IP:   {alert.get('dst_ip', '-')}")
        console.print(f"  源端口:   {alert.get('src_port', '-')}")
        console.print(f"  目标端口: {alert.get('dst_port', '-')}")
        console.print(f"  协议:     {alert.get('protocol', '-')}")
        console.print(f"  Case ID:  {alert.get('case_id', '-')}")
        console.print(f"  误报标记: {alert.get('is_false_positive', False)}")

        raw_log = alert.get("raw_log")
        if raw_log:
            console.print(f"\n[bold]原始日志:[/]")
            console.print(f"  {raw_log[:500]}")
    finally:
        await db.close()


@alert_app.command("search")
def alert_search(
    src_ip: Optional[str] = typer.Option(None, help="按源IP搜索"),
    days: int = typer.Option(7, help="搜索天数"),
    limit: int = typer.Option(20, help="显示数量"),
):
    """搜索告警"""
    asyncio.run(_alert_list(None, None, limit))
