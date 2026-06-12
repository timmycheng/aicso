"""Case管理CLI命令"""
from __future__ import annotations

import asyncio
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

case_app = typer.Typer(help="Case（案件）管理")
console = Console()


@case_app.command("create")
def case_create(
    title: str = typer.Option(..., help="Case标题"),
    severity: str = typer.Option("medium", help="严重级别: critical/high/medium/low/info"),
):
    """创建新Case"""
    asyncio.run(_case_create(title, severity))


async def _case_create(title: str, severity: str):
    from aicso.store.database import Database
    from aicso.store.case_store import CaseStore
    from aicso.models.case import Case, CaseSeverity, CaseStatus, SEVERITY_PRIORITY_MAP

    db = Database()
    await db.connect()
    try:
        store = CaseStore(db)
        import uuid
        from datetime import datetime
        sev = CaseSeverity(severity)
        case = Case(
            case_id=f"CSO-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}",
            title=title,
            severity=sev,
            status=CaseStatus.NEW,
            priority=SEVERITY_PRIORITY_MAP.get(sev, 3),
        )
        await store.create(case)
        console.print(f"[green]OK[/] Case created: [bold]{case.case_id}[/]")
        console.print(f"  标题: {case.title}")
        console.print(f"  严重级别: {case.severity.value}")
        console.print(f"  优先级: P{case.priority.value}")
    finally:
        await db.close()


@case_app.command("list")
def case_list(
    status: Optional[str] = typer.Option(None, help="按状态筛选"),
    severity: Optional[str] = typer.Option(None, help="按严重级别筛选"),
    limit: int = typer.Option(20, help="显示数量"),
):
    """列出Case"""
    asyncio.run(_case_list(status, severity, limit))


async def _case_list(status: Optional[str], severity: Optional[str], limit: int):
    from aicso.store.database import Database
    from aicso.store.case_store import CaseStore

    db = Database()
    await db.connect()
    try:
        store = CaseStore(db)
        cases = await store.list_cases(status=status, severity=severity, limit=limit)
        if not cases:
            console.print("[yellow]没有找到Case[/]")
            return

        table = Table(title=f"Case列表 (共 {len(cases)} 条)")
        table.add_column("Case ID", style="cyan")
        table.add_column("标题", max_width=40)
        table.add_column("严重级别", style="bold")
        table.add_column("状态")
        table.add_column("负责人")
        table.add_column("创建时间")

        severity_colors = {
            "critical": "red", "high": "yellow", "medium": "blue", "low": "green", "info": "white"
        }
        for c in cases:
            sev = c.get("severity", "medium")
            color = severity_colors.get(sev, "white")
            table.add_row(
                c["case_id"],
                c["title"][:40] if c.get("title") else "",
                f"[{color}]{sev}[/]",
                c.get("status", ""),
                c.get("assignee_id", "-"),
                str(c.get("created_at", ""))[:19],
            )
        console.print(table)
    finally:
        await db.close()


@case_app.command("show")
def case_show(case_id: str = typer.Argument(help="Case ID")):
    """查看Case详情"""
    asyncio.run(_case_show(case_id))


async def _case_show(case_id: str):
    from aicso.store.database import Database
    from aicso.store.case_store import CaseStore
    from aicso.store.alert_store import AlertStore

    db = Database()
    await db.connect()
    try:
        case_store = CaseStore(db)
        alert_store = AlertStore(db)

        case = await case_store.get(case_id)
        if not case:
            console.print(f"[red]Case不存在: {case_id}[/]")
            return

        console.print(f"\n[bold cyan]Case: {case['case_id']}[/]")
        console.print(f"  标题:     {case.get('title', '')}")
        console.print(f"  严重级别: {case.get('severity', '')}")
        console.print(f"  状态:     {case.get('status', '')}")
        console.print(f"  优先级:   P{case.get('priority', '')}")
        console.print(f"  负责人:   {case.get('assignee_id', '-')}")
        console.print(f"  创建时间: {case.get('created_at', '')}")
        console.print(f"  AI摘要:   {case.get('ai_summary', '-')}")
        console.print(f"  AI建议:   {case.get('ai_recommendation', '-')}")

        # 关联告警
        alerts = await alert_store.list_alerts(case_id=case_id, limit=10)
        if alerts:
            console.print(f"\n[bold]关联告警 ({len(alerts)}条):[/]")
            for a in alerts:
                console.print(f"  - [{a.get('severity', '?')}] {a.get('rule_name', 'N/A')} | "
                            f"src={a.get('src_ip', 'N/A')} -> dst={a.get('dst_ip', 'N/A')}")

        # 事件时间线
        events = await case_store.get_events(case_id)
        if events:
            console.print(f"\n[bold]事件时间线 ({len(events)}条):[/]")
            for e in events[-10:]:
                console.print(f"  [{str(e.get('timestamp', ''))[:19]}] "
                            f"{e.get('event_type', '')} by {e.get('actor', '')}")
    finally:
        await db.close()


@case_app.command("update")
def case_update(
    case_id: str = typer.Argument(help="Case ID"),
    status: Optional[str] = typer.Option(None, help="新状态"),
    assignee: Optional[str] = typer.Option(None, help="负责人"),
    resolution: Optional[str] = typer.Option(None, help="处置结果"),
):
    """更新Case"""
    asyncio.run(_case_update(case_id, status, assignee, resolution))


async def _case_update(case_id: str, status: Optional[str], assignee: Optional[str], resolution: Optional[str]):
    from aicso.store.database import Database
    from aicso.store.case_store import CaseStore
    from aicso.models.case import CaseStatus

    db = Database()
    await db.connect()
    try:
        store = CaseStore(db)
        case_data = await store.get(case_id)
        if not case_data:
            console.print(f"[red]Case不存在: {case_id}[/]")
            return

        from aicso.models.case import Case, CaseSeverity, CasePriority
        case = Case(
            case_id=case_data["case_id"],
            title=case_data["title"],
            severity=CaseSeverity(case_data["severity"]),
            status=CaseStatus(case_data["status"]),
            priority=CasePriority(case_data["priority"]),
            assignee_id=case_data.get("assignee_id"),
            resolution=case_data.get("resolution"),
        )

        if status:
            new_status = CaseStatus(status)
            event = case.transition_to(new_status, actor="cli_user", reason="CLI update")
            await store.add_event(case_id, event)
            console.print(f"[green]OK[/] Status updated: {case_data['status']} -> {status}")

        if assignee:
            case.assignee_id = assignee
            console.print(f"[green]OK[/] Assignee updated: {assignee}")

        if resolution:
            case.resolution = resolution
            console.print(f"[green]OK[/] Resolution updated")

        await store.update(case)
    finally:
        await db.close()


@case_app.command("close")
def case_close(case_id: str = typer.Argument(help="Case ID")):
    """关闭Case"""
    asyncio.run(_case_update(case_id, "closed", None, None))
