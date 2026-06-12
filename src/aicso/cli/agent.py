"""Agent管理CLI命令"""
from __future__ import annotations

import asyncio
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

agent_app = typer.Typer(help="Agent（智能体）管理")
console = Console()


@agent_app.command("status")
def agent_status():
    """查看Agent状态"""
    table = Table(title="Agent状态")
    table.add_column("Agent", style="cyan")
    table.add_column("描述")
    table.add_column("状态")
    table.add_column("工具")

    agents = [
        ("triage", "告警分诊Agent", "idle", "search_alerts, search_cases, query_asset"),
        ("investigation", "事件调查Agent", "idle", "search_alerts, query_asset, lookup_threat_intel"),
        ("intel", "威胁情报Agent", "idle", "lookup_threat_intel, search_ioc"),
        ("response", "响应执行Agent", "idle", "execute_response_action"),
        ("report", "报告生成Agent", "idle", "-"),
    ]
    for name, desc, status, tools in agents:
        table.add_row(name, desc, f"[green]{status}[/]", tools)
    console.print(table)


@agent_app.command("investigate")
def agent_investigate(case_id: str = typer.Argument(help="Case ID")):
    """启动Case调查"""
    asyncio.run(_agent_investigate(case_id))


async def _agent_investigate(case_id: str):
    from aicso.config import load_config
    from aicso.store.database import Database
    from aicso.store.case_store import CaseStore
    from aicso.store.alert_store import AlertStore
    from aicso.store.vector_store import VectorStore
    from aicso.core.event_bus import EventBus
    from aicso.core.context import ContextManager
    from aicso.core.approval import ApprovalEngine
    from aicso.core.orchestrator import Orchestrator
    from aicso.agents.investigation import InvestigationAgent
    from aicso.agents.intel import IntelAgent

    config = load_config()

    db = Database()
    await db.connect()
    try:
        case_store = CaseStore(db)
        alert_store = AlertStore(db)

        case = await case_store.get(case_id)
        if not case:
            console.print(f"[red]Case不存在: {case_id}[/]")
            return

        console.print(f"[bold]正在调查Case: {case_id}...[/]")

        vs = VectorStore(path=config.vector_store.path)
        await vs.connect()

        event_bus = EventBus()
        context_manager = ContextManager(case_store, alert_store, vs)
        approval_engine = ApprovalEngine(event_bus)

        orchestrator = Orchestrator(case_store, alert_store, context_manager, event_bus, approval_engine)
        orchestrator.register_agent(InvestigationAgent(llm_provider=config.llm.default_provider))
        orchestrator.register_agent(IntelAgent(llm_provider=config.llm.default_provider))

        result = await orchestrator.investigate_case(case_id)

        console.print("\n[bold green]调查完成！[/]")
        if result:
            import json
            console.print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
        else:
            console.print("[yellow]未获取到调查结果[/]")

        await vs.close()
    finally:
        await db.close()


@agent_app.command("report")
def agent_report(case_id: str = typer.Argument(help="Case ID")):
    """生成事件报告"""
    asyncio.run(_agent_report(case_id))


async def _agent_report(case_id: str):
    from aicso.config import load_config
    from aicso.store.database import Database
    from aicso.store.case_store import CaseStore
    from aicso.store.alert_store import AlertStore
    from aicso.store.vector_store import VectorStore
    from aicso.core.event_bus import EventBus
    from aicso.core.context import ContextManager
    from aicso.core.approval import ApprovalEngine
    from aicso.core.orchestrator import Orchestrator
    from aicso.agents.triage import TriageAgent
    from aicso.agents.investigation import InvestigationAgent
    from aicso.agents.intel import IntelAgent
    from aicso.agents.response import ResponseAgent
    from aicso.agents.report import ReportAgent

    config = load_config()

    db = Database()
    await db.connect()
    try:
        case_store = CaseStore(db)
        alert_store = AlertStore(db)

        case = await case_store.get(case_id)
        if not case:
            console.print(f"[red]Case不存在: {case_id}[/]")
            return

        console.print(f"[bold]正在生成报告: {case_id}...[/]")

        vs = VectorStore(path=config.vector_store.path)
        await vs.connect()

        event_bus = EventBus()
        context_manager = ContextManager(case_store, alert_store, vs)
        approval_engine = ApprovalEngine(event_bus)

        orchestrator = Orchestrator(case_store, alert_store, context_manager, event_bus, approval_engine)
        for agent_cls in [TriageAgent, InvestigationAgent, IntelAgent, ResponseAgent, ReportAgent]:
            orchestrator.register_agent(agent_cls(llm_provider=config.llm.default_provider))

        report = await orchestrator.generate_report(case_id)

        console.print("\n[bold green]报告生成完成！[/]\n")
        console.print(report)

        await vs.close()
    finally:
        await db.close()


@agent_app.command("chat")
def agent_chat():
    """进入Agent对话模式"""
    console.print("[bold cyan]AiCSO Agent Chat[/]")
    console.print("输入问题与Agent对话，输入 'quit' 退出\n")
    console.print("[yellow]注意：需要配置LLM Provider后才能使用Agent对话功能[/]\n")

    while True:
        try:
            user_input = console.input("[bold green]> [/]")
            if user_input.strip().lower() in ("quit", "exit", "q"):
                console.print("[dim]再见！[/]")
                break
            if not user_input.strip():
                continue
            console.print("[yellow]Agent对话功能将在后续版本中实现[/]")
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]再见！[/]")
            break
