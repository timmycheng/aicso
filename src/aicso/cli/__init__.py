"""CLI命令入口"""
from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from rich.console import Console

from aicso.cli.case import case_app
from aicso.cli.alert import alert_app
from aicso.cli.agent import agent_app
from aicso.cli.datasource import ds_app

app = typer.Typer(
    name="aicso",
    help="AiCSO - AI Cyber Security Operations\n以Case为中心的AI-Native安全运营Agent框架",
    no_args_is_help=True,
)
console = Console()

app.add_typer(case_app, name="case", help="Case（案件）管理")
app.add_typer(alert_app, name="alert", help="Alert（告警）管理")
app.add_typer(agent_app, name="agent", help="Agent（智能体）管理")
app.add_typer(ds_app, name="datasource", help="DataSource（数据源）管理")


@app.command()
def version():
    """显示版本信息"""
    from aicso import __version__
    console.print(f"[bold green]AiCSO[/] v{__version__}")
    console.print("AI Cyber Security Operations")


@app.command()
def init(
    config_path: str = typer.Option("config.yaml", help="配置文件路径"),
    db_path: str = typer.Option("aicso.db", help="数据库文件路径"),
):
    """初始化AiCSO"""
    asyncio.run(_init(config_path, db_path))


async def _init(config_path: str, db_path: str):
    """异步初始化"""
    from aicso.store.database import Database

    console.print("[bold]正在初始化AiCSO...[/]")

    # 初始化数据库
    db = Database(db_path)
    await db.connect()
    await db.init_tables()
    await db.close()

    console.print(f"[green]OK[/] Database initialized: {db_path}")

    # 检查配置文件
    if Path(config_path).exists():
        console.print(f"[green]OK[/] Config file exists: {config_path}")
    else:
        console.print(f"[yellow]![/] Config file not found, using defaults: {config_path}")

    console.print("[bold green]AiCSO initialization complete![/]")
    console.print("\nQuick start:")
    console.print("  aicso case create --title 'Test Alert' --severity medium")
    console.print("  aicso case list")
    console.print("  aicso agent chat")


if __name__ == "__main__":
    app()
