"""数据库初始化脚本"""
import asyncio
import sys
from pathlib import Path

# 添加项目路径
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aicso.store.database import Database


async def init(db_path: str = "aicso.db"):
    print(f"Initializing database: {db_path}")
    db = Database(db_path)
    await db.connect()
    await db.init_tables()
    await db.close()
    print("Database initialized successfully!")


if __name__ == "__main__":
    db_path = sys.argv[1] if len(sys.argv) > 1 else "aicso.db"
    asyncio.run(init(db_path))
