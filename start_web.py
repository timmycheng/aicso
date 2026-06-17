"""Web服务启动脚本"""
import uvicorn

from aicso.logging import setup_logging

if __name__ == "__main__":
    setup_logging(level="INFO")
    uvicorn.run(
        "aicso.api.app:app",
        host="127.0.0.1",
        port=8080,
        log_level="info",
    )
