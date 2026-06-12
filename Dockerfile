FROM python:3.11-slim

WORKDIR /app

# 安装系统依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# 复制依赖文件
COPY pyproject.toml README.md LICENSE ./
COPY src/ src/

# 安装Python依赖
RUN pip install --no-cache-dir -e .

# 复制配置和数据
COPY config.yaml ./
COPY playbooks/ playbooks/
COPY skills/ skills/

# 创建数据目录
RUN mkdir -p data/chromadb

# 初始化数据库
RUN python -c "import asyncio; from aicso.store.database import Database; db = Database('./aicso.db'); asyncio.run(db.connect()); asyncio.run(db.init_tables()); asyncio.run(db.close())"

# 暴露端口（后续API用）
EXPOSE 8000

# 入口点
ENTRYPOINT ["aicso"]
CMD ["--help"]
