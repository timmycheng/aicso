# AiCSO

**AI Cyber Security Operations** — 以Case为中心的AI-Native安全运营Agent框架

## 特性

- **Case为中心**：统一的安全事件管理视图
- **AI-Native**：Agent驱动的告警研判、事件调查、响应编排
- **混合Agent架构**：多专业Agent协作，编排引擎统一调度
- **MCP协议支持**：标准化工具接入，可扩展性强
- **分级审批**：低风险自动执行，高风险人工审批
- **轻量起步**：CLI/TUI即可使用，无需重资产部署
- **完全开源**：Apache 2.0协议，社区驱动

## 快速开始

### 安装

```bash
# 克隆项目
git clone https://github.com/aicso/aicso.git
cd aicso

# 安装依赖
pip install -e .

# 或使用开发模式
pip install -e ".[dev]"
```

### 初始化

```bash
# 初始化数据库
aicso init

# 配置LLM Provider
export DEEPSEEK_API_KEY=your_api_key
# 或编辑 config.yaml
```

### 基本使用

```bash
# Case管理
aicso case create --title "疑似钓鱼攻击" --severity high
aicso case list
aicso case show CSO-20260612-ABC123

# 告警管理
aicso alert list
aicso alert show alert-001

# Agent交互
aicso agent status
aicso agent investigate CSO-20260612-ABC123
aicso agent report CSO-20260612-ABC123
```

## 项目结构

```
aicso/
├── src/aicso/
│   ├── cli/          # CLI命令
│   ├── core/         # 核心引擎（编排、上下文、审批、事件总线）
│   ├── agents/       # Agent实现（分诊、调查、情报、响应、报告）
│   ├── models/       # 数据模型（Case、Alert、Asset、IoC、Playbook）
│   ├── store/        # 存储层（SQLite、ChromaDB）
│   ├── adapters/     # 数据源适配器
│   ├── aggregator/   # 告警聚合引擎
│   ├── playbook/     # Playbook引擎
│   ├── security/     # 安全模块
│   └── api/          # REST API
├── skills/           # 内置Skills
├── playbooks/        # 内置Playbook模板
├── tests/            # 测试
└── docker/           # Docker配置
```

## 文档

- [产品需求文档 (PRD)](docs/PRD.md)
- [技术方案设计](docs/TECHNICAL_DESIGN.md)
- [产品白皮书](docs/WHITEPAPER.md)

## 开发

```bash
# 运行测试
pytest

# 代码检查
ruff check src/

# 类型检查
mypy src/
```

## License

Apache License 2.0
