# AiCSO

**AI Cyber Security Operations** — 以Case为中心的AI-Native安全运营Agent框架

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11+-green.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/Tests-53%20passed-brightgreen.svg)](#测试)

## 简介

AiCSO 是一个面向企业SOC团队的安全运营Agent框架。它不是在传统SOC工具上叠加AI助手，而是用AI重构安全运营的每一个环节——从告警接入、智能研判、事件调查到响应处置，全部由专业Agent协作完成，人类分析师负责决策和监督。

**核心理念**：
- **Case为中心** — 所有安全运营围绕Case展开，打破工具孤岛
- **AI-Native** — Agent驱动，而非规则驱动
- **人在回路** — AI分析，人做决策，高风险操作必须审批
- **开源开放** — Apache 2.0，社区驱动，无厂商锁定

## 功能概览

| 模块 | 功能 |
|------|------|
| **Case管理** | CRUD、状态机（New→Assigned→Investigating→Responding→Resolved→Closed）、SLA管理 |
| **告警聚合** | 规则引擎（同源IP/目标资产/规则分类）+ AI语义聚合 |
| **AI Agent** | 5个专业Agent：分诊、调查、情报、响应、报告 |
| **数据源** | Kafka、REST API、Syslog、JSON文件（可扩展） |
| **Playbook** | YAML定义、步骤编排、条件分支、执行审计 |
| **审批引擎** | 三级风险分级（低/中/高），低风险自动执行，高风险人工审批 |
| **安全** | RBAC权限、4层Prompt注入防护、操作审计 |

## 快速开始

### 安装

```bash
git clone https://github.com/timmycheng/aicso.git
cd aicso
pip install -e .
```

### 初始化

```bash
aicso init
```

### 基本使用

```bash
# 启动Web平台
aicso-web
# 浏览器访问 http://localhost:8000

# CLI模式（仍然可用）
aicso case create --title "Phishing Attack" --severity high
aicso case list
```

## 数据源配置

在 `config.yaml` 中配置数据源：

### Kafka（内网SIEM常用）

```yaml
datasources:
  siem_kafka:
    type: kafka
    enabled: true
    config:
      bootstrap_servers: 10.0.0.1:9092
      topic: siem-alerts
      group_id: aicso-consumer
      message_format: json
      field_mapping:
        alert_id: alert_id
        rule_name: rule_name
        severity: severity
        src_ip: src_ip
        dst_ip: dst_ip
        timestamp: timestamp
      severity_mapping:
        1: critical
        2: high
        3: medium
        4: low
        5: info
```

### REST API（SIEM HTTP接口）

```yaml
datasources:
  siem_api:
    type: rest_api
    enabled: true
    config:
      base_url: https://siem.example.com/api/v1
      auth_type: bearer
      api_token: ${SIEM_API_TOKEN}
      alerts_endpoint: /alerts
      field_mapping:
        alert_id: id
        rule_name: rule.name
        severity: level
        src_ip: src_addr
        dst_ip: dst_addr
```

## Agent架构

```
┌─────────────────────────────────────────────────┐
│                Orchestrator（编排引擎）            │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐      │
│   │  Task    │  │  Agent   │  │ Context  │      │
│   │ Manager  │  │ Registry │  │ Manager  │      │
│   └──────────┘  └──────────┘  └──────────┘      │
└───────────────────────┬─────────────────────────┘
                        │
     ┌──────────────────┼──────────────────┐
     │                  │                  │
┌────┴─────┐     ┌──────┴─────┐     ┌──────┴─────┐
│  Triage  │     │Investigation│    │  Response  │
│  Agent   │     │   Agent    │    │   Agent    │
└──────────┘     └────────────┘    └────────────┘
     │                  │                  │
┌────┴─────┐     ┌──────┴─────┐
│  Intel   │     │   Report   │
│  Agent   │     │   Agent    │
└──────────┘     └────────────┘
```

- **Orchestrator** — 接收告警，调度Agent，管理上下文
- **TriageAgent** — 告警分类、初步研判、置信度评分
- **InvestigationAgent** — 深入调查、攻击链还原、关联分析
- **IntelAgent** — 威胁情报查询、IoC分析、ATT&CK映射
- **ResponseAgent** — 制定响应方案、评估风险级别
- **ReportAgent** — 生成事件报告

## Web平台

AiCSO提供Web管理界面，启动后访问 `http://localhost:8000`：

```bash
aicso-web
```

| 页面 | 路径 | 功能 |
|------|------|------|
| 仪表盘 | `/` | 概览统计、最近Case |
| Case管理 | `/cases` | Case列表、新建、详情、状态更新 |
| 告警管理 | `/alerts` | 告警列表、详情查看 |
| Agent | `/agents` | Agent状态、启动调查、生成报告 |
| 数据源 | `/datasources` | 已配置数据源列表 |

JSON API端点：
- `GET /cases/api/list` - Case列表
- `GET /cases/api/{case_id}` - Case详情
- `GET /alerts/api/list` - 告警列表
- `GET /alerts/api/{alert_id}` - 告警详情
- `GET /agents/api/status` - Agent状态
- `GET /datasources/api/list` - 数据源列表

## 项目结构

```
aicso/
├── src/aicso/
│   ├── api/              # Web平台（FastAPI + Jinja2）
│   │   ├── app.py        # FastAPI应用入口
│   │   ├── deps.py       # 依赖注入
│   │   ├── routes/       # 路由（case/alert/agent/datasource）
│   │   ├── templates/    # Jinja2 HTML模板
│   │   └── static/       # 静态资源
│   ├── cli/              # CLI命令（case/alert/agent/datasource）
│   ├── core/             # 核心引擎（编排器、事件总线、审批、上下文）
│   ├── agents/           # 5个AI Agent实现
│   ├── models/           # 数据模型（Case、Alert、Asset、IoC、Playbook）
│   ├── store/            # 存储层（SQLite、ChromaDB向量库）
│   ├── adapters/         # 数据源适配器（Kafka、REST API、Syslog、JSON）
│   ├── aggregator/       # 告警聚合引擎
│   ├── playbook/         # Playbook解析器和执行器
│   ├── security/         # 安全模块（RBAC、审计、Prompt注入防护）
│   └── config.py         # 配置管理
├── playbooks/            # 内置Playbook模板（钓鱼/暴力破解/恶意软件）
├── skills/               # Skill插件
├── tests/                # 53个测试（单元+集成）
├── scripts/              # 辅助脚本（数据库初始化、种子数据）
├── docs/                 # 产品文档（PRD/技术方案/白皮书）
├── config.yaml           # 配置文件
└── pyproject.toml        # 项目配置
```

## 离线部署

适用于内网无外网环境，使用Docker镜像方式部署：

```bash
# 有网机器：构建镜像并导出
docker build -t aicso:latest .
docker save aicso:latest -o aicso-docker.tar

# 拷贝到内网后：加载镜像并启动
docker load -i aicso-docker.tar
docker compose up -d
# 浏览器访问 http://localhost:8000
```

## 文档

| 文档 | 说明 |
|------|------|
| [PRD](docs/PRD.md) | 产品需求文档：背景、功能规划、竞品分析、路线图 |
| [技术方案](docs/TECHNICAL_DESIGN.md) | 架构设计、Agent详细设计、接口定义、存储方案 |
| [白皮书](docs/WHITEPAPER.md) | 产品理念、核心能力、典型场景、部署方案 |

## 测试

```bash
# 运行全部测试
pytest

# 运行单元测试
pytest tests/unit/

# 运行集成测试
pytest tests/integration/
```

## 开发

```bash
# 安装开发依赖
pip install -e ".[dev]"

# 代码检查
ruff check src/

# 格式化
ruff format src/
```

## License

[Apache License 2.0](LICENSE)
