# AiCSO

**AI Cyber Security Operations** — 以Case为中心的AI-Native安全运营Agent框架

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11+-green.svg)](https://www.python.org/)
[![CI](https://github.com/timmycheng/aicso/actions/workflows/ci.yml/badge.svg)](https://github.com/timmycheng/aicso/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/Tests-283%20passed-brightgreen.svg)](#测试)

## 简介

AiCSO 是一个面向企业SOC团队的安全运营Agent框架。它不是在传统SOC工具上叠加AI助手，而是用AI重构安全运营的每一个环节——流式告警经分流引擎智能汇入Case，Case上下文持续生长为单一真实事件，AI负责分析研判，人类分析师负责决策和监督。

**核心理念**：
- **Case为中心** — Case是安全运营的唯一消费单位，告警分流汇入、合并拆分、持续生长
- **AI-Native** — 判定型决策交给判定模型（[象信AI System One](https://xiangxinai.cn)），生成型任务交给LLM Agent，检索交给本地实体索引
- **人在回路** — AI分析，人做决策，高风险操作必须审批；人工处置结论反哺后续判定
- **零丢弃** — 有界队列+过载兜底+重启回灌+at-least-once消费，告警不静默丢失
- **开源开放** — Apache 2.0，社区驱动，无厂商锁定

## 架构总览

```
数据源(Kafka/REST) ──► 统一Schema映射(schema: auto|ecs|generic)
                          │
                          ▼
                   ┌─────────────────────────────┐
                   │   分流引擎 RouterEngine       │
                   │  候选实体索引 · 微批切分       │
                   │  System One判定 · 本地兜底    │
                   │  决策缓存 · 误报签名记忆       │
                   │  过载模式 · 参数自适应微调     │
                   └──────────┬──────────────────┘
                              ▼
              Case（唯一消费单位，持续生长）
   ├─ S2初始研判：真伪/攻击分类/严重度/优先级Score（含资产重要性）
   ├─ 合并/拆分引擎：热+冷候选发现 → 判定 → 幂等执行 → 证据链
   ├─ OpsRecord：Agent/人工/系统操作统一落时间线
   └─ 人工处置反馈：误报记忆 · 合并样本few-shot · 实体存活率报告
```

## 功能概览

| 模块 | 功能 |
|------|------|
| **分流引擎** | 候选实体索引（类型化实体白名单）、微批token预算切分、System One并行判定（置信度阈值）、LocalFallback本地兜底、决策缓存、误报签名免路由、三级水位过载模式、422二分重试、参数自适应微调器（有界自调+审计+一键回滚） |
| **Case管理** | CRUD、状态机、SLA管理、优先级（System One Score判定：severity+资产重要性输入，critical资产至少P2）、keyword搜索、合并/拆分关联链 |
| **合并/拆分引擎** | 热发现（实体倒排索引）+冷发现（DB共享IP）、System One裁决、幂等执行、关联证据链、人工合并沉淀处置样本（few-shot反哺裁决）、实体类型存活率报告 |
| **认知任务分发** | 判定型→System One（Noul/Choice/Score，低置信转人工复核）；生成型→LLM Agent（关闭时标needs_review） |
| **OpsRecord** | Agent/人工/系统对Case的每一次操作统一落库+时间线镜像（调查/报告/合并/拆分/人工处置） |
| **统一Schema映射** | 内置ECS profile + auto探测 + generic兜底；自定义field_mapping/entity_mapping覆盖；severity双策略（文本枚举+数值阈值）+自定义映射；映射自动建议（本地规则推断→试算验证→人工确认） |
| **数据源** | Kafka（at-least-once手动提交位点、失败rewind、lag指标）、REST API、Syslog、JSON文件 |
| **Playbook** | YAML定义、步骤编排、动作处理器真实执行、条件分支、审批门控、执行审计 |
| **审批引擎** | 三级风险分级（低/中/高），高风险人工审批 |
| **AI Agent** | 5个专业Agent：分诊、调查、情报、响应、报告 |
| **保留策略** | 按天清理告警（范围可配：仅孤立/含已关闭Case），零丢弃约束 |
| **安全** | RBAC权限、Prompt注入防护、操作审计、凭据仅走环境变量（`${ENV}`展开） |

## 快速开始

### 安装

```bash
git clone https://github.com/timmycheng/aicso.git
cd aicso

# 推荐 uv
uv sync -p 3.11                # 基础依赖
uv sync --extra kafka -p 3.11  # 需要 Kafka 数据源时

# 或 pip
pip install -e ".[kafka]"
```

### 初始化

```bash
aicso init
```

System One 判定模型密钥通过环境变量注入（config.yaml 中 `${XX-AI-KEY}` 展开，未配置时引擎进入纯本地兜底模式）：

```bash
export XX-AI-KEY=sk-...        # 象信AI API key
```

### 基本使用

```bash
# 启动Web平台
aicso-web
# 浏览器访问 http://localhost:8000

# CLI模式
aicso case create --title "Phishing Attack" --severity high
aicso case list
```

不接真实数据源时，可用 Mock 注入页（`/mock`）生成模拟告警体验完整分流链路（无 System One key 时走本地兜底规则）。

## 数据源配置

在 `config.yaml` 中配置数据源。字段映射走统一Schema引擎：`schema: auto`（默认，自动探测ECS）| `ecs`（Elastic Common Schema零配置）| `generic`（自定义field_mapping覆盖默认路径）。severity 支持双字段：`severity_text`（文本枚举 critical/high/medium/low/info）与 `severity_int`（数值，配 severity_mapping 或按阈值）。

### Kafka（内网SIEM常用）

```yaml
datasources:
  siem_kafka:
    type: kafka
    enabled: true
    poll_interval: 5
    config:
      bootstrap_servers: 10.0.0.1:9092
      topic: siem-alerts
      group_id: aicso-prod-siem        # 独立消费组：同组互抢分区、跨环境勿共用
      schema: generic
      field_mapping:
        alert_id: alert_id
        rule_name: rule_name
        severity_text: severity        # 文本severity路径
        src_ip: src_ip
        dst_ip: dst_ip
        timestamp: occur_time
      severity_mapping:                # 数值刻度或非规范词 → 规范词表
        1: critical
        2: high
        3: medium
        4: low
        5: info
      sasl_mechanism: ${KAFKA_SASL}    # 可选：SASL/SSL认证
      sasl_username: ${KAFKA_USER}
      sasl_password: ${KAFKA_PASS}
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
      schema: ecs                      # ECS格式源零字段配置
```

Web端「数据源」页提供**映射试算**（粘贴样本验证归一化结果）与**映射自动建议**（本地规则推断草稿 + Kafka活体采样，系统提议、人工确认）。

## Web平台

启动 `aicso-web` 后访问 `http://localhost:8000`：

| 页面 | 路径 | 功能 |
|------|------|------|
| 仪表盘 | `/` | 概览统计、严重度分布、最近Case |
| Case管理 | `/cases` | 列表（状态/严重度/keyword过滤）、详情时间线、状态更新、合并拆分关联链 |
| 告警管理 | `/alerts` | 告警列表、详情、路由归属 |
| 分流控制台 | `/router` | 引擎状态/指标、候选合并裁决、合并拆分执行、微调器、误报处置 |
| Agent | `/agents` | Agent状态、启动调查、生成报告 |
| 数据源 | `/datasources` | 数据源列表/状态、映射试算、映射自动建议 |
| Mock注入 | `/mock` | 生成模拟告警（8类攻击模板），体验分流链路 |

常用JSON API：

```
GET  /api/metrics                          # 引擎指标（吞吐/延迟分位/置信度直方图/积压）
GET  /router/api/status                    # 分流引擎状态（模式/水位/队列）
GET  /router/api/tuner                     # 参数自适应微调器快照（POST .../rollback 回滚）
GET  /router/api/decisions                 # 路由决策审计
POST /router/api/merge/evaluate            # 候选对合并裁决
POST /router/api/merge/execute             # 执行合并
POST /router/api/split                     # 拆分
POST /router/api/merge-sweep               # 周期扫描（含冷发现）
POST /router/api/alerts/{id}/false-positive # 误报标记（窗口内同签名免路由）
GET  /router/api/entity-survival           # 实体类型存活率报告
GET  /cases/api/list?q=keyword             # Case搜索
GET  /cases/api/{id}/correlations          # 合并/拆分关联链与证据
GET  /cases/api/{id}/context               # Case完整运营视图
POST /cases/api/{id}/ops                   # 记录人工操作（OpsRecord）
POST /datasources/api/test-mapping         # 映射试算
POST /datasources/api/suggest-mapping      # 映射自动建议（粘贴样本）
GET  /approvals/api/pending               # 待审批动作（POST approve/reject）
```

## 测试与仿真

```bash
# 全量测试（密闭：不依赖外部API/网络，~11s）
pytest

# 仿真套件：分流/合并/拆分全场景29项断言（--with-systemone附加真实API语义抽检）
uv run python scripts/simulation_test.py

# 真实数据集回放：direct=本地引擎记分卡 / kafka=produce走真实链路
uv run python scripts/replay_dataset.py <数据集路径>... --mode direct
```

## 项目结构

```
aicso/
├── src/aicso/
│   ├── api/              # Web平台（FastAPI + Jinja2，无SPA/构建链——内网离线约束）
│   │   ├── routes/       # case/alert/router/approval/datasource/metrics/mock/agent
│   │   ├── templates/    # Jinja2 HTML模板 + 设计令牌CSS + SVG图标宏
│   │   └── static/
│   ├── router/           # 分流引擎：engine/index/fallback/batcher/merge/metrics/tuner
│   ├── cognition/        # S2判定型任务分发（System One：Noul/Choice/Score）
│   ├── mapping/          # 统一Schema映射：engine/profiles/suggest（自动建议）
│   ├── core/             # 编排器、事件总线、审批、上下文、OpsService、保留策略
│   ├── agents/           # 5个LLM Agent（分诊/调查/情报/响应/报告）
│   ├── models/           # Case/Alert/Asset/IoC/Playbook/RoutingDecision/OpsRecord
│   ├── store/            # 存储层（SQLite WAL + 写缓冲批量提交；ChromaDB为vector extra）
│   ├── systemone/        # 象信AI System One异步客户端 + token估算
│   ├── adapters/         # 数据源适配器（Kafka/REST/Syslog/JSON）
│   ├── playbook/         # Playbook解析器 + 执行器（动作注册/条件分支）
│   ├── cli/              # CLI命令（case/alert/agent/datasource）
│   └── config.py         # 配置管理（${ENV}展开、.env加载）
├── playbooks/            # 内置Playbook模板（钓鱼/暴力破解/恶意软件）
├── skills/               # Skill插件（phishing-response）
├── tests/                # 283个测试（密闭fixture，单元+集成+页面冒烟+仿真回归）
├── scripts/              # 仿真测试/数据集回放/压测/种子数据/离线打包
├── docs/                 # 文档（PRD/技术方案/白皮书/重构设计/扩展设计）
├── Dockerfile            # 离线镜像（kafka extra）
└── docker-compose.yml
```

## Agent与判定分工

```
编排器 Orchestrator ── S2任务分发（按任务类型选引擎）
│
├─ 判定型 → 象信AI System One（校准置信度，低于阈值转人工复核）
│    ├─ 告警分流归属（Choice：汇入候选Case / 新建）
│    ├─ Case合并裁决（Choice：并入A / 并入B / 不合并）
│    └─ 初始研判（真伪Noul · 攻击分类Choice · 严重度Choice · 优先级Score）
│
├─ 生成型 → LLM Agent（litellm，llm.enabled=false时标needs_review）
│    ├─ TriageAgent    叙述摘要与研判建议
│    ├─ InvestigationAgent  深入调查、攻击链还原
│    ├─ IntelAgent     威胁情报查询、IoC分析
│    ├─ ResponseAgent  响应方案与风险分级
│    └─ ReportAgent    事件报告
│
└─ 检索型 → 本地实体索引（不交给任何模型）
```

人工处置闭环：分析师标记误报（窗口内同签名免路由）、人工合并沉淀处置样本（作为few-shot证据反哺后续裁决）、实体存活率报告辅助调优实体白名单。

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
| [重构设计](docs/REFACTOR_DESIGN.md) | Case-centric流式架构：分流引擎、Case生长模型、认知任务映射、生产化骨架 |
| [扩展设计](docs/SCALING_DESIGN.md) | 多副本分区、Case所有权lease、组件外置映射与阶段化迁移路径 |

## 重构状态

Case-centric 流式重构**已完成**：[Epic #1](https://github.com/timmycheng/aicso/issues/1)（P1-P3分流/认知/合并拆分/OpsRecord/保留策略）、前端重构 Epic #22、自适应闭环 Epic #47（分层关联/映射自动建议/参数微调/处置反馈）、全仓code review #56（51项修复）及后续增强 #57（16项）均已合并关闭。原告警聚合模块（aggregator）已由分流引擎（`src/aicso/router/`）取代。当前仓库无遗留 backlog。

## 开发

```bash
# 安装开发依赖
uv sync --extra dev -p 3.11    # 或 pip install -e ".[dev]"

# 代码检查（CI门禁：ruff + pytest 全绿）
ruff check src/ tests/

# 运行全部测试（pytest-timeout 单测120s防挂死）
pytest
```

开发约定：GitHub issue → feature 分支 → PR（正文写 Closes #N 与验证结果）→ CI 绿 → squash merge；提交信息用 conventional commits。

## License

[Apache License 2.0](LICENSE)
