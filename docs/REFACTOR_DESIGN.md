# AiCSO Case-centric 流式重构设计

> 状态：已评审通过（2026-11-06）　|　范围：P1 分流骨架实施依据　|　关联：[Epic #1](https://github.com/timmycheng/aicso/issues/1)

---

## 1. 背景与问题

当前架构的根本局限：**alert 才是流水线的处理单位，Case 只是"时间窗口内去重后的告警容器"**。三个结构性问题：

| # | 问题 | 代码位置 | 后果 |
|---|------|----------|------|
| 1 | **LLM 在热路径上**——每个新 Case 由 TriageAgent 生成聚合规则，规则质量依赖 LLM 可用性与延迟 | `core/orchestrator.py:158` `_run_triage_with_ai_rule` | 高频流入时认知环节成为瓶颈；LLM 故障即规则断供 |
| 2 | **规则匹配 O(N) 遍历**——`try_aggregate` 对所有 AI 规则×维度循环构建 key | `aggregator/engine.py:122` | 规则数线性增长后路由延迟线性恶化，高频流必然积压 |
| 3 | **状态不可恢复**——路由状态全在单进程内存；重启恢复时 `created_at` 重置，窗口语义丢失 | `api/deps.py:34` `_restore_aggregation_rules` | 重启后聚合行为错乱；队列满直接丢告警（`orchestrator.py:150`） |

### 新方向（已确认）

1. **Case 是安全运营的唯一消费单位**：流式告警经分流引擎汇入（已有的或新建的）Case，Case 上下文持续"生长"，最终收敛为一个真实需要处置的单一事件；在其之上由 Agent/人工执行继续调查、补充日志与告警上下文、调用 playbook 自动化、拉人协作、人工处置记录等操作。
2. **分流引擎（System 1）不自研**：调用[象信AI](https://xiangxinai.cn)的 **System One 判定模型 API** 实现；冷路径同样以 System One 为主力（判定型任务），LLM/人工按任务类型配合。
3. **面向生产环境、大量告警日志设计**：本阶段以 MVP 形态落地（单进程 asyncio + SQLite，零新增外部中间件），但组件边界按"未来可外置/可拆分"设计，保留向 Kafka/Redis/Postgres 平滑迁移的空间。

---

## 2. 目标与非目标

### 目标

- 单节点吞吐 **≥500 alerts/s**，路由决策 **P99 < 1s**，不因分流产生积压
- 告警零丢弃：过载走背压与降级，而不是丢数据
- 重启后路由行为正确（窗口语义不因恢复而失真）
- System One 不可用时系统整体可用（本地兜底规则接管，决策标记降级）
- 冷/热路径都优先使用 System One；LLM 仅承担生成型任务；人工承担高风险决策

### 非目标（本期不做，见 §13 路线与 backlog）

- Kafka/Redis/Postgres 等外部中间件接入（仅预留接口缝）
- 多副本/多进程分区部署（仅文档记录迁移缝）
- 认知引擎完整闭环（合并/拆分引擎、规则蒸馏回流）——P2
- RBAC/Prompt注入防护等 security 模块（与本次重构无关，文档领先代码的现状另行处理）

---

## 3. 概念模型

### 3.1 三个核心对象的重定义

```
Alert   信号。不可变、append-only、高频流入的素材。不是工作对象。
Case    运营单元。由分流引擎持续吸收相关告警而"生长"的活事件，
        最终收敛为一个真实需要处置的单一事件。
Ops     运营操作。发生在 Case 之上的一切动作：
        Agent 调查 / 补充日志与告警上下文 / playbook 自动化 / 拉人协作 / 人工处置记录。
```

### 3.2 Case 上下文的"生长"

Case 上下文由四类只追加（append-only）的内容构成：

| 维度 | 内容 | 现状 |
|------|------|------|
| 时间线 timeline | 全生命周期事件（告警汇入/状态变更/AI分析/操作记录） | 已有（`models/case.py` CaseEvent） |
| 实体图 entities | src_ip/dst_ip/账户/主机/域名/文件等实体的抽取与关联 | **新增**（P1 先建索引，P2 完整实体图） |
| 补充上下文 | 人工/系统补充的日志片段、关联告警、资产信息 | **新增**（P2 OpsRecord 承载） |
| 操作记录 ops | Agent/人工在 Case 上的每一次操作及结果 | **新增**（P2 OpsRecord） |

**生长语义**：分流引擎每次汇入告警 = 一次生长；认知引擎每次分析 = 一次生长；人工补充 = 一次生长。Case 的标题/严重度/置信度可以随生长被修正（如多告聚合并入后升级严重度）。

---

## 4. 双路径架构总览

```
                     ┌─────────────────────── 热路径（System 1，分流）───────────────────────┐
 数据源(Kafka/REST/   │  Ingest ─→ 候选索引 ─→ 微批聚合 ─→ System One API ─→ 决策应用        │
 Syslog/JSON/Mock) ──┼─  批量持久化   (本地倒排    (100ms/50条     (Choice判定:      ┌─ 汇入已有Case  │
                     │              粗筛top-K)   或token上限)     哪个Case or 新建)  └─ 新建Case     │
                     └───────────────────────────────────────────┬──────────────────────────────┘
                                                                 │ 新Case事件
                     ┌─────────────────── 冷路径（System 2，认知）────────────────┴──────────────┐
                     │  S2 任务队列（有界、可延迟、不阻塞热路径）                                  │
                     │    ├─ 判定型任务 → System One（真伪/严重度/攻击分类/优先级/是否合并）        │
                     │    ├─ 生成型任务 → LLM（litellm：调查叙述/事件报告）                        │
                     │    ├─ 高风险决策 → 人工（ApprovalEngine 审批）                             │
                     │    └─ 检索型任务 → 本地实体索引（候选Case/候选合并对——检索不交给模型）        │
                     │  产出：Case 分析结论 / 合并拆分建议(P2) / 蒸馏知识(P2)                      │
                     └──────────────────────────────────────────────────────────────────────────┘
```

**热/冷是设计上的定义，不是引擎绑定**：热路径要求确定性时延（当前由 System One + 本地索引承担）；冷路径允许滞后，按任务性质选择引擎（System One 判定 / LLM 生成 / 人工审批），这正是"任务→引擎映射"而非"冷路径=LLM"。

---

## 5. 分流引擎设计（P1 核心）

### 5.1 分层判定：本地粗筛 + System One 精判

象信官方建议"先在代码里粗筛候选，或改成分层选择"。设计完全遵循：

```
alert ──→ ①候选生成（纯本地，0成本，~µs级）
             实体倒排索引: entity_key ─→ [活跃Case槽位]
             按 (共享实体数, 最近活跃) 打分取 top-K（K≤10）
             ⚠ 实体仅含 源IP/目标IP/pair——rule_id 不参与候选生成：
               同一检测规则全网多目标触发是SIEM常态，仅同规则=同类攻击
               而非同一事件（issue #31）；rule_id 仅保留在决策缓存签名
          ↓
          ②System One 判定（一次API调用，微批内并行多问题）
             state    = 告警紧凑摘要（~300 token 内）
             question = Choice: "该告警应汇入哪个Case？"
                        criteria = {case_id: "一句话Case摘要"} × K + {"__new__": "与现有Case均无关，新建"}
          ↓
          ③决策应用（纯本地）
             choice=__new__ 或 confidence < 阈值 → 新建Case（低于阈值同时进复核队列）
             否则 → 汇入所选Case（更新 alert.case_id + Case时间线 + 索引活跃度）
```

为什么不用 System One 直接对全部活跃 Case 选择：Choice 上限 255 选项（422 错误）；活跃 Case 数不可控；state 里塞全部 Case 摘要会撞 64k 预算。分层后单题选项 ≤11，state 独立于 Case 总量。

### 5.2 微批与吞吐预算

**约束（象信 API，组织级配额）**：

| 项 | 值 | 来源 |
|----|----|------|
| 请求速率 | **1,200 req/min = 20 req/s**，超出 429 + retry-after | docs /api |
| 单请求 token | 64k（state+questions），超出 422 | docs /api |
| 单题选项 | Choice ≤255 | docs /api |
| 延迟 | ~70–500ms | 官网 |
| 价格 | ¥0.042/百万输入 token，输出免费 | 官网 |

**微批设计（RoutingBatcher）**：

- 聚批窗口 `batch_window_ms=100`：窗口内到达的告警合成**一次** API 请求，每条告警一个 Choice 问题
- 批上限 `batch_max_alerts=50`；同时按 token 估算器裁剪（单告警 state ~300 + 单题 ~100 → 50条 ≈ 20k token ≪ 64k）
- **吞吐上限 = 20 req/s × 50 条 ≈ 1,000 alerts/s**（组织级）；超限进入有界队列排队（§5.7）
- 路由延迟预算：等批 ≤100ms + API ≤500ms + 应用 ~ms → **P99 < 1s**，达标
- 时效语义：告警**先持久化后路由**——路由延迟不丢数据，只推迟"归 Case"的时间点

### 5.3 置信度策略

- `confidence ≥ 0.6`（可配 `confidence_threshold`）：自动执行路由决策
- `confidence < 0.6`：保守动作——**新建独立 Case**（宁可分裂不可错并），同时产生一条 `routing_review` 时间线事件进人工复核视图
- **滞回**：confidence 在阈值附近抖动不会反复改判——路由决策一旦生效不可逆（Case 只进不出，纠正靠 P2 的合并/拆分），天然免疫临界抖动
- 注意：象信文档说明重复调用概率有小幅浮点抖动，**测试一律区间断言，禁止精确相等**

### 5.4 决策缓存

同实体签名（`src_ip+dst_ip+rule_id` 归一化）在 `cache_ttl_seconds=60` 内的重复告警直接复用上一次决策（汇入同一 Case），不发 API 调用——SSH 暴破等高频同源告警流的调用量从 N 次降到 O(distinct 签名) 次。缓存命中同样记 `RoutingDecision(source=cache)` 供审计与统计。

### 5.5 降级链（System One 不可用时）

```
API 调用失败
  ├─ 429/529 → 按 retry-after(ms优先) 退避等待后重试（≤2次，批保留）
  ├─ 其他5xx/网络 → 指数退避+抖动重试（0.5s起，≤5s，≤3次）
  └─ 仍失败 → 切换 LocalFallback
LocalFallback（本地兜底规则，无外部依赖）
  ├─ 规则：src_ip+dst_ip 精确匹配活跃索引（沿用现 engine.py 即时规则逻辑）
  ├─ 命中 → 汇入已有Case；未命中 → 新建Case并注册兜底槽位
  └─ 决策标记 degraded=true，指标 degraded_total 计数
恢复探测：降级后每 30s 发一个探针请求（1个廉价 Noul 问题），成功即自动切回主路径
配置 `system_one.enabled=false` 时：纯本地模式（对齐内网无外网部署形态，等同现 llm.enabled 开关哲学）
```

### 5.6 状态与恢复

本地需要持久/可重建的状态大幅收敛（对比旧设计需恢复规则 TTL 语义）：

| 状态 | 位置 | 恢复方式 |
|------|------|----------|
| 候选索引（entity→活跃Case槽位+活跃度） | 内存 | **从 DB 活跃 Case 重建**：读 alert 实体列与 case 关联重建槽位；活跃度按最近汇入时间。不依赖快照 |
| 决策缓存 | 内存 | 丢失即重建（60s TTL，代价可忽略） |
| 路由决策审计 | `routing_decisions` 表 | 已持久化，天然可恢复 |
| 未路由告警 | alerts 表（`routed_at IS NULL`） | 启动时扫描回灌路由队列——重启零丢失 |

根治旧问题：`deps.py:34` 恢复时 `created_at` 重置导致窗口语义丢失——新设计中**不存在需要恢复的规则 TTL 状态**，窗口语义由 Case 活跃度承载，重建即正确。

### 5.7 背压（不丢数据）

```
                有界队列(默认 10,000，可配) ──→ RoutingBatcher
DataSourceManager ──→                           │ 队列水位
                    ≥80%: 告警日志 + 指标 queue_high_water
                    ≥95%: 进入过载模式——暂停 System One 调用，
                          LocalFallback 接管（时延优先，决策质量次之），
                          批量 API 调用留待水位回落
                    100%: 阻塞上游 poll（背压传导到数据源），
                          绝不丢弃告警
```

废除 `orchestrator.py:150` 的"triage 队列满即丢"：triage（分诊分析）本质是冷路径任务，满时**延迟**而非丢弃。

### 5.8 Ingest（写入路径）

- 告警规范化后**批量写** SQLite（复用现有 WriteBuffer，50条/0.1s flush）
- 写入字段新增：`routed_at`（路由完成时间，NULL=待路由）、`routing_rule`（决策来源 system_one/cache/fallback）
- 积压年龄指标 = `now - ingested_at`（对 `routed_at IS NULL` 的行取 max）——这是"不积压"的直接观测量

---

## 6. 认知引擎（冷路径）：任务→引擎映射

| 任务类型 | 引擎 | 说明 |
|----------|------|------|
| 告警真伪判断 | **System One**（Noul） | 校准置信度天然支持"低于阈值转人工" |
| 严重度评级 | **System One**（Choice: critical/high/medium/low/info） | 替代现 TriageAgent 的该职责 |
| 攻击分类 | **System One**（Choice: 暴破/钓鱼/恶意软件/横向移动/外传/提权/扫描/Web攻击/未知） | 与 mock_producer 8类模板对齐 |
| Case 优先级 | **System One**（Score） | 输入 severity+资产重要性 |
| 是否与某Case合并（P2） | **System One**（Choice: 合并入A/合并入B/不合并） | 候选对由实体索引给出 |
| 调查叙述/攻击链还原 | **LLM**（litellm，保留 DeepSeek 等） | 生成型任务，System One 不产文字 |
| 事件报告 | **LLM**（保留） | 同上 |
| 高风险处置 | **人工**（ApprovalEngine，现有） | 不变 |
| 路由候选/合并候选检索 | **本地实体索引** | 检索型任务不交给任何模型 |

- 并发有界（默认 S2 并发=3，可配）、任务超时、失败重试一次后标 `needs_review`
- S2 滞后不影响热路径：新 Case 的首次判定排在队列里，几秒延迟可接受
- `llm.enabled=false` 时生成型任务标 `needs_review` 转人工，判定型照常走 System One
- `system_one.enabled=false` 时判定型也降级为规则/人工，系统退化为纯人工+LLM 模式

---

## 7. Case 生长与运营操作（Ops）

- **所有**对 Case 的操作统一为 OpsRecord 落时间线：`{actor: agent|human|system, action, params, result, ts}`
- 运营操作清单（用户方向 #1）：继续调查（Agent）、补充日志/告警/资产上下文（人工）、调用 playbook 自动化（现有 executor + 审批）、拉人协作（assign/mention）、人工处置记录（CLI/Web 表单）
- P1 先落 `RoutingDecision` 与现有时间线；OpsRecord 模型与上下文组装 API 在 P2（issue #9）

---

## 8. 合并/拆分（P2）

- **触发**：实体索引周期扫描共享实体多的 Case 对（候选）；System One Choice 判定（合并入谁/不合并/拆分建议）
- **Merge**：主 Case 吸收对方告警/时间线/实体，被并 Case 置 `merged_into=主Case` 并停止活跃；时间线双向记录审计
- **Split**：从 Case 拆出告警子集新建 Case，`split_from` 回链；双方时间线记录
- 幂等：merge/split 操作带幂等键（case_id+告警集指纹），重复执行不产生二次效应

---

## 9. 数据模型变化

```sql
-- 新增（P1）
CREATE TABLE routing_decisions (
  id TEXT PRIMARY KEY,          -- ULID
  alert_id TEXT NOT NULL,
  case_id TEXT,                 -- 决策目标（新建时为新建的case_id）
  decision TEXT NOT NULL,       -- route_to | new_case | fallback | cache_hit
  confidence REAL,              -- System One 置信度（fallback/cache 为 NULL）
  degraded INTEGER DEFAULT 0,   -- 是否降级决策
  latency_ms REAL,              -- 该告警从ingest到路由完成的耗时
  created_at TEXT NOT NULL
);

-- alerts 表新增列
  routed_at TEXT,               -- 路由完成时间（NULL=待路由，用于积压观测与重启回灌）
  routing_source TEXT           -- system_one | cache | fallback

-- cases 表新增列（P2 用，P1 先建列）
  merged_into TEXT,             -- 合并重定向
  split_from TEXT               -- 拆分回链
```

- 原 Case metadata 中的 `aggregation_rule` **废弃**（迁移期读取兼容，写入停止）
- `RoutingDecision` 替代原设计中的 RoutingRule 表——规则本身外置到 System One，本地只留决策审计

---

## 10. 配置与密钥

```yaml
# config.yaml 新增段
system_one:
  enabled: true                    # false = 纯本地兜底分流（内网无外网形态）
  base_url: https://api.xiangxinai.cn/v1
  api_key: ${XX-AI-KEY}            # 复用 config.py 现有 ${ENV} 展开器
  model: xiangxin-latest
  batch_window_ms: 100
  batch_max_alerts: 50
  timeout_ms: 2000
  confidence_threshold: 0.6
  cache_ttl_seconds: 60
  fallback: local_rules
  candidate_top_k: 10
  review_queue_enabled: true       # 低置信度进人工复核

routing:
  queue_max_size: 10000
  high_water_mark: 0.8
  overload_mark: 0.95
  s2_concurrency: 3
```

- **.env 加载**：启动时轻量读取项目根 `.env` 注入 `os.environ`（自实现 ~15 行，不引 python-dotenv 依赖），随后现有 `_resolve_env_vars` 完成展开
- `.env` 不入库（已确认本地存在 `XX-AI-KEY`）；`.env.example` 提供模板
- 开关矩阵：`system_one.enabled` × `llm.enabled` 四种组合全部可用（纯本地 / 仅判定 / 仅生成 / 全功能）

---

## 11. 指标与可观测性

`GET /api/metrics`（JSON，P1；Prometheus 格式留 P3）：

| 指标 | 意义 |
|------|------|
| `routing_latency_ms`（histogram: p50/p95/p99） | ingest→路由完成 |
| `backlog_age_ms`（max over unrouted alerts） | **积压的直接观测** |
| `queue_depth` / `queue_high_water_events` | 背压水位 |
| `systemone_requests_total` / `tokens_in_total` / `cache_hit_total` | 调用量与成本（¥ = tokens×0.042/1M） |
| `degraded_total` / `fallback_active` | 降级状态 |
| `confidence_histogram` | 判定质量分布 |
| `cases_created_total` / `alerts_routed_total` / `route_to_ratio` | 分流效果（并入率） |

结构化日志沿用 structlog（控制台+文件双输出已有）。

---

## 12. 生产化骨架与迁移缝

MVP 单进程内实现，每个组件的接口按外置形态设计：

| 组件 | MVP（P1） | 生产迁移缝（P3+） | 缝的定义 |
|------|-----------|-------------------|----------|
| 路由任务队列 | asyncio.Queue（进程内） | Kafka / Redis Stream | `AlertSink` 接口：put/batch/consume |
| 状态存储 | SQLite（WAL+批量写） | Postgres（cases/events/decisions）+ ClickHouse（alerts 海量） | Store 层已是接口，补 async profile 工厂 |
| 路由热状态 | 内存索引+缓存 | Redis（共享索引，多副本前提） | `CaseRoutingIndex` 抽象基类，内存实现为默认 |
| 判定引擎 | 象信云 API | 内网部署象信私有化端点（base_url 可配，已天然支持） | base_url 即缝 |
| 执行形态 | uvicorn 单进程 monolith | ingest/router/s2 分进程部署 | 组件间已无共享可变状态（索引外置后） |

多副本正确性前提（记录不实现）：partition key（如 src_ip hash）分片告警流 + case 所有权 lease——**完整设计已独立成文：[SCALING_DESIGN.md](SCALING_DESIGN.md)**（分区拓扑、lease 协议、组件外置映射与阶段化迁移路径）。

---

## 13. 分阶段路线

### P1 分流骨架（Epic #1，本轮）
1. ~~存量治理与 CI 门禁~~（#2 ✅ PR#12）
2. ~~设计文档~~（#3 本 PR）
3. System One 客户端与配置（#4）
4. Router 引擎替换 aggregator：索引/微批/降级/恢复/背压/metrics/路由页（#5）
5. 压测与降级演练（#6）

**验收**：pytest 全绿（存量87+新增）、ruff 干净、CI 门禁生效；压测 ≥500 alerts/s、路由 P99<1s；中断 System One 模拟（断网/429注入）降级接管；重启恢复后路由语义正确。

### P2 生长与认知闭环
认知任务映射落地（#7）、合并/拆分（#8）、OpsRecord 与上下文组装（#9）。

### P3 生产硬化
保留策略与存储 profile（#10）、多副本迁移缝文档化（#11）、Prometheus 指标、告警面板。

---

## 14. 风险与对策

| 风险 | 对策 |
|------|------|
| 象信云 API 可用性 | 降级链（§5.5）+ `enabled=false` 纯本地模式；后续内网私有化端点只需换 base_url |
| 组织级 1,200 req/min 配额被多环境共享 | 微批（§5.2）+ 决策缓存（§5.4）+ 调用量指标告警；必要时联系象信提额（wanglei@xiangxinai.cn） |
| 概率浮点抖动导致测试不稳定 | 区间断言；决策不可逆设计天然免疫临界抖动（§5.3） |
| 64k 预算超限（422） | token 估算器动态裁批；state 紧凑模板固定上限 |
| System One 判定质量不如预期 | confidence 阈值保守侧（错并代价>错分）；复核队列兜底；P2 蒸馏回路持续改进；决策审计支持回归评估 |
| 大量告警下 SQLite 容量 | P3 分区+保留策略（#10）；alerts 表 append-only 适合归档 |
| 单进程内存态 | MVP 明示单副本部署；迁移缝已定义（§12） |

---

## 15. 象信 System One API 事实清单（实现依据）

- 端点：`POST https://api.xiangxinai.cn/v1/systemone`，`Authorization: Bearer <key>`
- 请求：`{"state": "<文本>", "model": "xiangxin-latest", "questions": {"<名>": {"type": "choice|score|noul", "instructions": "...", "criteria": {...}|[...]}}}`
- 响应：`{"answers": {"<名>": {"type", "choice"|"score"|"noul", "confidence", "probabilities", "legend"?}}, "usage": {"input_tokens", "output_tokens"}}`
- SDK：`xiangxin-sdk`（Python≥3.10，同步接口）；**本项目采用自写 async httpx 薄客户端**（全 asyncio 栈），请求/响应结构以本文档为准，SDK 作对照
- 错误处理：429/529 → retry-after(ms 优先) 退避；5xx → 0.5s 起指数退避+抖动 ≤3 次；422 → 请求构造问题（选项>255 / token>64k），不重试；402 余额、401 key 错误 → 直接告警降级
- 参考：[快速开始](https://docs.xiangxinai.cn/introduction/quickstart) ｜ [API 参考](https://docs.xiangxinai.cn/api) ｜ [官网](https://xiangxinai.cn)

---

## 16. P1 实现期验证清单

- [ ] 真实 key 冒烟：单请求 state+Choice（scripts/systemone_smoke.py），验证连通/响应结构/计费
- [ ] 微批正确性：100ms 窗口内 N 条告警合成 1 次请求，answers 与告警一一对应
- [ ] 降级演练：mock 断网 → LocalFallback 接管 → 恢复探测切回，degraded 计数正确
- [ ] 429 注入：按 retry-after 退避，不风暴
- [ ] 重启恢复：活跃 Case 索引重建后路由行为与重启前一致；未路由告警回灌零丢失
- [ ] 背压：灌入超量告警，队列水位触发过载模式，无丢弃
- [ ] 压测报告：≥500 alerts/s、P99<1s、积压年龄收敛（scripts/load_test.py）
