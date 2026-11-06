# AiCSO 多副本扩展与迁移缝设计（P3）

> 状态：设计记录（按 issue #11 约定本期仅文档，不实现）　|　关联：[REFACTOR_DESIGN §12](REFACTOR_DESIGN.md)

---

## 1. 何时需要多副本

单副本 MVP（单进程 asyncio + SQLite）的容量边界与突破信号：

| 维度 | 单副本边界 | 突破信号 |
|------|-----------|----------|
| 告警吞吐 | ~1275 alerts/s（本地兜底实测） | 持续逼近 CPU/写瓶颈 |
| System One 判定 | 组织级 1200 req/min ≈ 1000 alerts/s（微批摊薄） | 配额打满且提额不可行 |
| 可用性 | 单点 | HA 要求 |
| 存储 | SQLite 单机文件 | 多机共享/容量（见 profile 缝） |

**原则：不为扩展而扩展**。单副本未达边界前，扩容优先级是：提额/私有化端点 > 纵向扩容 > 本设计的多副本。

## 2. 告警流分区（Partition）

### 2.1 Partition Key

```
partition = hash(src_ip) % N     # N = 分片数
```

- **为什么按 src_ip**：同源告警必须落同一分片，才能保证"同源告警汇入同一Case"的窗口语义在分片间不被撕裂
- 候选备选：`hash(src_ip+dst_ip)`（更细，但同一源多目标的攻击链会被拆散）、`hash(alert.entity_signature)`（复用决策缓存签名语义）
- 实体跨源场景（如 C2 基础设施关联多源）由 **合并引擎（P2 #8）跨Case收敛**，不依赖分区正确性

### 2.2 分区拓扑

```
                       ┌─ partition 0 ─→ Router副本0（S1+S2）──┐
数据源 → Ingest层 ──────┼─ partition 1 ─→ Router副本1 ──────────┼─→ 共享存储
(Kafka按key分区)       └─ partition 2 ─→ Router副本2 ──────────┘
```

- Ingest 层：Kafka 生产者按 key 分区（`AlertSink` 接口缝，见 §4）
- 每个分片一个 RouterEngine 实例，索引/缓存/微批全部分片私有——**无共享可变状态**

## 3. Case 所有权 Lease

### 3.1 问题

S1 路由按分片独占即可；但 **Case 的写操作**（S2 研判修正严重度、OpsRecord、合并/拆分、状态流转）可能跨分片（C2 基础设施的 Case 涉及多源告警，各源在不同分片路由）。并发写同一 Case 行必须串行化。

### 3.2 Lease 协议

```
lease记录: (case_id, owner_node, lease_until)
获取:     UPDATE case_leases SET owner=?, lease_until=now+TTL
          WHERE case_id=? AND (lease_until < now OR owner=?)
          -- 单行原子抢占（Postgres行锁天然支持）
续约:     S2任务执行中每 TTL/2 续一次；任务时长> TTL 则分段持有
释放:     任务完成即释放；节点宕机靠 TTL 自然过期（建议 TTL=60s）
等待:     抢占失败 → 指数退避重试（上限后转人工复核队列）
```

- 粒度：**per-Case**，不锁全表
- 死锁自由：单 Case 单锁，合并引擎的跨 Case 操作按 case_id 排序后依次取锁（防环）
- SQLite 无行锁语义——lease 表实现属于 Postgres profile 的一部分（§4 阶段C）

### 3.3 与现有幂等设计的衔接

- merge 已按 `merged_into` 状态幂等（#8）——多副本下重复调度安全
- 路由幂等：alert_id 主键 + `routed_at` 判定——at-least-once 投递不产生双路由
- System One 判定可重入：同一告警重判结果概率抖动（象信文档明示）由"决策不可逆"吸收（§5.3 滞回）

## 4. 组件外置映射与缝的现状

| 组件 | 现状（MVP） | 外置目标 | 缝就位情况 |
|------|------------|----------|-----------|
| 路由队列 | `RoutingBatcher`（进程内 asyncio.Queue） | Kafka / Redis Stream | ✅ 接口已收敛：`try_put/collect/get_nowait` 三方法，换实现不改引擎 |
| 候选索引 | `CaseRoutingIndex`（内存） | Redis hash/SET | ✅ `add_case/record_hit/candidates/deactivate/rebuild/contains` 已抽象；换 Redis 实现保持签名 |
| 存储 | SQLite（profile="sqlite"） | Postgres（cases/events/decisions/leases）+ ClickHouse（alerts海量） | ✅ `database.profile` 配置缝 + 显式 NotImplementedError（#20）；SQL 方言差异集中在 store 层 |
| 判定引擎 | 象信云 API | 内网私有化端点 | ✅ `base_url` 即缝，零代码变更 |
| S2 任务队列 | orchestrator 内部 queue | 独立 worker 进程 | ✅ S2Dispatcher/Agent 无进程内绑定状态 |
| 事件总线 | EventBus 内存 Pub/Sub | Redis Pub/Sub | ⚠ 接口已收敛（publish/subscribe），需新增后端实现 |
| 审计 | SQLite 表 | 不变（随存储 profile） | ✅ |

## 5. 阶段化迁移路径

```
阶段A（当前）: 单进程 monolith
  └ 全部内存队列+SQLite，内网单机 Docker

阶段B: 队列外置，读写分离（单写多读）
  ├ Kafka/Redis 承接告警流（AlertSink 实现）
  ├ ingest 独立进程（数据源轮询 → 生产者）
  ├ Router+S2 仍单副本（消费消费）
  └ 存储仍 SQLite → 触发容量边界后进 C

阶段C: 多副本分区 + lease
  ├ Kafka 按 src_ip 分区 → N 个 Router 副本
  ├ Postgres profile（case/event/decision/lease 表）
  ├ alerts 迁 ClickHouse（保留策略由 TTL 语义替代）
  └ Case 写操作经 lease 协调（§3）

每阶段独立可回退；阶段B不引入lease（单副本写者），阶段C才需要。
```

## 6. 不做什么

- 不在单副本阶段预写 lease/分区代码（YAGNI——缝已就位，外置时按 §4 映射实现）
- 不做跨分片分布式事务：Case 间操作以幂等+补偿（merge 幂等键）替代
- 不做自动分片再均衡：N 固定，扩容=改配置+按新 key 重放（告警不可变，重放安全）
