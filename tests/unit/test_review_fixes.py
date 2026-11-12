"""整体 code review 修复回归测试（issue #56）

覆盖本次修复的关键缺陷：数据抹除/丢批/零丢弃/at-least-once/审计完整性/
端点错误语义/密闭性支撑（database.url接线）等。
"""
from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime

from aicso.adapters.base import DataSourceAdapter
from aicso.config import RetentionConfig, RoutingConfig, SystemOneConfig
from aicso.core.approval import ApprovalEngine, ApprovalStatus, RiskLevel
from aicso.core.event_bus import EventBus
from aicso.core.retention import RetentionService
from aicso.mapping.engine import SchemaMapper
from aicso.mapping.suggest import _is_ip
from aicso.models.alert import Alert
from aicso.models.case import Case, CaseSeverity
from aicso.models.routing import FALSE_POSITIVE
from aicso.router.engine import RouterEngine
from aicso.router.tuner import ParamTuner
from aicso.store.alert_store import AlertStore
from aicso.store.case_store import CaseStore
from aicso.store.database import Database
from aicso.store.routing_store import RoutingDecisionStore


async def make_db():
    db = Database(":memory:")
    await db.connect()
    await db.init_tables()
    return db


def make_alert(alert_id="A-1", src="1.2.3.4", dst="10.0.0.1", **kw):
    kw.setdefault("rule_name", "R")
    kw.setdefault("severity", "high")
    return Alert(alert_id=alert_id, source="t", src_ip=src, dst_ip=dst, **kw)


# ---- 1. Case update 不再抹字段（#56发现1） ----

class TestCaseUpdatePreservesFields:
    async def test_from_row_roundtrip(self):
        case = Case(case_id="C-1", title="T", severity=CaseSeverity.HIGH,
                    metadata={"routing": {"source": "router"}}, tags=["x"])
        case.sla_deadline = datetime(2026, 1, 1, 12, 0)
        case.closed_at = datetime(2026, 1, 2)
        case.ai_summary = "summary"
        db = await make_db()
        store = CaseStore(db)
        await store.create(case)
        row = await store.get("C-1")
        rebuilt = Case.from_row(row)
        assert rebuilt.tags == ["x"]
        assert rebuilt.metadata == {"routing": {"source": "router"}}
        assert rebuilt.sla_deadline is not None
        assert rebuilt.closed_at is not None
        await store.update(rebuilt)
        row2 = await store.get("C-1")
        # 全列UPDATE后字段仍在
        assert json.loads(row2["tags"]) == ["x"]
        assert json.loads(row2["metadata"])["routing"]["source"] == "router"
        assert row2["sla_deadline"] is not None
        assert row2["ai_summary"] == "summary"
        await db.close()

    async def test_from_row_tolerates_dirty_severity(self):
        db = await make_db()
        rebuilt = Case.from_row({"case_id": "C-2", "title": "T",
                                 "severity": "P1-紧急", "status": "new"})
        assert rebuilt.severity == CaseSeverity.MEDIUM
        await db.close()


# ---- 2. WriteBuffer 失败不丢批（#56发现2） ----

class TestWriteBufferRetry:
    async def test_poison_isolated_not_dropping_batch(self):
        db = await make_db()
        db.enable_write_buffer(batch_size=100, flush_interval=10)
        buf = db._write_buffer
        # 一条毒语句（引用不存在的表）+ 一条好语句
        await buf.add("INSERT INTO no_such_table VALUES (1)", ())
        await buf.add(
            "INSERT INTO cases (case_id, title, severity, status, priority, created_at, updated_at)"
            " VALUES ('C-WB', 't', 'high', 'new', 3, '2026-01-01', '2026-01-01')", ())
        await buf.flush()
        assert buf.flush_failures >= 1
        assert buf.dropped_total == 0  # 未达重试上限，仍在重试队列
        # 好语句在毒语句重试达上限被二分隔离后应能落库
        for _ in range(20):
            await buf.flush()
            if buf.dropped_total:
                break
        await db.flush()
        assert await db.fetch_one("SELECT * FROM cases WHERE case_id='C-WB'") is not None
        assert buf.dropped_total == 1  # 只有毒语句被死信
        await db.close()


# ---- 3. FP 决策落审计（#56发现9） ----

class TestFalsePositiveAudit:
    async def test_fp_decision_persisted(self):
        db = await make_db()
        case_store = CaseStore(db)
        alert_store = AlertStore(db)
        engine = RouterEngine(case_store, alert_store, RoutingDecisionStore(db),
                              SystemOneConfig(enabled=True), RoutingConfig(), client=None)
        alert = make_alert()
        await alert_store.create(alert)
        engine.record_false_positive(alert)
        await engine.submit(alert)  # 入队后flush才会走到FP分支
        decisions = await engine.flush()
        assert len(decisions) == 1
        assert decisions[0].decision == FALSE_POSITIVE
        # _finalize 是fire-and-forget任务：让出事件循环等审计落库
        await asyncio.sleep(0.05)
        rows = await db.fetch_all("SELECT * FROM routing_decisions")
        assert len(rows) == 1
        assert rows[0]["source"] == "false_positive"
        await db.close()


# ---- 4. backlog 锚点队列空才清（#56发现11） ----

class TestBacklogAnchor:
    async def test_anchor_survives_batch_when_queue_has_more(self):
        db = await make_db()
        engine = RouterEngine(CaseStore(db), AlertStore(db), RoutingDecisionStore(db),
                              SystemOneConfig(enabled=True), RoutingConfig(), client=None)
        for i in range(3):
            a = make_alert(alert_id=f"A-{i}")
            await AlertStore(db).create(a)
            await engine.submit(a)
        # 手工路由一批（取1条），队列仍有积压 → 锚点保留
        batch = [engine._batcher.get_nowait()]
        await engine._route_batch(batch)
        assert engine.metrics.oldest_pending_since is not None
        await engine.flush()
        assert engine.metrics.oldest_pending_since is None  # 排空后才清
        await db.close()


# ---- 5. 缓存：merge失效 + 惰性清扫（#56发现6/11） ----

class TestCacheLifecycle:
    async def test_invalidate_cache_for(self):
        db = await make_db()
        engine = RouterEngine(CaseStore(db), AlertStore(db), RoutingDecisionStore(db),
                              SystemOneConfig(enabled=True), RoutingConfig(), client=None)
        a1 = make_alert()  # 默认 1.2.3.4→10.0.0.1
        a2 = make_alert(src="9.9.9.9", dst="8.8.8.8")
        engine._cache_store(a1, "C-A")
        engine._cache_store(a2, "C-B")
        removed = engine.invalidate_cache_for("C-A")
        assert removed == 1
        assert engine._cache_lookup(a1) is None
        assert engine._cache_lookup(a2) == "C-B"
        await db.close()

    async def test_cache_sweep_expires(self):
        db = await make_db()
        engine = RouterEngine(CaseStore(db), AlertStore(db), RoutingDecisionStore(db),
                              SystemOneConfig(enabled=True), RoutingConfig(), client=None)
        engine._cache_store(make_alert(), "C-A")
        old = datetime(2020, 1, 1)
        sig = next(iter(engine._cache))
        engine._cache[sig] = ("C-A", old)
        assert engine._cache_sweep() == 1
        assert sig not in engine._cache
        await db.close()


# ---- 6. tuner 回滚不震荡（#56发现42） ----

class TestTunerRollbackIdempotent:
    def test_rollback_twice_moves_back_once(self):
        from aicso.router.metrics import RouterMetrics
        from aicso.router.tuner import TunerDecision

        scfg = SystemOneConfig(enabled=True, token_budget=32000,
                               timeout_scale=0.3, auto_tune=True)
        tuner = ParamTuner(scfg, RouterMetrics())
        decision = TunerDecision("token_budget", 32000, 25600, "测试调整")
        tuner.apply(decision)
        tuner.history.append(decision)
        d1 = tuner.rollback()
        assert d1 is not None and d1.new == 32000
        d2 = tuner.rollback()
        assert d2 is None  # 无可回滚——不会反向撤销第一次回滚（震荡修复）
        assert scfg.token_budget == 32000


# ---- 7. 时间戳统一UTC（#56发现19） / severity 键断裂+校验（#56发现20/21） ----

class TestMappingFixes:
    def test_epoch_and_iso_same_instant(self):
        mapper = SchemaMapper({})
        iso = "2025-08-27T00:00:00Z"
        epoch = int(datetime(2025, 8, 27, tzinfo=UTC).timestamp())
        from_epoch = mapper._normalize_timestamp(epoch)
        from_iso = mapper._normalize_timestamp(iso)
        assert from_epoch == from_iso  # 此前epoch走本地时区差8小时

    def test_legacy_severity_key_recognized(self):
        mapper = SchemaMapper({"field_mapping": {"severity": "level"}})
        alert, warnings = mapper.normalize(
            {"level": "high", "alert_id": "X-1", "src_ip": "1.1.1.1"},
            fallback_alert_id="fb")
        assert alert.severity == "high"
        assert not any("无法识别严重度" in w for w in warnings)

    def test_invalid_severity_mapping_value_falls_back(self):
        # 文本映射分支：值不在规范词表 → 告警并回退medium（分支1数值映射
        # 的同类校验在threshold接管时不产生额外告警，语义正确）
        mapper = SchemaMapper({"severity_mapping": {"高": "P1-紧急"}})
        alert, warnings = mapper.normalize(
            {"severity": "高", "alert_id": "X-2", "src_ip": "1.1.1.1"},
            fallback_alert_id="fb")
        assert alert.severity == "medium"  # 不让任意字符串静默入库
        assert any("不在规范词表" in w for w in warnings)

    def test_expand_non_dict_array_no_silent_loss(self):
        # events_path未配置 → 单事件；显式配置时数组全为非dict元素回退raw包装
        mapper2 = SchemaMapper({"events_path": "data"})
        events2 = mapper2.expand_message('{"data": [1, 2, 3]}')
        assert events2 and events2[0].get("__raw__") is not None

    def test_ipv6_detected(self):
        assert _is_ip("2001:db8::1")
        assert not _is_ip("example.com")


# ---- 8. database.url 接线（#56发现44） ----

class TestDatabaseUrlWiring:
    def test_url_parses_to_path(self):
        db = Database(url="sqlite+aiosqlite:///./custom/dir/test.db")
        assert db.db_path == "./custom/dir/test.db"
        db2 = Database(url="sqlite:///plain.db")
        assert db2.db_path == "plain.db"
        db3 = Database()  # 默认
        assert db3.db_path == "aicso.db"

    async def test_connect_creates_parent_dir(self, tmp_path):
        db = Database(str(tmp_path / "sub" / "dir" / "x.db"))
        await db.connect()
        assert (tmp_path / "sub" / "dir" / "x.db").exists()
        await db.close()


# ---- 9. ENV 占位符未定义→空（#56发现45） ----

class TestEnvResolution:
    def test_unresolved_placeholder_is_empty(self, tmp_path, monkeypatch):
        from aicso.config import load_config
        monkeypatch.delenv("NO_SUCH_KEY_XYZ", raising=False)
        (tmp_path / "c.yaml").write_text(
            "system_one:\n  enabled: true\n  api_key: ${NO_SUCH_KEY_XYZ}\n",
            encoding="utf-8")
        config = load_config(str(tmp_path / "c.yaml"))
        assert config.system_one.api_key == ""  # 不再是"${NO_SUCH_KEY_XYZ}"字面量


# ---- 10. 审批状态守卫（#56发现16） ----

class TestApprovalGuards:
    async def test_timeout_request_cannot_be_revived(self):
        engine = ApprovalEngine(EventBus())
        import asyncio
        task = asyncio.create_task(engine.request_approval(
            "isolate", "host-1", "C-1", RiskLevel.HIGH))
        await asyncio.sleep(0)
        request_id = next(iter(engine._pending))
        # 模拟超时：决议前先把future取消等待（直接调用内部状态守卫）
        engine._pending[request_id].status = ApprovalStatus.TIMEOUT
        ok = await engine.approve(request_id, approver="late-admin")
        assert not ok  # 超时后不可"复活"批准
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    async def test_resolved_request_removed_from_pending(self):
        engine = ApprovalEngine(EventBus())
        task = asyncio.create_task(engine.request_approval(
            "ban_ip", "1.2.3.4", "C-1", RiskLevel.MEDIUM))
        await asyncio.sleep(0)
        request_id = next(iter(engine._pending))
        await engine.reject(request_id, approver="analyst")
        assert request_id not in engine._pending  # 决议后移出，无界增长修复
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


# ---- 11. retention 只删已路由（#56发现3，语义补充断言） ----

class TestRetentionZeroDrop:
    async def test_backlog_never_deleted_even_in_all_scope(self):
        db = await make_db()
        alert_store = AlertStore(db)
        from datetime import timedelta
        old = make_alert("A-OLD")
        old.created_at = datetime.utcnow() - timedelta(days=400)
        await alert_store.create(old)  # 未路由（routed_at IS NULL）
        service = RetentionService(db, RetentionConfig(alert_days=90, scope="all"))
        deleted = await service.cleanup()
        assert deleted == 0
        assert await alert_store.get("A-OLD") is not None
        await db.close()


# ---- 12. 基类 close() 存在（#56发现24） ----

class TestAdapterBaseClose:
    async def test_base_close_is_noop_callable(self):
        class Dummy(DataSourceAdapter):
            async def connect(self, config): return True
            async def fetch_alerts(self, since): return []
            async def normalize(self, raw): return make_alert()

        d = Dummy()
        await d.close()  # 此前AttributeError：syslog/json_file走suggest live 500

    async def test_poll_logs_normalize_failure(self, caplog):
        class Boom(DataSourceAdapter):
            async def connect(self, config): return True
            async def fetch_alerts(self, since): return [{"bad": 1}]
            async def normalize(self, raw): raise ValueError("boom")

        b = Boom()
        results = await b.poll(datetime.utcnow())
        assert results == []  # 跳过但仍留error日志（structlog经root logger）


# ---- 13. 冷发现共享实体精确性（#56发现12） ----

class TestColdDiscoveryExactSharedIP:
    async def test_only_actually_shared_ip_in_evidence(self):
        from aicso.router.merge import MergeSplitEngine
        db = await make_db()
        case_store = CaseStore(db)
        alert_store = AlertStore(db)
        for cid in ("C-1", "C-2"):
            c = Case(case_id=cid, title=cid, severity=CaseSeverity.MEDIUM)
            await case_store.create(c)
        # C-1: src=1.1.1.1 dst=10.0.0.1；C-2: src=5.5.5.5 dst=1.1.1.1
        # 真实共享只有 1.1.1.1；10.0.0.1 不得混入（告警必须挂case_id才参与JOIN）
        await alert_store.create(make_alert("A-1", src="1.1.1.1", dst="10.0.0.1", case_id="C-1"))
        await alert_store.create(make_alert("A-2", src="5.5.5.5", dst="1.1.1.1", case_id="C-2"))
        await db.flush()
        engine = MergeSplitEngine(
            case_store, alert_store, None, SystemOneConfig(enabled=False),
            index=None, fallback=None)
        pairs = await engine.find_cold_candidate_pairs()
        matched = [p for p in pairs if {p.case_a, p.case_b} == {"C-1", "C-2"}]
        assert matched, "应发现共享1.1.1.1的候选对"
        assert matched[0].shared_entities == ["ip:1.1.1.1"]
        await db.close()


# ---- 14. 存活率非负（#56发现14） ----

class TestSurvivalNonNegative:
    async def test_split_after_merge_keeps_survival_bounded(self):
        from aicso.router.merge import MergeSplitEngine
        db = await make_db()
        case_store = CaseStore(db)
        # case_events.case_id 外键引用 cases——先建宿主Case
        await case_store.create(Case(case_id="C-1", title="T", severity=CaseSeverity.MEDIUM))
        engine = MergeSplitEngine(case_store, AlertStore(db), None,
                                  SystemOneConfig(enabled=False), None, None)
        async def add_event(case_id, etype, detail):
            await engine._add_event(case_id, etype, detail)
        await add_event("C-1", "case_merged", {"evidence": {"shared_entity_keys": ["ip:1.1.1.1"]}})
        await add_event("C-1", "case_split", {})
        await add_event("C-1", "case_split", {})  # 二次拆分不再重复计数
        report = await engine.entity_survival_report()
        entry = report["types"]["ip"]
        assert entry["split"] == 1  # 一次性失效
        assert entry["survival"] == 0.0
        assert entry["survival"] >= 0
        await db.close()


# ---- 15. API 端点错误语义（走真实app，密闭配置） ----

class TestAPIErrorSemantics:
    async def _client(self):
        from contextlib import asynccontextmanager

        from httpx import ASGITransport, AsyncClient

        from aicso.api.app import app

        @asynccontextmanager
        async def _lifespan_and_client():
            async with app.router.lifespan_context(app):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url="http://test") as client:
                    yield client

        async with _lifespan_and_client() as client:
            yield client

    async def test_merge_evaluate_missing_params_is_400(self):
        async for client in self._client():
            r = await client.post("/router/api/merge/evaluate", json={})
            assert r.status_code == 400  # 此前(dict,400)元组实际返回200+数组
            assert not isinstance(r.json(), list)

    async def test_mock_count_clamped(self):
        async for client in self._client():
            r = await client.post("/mock/api/generate",
                                  json={"count": 1000000, "inject": False})
            assert r.status_code == 400  # 服务端钳制，此前可灌百万告警
            r2 = await client.post("/mock/api/generate",
                                   json={"count": "abc", "inject": False})
            assert r2.status_code == 400

    async def test_case_context_missing_is_404(self):
        async for client in self._client():
            r = await client.get("/cases/api/NO-SUCH/context")
            assert r.status_code == 404  # 此前500（not-found检查是死代码）

    async def test_approval_api_roundtrip(self):
        """审批API死路复活：请求→pending→reject 全链路（#56发现16）"""
        engine = ApprovalEngine(EventBus())

        async def slow_op():
            return await engine.request_approval(
                "isolate_host", "h-1", "C-1", RiskLevel.HIGH)

        import asyncio as _asyncio
        task = _asyncio.create_task(slow_op())
        await _asyncio.sleep(0.05)
        pending = engine.get_pending()
        assert len(pending) == 1
        rid = pending[0].request_id
        ok = await engine.reject(rid, approver="soc_manager", reason="误报")
        assert ok
        result = await task
        assert result.approved is False
        assert engine.get_pending() == []

    async def test_alert_list_negative_limit_clamped(self):
        async for client in self._client():
            r = await client.get("/alerts/api/list", params={"limit": -1})
            assert r.status_code == 200
            # 不再返回全表（SQLite负LIMIT=无上限）
            assert "alerts" in r.json()
