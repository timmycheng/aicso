"""告警保留策略与存储profile缝测试（issue #10）"""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from aicso.config import RetentionConfig
from aicso.core.retention import RetentionService
from aicso.models.alert import Alert
from aicso.models.case import Case, CaseSeverity, CaseStatus
from aicso.store.alert_store import AlertStore
from aicso.store.case_store import CaseStore
from aicso.store.database import Database


async def make_setup():
    db = Database(":memory:")
    await db.connect()
    await db.init_tables()
    return db, CaseStore(db), AlertStore(db)


async def seed_alert(alert_store, alert_id, case_id=None, age_days=0, routed=True):
    """routed=False 模拟路由积压（routed_at IS NULL）——零丢弃语义下永不清理"""
    created = datetime.utcnow() - timedelta(days=age_days)
    alert = Alert(
        alert_id=alert_id, source="t", rule_name="R", severity="high",
        src_ip="1.1.1.1", dst_ip="10.0.0.1", case_id=case_id,
        created_at=created,
    )
    await alert_store.create(alert)
    if routed:
        if case_id:
            await alert_store.mark_routed(alert_id, case_id, "system_one")
        else:
            # 已路由但无Case的孤立告警（如误报消费）也应可被清理
            await alert_store.mark_false_positive(alert_id)


async def seed_case(case_store, case_id, status=CaseStatus.NEW):
    case = Case(case_id=case_id, title="T", severity=CaseSeverity.MEDIUM,
                status=status)
    case.record_case_created()
    await case_store.create(case)


class TestProfileSeam:
    def test_sqlite_default_ok(self):
        db = Database()  # 默认sqlite
        assert db.profile == "sqlite"

    def test_postgres_profile_raises_with_pointer(self):
        with pytest.raises(NotImplementedError, match="REFACTOR_DESIGN"):
            Database(profile="postgres")  # 配置缝：显式失败+文档指引


class TestRetentionCleanup:
    async def test_disabled_when_zero_days(self):
        db, case_store, alert_store = await make_setup()
        await seed_alert(alert_store, "A-1", age_days=400)
        service = RetentionService(db, RetentionConfig(alert_days=0))
        assert await service.cleanup() == 0
        assert await alert_store.get("A-1") is not None
        await db.close()

    async def test_closed_cases_scope(self):
        db, case_store, alert_store = await make_setup()
        await seed_case(case_store, "C-CLOSED", status=CaseStatus.CLOSED)
        await seed_case(case_store, "C-ACTIVE", status=CaseStatus.INVESTIGATING)
        # 过期+已关闭Case → 删
        await seed_alert(alert_store, "A-OLD-CLOSED", case_id="C-CLOSED", age_days=100)
        # 过期+活跃Case → 留
        await seed_alert(alert_store, "A-OLD-ACTIVE", case_id="C-ACTIVE", age_days=100)
        # 过期+孤立（已路由误报）→ 删
        await seed_alert(alert_store, "A-OLD-ORPHAN", age_days=100)
        # 未过期 → 留
        await seed_alert(alert_store, "A-NEW", case_id="C-CLOSED", age_days=1)
        # 过期+未路由积压（routed_at IS NULL）→ 留（零丢弃，review #56发现3）
        await seed_alert(alert_store, "A-OLD-BACKLOG", age_days=100, routed=False)

        service = RetentionService(db, RetentionConfig(alert_days=90, scope="closed_cases"))
        deleted = await service.cleanup()
        assert deleted == 2
        assert await alert_store.get("A-OLD-CLOSED") is None
        assert await alert_store.get("A-OLD-ORPHAN") is None
        assert await alert_store.get("A-OLD-ACTIVE") is not None
        assert await alert_store.get("A-NEW") is not None
        assert await alert_store.get("A-OLD-BACKLOG") is not None
        await db.close()

    async def test_orphan_only_scope(self):
        db, case_store, alert_store = await make_setup()
        await seed_case(case_store, "C-CLOSED", status=CaseStatus.CLOSED)
        await seed_alert(alert_store, "A-OLD-CLOSED", case_id="C-CLOSED", age_days=100)
        await seed_alert(alert_store, "A-OLD-ORPHAN", age_days=100)
        await seed_alert(alert_store, "A-OLD-BACKLOG", age_days=100, routed=False)

        service = RetentionService(db, RetentionConfig(alert_days=90, scope="orphan_only"))
        deleted = await service.cleanup()
        assert deleted == 1
        assert await alert_store.get("A-OLD-CLOSED") is not None
        assert await alert_store.get("A-OLD-ORPHAN") is None
        assert await alert_store.get("A-OLD-BACKLOG") is not None
        await db.close()

    async def test_all_scope(self):
        db, case_store, alert_store = await make_setup()
        await seed_case(case_store, "C-ACTIVE", status=CaseStatus.NEW)
        await seed_alert(alert_store, "A-OLD-ACTIVE", case_id="C-ACTIVE", age_days=100)
        await seed_alert(alert_store, "A-NEW", age_days=1)
        await seed_alert(alert_store, "A-OLD-BACKLOG", age_days=100, routed=False)

        service = RetentionService(db, RetentionConfig(alert_days=90, scope="all"))
        deleted = await service.cleanup()
        assert deleted == 1
        assert await alert_store.get("A-OLD-ACTIVE") is None
        assert await alert_store.get("A-NEW") is not None
        assert await alert_store.get("A-OLD-BACKLOG") is not None
        await db.close()

    async def test_invalid_scope_noop(self):
        db, case_store, alert_store = await make_setup()
        await seed_alert(alert_store, "A-1", age_days=100)
        service = RetentionService(db, RetentionConfig(alert_days=90, scope="bogus"))
        assert await service.cleanup() == 0
        assert await alert_store.get("A-1") is not None
        await db.close()

    async def test_periodic_start_stop(self):
        db, case_store, alert_store = await make_setup()
        service = RetentionService(
            db, RetentionConfig(alert_days=90, cleanup_interval_minutes=1))
        service.start()
        assert service._running is True
        await service.stop()
        assert service._running is False
        # alert_days=0 不启动
        service2 = RetentionService(db, RetentionConfig(alert_days=0))
        service2.start()
        assert service2._running is False
        await db.close()
