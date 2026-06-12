"""生成测试数据脚本"""
import asyncio
import sys
import uuid
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aicso.store.database import Database
from aicso.store.case_store import CaseStore
from aicso.store.alert_store import AlertStore
from aicso.models.case import Case, CaseSeverity, CaseStatus
from aicso.models.alert import Alert


async def seed(db_path: str = "aicso.db"):
    print(f"Seeding database: {db_path}")
    db = Database(db_path)
    await db.connect()

    case_store = CaseStore(db)
    alert_store = AlertStore(db)

    # 创建测试Case
    cases_data = [
        ("疑似钓鱼攻击-财务部", CaseSeverity.HIGH, CaseStatus.INVESTIGATING),
        ("暴力破解攻击-VPN", CaseSeverity.CRITICAL, CaseStatus.RESPONDING),
        ("异常外联行为", CaseSeverity.MEDIUM, CaseStatus.NEW),
        ("弱密码告警", CaseSeverity.LOW, CaseStatus.RESOLVED),
        ("挖矿行为检测", CaseSeverity.HIGH, CaseStatus.ASSIGNED),
    ]

    for i, (title, severity, status) in enumerate(cases_data):
        case_id = f"CSO-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        case = Case(
            case_id=case_id,
            title=title,
            severity=severity,
            status=status,
            assignee_id=f"analyst_{(i % 3) + 1}",
        )
        await case_store.create(case)

        # 为每个Case创建1-3条告警
        for j in range(i % 3 + 1):
            alert = Alert(
                alert_id=f"ALT-{uuid.uuid4().hex[:8]}",
                source=["suricata", "edr", "waf", "siem"][j % 4],
                rule_name=f"Rule-{title[:10]}-{j}",
                severity=severity.value,
                src_ip=f"10.0.{i}.{j + 1}",
                dst_ip=f"192.168.1.{i * 10 + j}",
                timestamp=datetime.utcnow() - timedelta(hours=i),
            )
            await alert_store.create(alert)
            await alert_store.update_case_id(alert.alert_id, case_id)

    print(f"Created {len(cases_data)} test cases with alerts")
    await db.close()


if __name__ == "__main__":
    db_path = sys.argv[1] if len(sys.argv) > 1 else "aicso.db"
    asyncio.run(seed(db_path))
