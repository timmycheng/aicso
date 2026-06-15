"""Mock告警生成器 - 生成Elastic Security (ECS)格式的仿真安全告警"""
from __future__ import annotations

import json
import random
import uuid
from datetime import datetime, timedelta
from pathlib import Path

from aicso.models.alert import Alert

_INTERNAL_SUBNETS = ["10.0.0", "10.0.1", "10.0.2", "172.16.1", "172.16.2", "192.168.1"]
_EXTERNAL_IPS = [
    "103.216.152.45", "45.77.65.211", "185.220.101.34", "91.215.85.19",
    "77.247.181.163", "198.51.100.23", "203.0.113.45", "192.0.2.78",
]
_HOSTNAMES = [
    "DC-SRV-01", "WEB-SRV-03", "DB-SRV-02", "WORKSTATION-PC015",
    "WORKSTATION-PC023", "FILE-SRV-01", "MAIL-SRV-02", "APP-SRV-01",
]
_USERS = [
    "zhangwei", "lihua", "wangfang", "chenming", "liuyang",
    "admin", "svc_backup", "svc_sql", "administrator", "guest",
]
_DOMAINS = ["CORP", "ACME", "EXAMPLE"]

_RULE_TEMPLATES = [
    {
        "category": "brute_force",
        "rule_id": "rule-001",
        "rule_name": "SSH暴力破解检测",
        "rule_description": "检测短时间内同一源IP对目标主机的大量SSH登录失败尝试",
        "severity": "high",
        "src_port_range": (49152, 65535),
        "dst_port": 22,
        "protocol": "tcp",
        "event_action": "ssh_login_failure",
        "event_outcome": "failure",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "Brute Force - T1110",
        "count_range": (50, 500),
    },
    {
        "category": "phishing",
        "rule_id": "rule-002",
        "rule_name": "可疑钓鱼邮件附件检测",
        "rule_description": "检测包含可执行附件或宏文档的可疑入站邮件",
        "severity": "medium",
        "src_port_range": (25, 25),
        "dst_port_range": (1024, 65535),
        "protocol": "tcp",
        "event_action": "email_attachment_received",
        "event_outcome": "success",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "Phishing - T1566",
    },
    {
        "category": "malware",
        "rule_id": "rule-003",
        "rule_name": "恶意软件C2通信检测",
        "rule_description": "检测主机向已知C2服务器的出站连接",
        "severity": "critical",
        "src_port_range": (1024, 65535),
        "dst_port": 443,
        "protocol": "tcp",
        "event_action": "network_connection_denied",
        "event_outcome": "failure",
        "mitre_tactic": "Command and Control",
        "mitre_technique": "Application Layer Protocol - T1071",
    },
    {
        "category": "lateral_movement",
        "rule_id": "rule-004",
        "rule_name": "横向移动-PsExec远程执行",
        "rule_description": "检测通过PsExec进行的远程命令执行活动",
        "severity": "high",
        "src_port_range": (49152, 65535),
        "dst_port": 445,
        "protocol": "tcp",
        "event_action": "process_creation",
        "event_outcome": "success",
        "mitre_tactic": "Lateral Movement",
        "mitre_technique": "Remote Services - T1021",
    },
    {
        "category": "data_exfiltration",
        "rule_id": "rule-005",
        "rule_name": "大量数据外传检测",
        "rule_description": "检测单个主机短时间内向外部传输异常大量数据",
        "severity": "critical",
        "src_port_range": (1024, 65535),
        "dst_port": 443,
        "protocol": "tcp",
        "event_action": "network_bytes_out",
        "event_outcome": "success",
        "mitre_tactic": "Exfiltration",
        "mitre_technique": "Exfiltration Over C2 Channel - T1041",
    },
    {
        "category": "privilege_escalation",
        "rule_id": "rule-006",
        "rule_name": "异常特权提升检测",
        "rule_description": "检测非特权用户通过可疑方式获取管理员权限",
        "severity": "high",
        "src_port_range": (0, 0),
        "dst_port": 0,
        "protocol": "tcp",
        "event_action": "privilege_escalation",
        "event_outcome": "success",
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "Exploitation for Privilege Escalation - T1068",
    },
    {
        "category": "port_scan",
        "rule_id": "rule-007",
        "rule_name": "端口扫描检测",
        "rule_description": "检测单个源IP对目标主机的大量端口扫描行为",
        "severity": "medium",
        "src_port_range": (49152, 65535),
        "dst_port_range": (1, 1024),
        "protocol": "tcp",
        "event_action": "port_scan_detected",
        "event_outcome": "unknown",
        "mitre_tactic": "Reconnaissance",
        "mitre_technique": "Active Scanning - T1046",
    },
    {
        "category": "web_attack",
        "rule_id": "rule-008",
        "rule_name": "SQL注入攻击检测",
        "rule_description": "检测HTTP请求中的SQL注入攻击特征",
        "severity": "high",
        "src_port_range": (1024, 65535),
        "dst_port": 80,
        "protocol": "tcp",
        "event_action": "sql_injection_attempt",
        "event_outcome": "failure",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "Exploit Public-Facing Application - T1190",
    },
]


def _rand_ip(subnet: str) -> str:
    return f"{subnet}.{random.randint(1, 254)}"


def _pick_src_ip() -> str:
    return _rand_ip(random.choice(_INTERNAL_SUBNETS))


def _pick_dst_ip(category: str) -> str:
    if category in ("data_exfiltration", "malware", "c2"):
        return random.choice(_EXTERNAL_IPS)
    return _rand_ip(random.choice(_INTERNAL_SUBNETS))


def _build_ecs_alert(template: dict, timestamp: datetime) -> dict:
    """构建Elastic ECS格式的告警原始数据"""
    category = template["category"]
    src_ip = _pick_src_ip()
    dst_ip = _pick_dst_ip(category)
    src_port = (
        random.randint(*template["src_port_range"])
        if template["src_port_range"] != (0, 0) else 0
    )
    dst_port = template.get("dst_port") or random.randint(
        *template.get("dst_port_range", (80, 443))
    )
    hostname = random.choice(_HOSTNAMES)
    user = random.choice(_USERS)
    domain = random.choice(_DOMAINS)

    ecs = {
        "@timestamp": timestamp.isoformat() + "Z",
        "event": {
            "kind": "alert",
            "category": _map_category(category),
            "action": template["event_action"],
            "outcome": template["event_outcome"],
            "severity": _severity_to_ecs_int(template["severity"]),
            "dataset": "elastic.security",
            "provider": "elastic",
        },
        "rule": {
            "id": template["rule_id"],
            "name": template["rule_name"],
            "description": template["rule_description"],
            "severity": template["severity"],
            "risk_score": _severity_to_risk(template["severity"]),
            "type": "query",
            "version": "1.0.0",
            "tags": ["attack", category],
        },
        "source": {
            "ip": src_ip,
            "port": src_port,
            "bytes": random.randint(100, 50000),
            "packets": random.randint(1, 500),
        },
        "destination": {
            "ip": dst_ip,
            "port": dst_port,
            "bytes": random.randint(100, 500000),
            "packets": random.randint(1, 5000),
        },
        "network": {
            "transport": template["protocol"],
            "protocol": _port_to_protocol(dst_port),
            "direction": (
                "inbound" if category in ("brute_force", "phishing", "web_attack", "port_scan")
                else "outbound"
            ),
            "bytes": random.randint(1000, 500000),
        },
        "host": {
            "name": hostname,
            "os": {
                "family": "windows",
                "name": "Windows Server 2022",
                "version": "10.0",
            },
            "ip": [dst_ip, _rand_ip("10.0.0")],
        },
        "user": {
            "name": user,
            "domain": domain,
        },
        "agent": {
            "id": str(uuid.uuid4()),
            "name": f"elastic-agent-{hostname.lower()}",
            "version": "8.12.0",
            "type": "filebeat",
        },
        "threat": {
            "framework": "MITRE ATT&CK",
            "tactic": {
                "id": _tactic_id(template["mitre_tactic"]),
                "name": template["mitre_tactic"],
                "reference": f"https://attack.mitre.org/tactics/{_tactic_id(template['mitre_tactic'])}/",
            },
            "technique": [
                {
                    "id": (
                        template["mitre_technique"].split(" - ")[-1]
                        if " - " in template["mitre_technique"] else ""
                    ),
                    "name": (
                        template["mitre_technique"].split(" - ")[0]
                        if " - " in template["mitre_technique"]
                        else template["mitre_technique"]
                    ),
                }
            ],
        },
        "tags": ["elastic.security", f"attack.{category}"],
        "_ecs_version": "8.10.0",
    }

    # 添加分类特有字段
    if category == "brute_force":
        ecs["event"]["count"] = random.randint(*template["count_range"])
        ecs["source"]["user"] = {"name": user}

    if category == "malware":
        ecs["file"] = {
            "name": f"{random.choice(['svchost', 'update', 'runtime', 'helper'])}.exe",
            "hash": {"sha256": uuid.uuid4().hex + uuid.uuid4().hex},
            "size": random.randint(50000, 5000000),
            "pe": {"imphash": uuid.uuid4().hex[:32]},
        }
        ecs["process"] = {
            "name": ecs["file"]["name"],
            "pid": random.randint(1000, 65535),
            "command_line": f"C:\\Windows\\Temp\\{ecs['file']['name']}",
            "hash": {"sha256": ecs["file"]["hash"]["sha256"]},
        }

    if category == "data_exfiltration":
        ecs["source"]["bytes"] = random.randint(10000000, 500000000)

    if category == "web_attack":
        ecs["url"] = {
            "full": f"http://{dst_ip}/api/login?username={user}' OR 1=1--",
            "path": "/api/login",
            "query": f"username={user}' OR 1=1--",
        }
        ecs["http"] = {
            "request": {"method": "GET"},
            "response": {"status_code": 403},
        }
        ecs["user_agent"] = {
            "original": "sqlmap/1.7.2",
        }

    if category == "lateral_movement":
        ecs["process"] = {
            "name": "PsExec.exe",
            "pid": random.randint(1000, 65535),
            "command_line": f"psexec \\\\{hostname} -u {domain}\\{user} cmd.exe",
            "parent": {"name": "cmd.exe", "pid": random.randint(100, 9999)},
        }

    return ecs


def _map_category(category: str) -> str:
    mapping = {
        "brute_force": "authentication",
        "phishing": "email",
        "malware": "malware",
        "lateral_movement": "process",
        "data_exfiltration": "network",
        "privilege_escalation": "process",
        "port_scan": "network",
        "web_attack": "web",
    }
    return mapping.get(category, "intrusion_detection")


def _severity_to_ecs_int(severity: str) -> int:
    return {"critical": 90, "high": 70, "medium": 50, "low": 30, "info": 10}.get(severity, 50)


def _severity_to_risk(severity: str) -> int:
    return {"critical": 99, "high": 73, "medium": 47, "low": 21, "info": 5}.get(severity, 47)


def _port_to_protocol(port: int) -> str:
    mapping = {
        22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 443: "https", 445: "smb",
        3389: "rdp", 3306: "mysql", 5432: "postgresql",
    }
    return mapping.get(port, "unknown")


def _tactic_id(tactic: str) -> str:
    mapping = {
        "Credential Access": "TA0006",
        "Initial Access": "TA0001",
        "Command and Control": "TA0011",
        "Lateral Movement": "TA0008",
        "Exfiltration": "TA0010",
        "Privilege Escalation": "TA0004",
        "Reconnaissance": "TA0043",
    }
    return mapping.get(tactic, "TA0001")


def ecs_to_alert(ecs: dict) -> Alert:
    """将ECS格式告警转换为AiCSO Alert模型"""
    return Alert(
        alert_id=f"ecs-{uuid.uuid4().hex[:8]}",
        source=ecs.get("event", {}).get("dataset", "elastic.security"),
        rule_id=ecs.get("rule", {}).get("id"),
        rule_name=ecs.get("rule", {}).get("name"),
        severity=ecs.get("rule", {}).get("severity", "medium"),
        timestamp=datetime.fromisoformat(ecs["@timestamp"].rstrip("Z")),
        src_ip=ecs.get("source", {}).get("ip"),
        dst_ip=ecs.get("destination", {}).get("ip"),
        src_port=ecs.get("source", {}).get("port"),
        dst_port=ecs.get("destination", {}).get("port"),
        protocol=ecs.get("network", {}).get("transport"),
        raw_log=json.dumps(ecs, ensure_ascii=False),
        enriched_data={
            "ecs_version": ecs.get("_ecs_version"),
            "mitre_tactic": ecs.get("threat", {}).get("tactic", {}).get("name"),
            "mitre_technique": (
                ecs.get("threat", {}).get("technique", [{}])[0].get("name")
                if ecs.get("threat", {}).get("technique") else None
            ),
            "host": ecs.get("host", {}).get("name"),
            "user": ecs.get("user", {}).get("name"),
            "risk_score": ecs.get("rule", {}).get("risk_score"),
            "event_action": ecs.get("event", {}).get("action"),
            "event_outcome": ecs.get("event", {}).get("outcome"),
        },
    )


def generate_mock_alerts(count: int = 10, categories: list[str] | None = None) -> list[dict]:
    """生成指定数量的ECS格式仿真告警

    Args:
        count: 生成数量
        categories: 指定攻击类别，None表示随机

    Returns:
        ECS格式告警列表
    """
    now = datetime.utcnow()
    alerts = []
    for i in range(count):
        if categories:
            tpl = random.choice([t for t in _RULE_TEMPLATES if t["category"] in categories])
        else:
            tpl = random.choice(_RULE_TEMPLATES)
        ts = now - timedelta(minutes=random.randint(0, 120), seconds=random.randint(0, 59))
        ecs = _build_ecs_alert(tpl, ts)
        alerts.append(ecs)
    return alerts


def save_mock_alerts(alerts: list[dict], file_path: str) -> str:
    """将ECS告警保存为JSON文件（AiCSO兼容格式）"""
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # 保存为AiCSO JSON adapter兼容格式
    aicso_alerts = []
    for ecs in alerts:
        a = ecs_to_alert(ecs)
        aicso_alerts.append({
            "alert_id": a.alert_id,
            "source": a.source,
            "rule_id": a.rule_id,
            "rule_name": a.rule_name,
            "severity": a.severity,
            "timestamp": a.timestamp.isoformat(),
            "src_ip": a.src_ip,
            "dst_ip": a.dst_ip,
            "src_port": a.src_port,
            "dst_port": a.dst_port,
            "protocol": a.protocol,
            "raw_log": a.raw_log,
        })
    with open(path, "w", encoding="utf-8") as f:
        json.dump(aicso_alerts, f, ensure_ascii=False, indent=2)
    return str(path)
