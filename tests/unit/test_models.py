"""模型层测试"""
import pytest
from datetime import datetime

from aicso.models.case import (
    Case, CaseStatus, CaseSeverity, CasePriority,
    SEVERITY_PRIORITY_MAP, CASE_TRANSITIONS,
)
from aicso.models.alert import Alert
from aicso.models.asset import Asset, AssetCriticality
from aicso.models.ioc import IoC, IoCType
from aicso.models.playbook import Playbook, PlaybookStep, RiskLevel


class TestCaseModel:
    def test_create_case(self):
        case = Case(case_id="CSO-001", title="Test Case")
        assert case.case_id == "CSO-001"
        assert case.status == CaseStatus.NEW
        assert case.severity == CaseSeverity.MEDIUM
        assert case.priority == CasePriority.P3

    def test_severity_priority_mapping(self):
        assert SEVERITY_PRIORITY_MAP[CaseSeverity.CRITICAL] == CasePriority.P1
        assert SEVERITY_PRIORITY_MAP[CaseSeverity.HIGH] == CasePriority.P2
        assert SEVERITY_PRIORITY_MAP[CaseSeverity.MEDIUM] == CasePriority.P3
        assert SEVERITY_PRIORITY_MAP[CaseSeverity.LOW] == CasePriority.P4
        assert SEVERITY_PRIORITY_MAP[CaseSeverity.INFO] == CasePriority.P5

    def test_valid_transition(self):
        case = Case(case_id="CSO-001", title="Test")
        event = case.transition_to(CaseStatus.ASSIGNED, actor="user1", reason="test")
        assert case.status == CaseStatus.ASSIGNED
        assert event.event_type == "status_change"
        assert event.detail["from"] == "new"
        assert event.detail["to"] == "assigned"

    def test_invalid_transition(self):
        case = Case(case_id="CSO-001", title="Test")
        with pytest.raises(ValueError, match="Invalid transition"):
            case.transition_to(CaseStatus.CLOSED, actor="user1")

    def test_transition_new_to_assigned(self):
        case = Case(case_id="CSO-001", title="Test")
        case.transition_to(CaseStatus.ASSIGNED, actor="user")
        assert case.status == CaseStatus.ASSIGNED

    def test_transition_assigned_to_investigating(self):
        case = Case(case_id="CSO-001", title="Test")
        case.transition_to(CaseStatus.ASSIGNED, actor="user")
        case.transition_to(CaseStatus.INVESTIGATING, actor="user")
        assert case.status == CaseStatus.INVESTIGATING

    def test_transition_investigating_to_resolved(self):
        case = Case(case_id="CSO-001", title="Test")
        case.transition_to(CaseStatus.ASSIGNED, actor="user")
        case.transition_to(CaseStatus.INVESTIGATING, actor="user")
        case.transition_to(CaseStatus.RESOLVED, actor="user")
        assert case.status == CaseStatus.RESOLVED

    def test_transition_resolved_to_closed(self):
        case = Case(case_id="CSO-001", title="Test")
        case.transition_to(CaseStatus.ASSIGNED, actor="user")
        case.transition_to(CaseStatus.INVESTIGATING, actor="user")
        case.transition_to(CaseStatus.RESOLVED, actor="user")
        case.transition_to(CaseStatus.CLOSED, actor="user")
        assert case.status == CaseStatus.CLOSED
        assert case.closed_at is not None

    def test_add_alert(self):
        case = Case(case_id="CSO-001", title="Test")
        alert = Alert(alert_id="A-001", source="test", rule_name="test_rule")
        event = case.add_alert(alert, reason="auto")
        assert len(case.alerts) == 1
        assert case.alerts[0].alert_id == "A-001"
        assert event.event_type == "alert_added"

    def test_reopen_closed_case(self):
        case = Case(case_id="CSO-001", title="Test")
        case.transition_to(CaseStatus.ASSIGNED, actor="user")
        case.transition_to(CaseStatus.INVESTIGATING, actor="user")
        case.transition_to(CaseStatus.RESOLVED, actor="user")
        case.transition_to(CaseStatus.CLOSED, actor="user")
        case.transition_to(CaseStatus.NEW, actor="user")
        assert case.status == CaseStatus.NEW


class TestAlertModel:
    def test_create_alert(self):
        alert = Alert(
            alert_id="A-001",
            source="suricata",
            rule_name="SQL Injection",
            severity="high",
            src_ip="1.2.3.4",
            dst_ip="192.168.1.100",
        )
        assert alert.alert_id == "A-001"
        assert alert.source == "suricata"
        assert alert.src_ip == "1.2.3.4"
        assert alert.is_false_positive is False

    def test_alert_defaults(self):
        alert = Alert(alert_id="A-001", source="test")
        assert alert.severity == "medium"
        assert alert.is_false_positive is False
        assert alert.case_id is None


class TestAssetModel:
    def test_create_asset(self):
        asset = Asset(
            asset_id="ASSET-001",
            hostname="web-server-01",
            ip_address="192.168.1.100",
            criticality=AssetCriticality.HIGH,
        )
        assert asset.hostname == "web-server-01"
        assert asset.criticality == AssetCriticality.HIGH


class TestIoCModel:
    def test_create_ioc(self):
        ioc = IoC(ioc_id="IOC-001", type=IoCType.IP, value="1.2.3.4", confidence=0.9)
        assert ioc.type == IoCType.IP
        assert ioc.confidence == 0.9


class TestPlaybookModel:
    def test_create_playbook(self):
        pb = Playbook(
            playbook_id="phishing",
            name="Phishing Response",
            steps=[
                PlaybookStep(name="Extract IoC", action="extract_ioc", auto=True),
                PlaybookStep(name="Block IP", action="block_ip", approval_required=True, risk_level=RiskLevel.MEDIUM),
            ],
        )
        assert len(pb.steps) == 2
        assert pb.steps[0].auto is True
        assert pb.steps[1].approval_required is True
