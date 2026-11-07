import os
from datetime import datetime, timezone
import pytest
from backend.ingestion import (
    parse_syslog, 
    parse_auth_log, 
    parse_nginx_access, 
    parse_windows_event_json,
    process_log_entry,
    process_log_entries,
)
from backend.schemas import LogEventCreate
from backend.database import AlertDB, LogEventDB


def test_health_check(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["database"] == "connected"
    assert data["rules_loaded"] > 0


def test_ingest_single_event(client):
    event_data = {
        "host": "web-srv-01",
        "severity": "info",
        "category": "system",
        "message": "User session started",
        "raw": "User session started raw"
    }
    response = client.post("/api/ingest", json=event_data)
    assert response.status_code == 200
    data = response.json()
    assert data["host"] == "web-srv-01"
    assert data["severity"] == "info"
    assert "id" in data


def test_ingest_batch_events(client):
    batch = [
        {"host": "host-1", "severity": "info", "category": "system", "message": "msg 1"},
        {"host": "host-2", "severity": "medium", "category": "web", "message": "msg 2"},
        {"host": "host-3", "severity": "high", "category": "auth", "message": "msg 3"},
    ]
    response = client.post("/api/ingest/batch", json=batch)
    assert response.status_code == 200
    events = response.json()
    assert len(events) == 3
    assert events[1]["category"] == "web"


def test_timestamp_parsers():
    # Test syslog timestamp parser
    syslog_line = "Oct 11 12:05:01 web-server sshd[1235]: Failed password for root from 10.0.0.5"
    parsed_syslog = parse_syslog(syslog_line)
    assert parsed_syslog.timestamp is not None
    assert parsed_syslog.timestamp.month == 10
    assert parsed_syslog.timestamp.day == 11
    assert parsed_syslog.host == "web-server"

    # Test nginx timestamp parser
    nginx_line = '192.168.1.50 - - [10/Oct/2023:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326'
    parsed_nginx = parse_nginx_access(nginx_line)
    assert parsed_nginx.timestamp is not None
    assert parsed_nginx.timestamp.year == 2023
    assert parsed_nginx.timestamp.month == 10
    assert parsed_nginx.host == "192.168.1.50"

    # Test windows event parser
    win_line = '{"EventID": 1102, "Computer": "WinServer-01", "Message": "Audit log cleared.", "Level": 1, "TimeCreated": "2023-10-11T12:00:00Z"}'
    parsed_win = parse_windows_event_json(win_line)
    assert parsed_win.timestamp is not None
    assert parsed_win.host == "WinServer-01"
    assert parsed_win.severity == "high"


def test_correlation_bug_fix(db_session):
    """
    Verify that 5 benign events do NOT trigger a brute-force alert,
    whereas 5 failed login events DO trigger the alert.
    """
    now = datetime.now(timezone.utc)
    
    # 1. Ingest 5 benign info logs from host "srv-safe"
    benign_events = [
        LogEventCreate(
            timestamp=now,
            host="srv-safe",
            severity="info",
            category="system",
            message=f"System normal check {i}"
        )
        for i in range(5)
    ]
    process_log_entries(benign_events, db_session)

    # Verify no brute-force alert was triggered for srv-safe
    safe_alerts = db_session.query(AlertDB).filter(
        AlertDB.rule_name == "Brute Force Attempt",
        AlertDB.description.contains("srv-safe")
    ).all()
    assert len(safe_alerts) == 0

    # 2. Ingest 5 failed login (high severity auth) logs from host "srv-attacked"
    attack_events = [
        LogEventCreate(
            timestamp=now,
            host="srv-attacked",
            severity="high",
            category="auth",
            message=f"Failed password for invalid user admin from 10.0.0.{i}"
        )
        for i in range(5)
    ]
    process_log_entries(attack_events, db_session)

    # Verify brute-force alert WAS triggered for srv-attacked
    attack_alerts = db_session.query(AlertDB).filter(
        AlertDB.rule_name == "Brute Force Attempt",
        AlertDB.description.contains("srv-attacked")
    ).all()
    assert len(attack_alerts) == 1
    assert attack_alerts[0].severity == "critical"
    assert attack_alerts[0].events_correlated >= 5


def test_file_ingestion(client):
    # Upload auth.log sample file
    sample_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "sample_logs", "auth.log")
    with open(sample_path, "rb") as f:
        response = client.post(
            "/api/ingest/file",
            data={"log_type": "auth"},
            files={"file": ("auth.log", f, "text/plain")}
        )
    assert response.status_code == 200
    assert response.json()["count"] > 0

    # Check that events were stored
    events_res = client.get("/api/events?category=auth")
    assert events_res.status_code == 200
    assert len(events_res.json()) > 0

    # Check alerts were triggered (Brute force rule triggers for auth.log)
    alerts_res = client.get("/api/alerts")
    assert alerts_res.status_code == 200
    assert len(alerts_res.json()) > 0


def test_alert_acknowledgment(client, db_session):
    # Create test alert
    alert = AlertDB(
        rule_name="Test Rule",
        severity="high",
        description="Test alert description",
        events_correlated=1,
        acknowledged=0,
        timestamp=datetime.now(timezone.utc)
    )
    db_session.add(alert)
    db_session.commit()
    db_session.refresh(alert)

    # Acknowledge via API
    response = client.put(f"/api/alerts/{alert.id}/acknowledge")
    assert response.status_code == 200
    assert response.json()["acknowledged"] == 1


def test_analytics_endpoints(client):
    # Ingest event for analytics
    event = {
        "host": "analytics-host",
        "severity": "medium",
        "category": "web",
        "message": "GET /api/test - Status 404"
    }
    client.post("/api/ingest", json=event)

    top_ips = client.get("/api/stats/top-ips").json()
    assert isinstance(top_ips, list)
    assert any(item["host"] == "analytics-host" for item in top_ips)

    categories = client.get("/api/stats/categories").json()
    assert isinstance(categories, list)
    assert any(item["category"] == "web" for item in categories)

    timeline = client.get("/api/stats/timeline").json()
    assert isinstance(timeline, list)


def test_alert_triage_and_mitre(client, db_session):
    alert = AlertDB(
        rule_name="Brute Force Attempt",
        severity="critical",
        description="Multiple failed login attempts",
        events_correlated=5,
        acknowledged=0,
        mitre_technique="T1110.001",
        mitre_tactic="Credential Access",
        status="new",
        timestamp=datetime.now(timezone.utc)
    )
    db_session.add(alert)
    db_session.commit()
    db_session.refresh(alert)

    # Triage alert
    triage_payload = {
        "status": "resolved",
        "assigned_to": "analyst-alice",
        "resolution_notes": "Blocked IP via firewall."
    }
    response = client.put(f"/api/alerts/{alert.id}/triage", json=triage_payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "resolved"
    assert data["assigned_to"] == "analyst-alice"
    assert data["resolution_notes"] == "Blocked IP via firewall."
    assert data["acknowledged"] == 1
    assert data["mitre_technique"] == "T1110.001"
    assert data["mitre_tactic"] == "Credential Access"

