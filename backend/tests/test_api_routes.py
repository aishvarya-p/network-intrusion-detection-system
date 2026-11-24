"""
Automated API tests for FastAPI endpoints:
- System Health endpoint (/health)
- Traffic Retrieval with pagination and filtering (/traffic)
- Alerts Retrieval with filtering (/alerts)
- Dashboard Statistics (/stats)
- Synthetic Traffic Simulation (/simulate)
- CSV Dataset Ingestion (/upload-csv)
"""

import io
from pathlib import Path
import pytest
from backend.app.models.flow_models import TrafficFlow, SecurityAlert


def test_health_endpoint(client):
    """Verifies the health check endpoint returns 200 with all components healthy."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["model_loaded"] is True
    assert data["database_status"] == "connected"
    assert "version" in data
    assert "timestamp" in data


def test_traffic_retrieval_and_pagination(client, db_session):
    """Verifies /traffic returns paginated records."""
    # 1. Empty traffic table
    res_empty = client.get("/traffic")
    assert res_empty.status_code == 200
    assert res_empty.json()["total"] == 0
    assert res_empty.json()["items"] == []

    # 2. Add 5 sample records
    for i in range(5):
        flow = TrafficFlow(
            source_ip=f"192.168.1.{100 + i}",
            destination_ip="10.0.0.10",
            source_port=50000 + i,
            destination_port=443,
            protocol="TCP",
            packet_count=10,
            byte_count=1500,
            duration=0.5,
            is_suspicious=(i % 2 == 1)
        )
        db_session.add(flow)
    db_session.commit()

    # 3. Query with limit and offset
    res_paged = client.get("/traffic?limit=2&offset=0")
    assert res_paged.status_code == 200
    data = res_paged.json()
    assert data["total"] == 5
    assert len(data["items"]) == 2


def test_traffic_filtering(client, db_session):
    """Verifies /traffic filtering by protocol and suspicious status."""
    flow1 = TrafficFlow(
        source_ip="192.168.1.101", destination_ip="10.0.0.10",
        source_port=50001, destination_port=443, protocol="TCP",
        is_suspicious=False
    )
    flow2 = TrafficFlow(
        source_ip="192.168.1.102", destination_ip="10.0.0.5",
        source_port=50002, destination_port=53, protocol="UDP",
        is_suspicious=True
    )
    db_session.add_all([flow1, flow2])
    db_session.commit()

    # Filter by UDP
    res_udp = client.get("/traffic?protocol=UDP")
    assert res_udp.status_code == 200
    items = res_udp.json()["items"]
    assert len(items) == 1
    assert items[0]["protocol"] == "UDP"

    # Filter by suspicious=True
    res_susp = client.get("/traffic?is_suspicious=true")
    assert res_susp.status_code == 200
    items = res_susp.json()["items"]
    assert len(items) == 1
    assert items[0]["is_suspicious"] is True


def test_alerts_retrieval_and_filtering(client, db_session):
    """Verifies /alerts returns security incidents and respects severity filters."""
    alert1 = SecurityAlert(
        source_ip="198.51.100.99", destination_ip="10.0.0.10",
        severity="HIGH", alert_type="PORT_SCAN", description="Port probe detected"
    )
    alert2 = SecurityAlert(
        source_ip="198.51.100.54", destination_ip="10.0.0.15",
        severity="MEDIUM", alert_type="ML_ANOMALY", description="Statistical anomaly"
    )
    db_session.add_all([alert1, alert2])
    db_session.commit()

    # Query all
    res_all = client.get("/alerts")
    assert res_all.status_code == 200
    assert res_all.json()["total"] == 2

    # Query filtered by severity=HIGH
    res_high = client.get("/alerts?severity=HIGH")
    assert res_high.status_code == 200
    items = res_high.json()["items"]
    assert len(items) == 1
    assert items[0]["severity"] == "HIGH"


def test_stats_endpoint(client, db_session):
    """Verifies /stats aggregates KPI counts and protocol breakdowns."""
    flow = TrafficFlow(
        source_ip="192.168.1.101", destination_ip="10.0.0.10",
        source_port=50000, destination_port=80, protocol="TCP",
        is_suspicious=True, detected_category="Port Scan Probe"
    )
    alert = SecurityAlert(
        flow=flow, source_ip=flow.source_ip, destination_ip=flow.destination_ip,
        severity="HIGH", alert_type="PORT_SCAN", description="Test Alert"
    )
    db_session.add(flow)
    db_session.add(alert)
    db_session.commit()

    response = client.get("/stats")
    assert response.status_code == 200
    stats = response.json()
    assert stats["total_traffic"] == 1
    assert stats["suspicious_traffic"] == 1
    assert stats["threat_percentage"] == 100.0
    assert stats["total_alerts"] == 1
    assert stats["traffic_by_protocol"]["TCP"] == 1
    assert stats["alerts_by_severity"]["HIGH"] == 1
    assert "Port Scan Probe" in stats["detection_categories"]


def test_simulate_endpoint(client, db_session):
    """Verifies POST /simulate generates, scores, and stores synthetic batches."""
    payload = {
        "total_flows": 30,
        "anomaly_ratio": 0.20,
        "attack_types": ["PORT_SCAN", "SYN_FLOOD"]
    }
    response = client.post("/simulate", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["total_generated"] == 30
    assert data["normal_count"] + data["suspicious_count"] == 30
    assert data["alerts_generated"] > 0
    assert isinstance(data["alerts_summary"], list)

    # Verify database persistence
    db_flows_count = db_session.query(TrafficFlow).count()
    assert db_flows_count == 30

    db_alerts_count = db_session.query(SecurityAlert).count()
    assert db_alerts_count == data["alerts_generated"]


def test_simulate_validation_bounds(client):
    """Verifies bounds checking on /simulate payload."""
    # total_flows = 0 (violates ge=1)
    res_zero = client.post("/simulate", json={"total_flows": 0})
    assert res_zero.status_code == 422

    # total_flows = 5000 (violates le=1000)
    res_huge = client.post("/simulate", json={"total_flows": 5000})
    assert res_huge.status_code == 422

    # anomaly_ratio > 1.0 (violates le=1.0)
    res_ratio = client.post("/simulate", json={"total_flows": 50, "anomaly_ratio": 1.5})
    assert res_ratio.status_code == 422


def test_upload_csv_valid_file(client, db_session):
    """Verifies uploading a well-formed CSV parses and ingests rows into SQLite."""
    csv_path = Path("backend/data/samples/sample_network_traffic.csv")
    assert csv_path.exists()

    with open(csv_path, "rb") as f:
        response = client.post(
            "/upload-csv",
            files={"file": ("sample.csv", f, "text/csv")}
        )

    assert response.status_code == 200
    data = response.json()
    assert data["filename"] == "sample.csv"
    assert data["rows_accepted"] == 10
    assert data["rows_rejected"] == 0
    assert data["alerts_generated"] > 0

    # Verify SQLite persistence
    assert db_session.query(TrafficFlow).count() == 10


def test_upload_csv_malformed_rows_safety(client, db_session):
    """Verifies malformed rows are safely rejected without crashing the API."""
    csv_path = Path("backend/data/samples/malformed_traffic.csv")
    assert csv_path.exists()

    with open(csv_path, "rb") as f:
        response = client.post(
            "/upload-csv",
            files={"file": ("malformed.csv", f, "text/csv")}
        )

    assert response.status_code == 200
    data = response.json()
    assert data["rows_accepted"] == 2
    assert data["rows_rejected"] == 3
    assert len(data["errors"]) == 3
    assert db_session.query(TrafficFlow).count() == 2


def test_upload_csv_missing_required_columns(client):
    """Verifies a 400 error is returned when required columns are absent."""
    invalid_csv = b"source_ip,destination_ip,protocol\n192.168.1.1,10.0.0.1,TCP\n"
    response = client.post(
        "/upload-csv",
        files={"file": ("bad_header.csv", io.BytesIO(invalid_csv), "text/csv")}
    )
    assert response.status_code == 400
    assert "missing required columns" in response.json()["detail"].lower()


def test_upload_csv_invalid_extension(client):
    """Verifies non-CSV files are rejected with 400."""
    fake_exe = b"MZ\x90\x00\x03\x00\x00\x00"
    response = client.post(
        "/upload-csv",
        files={"file": ("payload.exe", io.BytesIO(fake_exe), "application/octet-stream")}
    )
    assert response.status_code == 400
    assert "invalid file format" in response.json()["detail"].lower()


def test_upload_empty_csv(client):
    """Verifies empty files return a 400 error."""
    response = client.post(
        "/upload-csv",
        files={"file": ("empty.csv", io.BytesIO(b""), "text/csv")}
    )
    assert response.status_code == 400
    assert "file is empty" in response.json()["detail"].lower()
