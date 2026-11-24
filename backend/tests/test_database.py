"""
Automated unit tests for SQLAlchemy database models and database persistence.
"""

from datetime import datetime, timezone
import pytest
from backend.app.models.flow_models import TrafficFlow, SecurityAlert


def test_create_and_retrieve_traffic_flow(db_session):
    """Verifies creating a TrafficFlow record and querying it from the database."""
    flow = TrafficFlow(
        source_ip="192.168.1.101",
        destination_ip="10.0.0.10",
        source_port=54321,
        destination_port=443,
        protocol="TCP",
        packet_count=25,
        byte_count=15420,
        duration=1.25,
        tcp_flags="ACK",
        is_synthetic=True,
        simulation_label="NORMAL"
    )

    db_session.add(flow)
    db_session.commit()
    db_session.refresh(flow)

    assert flow.id is not None
    assert flow.source_ip == "192.168.1.101"
    assert flow.destination_ip == "10.0.0.10"
    assert flow.destination_port == 443
    assert flow.protocol == "TCP"
    assert flow.packet_count == 25
    assert flow.byte_count == 15420
    assert flow.is_synthetic is True
    assert flow.simulation_label == "NORMAL"
    assert flow.is_suspicious is False


def test_create_security_alert_linked_to_flow(db_session):
    """Verifies creating a SecurityAlert linked to an underlying TrafficFlow via foreign key."""
    flow = TrafficFlow(
        source_ip="198.51.100.99",
        destination_ip="10.0.0.10",
        source_port=49999,
        destination_port=22,
        protocol="TCP",
        packet_count=1,
        byte_count=48,
        duration=0.005,
        tcp_flags="SYN",
        is_synthetic=True,
        simulation_label="PORT_SCAN",
        is_suspicious=True,
        anomaly_score=-0.28,
        detection_source="RULE_HEURISTIC",
        detected_category="Port Scan"
    )

    db_session.add(flow)
    db_session.commit()
    db_session.refresh(flow)

    alert = SecurityAlert(
        flow_id=flow.id,
        source_ip=flow.source_ip,
        destination_ip=flow.destination_ip,
        severity="HIGH",
        alert_type="PORT_SCAN",
        description="Port probe detected against SSH port 22 from external IP.",
        anomaly_score=flow.anomaly_score
    )

    db_session.add(alert)
    db_session.commit()
    db_session.refresh(alert)

    assert alert.id is not None
    assert alert.flow_id == flow.id
    assert alert.severity == "HIGH"
    assert alert.alert_type == "PORT_SCAN"
    assert len(flow.alerts) == 1
    assert flow.alerts[0].id == alert.id


def test_cascade_delete_flow(db_session):
    """Verifies that deleting a TrafficFlow cascades and deletes linked SecurityAlert records."""
    flow = TrafficFlow(
        source_ip="198.51.100.54",
        destination_ip="10.0.0.15",
        source_port=51234,
        destination_port=3306,
        protocol="TCP",
        packet_count=2,
        byte_count=80,
        is_suspicious=True
    )
    db_session.add(flow)
    db_session.commit()

    alert = SecurityAlert(
        flow_id=flow.id,
        source_ip=flow.source_ip,
        destination_ip=flow.destination_ip,
        severity="MEDIUM",
        alert_type="PORT_SCAN",
        description="Test cascade delete"
    )
    db_session.add(alert)
    db_session.commit()

    # Delete the flow
    db_session.delete(flow)
    db_session.commit()

    # Assert flow is gone
    queried_flow = db_session.query(TrafficFlow).filter_by(id=flow.id).first()
    assert queried_flow is None

    # Assert child alert is deleted by cascade
    queried_alert = db_session.query(SecurityAlert).filter_by(id=alert.id).first()
    assert queried_alert is None


def test_model_to_dict_conversion(db_session):
    """Verifies that to_dict() returns expected dictionary structure for API serialization."""
    flow = TrafficFlow(
        source_ip="192.168.1.105",
        destination_ip="198.51.100.10",
        source_port=50000,
        destination_port=80,
        protocol="TCP",
        packet_count=10,
        byte_count=1200,
        duration=0.5,
        tcp_flags="ACK",
        is_synthetic=True,
        simulation_label="NORMAL"
    )
    db_session.add(flow)
    db_session.commit()

    flow_dict = flow.to_dict()
    assert isinstance(flow_dict, dict)
    assert flow_dict["source_ip"] == "192.168.1.105"
    assert flow_dict["destination_ip"] == "198.51.100.10"
    assert flow_dict["protocol"] == "TCP"
    assert flow_dict["is_synthetic"] is True
