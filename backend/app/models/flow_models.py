"""
SQLAlchemy ORM models for Network Intrusion Detection System (NIDS).
Includes:
- TrafficFlow: Stores individual network flow summary records.
- SecurityAlert: Stores identified anomalies and threat alerts.
"""

from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, Float, Boolean, DateTime, Text, ForeignKey
)
from sqlalchemy.orm import relationship
from backend.app.database import Base


def utc_now():
    """Return current UTC timestamp with timezone."""
    return datetime.now(timezone.utc)


class TrafficFlow(Base):
    """
    Represents an aggregated network communication flow (5-tuple plus metrics).
    A flow captures metadata about packets transmitted between a source and destination
    over a time duration.
    """
    __tablename__ = "traffic_flows"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp = Column(DateTime, default=utc_now, index=True, nullable=False)

    # 5-Tuple Network Identification
    source_ip = Column(String(45), nullable=False, index=True)
    destination_ip = Column(String(45), nullable=False, index=True)
    source_port = Column(Integer, nullable=False)
    destination_port = Column(Integer, nullable=False, index=True)
    protocol = Column(String(10), nullable=False, index=True)  # TCP, UDP, ICMP

    # Flow Metrics
    packet_count = Column(Integer, nullable=False, default=1)
    byte_count = Column(Integer, nullable=False, default=64)
    duration = Column(Float, nullable=False, default=0.0)  # In seconds
    tcp_flags = Column(String(20), nullable=True, default="NONE")  # SYN, ACK, etc.

    # Dataset & Ground-Truth Provenance
    is_synthetic = Column(Boolean, nullable=False, default=True)
    simulation_label = Column(String(50), nullable=False, default="UNLABELED")  # e.g., NORMAL, PORT_SCAN, SYN_FLOOD

    # Detection Results (filled during or after ML & rule evaluation)
    anomaly_score = Column(Float, nullable=True)  # Negative values indicate outliers in Isolation Forest
    is_suspicious = Column(Boolean, nullable=False, default=False, index=True)
    detection_source = Column(String(50), nullable=True)  # "ML_ISOLATION_FOREST", "RULE_HEURISTIC", "HYBRID"
    detected_category = Column(String(50), nullable=True)  # Suggested attack category (Port Scan, DDoS, etc.)

    # Relationship to SecurityAlerts
    alerts = relationship("SecurityAlert", back_populates="flow", cascade="all, delete-orphan")

    def to_dict(self):
        """Converts model instance to a standard Python dictionary."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "duration": self.duration,
            "tcp_flags": self.tcp_flags,
            "is_synthetic": self.is_synthetic,
            "simulation_label": self.simulation_label,
            "anomaly_score": self.anomaly_score,
            "is_suspicious": self.is_suspicious,
            "detection_source": self.detection_source,
            "detected_category": self.detected_category,
        }


class SecurityAlert(Base):
    """
    Represents a security alert raised either by the ML anomaly detector
    or rule-based attack classifier.
    """
    __tablename__ = "security_alerts"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    flow_id = Column(Integer, ForeignKey("traffic_flows.id", ondelete="CASCADE"), nullable=True)
    timestamp = Column(DateTime, default=utc_now, index=True, nullable=False)

    # Incident Details
    source_ip = Column(String(45), nullable=False, index=True)
    destination_ip = Column(String(45), nullable=False, index=True)
    severity = Column(String(20), nullable=False, default="MEDIUM", index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    alert_type = Column(String(50), nullable=False, index=True)  # PORT_SCAN, SYN_FLOOD, DATA_BURST, ML_ANOMALY
    description = Column(Text, nullable=False)
    anomaly_score = Column(Float, nullable=True)
    is_resolved = Column(Boolean, nullable=False, default=False)

    # Back reference to flow
    flow = relationship("TrafficFlow", back_populates="alerts")

    def to_dict(self):
        """Converts alert instance to a standard Python dictionary."""
        return {
            "id": self.id,
            "flow_id": self.flow_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "severity": self.severity,
            "alert_type": self.alert_type,
            "description": self.description,
            "anomaly_score": self.anomaly_score,
            "is_resolved": self.is_resolved,
        }
