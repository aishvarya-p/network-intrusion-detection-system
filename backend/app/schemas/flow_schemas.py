"""
Pydantic Schemas for NIDS FastAPI application.
Ensures strong typing, request validation, and clean serialization.
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class HealthResponse(BaseModel):
    """Health check response schema."""
    status: str
    model_loaded: bool
    database_status: str
    timestamp: datetime
    version: str


class TrafficFlowItem(BaseModel):
    """Represents a single inspected network traffic flow record."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    packet_count: int
    byte_count: int
    duration: float
    tcp_flags: Optional[str] = "NONE"
    is_synthetic: bool = True
    simulation_label: str = "UNLABELED"
    anomaly_score: Optional[float] = None
    is_suspicious: bool = False
    detection_source: Optional[str] = None
    detected_category: Optional[str] = None


class TrafficListResponse(BaseModel):
    """Paginated list response for traffic records."""
    total: int
    limit: int
    offset: int
    items: List[TrafficFlowItem]


class SecurityAlertItem(BaseModel):
    """Represents an alert triggered by anomaly detection or rule signatures."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    flow_id: Optional[int] = None
    timestamp: datetime
    source_ip: str
    destination_ip: str
    severity: str
    alert_type: str
    description: str
    anomaly_score: Optional[float] = None
    is_resolved: bool = False


class AlertsListResponse(BaseModel):
    """Paginated list response for security alerts."""
    total: int
    limit: int
    offset: int
    items: List[SecurityAlertItem]


class SimulationRequest(BaseModel):
    """Request payload to simulate a batch of network flows."""
    total_flows: int = Field(default=50, ge=1, le=1000, description="Total flows to generate (1 to 1000)")
    anomaly_ratio: float = Field(default=0.15, ge=0.0, le=1.0, description="Proportion of simulated anomalous flows (0.0 to 1.0)")
    attack_types: Optional[List[str]] = Field(
        default=None,
        description="Optional list of attack patterns: 'PORT_SCAN', 'SYN_FLOOD', 'DATA_EXFILTRATION'"
    )


class SimulationResponse(BaseModel):
    """Response returned after running a traffic simulation."""
    message: str
    total_generated: int
    normal_count: int
    suspicious_count: int
    alerts_generated: int
    alerts_summary: List[Dict[str, Any]]


class CsvUploadResponse(BaseModel):
    """Response returned after parsing and analyzing an uploaded CSV dataset."""
    filename: str
    rows_processed: int
    rows_accepted: int
    rows_rejected: int
    normal_count: int
    suspicious_count: int
    alerts_generated: int
    errors: List[str]


class StatsResponse(BaseModel):
    """Dashboard statistics and summary metrics."""
    total_traffic: int
    normal_traffic: int
    suspicious_traffic: int
    threat_percentage: float
    total_alerts: int
    alerts_by_severity: Dict[str, int]
    traffic_by_protocol: Dict[str, int]
    detection_categories: Dict[str, int]
    recent_timeline: List[Dict[str, Any]]
