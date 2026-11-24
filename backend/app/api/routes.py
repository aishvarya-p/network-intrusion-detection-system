"""
FastAPI REST API routes for Network Intrusion Detection System (NIDS).
Includes endpoints for health check, traffic retrieval, alerts, statistics,
traffic simulation, and CSV dataset upload.
"""

from datetime import datetime, timezone
from typing import Optional, List
from fastapi import APIRouter, Depends, Query, HTTPException, UploadFile, File, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.app.database import get_db
from backend.app.models.flow_models import TrafficFlow, SecurityAlert
from backend.app.schemas.flow_schemas import (
    HealthResponse,
    TrafficListResponse,
    TrafficFlowItem,
    AlertsListResponse,
    SecurityAlertItem,
    SimulationRequest,
    SimulationResponse,
    CsvUploadResponse,
    StatsResponse
)
from backend.app.api.dependencies import get_detector
from backend.app.ml.detector import NetworkAnomalyDetector
from backend.app.services.traffic_generator import SyntheticTrafficGenerator
from backend.app.services.flow_processor import process_and_store_flows
from backend.app.services.csv_service import parse_csv_stream
from backend.app.services.stats_service import get_dashboard_stats

router = APIRouter()


@router.get(
    "/health",
    response_model=HealthResponse,
    tags=["System"],
    summary="System and Component Health Status"
)
def get_health(
    db: Session = Depends(get_db),
    detector: NetworkAnomalyDetector = Depends(get_detector)
):
    """
    Checks backend API status, SQLite database connectivity, and ML model loaded state.
    """
    db_status = "connected"
    try:
        db.execute(TrafficFlow.__table__.select().limit(1))
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"

    model_loaded = detector.is_trained

    return {
        "status": "healthy" if db_status == "connected" and model_loaded else "degraded",
        "model_loaded": model_loaded,
        "database_status": db_status,
        "timestamp": datetime.now(timezone.utc),
        "version": "0.1.0"
    }


@router.get(
    "/traffic",
    response_model=TrafficListResponse,
    tags=["Traffic"],
    summary="Retrieve Inspected Network Flows"
)
def list_traffic(
    limit: int = Query(default=50, ge=1, le=500, description="Max records to return"),
    offset: int = Query(default=0, ge=0, description="Pagination offset"),
    protocol: Optional[str] = Query(default=None, description="Filter by protocol: TCP, UDP, ICMP"),
    is_suspicious: Optional[bool] = Query(default=None, description="Filter by anomaly status"),
    db: Session = Depends(get_db)
):
    """
    Returns a paginated list of traffic flow records with optional filtering.
    """
    query = db.query(TrafficFlow)

    if protocol:
        query = query.filter(TrafficFlow.protocol == protocol.upper())
    if is_suspicious is not None:
        query = query.filter(TrafficFlow.is_suspicious == is_suspicious)

    total = query.count()
    items = query.order_by(desc(TrafficFlow.timestamp)).offset(offset).limit(limit).all()

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": items
    }


@router.get(
    "/alerts",
    response_model=AlertsListResponse,
    tags=["Alerts"],
    summary="Retrieve Flagged Security Alerts"
)
def list_alerts(
    limit: int = Query(default=50, ge=1, le=500, description="Max alerts to return"),
    offset: int = Query(default=0, ge=0, description="Pagination offset"),
    severity: Optional[str] = Query(default=None, description="Filter by severity: LOW, MEDIUM, HIGH, CRITICAL"),
    is_resolved: Optional[bool] = Query(default=None, description="Filter by resolution status"),
    db: Session = Depends(get_db)
):
    """
    Returns a paginated list of security alerts raised by ML and heuristic detection.
    """
    query = db.query(SecurityAlert)

    if severity:
        query = query.filter(SecurityAlert.severity == severity.upper())
    if is_resolved is not None:
        query = query.filter(SecurityAlert.is_resolved == is_resolved)

    total = query.count()
    items = query.order_by(desc(SecurityAlert.timestamp)).offset(offset).limit(limit).all()

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": items
    }


@router.get(
    "/stats",
    response_model=StatsResponse,
    tags=["Dashboard"],
    summary="SOC Dashboard Summary Metrics"
)
def get_stats(db: Session = Depends(get_db)):
    """
    Aggregates overall statistics for dashboard KPI cards, protocol charts, and alert breakdowns.
    """
    return get_dashboard_stats(db)


@router.post(
    "/simulate",
    response_model=SimulationResponse,
    tags=["Simulation"],
    summary="Generate & Inspect Synthetic Traffic Batch"
)
def simulate_traffic(
    request: SimulationRequest,
    db: Session = Depends(get_db),
    detector: NetworkAnomalyDetector = Depends(get_detector)
):
    """
    Simulates a batch of network flows (mix of normal and configurable attack patterns),
    evaluates each flow through the ML Isolation Forest and rule-based classifier,
    stores records in SQLite, and generates security alerts.
    """
    generator = SyntheticTrafficGenerator()
    generated_flows = generator.generate_batch(
        total_flows=request.total_flows,
        anomaly_ratio=request.anomaly_ratio,
        target_attack_types=request.attack_types
    )

    result = process_and_store_flows(db, generated_flows, detector)

    return {
        "message": f"Successfully simulated and analyzed {result['total_processed']} network flows.",
        "total_generated": result["total_processed"],
        "normal_count": result["normal_count"],
        "suspicious_count": result["suspicious_count"],
        "alerts_generated": result["alerts_generated"],
        "alerts_summary": result["alerts_summary"]
    }


@router.post(
    "/upload-csv",
    response_model=CsvUploadResponse,
    tags=["Ingestion"],
    summary="Upload & Ingest CSV Network Flow Dataset"
)
async def upload_csv_dataset(
    file: UploadFile = File(..., description="CSV file containing network flow records"),
    db: Session = Depends(get_db),
    detector: NetworkAnomalyDetector = Depends(get_detector)
):
    """
    Uploads a CSV file of network flows. Validates column headers, sanitizes rows,
    and runs the dual-engine detection pipeline.
    Required CSV columns: source_ip, destination_ip, destination_port, protocol.
    Optional columns: source_port, packet_count, byte_count, duration, tcp_flags.
    """
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file format. Please upload a valid .csv file."
        )

    try:
        content = await file.read()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to read file contents: {str(e)}"
        )

    if not content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The uploaded file is empty."
        )

    try:
        valid_flows, rejected_count, parse_errors = parse_csv_stream(content)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

    if not valid_flows and rejected_count > 0:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"All rows in the CSV were invalid or rejected. Errors: {'; '.join(parse_errors[:5])}"
        )

    # Process valid flows through detection pipeline
    result = process_and_store_flows(db, valid_flows, detector)

    return {
        "filename": file.filename,
        "rows_processed": len(valid_flows) + rejected_count,
        "rows_accepted": len(valid_flows),
        "rows_rejected": rejected_count,
        "normal_count": result["normal_count"],
        "suspicious_count": result["suspicious_count"],
        "alerts_generated": result["alerts_generated"],
        "errors": parse_errors
    }
