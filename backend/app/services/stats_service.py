"""
Dashboard Statistics and Metrics Aggregation Service.
Computes high-level SOC dashboard metrics directly from the SQLite database.
"""

from typing import Dict, Any, List
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.app.models.flow_models import TrafficFlow, SecurityAlert


def get_dashboard_stats(db: Session) -> Dict[str, Any]:
    """
    Computes real-time statistics across all stored traffic and security alerts.
    """
    # 1. Total flow counts
    total_traffic = db.query(func.count(TrafficFlow.id)).scalar() or 0
    suspicious_traffic = (
        db.query(func.count(TrafficFlow.id)).filter(TrafficFlow.is_suspicious == True).scalar() or 0
    )
    normal_traffic = total_traffic - suspicious_traffic

    threat_percentage = (
        round((suspicious_traffic / total_traffic) * 100.0, 2) if total_traffic > 0 else 0.0
    )

    # 2. Alert counts and severity breakdown
    total_alerts = db.query(func.count(SecurityAlert.id)).scalar() or 0

    severity_rows = (
        db.query(SecurityAlert.severity, func.count(SecurityAlert.id))
        .group_by(SecurityAlert.severity)
        .all()
    )
    alerts_by_severity = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for sev, count in severity_rows:
        if sev in alerts_by_severity:
            alerts_by_severity[sev] = count
        else:
            alerts_by_severity[sev] = count

    # 3. Traffic breakdown by protocol
    proto_rows = (
        db.query(TrafficFlow.protocol, func.count(TrafficFlow.id))
        .group_by(TrafficFlow.protocol)
        .all()
    )
    traffic_by_protocol = {proto: count for proto, count in proto_rows}

    # 4. Detection category breakdown
    category_rows = (
        db.query(TrafficFlow.detected_category, func.count(TrafficFlow.id))
        .filter(TrafficFlow.detected_category.isnot(None))
        .group_by(TrafficFlow.detected_category)
        .all()
    )
    detection_categories = {cat: count for cat, count in category_rows if cat}

    # 5. Recent activity timeline (latest 20 flows grouped chronologically)
    recent_flows = (
        db.query(TrafficFlow.timestamp, TrafficFlow.is_suspicious, TrafficFlow.anomaly_score)
        .order_by(TrafficFlow.timestamp.desc())
        .limit(30)
        .all()
    )

    recent_timeline = [
        {
            "timestamp": f.timestamp.isoformat() if f.timestamp else None,
            "is_suspicious": f.is_suspicious,
            "anomaly_score": f.anomaly_score
        }
        for f in reversed(recent_flows)
    ]

    return {
        "total_traffic": total_traffic,
        "normal_traffic": normal_traffic,
        "suspicious_traffic": suspicious_traffic,
        "threat_percentage": threat_percentage,
        "total_alerts": total_alerts,
        "alerts_by_severity": alerts_by_severity,
        "traffic_by_protocol": traffic_by_protocol,
        "detection_categories": detection_categories,
        "recent_timeline": recent_timeline
    }
