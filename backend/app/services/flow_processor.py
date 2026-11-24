"""
Core Flow Ingestion and Detection Processing Service.
Executes the tri-engine detection pipeline for both synthetic simulation and CSV uploads:
Raw Flow -> Feature Extraction -> ML Anomaly Scoring -> Stateless Rule Heuristics -> Stateful Time-Window Correlation -> SQLite Persistence -> Consolidated Alert Generation.
"""

from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Tuple, Optional, Set
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.app.models.flow_models import TrafficFlow, SecurityAlert
from backend.app.ml.detector import NetworkAnomalyDetector
from backend.app.ml.rule_classifier import RuleBasedClassifier
from backend.app.services.stateful_detector import StatefulPortScanDetector


def _parse_timestamp(ts: Any) -> datetime:
    """Helper to ensure timestamp is a timezone-aware UTC datetime."""
    if isinstance(ts, str):
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            return datetime.now(timezone.utc)
    elif isinstance(ts, datetime):
        if ts.tzinfo is None:
            return ts.replace(tzinfo=timezone.utc)
        return ts
    return datetime.now(timezone.utc)


def _map_alert_type(suggested_category: str) -> str:
    """Maps friendly rule category names to standard alert types."""
    if "Port Scan" in suggested_category:
        return "PORT_SCAN_SWEEP"
    elif "SYN Probe" in suggested_category:
        return "SYN_PROBE"
    elif "SYN Flood" in suggested_category:
        return "SYN_FLOOD"
    elif "Data Transfer" in suggested_category:
        return "DATA_BURST"
    return "HEURISTIC_MATCH"


def process_and_store_flows(
    db: Session,
    raw_flows: List[Dict[str, Any]],
    detector: NetworkAnomalyDetector,
    stateful_detector: Optional[StatefulPortScanDetector] = None
) -> Dict[str, Any]:
    """
    Executes the tri-engine detection pipeline on incoming flow records:
    1. Isolation Forest unsupervised anomaly scoring
    2. Stateless rule-based heuristic classification
    3. Stateful rolling time-window correlation (vertical port scan sweeps)

    Persists flow records and generates consolidated security alerts.
    """
    if not raw_flows:
        return {
            "total_processed": 0,
            "normal_count": 0,
            "suspicious_count": 0,
            "alerts_generated": 0,
            "alerts_summary": []
        }

    if stateful_detector is None:
        stateful_detector = StatefulPortScanDetector(window_seconds=60.0, min_distinct_ports=5)

    # 1. Historical Lookback Query:
    # Find the earliest timestamp in the current batch to query recent database records
    batch_timestamps = [_parse_timestamp(f.get("timestamp")) for f in raw_flows]
    min_batch_time = min(batch_timestamps)
    lookback_start = min_batch_time - timedelta(seconds=stateful_detector.window_seconds)

    # Query recent flows within lookback window to correlate across ingestion batches
    # Memory is strictly bounded to flows in the last window_seconds
    historical_entities = (
        db.query(TrafficFlow)
        .filter(TrafficFlow.timestamp >= lookback_start, TrafficFlow.timestamp <= min_batch_time)
        .all()
    )
    historical_flows = [h.to_dict() for h in historical_entities]

    # 2. Run Stateful Correlation
    scan_detections = stateful_detector.analyze_flows(
        flows=raw_flows,
        historical_flows=historical_flows
    )

    # Map participating batch indices to their stateful scan detection
    stateful_flow_indices: Set[int] = set()
    index_to_scan_map: Dict[int, Dict[str, Any]] = {}
    for scan in scan_detections:
        for idx in scan["participating_indices"]:
            stateful_flow_indices.add(idx)
            index_to_scan_map[idx] = scan

    # 3. Run unsupervised ML Isolation Forest detection
    ml_predictions = detector.predict(raw_flows)

    flows_to_insert: List[TrafficFlow] = []
    individual_alerts_to_insert: List[SecurityAlert] = []

    normal_count = 0
    suspicious_count = 0

    for i, flow_data in enumerate(raw_flows):
        ml_res = ml_predictions[i]
        ml_suspicious = bool(ml_res["is_suspicious"])
        anomaly_score = float(ml_res["anomaly_score"])

        # 4. Run stateless heuristic rule classifier
        rule_res = RuleBasedClassifier.classify_flow(flow_data)
        rule_triggered = bool(rule_res["rule_triggered"])

        # 5. Check if flow is part of a stateful scan
        is_stateful_scan = i in stateful_flow_indices
        scan_info = index_to_scan_map.get(i)

        # 6. Combined Attribution Logic
        is_suspicious = ml_suspicious or rule_triggered or is_stateful_scan

        # Attribution source:
        sources = []
        if is_stateful_scan:
            sources.append("STATEFUL_CORRELATION")
        if rule_triggered:
            sources.append("RULE_HEURISTIC")
        if ml_suspicious:
            sources.append("ML_ISOLATION_FOREST")

        if len(sources) > 1:
            detection_source = "HYBRID"
        elif len(sources) == 1:
            detection_source = sources[0]
        else:
            detection_source = None

        # Category designation
        if is_stateful_scan:
            detected_category = "Vertical Port Scan (Stateful)"
        elif rule_triggered and rule_res.get("suggested_category"):
            detected_category = rule_res["suggested_category"]
        elif ml_suspicious:
            detected_category = "Statistical Behavioral Anomaly"
        else:
            detected_category = None

        flow_time = _parse_timestamp(flow_data.get("timestamp"))

        # Build TrafficFlow ORM entity
        flow_entity = TrafficFlow(
            timestamp=flow_time,
            source_ip=str(flow_data.get("source_ip", "0.0.0.0")),
            destination_ip=str(flow_data.get("destination_ip", "0.0.0.0")),
            source_port=int(flow_data.get("source_port", 0)),
            destination_port=int(flow_data.get("destination_port", 0)),
            protocol=str(flow_data.get("protocol", "TCP")).upper(),
            packet_count=int(flow_data.get("packet_count", 1)),
            byte_count=int(flow_data.get("byte_count", 64)),
            duration=float(flow_data.get("duration", 0.0)),
            tcp_flags=str(flow_data.get("tcp_flags", "NONE")),
            is_synthetic=bool(flow_data.get("is_synthetic", True)),
            simulation_label=str(flow_data.get("simulation_label", "UNLABELED")),
            anomaly_score=anomaly_score,
            is_suspicious=is_suspicious,
            detection_source=detection_source,
            detected_category=detected_category
        )
        flows_to_insert.append(flow_entity)

        if is_suspicious:
            suspicious_count += 1

            # Only generate per-flow alerts for NON-scan threats (SYN floods, Exfiltration, ML anomalies)
            # Port scans receive a single CONSOLIDATED alert below to avoid flooding the SOC
            if not is_stateful_scan and (rule_triggered or ml_suspicious):
                # If it was an isolated SYN probe with no stateful scan confirmed, flag advisory SYN probe
                if rule_triggered:
                    severity = rule_res.get("severity", "MEDIUM")
                    alert_type = _map_alert_type(rule_res["suggested_category"])
                    reason = rule_res.get("reason", "Heuristic signature match.")
                    description = (
                        f"Advisory Alert: {rule_res['suggested_category']} detected. "
                        f"ML Anomaly Score: {anomaly_score:.2f}. Detail: {reason}"
                    )
                else:
                    severity = "HIGH" if anomaly_score >= 0.80 else ("MEDIUM" if anomaly_score >= 0.65 else "LOW")
                    alert_type = "ML_ANOMALY"
                    description = (
                        f"Statistical Outlier: Flow metrics deviate from baseline normal traffic "
                        f"(Anomaly Score: {anomaly_score:.2f}). Requires SOC analyst review."
                    )

                alert_entity = SecurityAlert(
                    flow=flow_entity,
                    timestamp=flow_time,
                    source_ip=flow_entity.source_ip,
                    destination_ip=flow_entity.destination_ip,
                    severity=severity,
                    alert_type=alert_type,
                    description=description,
                    anomaly_score=anomaly_score,
                    is_resolved=False
                )
                individual_alerts_to_insert.append(alert_entity)
        else:
            normal_count += 1

    # 7. Generate Consolidated Stateful Scan Alerts & Prevent Duplicates
    stateful_alerts_to_insert: List[SecurityAlert] = []
    updated_alert_ids: Set[int] = set()

    for scan in scan_detections:
        src_ip = scan["source_ip"]
        dst_ip = scan["destination_ip"]

        # Check if an unresolved PORT_SCAN_SWEEP alert already exists in SQLite within active window
        existing_alert = (
            db.query(SecurityAlert)
            .filter(
                SecurityAlert.source_ip == src_ip,
                SecurityAlert.destination_ip == dst_ip,
                SecurityAlert.alert_type == "PORT_SCAN_SWEEP",
                SecurityAlert.timestamp >= lookback_start,
                SecurityAlert.is_resolved == False
            )
            .first()
        )

        # Check whether this scan continues an existing active alert
        existing_alert_ts = _parse_timestamp(existing_alert.timestamp) if existing_alert else None
        is_ongoing = (
            existing_alert is not None
            and existing_alert.id not in updated_alert_ids
            and scan["window_start"] <= existing_alert_ts + timedelta(seconds=stateful_detector.window_seconds)
        )

        if is_ongoing:
            # Update existing alert description and timestamp instead of creating a duplicate alert
            existing_alert.description = (
                f"{scan['explanation']} (Updated with ongoing probes across batches)."
            )
            existing_alert.timestamp = scan["window_end"]
            if existing_alert.id is not None:
                updated_alert_ids.add(existing_alert.id)
        else:
            # Find the triggering flow entity in this batch to link the foreign key
            trigger_entity = None
            if scan.get("participating_indices"):
                trigger_idx = scan["participating_indices"][-1]
                if 0 <= trigger_idx < len(flows_to_insert):
                    trigger_entity = flows_to_insert[trigger_idx]

            consolidated_alert = SecurityAlert(
                flow=trigger_entity,
                timestamp=scan["window_end"],
                source_ip=src_ip,
                destination_ip=dst_ip,
                severity=scan["severity"],
                alert_type="PORT_SCAN_SWEEP",
                description=scan["explanation"],
                anomaly_score=trigger_entity.anomaly_score if trigger_entity else 0.50,
                is_resolved=False
            )
            stateful_alerts_to_insert.append(consolidated_alert)

    # 8. Atomic Database Commit
    all_new_alerts = individual_alerts_to_insert + stateful_alerts_to_insert
    db.add_all(flows_to_insert)
    db.add_all(all_new_alerts)
    db.commit()

    # Generate response summary
    alerts_summary = [
        {
            "id": a.id,
            "source_ip": a.source_ip,
            "destination_ip": a.destination_ip,
            "severity": a.severity,
            "alert_type": a.alert_type,
            "anomaly_score": a.anomaly_score
        }
        for a in all_new_alerts[:10]
    ]

    return {
        "total_processed": len(raw_flows),
        "normal_count": normal_count,
        "suspicious_count": suspicious_count,
        "alerts_generated": len(all_new_alerts),
        "alerts_summary": alerts_summary
    }
