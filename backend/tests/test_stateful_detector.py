"""
Automated Unit and Integration Tests for Stateful Port Scan Detection:
1. Positive detection (10 distinct ports in 20s triggers scan)
2. Legitimate multi-port activity (< 5 distinct ports does not trigger)
3. Interleaved traffic (scanner isolated despite normal background noise)
4. Window expiration (probes outside 60s window do not combine)
5. Same ports repeated (does not inflate distinct count)
6. Different destinations (ports on different targets are not combined into vertical scan)
7. Boundary condition (exactly 5 distinct ports triggers scan)
8. Insufficient evidence (1-2 isolated probes do not trigger stateful scan)

Integration tests:
- Scan sequence through full flow_processor pipeline
- Scan split across two separate ingestion batches (historical lookback)
- Duplicate alert prevention on ongoing bursts
- Existing ML and heuristic detection continue functioning
"""

from datetime import datetime, timezone, timedelta
import pytest

from backend.app.services.stateful_detector import StatefulPortScanDetector
from backend.app.services.traffic_generator import SyntheticTrafficGenerator
from backend.app.services.flow_processor import process_and_store_flows
from backend.app.models.flow_models import TrafficFlow, SecurityAlert
from backend.app.api.dependencies import get_detector


def test_positive_detection_vertical_scan():
    """10 distinct destination ports on a single target within 20 seconds triggers a vertical scan."""
    detector = StatefulPortScanDetector(window_seconds=60.0, min_distinct_ports=5)
    gen = SyntheticTrafficGenerator(seed=1)

    scan_flows = gen.generate_port_scan_sequence(
        scanner_ip="198.51.100.99",
        target_ip="10.0.0.10",
        num_ports=10,
        time_window_seconds=20.0
    )

    detections = detector.analyze_flows(scan_flows)
    assert len(detections) == 1
    d = detections[0]
    assert d["source_ip"] == "198.51.100.99"
    assert d["destination_ip"] == "10.0.0.10"
    assert d["distinct_port_count"] == 10
    assert len(d["destination_ports"]) == 10
    assert d["category"] == "Vertical Port Scan (Stateful)"
    assert d["severity"] == "HIGH"
    assert d["confidence"] == "HIGH"


def test_legitimate_multi_port_not_triggered():
    """Normal client activity connecting to fewer than 5 ports (e.g. HTTP, HTTPS, DNS) does not trigger scan."""
    detector = StatefulPortScanDetector(window_seconds=60.0, min_distinct_ports=5)
    now = datetime.now(timezone.utc)

    normal_flows = [
        {
            "timestamp": now,
            "source_ip": "192.168.1.105",
            "destination_ip": "10.0.0.10",
            "destination_port": 80,
            "protocol": "TCP",
            "packet_count": 25,
            "byte_count": 15000,
            "tcp_flags": "ACK"
        },
        {
            "timestamp": now + timedelta(seconds=2),
            "source_ip": "192.168.1.105",
            "destination_ip": "10.0.0.10",
            "destination_port": 443,
            "protocol": "TCP",
            "packet_count": 40,
            "byte_count": 28000,
            "tcp_flags": "ACK"
        },
        {
            "timestamp": now + timedelta(seconds=3),
            "source_ip": "192.168.1.105",
            "destination_ip": "10.0.0.10",
            "destination_port": 8080,
            "protocol": "TCP",
            "packet_count": 15,
            "byte_count": 8000,
            "tcp_flags": "ACK"
        }
    ]

    detections = detector.analyze_flows(normal_flows)
    assert len(detections) == 0


def test_interleaved_traffic_isolation():
    """Scanner flows interleaved with background traffic from legitimate hosts are correctly isolated."""
    detector = StatefulPortScanDetector(window_seconds=60.0, min_distinct_ports=5)
    gen = SyntheticTrafficGenerator(seed=2)

    scan_flows = gen.generate_port_scan_sequence(
        scanner_ip="198.51.100.77",
        target_ip="10.0.0.15",
        num_ports=7,
        time_window_seconds=15.0
    )

    # Background normal flows from random clients
    background_flows = [gen.generate_normal_flow() for _ in range(25)]

    # Interleave and sort by timestamp
    mixed_flows = scan_flows + background_flows
    mixed_flows.sort(key=lambda x: x["timestamp"])

    detections = detector.analyze_flows(mixed_flows)
    assert len(detections) == 1
    assert detections[0]["source_ip"] == "198.51.100.77"
    assert detections[0]["destination_ip"] == "10.0.0.15"
    assert detections[0]["distinct_port_count"] == 7


def test_window_expiration_does_not_trigger():
    """Probes occurring outside the 60s sliding window (e.g. 180s apart) do not combine into a scan."""
    detector = StatefulPortScanDetector(window_seconds=60.0, min_distinct_ports=5)
    base_time = datetime(2026, 11, 24, 10, 0, 0, tzinfo=timezone.utc)

    # 3 probes at t=0
    burst1 = [
        {
            "timestamp": base_time + timedelta(seconds=i),
            "source_ip": "198.51.100.54",
            "destination_ip": "10.0.0.10",
            "destination_port": 20 + i,
            "protocol": "TCP",
            "packet_count": 1,
            "byte_count": 48,
            "tcp_flags": "SYN"
        }
        for i in range(3)
    ]

    # 3 probes at t=180s (3 minutes later)
    burst2 = [
        {
            "timestamp": base_time + timedelta(seconds=180 + i),
            "source_ip": "198.51.100.54",
            "destination_ip": "10.0.0.10",
            "destination_port": 80 + i,
            "protocol": "TCP",
            "packet_count": 1,
            "byte_count": 48,
            "tcp_flags": "SYN"
        }
        for i in range(3)
    ]

    detections = detector.analyze_flows(burst1 + burst2)
    assert len(detections) == 0


def test_repeated_ports_do_not_inflate_count():
    """Multiple connection attempts to the same destination port do not inflate distinct port count."""
    detector = StatefulPortScanDetector(window_seconds=60.0, min_distinct_ports=5)
    base_time = datetime(2026, 11, 24, 10, 0, 0, tzinfo=timezone.utc)

    # 15 connection attempts, but only across 2 ports (80 and 443)
    repeated_flows = [
        {
            "timestamp": base_time + timedelta(seconds=i * 2),
            "source_ip": "198.51.100.22",
            "destination_ip": "10.0.0.10",
            "destination_port": 80 if i % 2 == 0 else 443,
            "protocol": "TCP",
            "packet_count": 1,
            "byte_count": 48,
            "tcp_flags": "SYN"
        }
        for i in range(15)
    ]

    detections = detector.analyze_flows(repeated_flows)
    assert len(detections) == 0


def test_different_destinations_not_combined():
    """Probes directed at different destination IPs are not combined into a vertical scan."""
    detector = StatefulPortScanDetector(window_seconds=60.0, min_distinct_ports=5)
    base_time = datetime(2026, 11, 24, 10, 0, 0, tzinfo=timezone.utc)

    # 6 probes from same source, but each targeting a different server
    distributed_flows = [
        {
            "timestamp": base_time + timedelta(seconds=i),
            "source_ip": "198.51.100.99",
            "destination_ip": f"10.0.0.{10 + i}",
            "destination_port": 22,
            "protocol": "TCP",
            "packet_count": 1,
            "byte_count": 48,
            "tcp_flags": "SYN"
        }
        for i in range(6)
    ]

    detections = detector.analyze_flows(distributed_flows)
    # Vertical scan detector requires >= 5 distinct ports on the SAME target
    assert len(detections) == 0


def test_boundary_condition_exactly_five_ports():
    """Exactly 5 distinct destination ports must trigger detection (boundary test)."""
    detector = StatefulPortScanDetector(window_seconds=60.0, min_distinct_ports=5)
    base_time = datetime(2026, 11, 24, 10, 0, 0, tzinfo=timezone.utc)

    five_port_flows = [
        {
            "timestamp": base_time + timedelta(seconds=i * 2),
            "source_ip": "198.51.100.99",
            "destination_ip": "10.0.0.10",
            "destination_port": 100 + i,
            "protocol": "TCP",
            "packet_count": 1,
            "byte_count": 48,
            "tcp_flags": "SYN"
        }
        for i in range(5)
    ]

    detections = detector.analyze_flows(five_port_flows)
    assert len(detections) == 1
    assert detections[0]["distinct_port_count"] == 5


def test_insufficient_evidence_individual_probes():
    """One or two isolated SYN probes must not trigger a stateful port scan."""
    detector = StatefulPortScanDetector(window_seconds=60.0, min_distinct_ports=5)
    gen = SyntheticTrafficGenerator(seed=3)

    probe1 = gen.generate_port_scan_flow(target_port=22)
    probe2 = gen.generate_port_scan_flow(target_port=80)

    detections = detector.analyze_flows([probe1, probe2])
    assert len(detections) == 0


# -------------------------------------------------------------
# Pipeline Integration Tests
# -------------------------------------------------------------

def test_pipeline_ingestion_and_consolidated_alert(db_session):
    """Verifies that an 8-port scan ingested through process_and_store_flows produces a single consolidated alert."""
    detector = get_detector()
    gen = SyntheticTrafficGenerator(seed=4)

    scan_flows = gen.generate_port_scan_sequence(
        scanner_ip="198.51.100.99",
        target_ip="10.0.0.10",
        num_ports=8,
        time_window_seconds=15.0
    )

    result = process_and_store_flows(db_session, scan_flows, detector)

    # All 8 flows should be flagged suspicious
    assert result["total_processed"] == 8
    assert result["suspicious_count"] == 8

    # A single consolidated alert should be generated (not 8 duplicate alerts)
    alerts = db_session.query(SecurityAlert).filter_by(source_ip="198.51.100.99").all()
    assert len(alerts) == 1
    assert alerts[0].alert_type == "PORT_SCAN_SWEEP"
    assert "8 distinct destination ports" in alerts[0].description


def test_scan_split_across_two_batches(db_session):
    """Verifies historical lookback: 3 probes in batch 1 + 3 probes in batch 2 trigger a correlated scan."""
    detector = get_detector()
    base_time = datetime.now(timezone.utc) - timedelta(seconds=20)

    # Batch 1: 3 probes (insufficient on its own)
    batch1 = [
        {
            "timestamp": base_time + timedelta(seconds=i),
            "source_ip": "198.51.100.88",
            "destination_ip": "10.0.0.10",
            "destination_port": 20 + i,
            "protocol": "TCP",
            "packet_count": 1,
            "byte_count": 48,
            "tcp_flags": "SYN"
        }
        for i in range(3)
    ]
    res1 = process_and_store_flows(db_session, batch1, detector)
    # Batch 1 does not exceed threshold 5, so no stateful alert yet
    scan_alerts_batch1 = db_session.query(SecurityAlert).filter_by(
        source_ip="198.51.100.88", alert_type="PORT_SCAN_SWEEP"
    ).all()
    assert len(scan_alerts_batch1) == 0

    # Batch 2: 3 more probes 5 seconds later (within the 60s window)
    batch2 = [
        {
            "timestamp": base_time + timedelta(seconds=10 + i),
            "source_ip": "198.51.100.88",
            "destination_ip": "10.0.0.10",
            "destination_port": 80 + i,
            "protocol": "TCP",
            "packet_count": 1,
            "byte_count": 48,
            "tcp_flags": "SYN"
        }
        for i in range(3)
    ]
    res2 = process_and_store_flows(db_session, batch2, detector)

    # Historical lookback in batch 2 should correlate with batch 1 and trigger PORT_SCAN_SWEEP!
    scan_alerts_batch2 = db_session.query(SecurityAlert).filter_by(
        source_ip="198.51.100.88", alert_type="PORT_SCAN_SWEEP"
    ).all()
    assert len(scan_alerts_batch2) == 1
    assert "6 distinct destination ports" in scan_alerts_batch2[0].description


def test_duplicate_alert_prevention_on_ongoing_burst(db_session):
    """Verifies that an extended port scan burst updates the existing alert rather than generating duplicates."""
    detector = get_detector()
    gen = SyntheticTrafficGenerator(seed=5)

    # Ingestion 1: 6 ports
    scan1 = gen.generate_port_scan_sequence(
        scanner_ip="198.51.100.99",
        target_ip="10.0.0.10",
        num_ports=6,
        time_window_seconds=10.0
    )
    process_and_store_flows(db_session, scan1, detector)

    alerts_after_1 = db_session.query(SecurityAlert).filter_by(
        source_ip="198.51.100.99", alert_type="PORT_SCAN_SWEEP"
    ).count()
    assert alerts_after_1 == 1

    # Ingestion 2: 4 more ports 5 seconds later
    scan2 = gen.generate_port_scan_sequence(
        scanner_ip="198.51.100.99",
        target_ip="10.0.0.10",
        num_ports=4,
        time_window_seconds=8.0,
        port_list=[9001, 9002, 9003, 9004]
    )
    process_and_store_flows(db_session, scan2, detector)

    alerts_after_2 = db_session.query(SecurityAlert).filter_by(
        source_ip="198.51.100.99", alert_type="PORT_SCAN_SWEEP"
    ).count()
    # Alert count must remain 1 (no duplicate alert row created)
    assert alerts_after_2 == 1


def test_existing_ml_and_heuristic_preservation(db_session):
    """Verifies that SYN floods and Data exfiltration continue to be detected alongside stateful scans."""
    detector = get_detector()
    gen = SyntheticTrafficGenerator(seed=6)

    syn_flood = gen.generate_syn_flood_flow()
    data_exfil = gen.generate_data_exfiltration_flow()

    res = process_and_store_flows(db_session, [syn_flood, data_exfil], detector)
    assert res["suspicious_count"] == 2
    assert res["alerts_generated"] == 2

    alert_types = [a.alert_type for a in db_session.query(SecurityAlert).all()]
    assert "SYN_FLOOD" in alert_types
    assert "DATA_BURST" in alert_types


def test_two_separate_scan_bursts_with_fifty_second_gap():
    """
    Two separate qualifying scan bursts against the same destination, with a 50-second gap
    between the end of the first burst and the start of the second, must produce two distinct incidents.
    """
    detector = StatefulPortScanDetector(window_seconds=60.0, min_distinct_ports=5)
    gen = SyntheticTrafficGenerator(seed=7)
    base_time = datetime(2026, 11, 24, 10, 0, 0, tzinfo=timezone.utc)

    # Burst 1: 5 distinct ports across 15 seconds (t = 0 to 15s) -> end = 15s
    burst1 = gen.generate_port_scan_sequence(
        scanner_ip="198.51.100.99",
        target_ip="10.0.0.10",
        num_ports=5,
        time_window_seconds=15.0,
        start_time=base_time,
        port_list=[21, 22, 23, 25, 80]
    )

    # 50-second gap: end of burst 1 is at 15s, so start of burst 2 is at 15 + 50 = 65s
    start_time_burst2 = base_time + timedelta(seconds=65)

    # Burst 2: 5 distinct ports across 15 seconds (t = 65 to 80s)
    burst2 = gen.generate_port_scan_sequence(
        scanner_ip="198.51.100.99",
        target_ip="10.0.0.10",
        num_ports=5,
        time_window_seconds=15.0,
        start_time=start_time_burst2,
        port_list=[8080, 8443, 9000, 3306, 5432]
    )

    combined_flows = burst1 + burst2
    detections = detector.analyze_flows(combined_flows)

    # Must produce exactly two distinct incidents, not merged into one
    assert len(detections) == 2, f"Expected 2 incidents, got {len(detections)}"

    inc1 = detections[0]
    assert inc1["distinct_port_count"] == 5
    assert set(inc1["destination_ports"]) == {21, 22, 23, 25, 80}

    inc2 = detections[1]
    assert inc2["distinct_port_count"] == 5
    assert set(inc2["destination_ports"]) == {8080, 8443, 9000, 3306, 5432}


def test_continuous_scan_ten_ports_thirty_seconds_consolidated():
    """
    One continuous scan across at least 10 distinct ports within 30 seconds
    must produce exactly one consolidated incident.
    """
    detector = StatefulPortScanDetector(window_seconds=60.0, min_distinct_ports=5)
    gen = SyntheticTrafficGenerator(seed=8)
    base_time = datetime(2026, 11, 24, 10, 0, 0, tzinfo=timezone.utc)

    # 10 distinct ports across 25 seconds (< 30s)
    scan_flows = gen.generate_port_scan_sequence(
        scanner_ip="198.51.100.99",
        target_ip="10.0.0.10",
        num_ports=10,
        time_window_seconds=25.0,
        start_time=base_time
    )

    detections = detector.analyze_flows(scan_flows)

    # All overlapping windows share probe flows and must merge into 1 incident
    assert len(detections) == 1, f"Expected 1 incident, got {len(detections)}"
    d = detections[0]
    assert d["distinct_port_count"] == 10
    assert len(d["destination_ports"]) == 10
    assert d["source_ip"] == "198.51.100.99"
    assert d["destination_ip"] == "10.0.0.10"


def test_two_separate_incidents_in_same_batch_produce_two_alerts(db_session):
    """
    Two separate scan incidents ingested in the same batch must generate two separate alerts.
    """
    detector = get_detector()
    gen = SyntheticTrafficGenerator(seed=9)
    base_time = datetime(2026, 11, 24, 10, 0, 0, tzinfo=timezone.utc)

    burst1 = gen.generate_port_scan_sequence(
        scanner_ip="198.51.100.99",
        target_ip="10.0.0.10",
        num_ports=5,
        time_window_seconds=15.0,
        start_time=base_time,
        port_list=[21, 22, 23, 25, 80]
    )

    burst2 = gen.generate_port_scan_sequence(
        scanner_ip="198.51.100.99",
        target_ip="10.0.0.10",
        num_ports=5,
        time_window_seconds=15.0,
        start_time=base_time + timedelta(seconds=65),
        port_list=[8080, 8443, 9000, 3306, 5432]
    )

    batch = burst1 + burst2
    res = process_and_store_flows(db_session, batch, detector)

    # Both separate incidents must generate an alert
    alerts = (
        db_session.query(SecurityAlert)
        .filter_by(source_ip="198.51.100.99", alert_type="PORT_SCAN_SWEEP")
        .order_by(SecurityAlert.timestamp)
        .all()
    )
    assert len(alerts) == 2, f"Expected 2 PORT_SCAN_SWEEP alerts, got {len(alerts)}"
    assert "5 distinct destination ports" in alerts[0].description
    assert "5 distinct destination ports" in alerts[1].description
