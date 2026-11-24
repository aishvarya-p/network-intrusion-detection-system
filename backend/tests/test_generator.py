"""
Automated unit tests for the Synthetic Traffic Generator.
Verifies normal flow generation, attack simulation patterns, batch generation, and DB insertion.
"""

from backend.app.services.traffic_generator import SyntheticTrafficGenerator
from backend.app.models.flow_models import TrafficFlow


def test_generate_normal_flow():
    """Verifies that normal flow records follow expected realistic network ranges."""
    gen = SyntheticTrafficGenerator(seed=42)
    flow = gen.generate_normal_flow()

    assert flow["is_synthetic"] is True
    assert flow["simulation_label"] == "NORMAL"
    assert flow["protocol"] in ["TCP", "UDP"]
    assert flow["packet_count"] >= 1
    assert flow["byte_count"] > 0
    assert flow["duration"] >= 0.0
    assert 1 <= flow["destination_port"] <= 65535
    assert 1024 <= flow["source_port"] <= 65535


def test_generate_port_scan_flow():
    """Verifies that port scan flows have signature characteristics (1-2 packets, SYN flag, small bytes)."""
    gen = SyntheticTrafficGenerator(seed=42)
    flow = gen.generate_port_scan_flow(target_port=22)

    assert flow["is_synthetic"] is True
    assert flow["simulation_label"] == "PORT_SCAN"
    assert flow["destination_port"] == 22
    assert flow["protocol"] == "TCP"
    assert flow["tcp_flags"] == "SYN"
    assert flow["packet_count"] in [1, 2]
    assert flow["byte_count"] <= 128  # Small probe packet
    assert flow["duration"] <= 0.1


def test_generate_syn_flood_flow():
    """Verifies SYN flood flow characteristics (high packet count, small bytes/packet, SYN flag)."""
    gen = SyntheticTrafficGenerator(seed=42)
    flow = gen.generate_syn_flood_flow(target_port=80)

    assert flow["is_synthetic"] is True
    assert flow["simulation_label"] == "SYN_FLOOD"
    assert flow["destination_port"] == 80
    assert flow["protocol"] == "TCP"
    assert flow["tcp_flags"] == "SYN"
    assert flow["packet_count"] >= 500  # High packet burst
    # Average bytes per packet should be small (40-60 bytes)
    avg_bytes = flow["byte_count"] / flow["packet_count"]
    assert 40 <= avg_bytes <= 60
    assert flow["duration"] <= 1.0


def test_generate_data_exfiltration_flow():
    """Verifies data exfiltration flow characteristics (large byte volume, MTU-sized packets)."""
    gen = SyntheticTrafficGenerator(seed=42)
    flow = gen.generate_data_exfiltration_flow()

    assert flow["is_synthetic"] is True
    assert flow["simulation_label"] == "DATA_EXFILTRATION"
    assert flow["byte_count"] >= 5_000_000  # Multi-megabyte volume
    assert flow["packet_count"] >= 1000
    assert flow["duration"] >= 10.0


def test_generate_batch_ratios():
    """Verifies batch generation correctly respects requested flow counts and anomaly ratios."""
    gen = SyntheticTrafficGenerator(seed=123)
    total_requested = 200
    anomaly_ratio = 0.20  # 20% anomalies = 40 anomalies, 160 normal
    batch = gen.generate_batch(total_flows=total_requested, anomaly_ratio=anomaly_ratio)

    assert len(batch) == total_requested

    normal_count = sum(1 for f in batch if f["simulation_label"] == "NORMAL")
    anomaly_count = sum(1 for f in batch if f["simulation_label"] != "NORMAL")

    assert normal_count == 160
    assert anomaly_count == 40

    # Verify chronological ordering
    timestamps = [f["timestamp"] for f in batch]
    assert timestamps == sorted(timestamps)


def test_batch_insertion_into_database(db_session):
    """Verifies that generated synthetic flow dictionaries can be persisted directly to SQLite."""
    gen = SyntheticTrafficGenerator(seed=999)
    batch = gen.generate_batch(total_flows=25, anomaly_ratio=0.20)

    # Convert dictionaries to ORM model instances
    db_models = [TrafficFlow(**flow_data) for flow_data in batch]
    db_session.add_all(db_models)
    db_session.commit()

    # Query from SQLite to verify persistence
    count = db_session.query(TrafficFlow).count()
    assert count == 25

    normal_in_db = db_session.query(TrafficFlow).filter_by(simulation_label="NORMAL").count()
    assert normal_in_db == 20
