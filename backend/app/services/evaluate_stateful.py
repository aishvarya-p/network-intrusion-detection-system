"""
Evaluation and benchmark script for StatefulPortScanDetector.
Evaluates precision, recall, F1-score, and confusion matrix on synthetic traffic.
"""

import numpy as np
from datetime import datetime, timezone, timedelta
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score
from backend.app.services.traffic_generator import SyntheticTrafficGenerator
from backend.app.services.stateful_detector import StatefulPortScanDetector

def evaluate():
    generator = SyntheticTrafficGenerator(seed=42)
    detector = StatefulPortScanDetector(window_seconds=60.0, min_distinct_ports=5)

    flows = []
    base_time = datetime(2026, 11, 24, 12, 0, 0, tzinfo=timezone.utc)

    # 1. 600 Normal flows (browsing, DNS, SSH, DB) across various IPs and ports
    for i in range(600):
        f = generator.generate_normal_flow()
        f["id"] = len(flows) + 1
        f["timestamp"] = base_time + timedelta(seconds=i * 0.5)
        flows.append(f)

    # 2. 100 SYN Flood flows (same IP, same port e.g. 80/443)
    for i in range(100):
        f = generator.generate_syn_flood_flow()
        f["id"] = len(flows) + 1
        f["timestamp"] = base_time + timedelta(seconds=i * 0.2)
        flows.append(f)

    # 3. 50 Data Exfiltration flows
    for i in range(50):
        f = generator.generate_data_exfiltration_flow()
        f["id"] = len(flows) + 1
        f["timestamp"] = base_time + timedelta(seconds=i * 1.0)
        flows.append(f)

    # 4. 20 Isolated sub-threshold SYN probes (< 5 ports, e.g. 1-3 probes per source IP)
    for i in range(20):
        f = generator.generate_port_scan_flow()
        f["id"] = len(flows) + 1
        f["source_ip"] = f"198.51.100.{150 + (i % 7)}"
        f["destination_ip"] = "192.168.1.50"
        f["destination_port"] = 1000 + i
        f["timestamp"] = base_time + timedelta(seconds=i * 2.0)
        flows.append(f)

    # 5. 5 Distinct Vertical Port Scan Sequences (each with 8 to 16 ports)
    scan_flow_ids = set()
    scan_sequences_count = 5
    for s in range(scan_sequences_count):
        attacker = f"203.0.113.{10 + s}"
        target = f"192.168.1.{20 + s}"
        scan_time = base_time + timedelta(seconds=30 + s * 45)
        seq = generator.generate_port_scan_sequence(
            scanner_ip=attacker,
            target_ip=target,
            num_ports=8 + s * 2,
            time_window_seconds=25.0,
            start_time=scan_time
        )
        for f in seq:
            f["id"] = len(flows) + 1
            scan_flow_ids.add(f["id"])
            flows.append(f)

    # Ensure all timestamps are datetime objects
    for f in flows:
        if isinstance(f["timestamp"], str):
            f["timestamp"] = datetime.fromisoformat(f["timestamp"])

    # Sort all flows chronologically
    flows.sort(key=lambda x: x["timestamp"])

    # Ground truth: 1 if flow is part of a multi-port vertical scan sequence, 0 otherwise
    y_true = np.array([1 if f["id"] in scan_flow_ids else 0 for f in flows])

    # Run Stateful Detector
    incidents = detector.analyze_flows(flows)

    # Collect participating flow indices
    detected_indices = set()
    for inc in incidents:
        detected_indices.update(inc["participating_indices"])

    y_pred = np.array([1 if i in detected_indices else 0 for i in range(len(flows))])

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)

    print("=" * 60)
    print("STATEFUL PORT SCAN DETECTOR - SYNTHETIC BENCHMARK EVALUATION")
    print("=" * 60)
    print(f"Total Flows Evaluated: {len(flows)}")
    print(f"  - Ground Truth Scan Flows (Positives): {len(scan_flow_ids)}")
    print(f"  - Benign / Non-Scan Flows (Negatives): {len(flows) - len(scan_flow_ids)}")
    print(f"Simulated Scan Incidents: {scan_sequences_count}")
    print(f"Detected Scan Incidents: {len(incidents)}")
    print("-" * 60)
    print(f"True Positives (TP):  {tp}")
    print(f"False Positives (FP): {fp}")
    print(f"True Negatives (TN):  {tn}")
    print(f"False Negatives (FN): {fn}")
    print("-" * 60)
    print(f"Precision: {prec:.4f} ({prec * 100:.2f}%)")
    print(f"Recall:    {rec:.4f} ({rec * 100:.2f}%)")
    print(f"F1-Score:  {f1:.4f}")
    print("=" * 60)
    print("INCIDENT DETAILS:")
    for i, inc in enumerate(incidents):
        print(f"  [{i+1}] {inc['source_ip']} -> {inc['destination_ip']} | "
              f"Distinct Ports: {inc['distinct_port_count']} | "
              f"Window: {inc['duration_seconds']}s | "
              f"Severity: {inc['severity']} | Conf: {inc['confidence']}")
    print("=" * 60)

if __name__ == "__main__":
    evaluate()
