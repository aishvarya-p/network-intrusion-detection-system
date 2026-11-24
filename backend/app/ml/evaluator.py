"""
Model Evaluation and Benchmark Harness for Network Intrusion Detection System.
Trains Isolation Forest on NORMAL baseline traffic and evaluates it on a test set
containing both normal flows and simulated attack patterns (Port Scan, SYN Flood, Data Exfiltration).
Calculates precision, recall, F1-score, and confusion matrix.
"""

from typing import Dict, Any, List
import numpy as np
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score

from backend.app.services.traffic_generator import SyntheticTrafficGenerator
from backend.app.ml.detector import NetworkAnomalyDetector
from backend.app.ml.rule_classifier import RuleBasedClassifier


def run_evaluation(
    train_normal_count: int = 1000,
    test_normal_count: int = 500,
    test_port_scan_count: int = 100,
    test_syn_flood_count: int = 100,
    test_exfiltration_count: int = 50,
    seed: int = 42
) -> Dict[str, Any]:
    """
    Executes a complete training and evaluation pipeline using reproducible synthetic datasets.
    """
    generator = SyntheticTrafficGenerator(seed=seed)

    # 1. Generate Training Baseline (Strictly NORMAL flows)
    print(f"Generating {train_normal_count} baseline NORMAL flows for training...")
    train_flows = [generator.generate_normal_flow() for _ in range(train_normal_count)]

    # 2. Train Isolation Forest Detector
    detector = NetworkAnomalyDetector(
        contamination=0.03,
        n_estimators=100,
        random_state=seed,
        threshold=0.0
    )
    detector.fit(train_flows)
    saved_path = detector.save()
    print(f"Model trained and saved to: {saved_path}")

    # 3. Generate Test Dataset with Ground Truth Labels
    test_flows: List[Dict[str, Any]] = []

    # Normal flows (y_true = 0)
    for _ in range(test_normal_count):
        test_flows.append(generator.generate_normal_flow())

    # Attack flows (y_true = 1)
    for _ in range(test_port_scan_count):
        test_flows.append(generator.generate_port_scan_flow())

    for _ in range(test_syn_flood_count):
        test_flows.append(generator.generate_syn_flood_flow())

    for _ in range(test_exfiltration_count):
        test_flows.append(generator.generate_data_exfiltration_flow())

    # Ground truth: 0 = Normal, 1 = Anomaly
    y_true = np.array([0 if f["simulation_label"] == "NORMAL" else 1 for f in test_flows])

    # 4. Predict using ML Isolation Forest
    ml_predictions = detector.predict(test_flows)
    y_pred_ml = np.array([1 if p["is_suspicious"] else 0 for p in ml_predictions])

    # 5. Calculate Standard Metrics
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred_ml).ravel()
    prec = precision_score(y_true, y_pred_ml, zero_division=0)
    rec = recall_score(y_true, y_pred_ml, zero_division=0)
    f1 = f1_score(y_true, y_pred_ml, zero_division=0)

    # 6. Detailed Breakdown by Attack Type
    attack_breakdown = {}
    for atk_type in ["PORT_SCAN", "SYN_FLOOD", "DATA_EXFILTRATION"]:
        atk_indices = [i for i, f in enumerate(test_flows) if f["simulation_label"] == atk_type]
        if atk_indices:
            caught = sum(y_pred_ml[i] for i in atk_indices)
            total = len(atk_indices)
            attack_breakdown[atk_type] = {
                "total": total,
                "detected": int(caught),
                "detection_rate": round(float(caught / total), 4)
            }

    # 7. Compare with Rule-Based Classifier
    rule_results = [RuleBasedClassifier.classify_flow(f) for f in test_flows]
    y_pred_rules = np.array([1 if r["rule_triggered"] else 0 for r in rule_results])
    r_tn, r_fp, r_fn, r_tp = confusion_matrix(y_true, y_pred_rules).ravel()
    rule_f1 = f1_score(y_true, y_pred_rules, zero_division=0)

    # 8. Analyze Specific False Positives and False Negatives
    false_positives = [
        test_flows[i] for i in range(len(test_flows)) if y_true[i] == 0 and y_pred_ml[i] == 1
    ]
    false_negatives = [
        test_flows[i] for i in range(len(test_flows)) if y_true[i] == 1 and y_pred_ml[i] == 0
    ]

    report = {
        "train_samples": train_normal_count,
        "test_total": len(test_flows),
        "test_normal": test_normal_count,
        "test_anomalous": len(test_flows) - test_normal_count,
        "confusion_matrix": {
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "true_positives": int(tp)
        },
        "metrics": {
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1_score": round(float(f1), 4),
            "accuracy": round(float((tp + tn) / len(test_flows)), 4)
        },
        "attack_breakdown": attack_breakdown,
        "rule_classifier_metrics": {
            "true_positives": int(r_tp),
            "false_positives": int(r_fp),
            "f1_score": round(float(rule_f1), 4)
        },
        "false_positive_count": len(false_positives),
        "false_negative_count": len(false_negatives),
        "sample_false_positive": false_positives[0] if false_positives else None,
        "sample_false_negative": false_negatives[0] if false_negatives else None
    }

    return report


if __name__ == "__main__":
    results = run_evaluation()
    print("\n--- EVALUATION SUMMARY ---")
    print(f"Accuracy:  {results['metrics']['accuracy'] * 100:.2f}%")
    print(f"Precision: {results['metrics']['precision'] * 100:.2f}%")
    print(f"Recall:    {results['metrics']['recall'] * 100:.2f}%")
    print(f"F1-Score:  {results['metrics']['f1_score'] * 100:.2f}%")
    print("\nConfusion Matrix:")
    print(f"  TN (Normal correctly classified):   {results['confusion_matrix']['true_negatives']}")
    print(f"  FP (Normal flagged as anomaly):     {results['confusion_matrix']['false_positives']}")
    print(f"  FN (Attacks missed):                {results['confusion_matrix']['false_negatives']}")
    print(f"  TP (Attacks correctly detected):    {results['confusion_matrix']['true_positives']}")
    print("\nAttack Detection Rates:")
    for atk, stats in results["attack_breakdown"].items():
        print(f"  {atk}: {stats['detected']}/{stats['total']} ({stats['detection_rate']*100:.1f}%)")
