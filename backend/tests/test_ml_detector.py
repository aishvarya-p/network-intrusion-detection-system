"""
Automated tests for Milestone 2:
- Feature extraction pipeline (normal, edge cases, NaN/inf safety)
- Isolation Forest detector (training, prediction, scoring range, save/load)
- Rule-based attack classification (heuristics, normal handling)
- Evaluator benchmark logic
"""

from pathlib import Path
import pytest
import numpy as np

from backend.app.ml.feature_pipeline import FeaturePipeline
from backend.app.ml.detector import NetworkAnomalyDetector
from backend.app.ml.rule_classifier import RuleBasedClassifier
from backend.app.ml.evaluator import run_evaluation
from backend.app.services.traffic_generator import SyntheticTrafficGenerator


def test_feature_pipeline_shape_and_names():
    """Verifies that the feature pipeline outputs the expected 13-feature matrix."""
    pipeline = FeaturePipeline()
    gen = SyntheticTrafficGenerator(seed=1)
    flows = [gen.generate_normal_flow() for _ in range(10)]

    matrix = pipeline.transform(flows)
    assert matrix.shape == (10, 13)
    assert len(pipeline.FEATURE_NAMES) == 13
    assert not np.isnan(matrix).any()
    assert not np.isinf(matrix).any()


def test_feature_pipeline_edge_cases():
    """Verifies pipeline robustness against missing keys, None values, zero duration, and negative numbers."""
    pipeline = FeaturePipeline()

    malformed_flows = [
        {},  # Empty dictionary
        {"duration": 0.0, "packet_count": 0, "byte_count": -50},  # Division by zero candidates
        {"destination_port": None, "protocol": None, "tcp_flags": None},  # Null values
        {"destination_port": 999999, "packet_count": "invalid_number"}  # Extreme / invalid types
    ]

    matrix = pipeline.transform(malformed_flows)
    assert matrix.shape == (4, 13)
    assert not np.isnan(matrix).any()
    assert not np.isinf(matrix).any()


def test_isolation_forest_train_and_predict():
    """Verifies that Isolation Forest trains on normal flows and returns valid prediction schemas."""
    gen = SyntheticTrafficGenerator(seed=10)
    train_flows = [gen.generate_normal_flow() for _ in range(100)]

    detector = NetworkAnomalyDetector(contamination=0.03, random_state=42)
    detector.fit(train_flows)
    assert detector.is_trained is True

    # Test prediction on normal and anomalous flows
    test_flows = [
        gen.generate_normal_flow(),
        gen.generate_syn_flood_flow(),
        gen.generate_data_exfiltration_flow()
    ]
    predictions = detector.predict(test_flows)

    assert len(predictions) == 3
    for pred in predictions:
        assert "is_suspicious" in pred
        assert isinstance(pred["is_suspicious"], bool)
        assert "anomaly_score" in pred
        assert 0.0 <= pred["anomaly_score"] <= 1.0
        assert "raw_decision_score" in pred
        assert isinstance(pred["raw_decision_score"], float)

    # SYN flood and Data exfiltration should be flagged as suspicious
    assert predictions[1]["is_suspicious"] is True
    assert predictions[2]["is_suspicious"] is True


def test_model_save_and_load(tmp_path: Path):
    """Verifies model serialization and deserialization via joblib."""
    gen = SyntheticTrafficGenerator(seed=20)
    train_flows = [gen.generate_normal_flow() for _ in range(50)]

    detector = NetworkAnomalyDetector(random_state=42)
    detector.fit(train_flows)

    model_file = tmp_path / "test_model.joblib"
    detector.save(model_file)
    assert model_file.exists()

    loaded_detector = NetworkAnomalyDetector().load(model_file)
    assert loaded_detector.is_trained is True

    # Verify identical prediction outputs
    sample_flow = [gen.generate_normal_flow()]
    orig_pred = detector.predict(sample_flow)
    loaded_pred = loaded_detector.predict(sample_flow)

    assert orig_pred[0]["anomaly_score"] == loaded_pred[0]["anomaly_score"]
    assert orig_pred[0]["is_suspicious"] == loaded_pred[0]["is_suspicious"]


def test_rule_based_classifier_patterns():
    """Verifies that RuleBasedClassifier identifies port scans, floods, and exfiltration."""
    gen = SyntheticTrafficGenerator(seed=30)

    # 1. Individual SYN probe flow
    scan_flow = gen.generate_port_scan_flow(target_port=22)
    res_scan = RuleBasedClassifier.classify_flow(scan_flow)
    assert res_scan["rule_triggered"] is True
    assert res_scan["suggested_category"] == "SYN Probe"
    assert res_scan["severity"] in ["MEDIUM", "HIGH"]

    # 2. SYN flood flow
    flood_flow = gen.generate_syn_flood_flow(target_port=80)
    res_flood = RuleBasedClassifier.classify_flow(flood_flow)
    assert res_flood["rule_triggered"] is True
    assert res_flood["suggested_category"] == "SYN Flood Pattern"
    assert res_flood["severity"] == "HIGH"

    # 3. Data exfiltration flow
    exfil_flow = gen.generate_data_exfiltration_flow()
    res_exfil = RuleBasedClassifier.classify_flow(exfil_flow)
    assert res_exfil["rule_triggered"] is True
    assert res_exfil["suggested_category"] == "Unusual Large Data Transfer"
    assert res_exfil["severity"] == "HIGH"

    # 4. Normal flow should NOT trigger rules
    normal_flow = gen.generate_normal_flow()
    res_norm = RuleBasedClassifier.classify_flow(normal_flow)
    assert res_norm["rule_triggered"] is False
    assert res_norm["suggested_category"] is None


def test_evaluator_benchmark_execution():
    """Verifies that run_evaluation executes successfully and calculates all required metrics."""
    results = run_evaluation(
        train_normal_count=200,
        test_normal_count=100,
        test_port_scan_count=20,
        test_syn_flood_count=20,
        test_exfiltration_count=10,
        seed=42
    )

    metrics = results["metrics"]
    cm = results["confusion_matrix"]

    assert metrics["precision"] > 0.80
    assert metrics["accuracy"] > 0.80
    total_samples = cm["true_negatives"] + cm["false_positives"] + cm["false_negatives"] + cm["true_positives"]
    assert total_samples == 150
    assert results["attack_breakdown"]["SYN_FLOOD"]["detection_rate"] >= 0.95
    assert results["attack_breakdown"]["DATA_EXFILTRATION"]["detection_rate"] >= 0.95
