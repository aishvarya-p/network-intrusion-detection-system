"""
Machine Learning Anomaly Detector for Network Intrusion Detection System.
Uses Scikit-learn's Isolation Forest algorithm.
Trained on baseline NORMAL network traffic to identify behavioral outliers.
"""

from pathlib import Path
import os
from typing import List, Dict, Any, Optional, Tuple
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from backend.app.ml.feature_pipeline import FeaturePipeline


MODEL_STORE_DIR = Path(__file__).resolve().parent / "model_store"
MODEL_STORE_DIR.mkdir(parents=True, exist_ok=True)
DEFAULT_MODEL_PATH = MODEL_STORE_DIR / "isolation_forest.joblib"


class NetworkAnomalyDetector:
    """
    Unsupervised Anomaly Detection engine using Isolation Forest.
    Trained strictly on baseline NORMAL traffic so it learns typical network behavior.
    New traffic that deviates (e.g. port scans, floods, unusual exfiltrations)
    is isolated in fewer tree splits and flagged as suspicious.
    """

    def __init__(
        self,
        contamination: float = 0.03,
        n_estimators: int = 100,
        random_state: int = 42,
        threshold: float = 0.0
    ):
        """
        Args:
            contamination: Expected proportion of outliers in the training baseline.
            n_estimators: Number of isolation trees in the ensemble forest.
            random_state: Deterministic seed for reproducible tree construction.
            threshold: Decision function threshold below which a flow is marked suspicious.
        """
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.threshold = threshold

        self.pipeline = FeaturePipeline()
        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1
        )
        self.is_trained = False
        self.training_sample_count = 0

    def fit(self, normal_flows: List[Dict[str, Any]]) -> "NetworkAnomalyDetector":
        """
        Trains the Isolation Forest model on baseline NORMAL traffic records.
        """
        if len(normal_flows) < 10:
            raise ValueError("Training requires at least 10 baseline normal flow records.")

        X = self.pipeline.transform(normal_flows)
        self.model.fit(X)
        self.is_trained = True
        self.training_sample_count = len(normal_flows)
        return self

    def score_single(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculates anomaly score and classification for a single flow dictionary.
        Returns:
            Dict containing:
            - is_suspicious: bool (True if anomalous, False if normal)
            - anomaly_score: float in [0.0, 1.0] (higher means more anomalous)
            - raw_decision_score: float (scikit-learn raw decision score, < 0 is outlier)
        """
        return self.predict([flow])[0]

    def predict(self, flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Evaluates a batch of flows.
        Returns list of prediction dicts matching the flow order.
        """
        if not self.is_trained:
            raise RuntimeError("Model is not trained. Call fit() or load() before predict().")

        if not flows:
            return []

        X = self.pipeline.transform(flows)
        # Scikit-learn decision_function: lower/negative values = anomalous, positive = inlier
        raw_scores = self.model.decision_function(X)

        results = []
        for raw_score in raw_scores:
            # Classification decision: below threshold means outlier
            is_suspicious = bool(raw_score < self.threshold)

            # Map raw score to intuitive [0.0, 1.0] SOC anomaly scale:
            # Sigmoid transformation: 1 / (1 + exp(12 * raw_score))
            # When raw_score = 0.0 -> normalized_score = 0.50
            # When raw_score < 0.0 (anomaly) -> normalized_score > 0.50 (up to 0.99)
            # When raw_score > 0.0 (normal) -> normalized_score < 0.50 (down to 0.05)
            normalized_score = float(1.0 / (1.0 + np.exp(12.0 * raw_score)))
            normalized_score = round(min(max(normalized_score, 0.0), 1.0), 4)

            results.append({
                "is_suspicious": is_suspicious,
                "anomaly_score": normalized_score,
                "raw_decision_score": round(float(raw_score), 4)
            })

        return results

    def save(self, filepath: Optional[Path] = None) -> Path:
        """
        Serializes and saves the trained model to disk using joblib.
        """
        if not self.is_trained:
            raise RuntimeError("Cannot save an untrained model.")

        save_path = filepath or DEFAULT_MODEL_PATH
        save_path.parent.mkdir(parents=True, exist_ok=True)

        payload = {
            "model": self.model,
            "contamination": self.contamination,
            "n_estimators": self.n_estimators,
            "random_state": self.random_state,
            "threshold": self.threshold,
            "training_sample_count": self.training_sample_count,
            "feature_names": self.pipeline.FEATURE_NAMES
        }
        joblib.dump(payload, save_path)
        return save_path

    def load(self, filepath: Optional[Path] = None) -> "NetworkAnomalyDetector":
        """
        Loads a previously saved model artifact from disk.
        """
        load_path = filepath or DEFAULT_MODEL_PATH
        if not load_path.exists():
            raise FileNotFoundError(f"Model file not found at: {load_path}")

        payload = joblib.load(load_path)
        self.model = payload["model"]
        self.contamination = payload.get("contamination", self.contamination)
        self.n_estimators = payload.get("n_estimators", self.n_estimators)
        self.random_state = payload.get("random_state", self.random_state)
        self.threshold = payload.get("threshold", self.threshold)
        self.training_sample_count = payload.get("training_sample_count", 0)
        self.is_trained = True
        return self
