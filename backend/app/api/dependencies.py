"""
FastAPI dependency injection utilities.
Provides database sessions and a cached instance of the ML anomaly detector.
"""

from typing import Optional
from backend.app.database import get_db, SessionLocal
from backend.app.ml.detector import NetworkAnomalyDetector, DEFAULT_MODEL_PATH
from backend.app.services.traffic_generator import SyntheticTrafficGenerator

_CACHED_DETECTOR: Optional[NetworkAnomalyDetector] = None


def get_detector() -> NetworkAnomalyDetector:
    """
    Returns the loaded NetworkAnomalyDetector instance.
    Initializes and trains on baseline normal traffic if no model artifact exists.
    """
    global _CACHED_DETECTOR
    if _CACHED_DETECTOR is not None and _CACHED_DETECTOR.is_trained:
        return _CACHED_DETECTOR

    detector = NetworkAnomalyDetector()
    if DEFAULT_MODEL_PATH.exists():
        detector.load(DEFAULT_MODEL_PATH)
    else:
        # Auto-train baseline if artifact is missing
        gen = SyntheticTrafficGenerator(seed=42)
        baseline = [gen.generate_normal_flow() for _ in range(500)]
        detector.fit(baseline)
        detector.save(DEFAULT_MODEL_PATH)

    _CACHED_DETECTOR = detector
    return _CACHED_DETECTOR
