"""
Services package for NIDS application logic.
"""

from backend.app.services.traffic_generator import SyntheticTrafficGenerator
from backend.app.services.flow_processor import process_and_store_flows
from backend.app.services.csv_service import parse_csv_stream
from backend.app.services.stats_service import get_dashboard_stats
from backend.app.services.stateful_detector import StatefulPortScanDetector

__all__ = [
    "SyntheticTrafficGenerator",
    "process_and_store_flows",
    "parse_csv_stream",
    "get_dashboard_stats",
    "StatefulPortScanDetector"
]
