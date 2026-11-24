"""
Feature Engineering Pipeline for Network Intrusion Detection System.
Transforms raw network flow dictionaries/records into numerical feature matrices for ML models.
Handles missing, null, or extreme values safely.
"""

from typing import List, Dict, Any, Tuple
import numpy as np
import pandas as pd


class FeaturePipeline:
    """
    Extracts statistical, behavioral, and structural network features from flow records.
    Features extracted:
    1.  packet_count: Total packets in flow.
    2.  byte_count: Total bytes transferred in flow.
    3.  duration: Flow duration in seconds.
    4.  packet_rate: Packets per second (detects floods and bursts).
    5.  byte_rate: Bytes per second (detects exfiltration and high-speed leaks).
    6.  avg_packet_size: Mean bytes per packet (distinguishes SYN probes from large payloads).
    7.  is_tcp: 1 if protocol is TCP, else 0.
    8.  is_udp: 1 if protocol is UDP, else 0.
    9.  is_icmp: 1 if protocol is ICMP, else 0.
    10. is_syn_flag: 1 if TCP SYN flag is present, else 0.
    11. is_ack_flag: 1 if TCP ACK flag is present, else 0.
    12. is_well_known_port: 1 if destination port is < 1024 (standard system services), else 0.
    13. destination_port_scaled: Destination port normalized to range [0.0, 1.0].
    """

    FEATURE_NAMES = [
        "packet_count",
        "byte_count",
        "duration",
        "packet_rate",
        "byte_rate",
        "avg_packet_size",
        "is_tcp",
        "is_udp",
        "is_icmp",
        "is_syn_flag",
        "is_ack_flag",
        "is_well_known_port",
        "destination_port_scaled"
    ]

    def extract_features_single(self, flow: Dict[str, Any]) -> List[float]:
        """
        Safely extracts the feature vector for a single flow dictionary.
        Gracefully handles missing keys, null values, and zero division.
        """
        # 1. Base flow metrics with safe fallbacks
        try:
            packet_count = float(flow.get("packet_count") or 1.0)
            if packet_count <= 0:
                packet_count = 1.0
        except (ValueError, TypeError):
            packet_count = 1.0

        try:
            byte_count = float(flow.get("byte_count") or 64.0)
            if byte_count < 0:
                byte_count = 64.0
        except (ValueError, TypeError):
            byte_count = 64.0

        try:
            duration = float(flow.get("duration") or 0.0)
            if duration < 0:
                duration = 0.0
        except (ValueError, TypeError):
            duration = 0.0

        # Safe denominator for rate calculations (avoid zero division)
        effective_duration = max(duration, 0.001)

        # 2. Derived behavioral rates (capped to prevent infinite floats)
        packet_rate = min(packet_count / effective_duration, 1_000_000.0)
        byte_rate = min(byte_count / effective_duration, 1_000_000_000.0)
        avg_packet_size = min(byte_count / max(packet_count, 1.0), 65_535.0)

        # 3. Protocol encoding
        protocol = str(flow.get("protocol") or "TCP").strip().upper()
        is_tcp = 1.0 if protocol == "TCP" else 0.0
        is_udp = 1.0 if protocol == "UDP" else 0.0
        is_icmp = 1.0 if protocol == "ICMP" else 0.0

        # 4. TCP Flags
        tcp_flags = str(flow.get("tcp_flags") or "").strip().upper()
        is_syn_flag = 1.0 if "SYN" in tcp_flags else 0.0
        is_ack_flag = 1.0 if "ACK" in tcp_flags else 0.0

        # 5. Destination Port Information
        try:
            dst_port = int(flow.get("destination_port") or 80)
            if not (0 <= dst_port <= 65535):
                dst_port = 80
        except (ValueError, TypeError):
            dst_port = 80

        is_well_known_port = 1.0 if dst_port < 1024 else 0.0
        dst_port_scaled = dst_port / 65535.0

        return [
            packet_count,
            byte_count,
            duration,
            packet_rate,
            byte_rate,
            avg_packet_size,
            is_tcp,
            is_udp,
            is_icmp,
            is_syn_flag,
            is_ack_flag,
            is_well_known_port,
            dst_port_scaled
        ]

    def transform(self, flows: List[Dict[str, Any]]) -> np.ndarray:
        """
        Transforms a list of flow records into a 2D NumPy array (N samples, 13 features).
        Replaces any accidental NaN or Inf values with 0.0.
        """
        if not flows:
            return np.empty((0, len(self.FEATURE_NAMES)), dtype=np.float64)

        matrix = [self.extract_features_single(flow) for flow in flows]
        arr = np.array(matrix, dtype=np.float64)

        # Final sanitization against edge-case numerical instabilities
        arr = np.nan_to_num(arr, nan=0.0, posinf=1_000_000.0, neginf=-1_000_000.0)
        return arr

    def transform_dataframe(self, df: pd.DataFrame) -> np.ndarray:
        """
        Helper method to extract features from a Pandas DataFrame (e.g. from uploaded CSV).
        """
        records = df.to_dict(orient="records")
        return self.transform(records)
