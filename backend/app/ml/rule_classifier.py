"""
Rule-Based Attack Classifier for Network Intrusion Detection.
Separates heuristic signature logic from machine learning anomaly detection.
Provides advisory suggestions (e.g. Possible Port Scan, Possible SYN Flood)
without treating heuristic patterns as confirmed malicious activity.
"""

from typing import Dict, Any, Optional


class RuleBasedClassifier:
    """
    Evaluates network flows against known traffic signature heuristics.
    Works independently of the unsupervised Isolation Forest model.
    """

    @staticmethod
    def classify_flow(flow: Dict[str, Any]) -> Dict[str, Any]:
        """
        Applies defensive heuristic rules to inspect flow characteristics.

        Returns:
            Dict containing:
            - rule_triggered: bool
            - suggested_category: Optional[str] (e.g. "Port Scan Probe")
            - severity: str ("LOW", "MEDIUM", "HIGH", "CRITICAL")
            - confidence: str ("LOW", "MEDIUM", "HIGH")
            - reason: str (Descriptive explanation noting it is a heuristic indicator)
        """
        try:
            packet_count = float(flow.get("packet_count") or 1.0)
            byte_count = float(flow.get("byte_count") or 64.0)
            duration = float(flow.get("duration") or 0.0)
        except (ValueError, TypeError):
            packet_count, byte_count, duration = 1.0, 64.0, 0.0

        protocol = str(flow.get("protocol") or "TCP").strip().upper()
        tcp_flags = str(flow.get("tcp_flags") or "").strip().upper()
        avg_packet_size = byte_count / max(packet_count, 1.0)
        packet_rate = packet_count / max(duration, 0.001)

        # -------------------------------------------------------------
        # Rule 1: Single SYN Probe Heuristic
        # Signature: 1-2 packets, minimal byte payload (SYN probe), short duration
        # Note: A single probe is not a confirmed port scan without stateful correlation.
        # -------------------------------------------------------------
        if (
            protocol == "TCP"
            and "SYN" in tcp_flags
            and packet_count <= 2
            and byte_count <= 128
            and duration <= 0.1
        ):
            return {
                "rule_triggered": True,
                "suggested_category": "SYN Probe",
                "severity": "MEDIUM",
                "confidence": "HIGH",
                "reason": (
                    f"Low packet count ({int(packet_count)}) with TCP SYN flag and zero payload data ({int(byte_count)} bytes). "
                    "Consistent with a single SYN connection probe."
                )
            }

        # -------------------------------------------------------------
        # Rule 2: SYN Flood / DoS Heuristic
        # Signature: High packet volume/rate, tiny packet payload, SYN flag
        # -------------------------------------------------------------
        if (
            protocol == "TCP"
            and "SYN" in tcp_flags
            and (packet_count >= 300 or packet_rate >= 1000.0)
            and avg_packet_size <= 80.0
            and duration <= 1.0
        ):
            return {
                "rule_triggered": True,
                "suggested_category": "SYN Flood Pattern",
                "severity": "HIGH",
                "confidence": "HIGH",
                "reason": (
                    f"High packet burst ({int(packet_count)} pkts in {duration:.3f}s, rate: {packet_rate:.0f} pkts/sec) "
                    f"with minimal payload size ({avg_packet_size:.1f} bytes/pkt) and TCP SYN flags. "
                    "Consistent with state-exhaustion denial of service."
                )
            }

        # -------------------------------------------------------------
        # Rule 3: Data Exfiltration / Unusual Volume Transfer
        # Signature: Large multi-megabyte volume, packets near MTU
        # -------------------------------------------------------------
        if byte_count >= 4_000_000 and avg_packet_size >= 1100.0:
            mb_transferred = byte_count / (1024 * 1024)
            return {
                "rule_triggered": True,
                "suggested_category": "Unusual Large Data Transfer",
                "severity": "HIGH",
                "confidence": "MEDIUM",
                "reason": (
                    f"High-volume data transfer ({mb_transferred:.2f} MB across {int(packet_count)} packets) "
                    f"with near-MTU average packet size ({avg_packet_size:.0f} bytes). "
                    "Potential bulk exfiltration or atypical backup burst."
                )
            }

        # Default: No heuristic rule matched
        return {
            "rule_triggered": False,
            "suggested_category": None,
            "severity": "LOW",
            "confidence": "LOW",
            "reason": "Traffic metrics fall within standard baseline operational ranges."
        }
