"""
Stateful Threat Detection Engine.
Correlates network flow records across a rolling time window to detect multi-flow threats,
specifically vertical port scanning (single source probing multiple distinct ports on a target).

Operates independently of the Isolation Forest ML feature pipeline (zero label leakage).
"""

from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Tuple, Optional, Set
from collections import defaultdict


class StatefulPortScanDetector:
    """
    Stateful Correlator for Vertical Port Scans.
    Groups flows by (source_ip, destination_ip) and inspects rolling time windows
    to identify whether a single host is systematically probing distinct service ports.
    """

    def __init__(
        self,
        window_seconds: float = 60.0,
        min_distinct_ports: int = 5,
        max_bytes_per_probe: int = 1000
    ):
        """
        Args:
            window_seconds: Duration of the rolling analysis window in seconds (default: 60.0s).
            min_distinct_ports: Minimum distinct destination ports contacted on the same target to trigger an alert (default: 5).
            max_bytes_per_probe: Ceiling on average bytes per probe to differentiate empty scan probes from completed bulk transfers.
        """
        self.window_seconds = float(window_seconds)
        self.min_distinct_ports = int(min_distinct_ports)
        self.max_bytes_per_probe = int(max_bytes_per_probe)

    @staticmethod
    def _parse_timestamp(ts: Any) -> datetime:
        """Helper to ensure timestamp is a timezone-aware UTC datetime."""
        if isinstance(ts, str):
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    return dt.replace(tzinfo=timezone.utc)
                return dt
            except Exception:
                return datetime.now(timezone.utc)
        elif isinstance(ts, datetime):
            if ts.tzinfo is None:
                return ts.replace(tzinfo=timezone.utc)
            return ts
        return datetime.now(timezone.utc)

    def _is_probe_like(self, flow: Dict[str, Any]) -> bool:
        """
        Conservative filter: Checks whether a flow possesses scan probe characteristics.
        Probes typically have low packet counts and small payloads (e.g. TCP SYN packets).
        """
        byte_count = float(flow.get("byte_count") or 0)
        packet_count = float(flow.get("packet_count") or 1)
        avg_bytes = byte_count / max(packet_count, 1.0)
        dst_port = flow.get("destination_port")

        if dst_port is None:
            return False

        try:
            port_num = int(dst_port)
            if not (0 <= port_num <= 65535):
                return False
        except (ValueError, TypeError):
            return False

        return avg_bytes <= self.max_bytes_per_probe

    def analyze_flows(
        self,
        flows: List[Dict[str, Any]],
        historical_flows: Optional[List[Dict[str, Any]]] = None
    ) -> List[Dict[str, Any]]:
        """
        Analyzes a batch of flows (with optional historical lookback context).
        Groups records by (source_ip, destination_ip) and evaluates rolling windows.

        Args:
            flows: Incoming flow records to evaluate.
            historical_flows: Recent flows from database to maintain window context across batches.

        Returns:
            List of detected scan event dictionaries.
        """
        if not flows and not historical_flows:
            return []

        # Combine historical context and incoming flows
        all_candidate_flows: List[Dict[str, Any]] = []

        if historical_flows:
            for f in historical_flows:
                item = dict(f)
                item["_is_historical"] = True
                all_candidate_flows.append(item)

        for idx, f in enumerate(flows):
            item = dict(f)
            item["_is_historical"] = False
            item["_original_index"] = idx
            all_candidate_flows.append(item)

        # 1. Group candidate flows strictly by (source_ip, destination_ip)
        pairs: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
        for f in all_candidate_flows:
            src = str(f.get("source_ip", "")).strip()
            dst = str(f.get("destination_ip", "")).strip()
            if src and dst and self._is_probe_like(f):
                pairs[(src, dst)].append(f)

        detections: List[Dict[str, Any]] = []

        # 2. Analyze each (source_ip, destination_ip) conversation pair
        for (src_ip, dst_ip), pair_flows in pairs.items():
            # Sort strictly chronologically
            pair_flows.sort(key=lambda x: self._parse_timestamp(x.get("timestamp")))

            n = len(pair_flows)
            if n < self.min_distinct_ports:
                continue

            # 3. Find all qualifying rolling windows:
            # A window [start_idx ... end_idx] qualifies if:
            # (timestamp[end_idx] - timestamp[start_idx]) <= window_seconds
            # AND distinct ports in window >= min_distinct_ports
            qualifying_windows: List[Dict[str, Any]] = []

            for end_idx in range(n):
                t_end = self._parse_timestamp(pair_flows[end_idx].get("timestamp"))
                t_cutoff = t_end - timedelta(seconds=self.window_seconds)

                # Find the earliest flow within window_seconds of t_end
                start_idx = end_idx
                while start_idx > 0 and self._parse_timestamp(pair_flows[start_idx - 1].get("timestamp")) >= t_cutoff:
                    start_idx -= 1

                window_slice = pair_flows[start_idx : end_idx + 1]
                distinct_ports = {int(f["destination_port"]) for f in window_slice}

                if len(distinct_ports) >= self.min_distinct_ports:
                    qualifying_windows.append({
                        "start_time": self._parse_timestamp(pair_flows[start_idx].get("timestamp")),
                        "end_time": t_end,
                        "ports": distinct_ports,
                        "flows": window_slice,
                        "flow_ids": {id(f) for f in window_slice}
                    })

            if not qualifying_windows:
                continue

            # 4. Merge contiguous/overlapping qualifying windows into cohesive scan incidents.
            # Two qualifying windows belong to the same scan incident if and only if they share
            # participating probe flows. Two separate scan bursts that do not share probe flows
            # remain distinct incidents, even if they occur within 60s of each other.
            merged_incidents: List[Dict[str, Any]] = []
            current_incident = qualifying_windows[0].copy()
            current_incident["flows"] = list(current_incident["flows"])
            current_incident["flow_ids"] = set(current_incident["flow_ids"])

            for next_win in qualifying_windows[1:]:
                # Check whether next window shares participating probe flows with the current incident
                shared_flows = current_incident["flow_ids"].intersection(next_win["flow_ids"])
                if shared_flows:
                    # Same ongoing continuous scan burst: merge window
                    current_incident["end_time"] = max(current_incident["end_time"], next_win["end_time"])
                    current_incident["ports"] = current_incident["ports"].union(next_win["ports"])
                    current_incident["flows"].extend(next_win["flows"])
                    current_incident["flow_ids"].update(next_win["flow_ids"])
                else:
                    # Separate scan incident: record current and begin new incident
                    merged_incidents.append(current_incident)
                    current_incident = next_win.copy()
                    current_incident["flows"] = list(current_incident["flows"])
                    current_incident["flow_ids"] = set(current_incident["flow_ids"])

            merged_incidents.append(current_incident)

            # 5. Format detection records
            for inc in merged_incidents:
                # Deduplicate flows in incident
                seen_flow_ids = set()
                deduped_flows = []
                for f in inc["flows"]:
                    fid = id(f)
                    if fid not in seen_flow_ids:
                        seen_flow_ids.add(fid)
                        deduped_flows.append(f)

                # Only trigger an alert if at least one flow in this incident is part of the incoming batch
                incoming_flows = [f for f in deduped_flows if not f.get("_is_historical", False)]
                if not incoming_flows:
                    continue

                participating_indices = [
                    f["_original_index"] for f in incoming_flows if "_original_index" in f
                ]

                sorted_ports = sorted(list(inc["ports"]))
                duration_seconds = round((inc["end_time"] - inc["start_time"]).total_seconds(), 2)

                # Confidence assessment based on TCP SYN flag proportion
                syn_count = sum(1 for f in deduped_flows if "SYN" in str(f.get("tcp_flags") or "").upper())
                confidence = "HIGH" if (syn_count / max(len(deduped_flows), 1)) >= 0.5 else "MEDIUM"

                ports_sample = sorted_ports[:8]
                ports_str = ", ".join(map(str, ports_sample))
                if len(sorted_ports) > 8:
                    ports_str += f", ... (+{len(sorted_ports) - 8} more)"

                detection_entry = {
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "distinct_port_count": len(sorted_ports),
                    "destination_ports": sorted_ports,
                    "window_start": inc["start_time"],
                    "window_end": inc["end_time"],
                    "duration_seconds": duration_seconds,
                    "category": "Vertical Port Scan (Stateful)",
                    "severity": "HIGH",
                    "confidence": confidence,
                    "explanation": (
                        f"Host {src_ip} probed {len(sorted_ports)} distinct destination ports "
                        f"({ports_str}) on target {dst_ip} within {duration_seconds:.1f}s "
                        f"(Threshold: >= {self.min_distinct_ports} distinct ports in {self.window_seconds:.0f}s window)."
                    ),
                    "participating_indices": participating_indices,
                    "triggering_flow": incoming_flows[-1]
                }
                detections.append(detection_entry)

        return detections
