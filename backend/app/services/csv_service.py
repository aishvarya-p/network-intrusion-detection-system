"""
CSV Dataset Parser and Ingestion Service.
Safely parses and validates uploaded CSV traffic files, sanitizes row contents,
and delegates valid rows to the detection pipeline.
"""

import csv
import io
import re
from typing import List, Dict, Any, Tuple

# Constants for upload safety
MAX_ALLOWED_FILE_BYTES = 5 * 1024 * 1024  # 5 MB
MAX_ALLOWED_ROWS = 5000                   # Prevent server memory exhaustion

REQUIRED_COLUMNS = {"source_ip", "destination_ip", "destination_port", "protocol"}


def is_valid_ip(ip_str: str) -> bool:
    """Basic validation for IPv4 format."""
    parts = ip_str.strip().split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit() or not (0 <= int(p) <= 255):
            return False
    return True


def parse_csv_stream(content: bytes) -> Tuple[List[Dict[str, Any]], int, List[str]]:
    """
    Parses CSV bytes safely into standardized flow dictionaries.

    Returns:
        (valid_flows, rejected_count, errors_list)
    """
    if len(content) > MAX_ALLOWED_FILE_BYTES:
        raise ValueError(f"Uploaded file exceeds maximum size limit of {MAX_ALLOWED_FILE_BYTES // (1024*1024)} MB.")

    try:
        text_stream = io.StringIO(content.decode("utf-8-sig", errors="replace"))
    except Exception as e:
        raise ValueError(f"Failed to decode CSV text: {str(e)}")

    reader = csv.DictReader(text_stream)

    if not reader.fieldnames:
        raise ValueError("CSV file is empty or missing a header row.")

    # Normalize header names to lowercase trimmed strings
    field_map = {col: col.strip().lower() for col in reader.fieldnames if col}
    normalized_headers = set(field_map.values())

    missing = REQUIRED_COLUMNS - normalized_headers
    if missing:
        raise ValueError(f"CSV is missing required columns: {', '.join(sorted(missing))}. "
                         f"Required: {', '.join(sorted(REQUIRED_COLUMNS))}")

    valid_flows: List[Dict[str, Any]] = []
    errors: List[str] = []
    rejected_count = 0

    for row_idx, row in enumerate(reader, start=2):  # Start at line 2 accounting for header
        if row_idx > MAX_ALLOWED_ROWS + 1:
            errors.append(f"Row limit reached ({MAX_ALLOWED_ROWS} rows). Remaining rows were skipped.")
            break

        # Remap row keys to normalized lowercase
        normalized_row = {field_map[k]: (v.strip() if isinstance(v, str) else v)
                          for k, v in row.items() if k in field_map}

        # 1. Validate required fields
        src_ip = normalized_row.get("source_ip", "")
        dst_ip = normalized_row.get("destination_ip", "")
        dst_port_raw = normalized_row.get("destination_port", "")
        protocol_raw = normalized_row.get("protocol", "")

        if not src_ip or not dst_ip or not dst_port_raw or not protocol_raw:
            rejected_count += 1
            if len(errors) < 10:
                errors.append(f"Row {row_idx}: Missing one or more required fields.")
            continue

        # 2. Validate Port numbers
        try:
            dst_port = int(dst_port_raw)
            if not (0 <= dst_port <= 65535):
                raise ValueError()
        except ValueError:
            rejected_count += 1
            if len(errors) < 10:
                errors.append(f"Row {row_idx}: Invalid destination_port '{dst_port_raw}' (must be 0-65535).")
            continue

        # Optional source port
        src_port_raw = normalized_row.get("source_port", "")
        try:
            src_port = int(src_port_raw) if src_port_raw else 50000
            if not (0 <= src_port <= 65535):
                src_port = 50000
        except ValueError:
            src_port = 50000

        # 3. Validate Protocol
        protocol = protocol_raw.upper()
        if protocol not in ["TCP", "UDP", "ICMP"]:
            rejected_count += 1
            if len(errors) < 10:
                errors.append(f"Row {row_idx}: Unsupported protocol '{protocol_raw}' (must be TCP, UDP, or ICMP).")
            continue

        # 4. Numeric metrics with safe defaults
        try:
            packet_count = max(int(float(normalized_row.get("packet_count") or 1)), 1)
        except (ValueError, TypeError):
            packet_count = 1

        try:
            byte_count = max(int(float(normalized_row.get("byte_count") or 64)), 0)
        except (ValueError, TypeError):
            byte_count = 64

        try:
            duration = max(float(normalized_row.get("duration") or 0.0), 0.0)
        except (ValueError, TypeError):
            duration = 0.0

        tcp_flags = normalized_row.get("tcp_flags") or "NONE"

        # Simulation label is stored purely for record/eval purposes; NEVER passed as ML feature
        sim_label = normalized_row.get("simulation_label") or "CSV_UPLOAD"

        flow_item = {
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": src_port,
            "destination_port": dst_port,
            "protocol": protocol,
            "packet_count": packet_count,
            "byte_count": byte_count,
            "duration": duration,
            "tcp_flags": tcp_flags,
            "is_synthetic": True,
            "simulation_label": sim_label
        }
        valid_flows.append(flow_item)

    return valid_flows, rejected_count, errors
