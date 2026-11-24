"""
Synthetic Network Traffic Generator.
Generates realistic, clearly labelled synthetic network traffic flows for testing and training.
Supported flow types:
- NORMAL: Everyday web, DNS, SSH, and database traffic.
- PORT_SCAN: Sequential/random port probing with minimal packet payloads and SYN flags.
- SYN_FLOOD: High-frequency bursts of SYN packets directed at a single target server.
- DATA_EXFILTRATION: Unusually large volume outbound data transfers.

ALL IP addresses used are reserved RFC 5737 Documentation ranges or RFC 1918 Private ranges.
NO LIVE ATTACKS OR EXTERNAL NETWORK PACKETS ARE TRANSMITTED.
"""

from datetime import datetime, timezone, timedelta
import random
from typing import List, Dict, Any, Optional

from backend.app.config import (
    SYNTHETIC_EXTERNAL_IPS,
    SYNTHETIC_INTERNAL_SERVERS,
    SYNTHETIC_INTERNAL_CLIENTS,
)


class SyntheticTrafficGenerator:
    """
    Generates synthetic network flow records with realistic metadata.
    Each generated flow dictionary matches the schema of the TrafficFlow database model.
    """

    def __init__(self, seed: Optional[int] = None):
        """Optionally set a random seed for reproducible test datasets."""
        if seed is not None:
            random.seed(seed)

    def _random_timestamp(self, minutes_ago: int = 10) -> datetime:
        """Generates a UTC timestamp within the last `minutes_ago` minutes."""
        now = datetime.now(timezone.utc)
        delta_seconds = random.randint(0, minutes_ago * 60)
        return now - timedelta(seconds=delta_seconds)

    def generate_normal_flow(self, timestamp: Optional[datetime] = None) -> Dict[str, Any]:
        """
        Simulates standard enterprise network activity:
        - HTTP / HTTPS web browsing
        - DNS queries
        - SSH administrative sessions
        - NTP time synchronizations
        - Internal database access
        """
        traffic_profiles = [
            # Profile 1: HTTPS Web Browsing
            {
                "protocol": "TCP",
                "dst_port": 443,
                "packet_range": (10, 120),
                "bytes_per_pkt": (200, 1100),
                "duration_range": (0.5, 8.0),
                "flags": "ACK",
                "is_outbound": True
            },
            # Profile 2: HTTP Web Browsing
            {
                "protocol": "TCP",
                "dst_port": 80,
                "packet_range": (5, 60),
                "bytes_per_pkt": (150, 800),
                "duration_range": (0.2, 5.0),
                "flags": "ACK",
                "is_outbound": True
            },
            # Profile 3: DNS Query & Response
            {
                "protocol": "UDP",
                "dst_port": 53,
                "packet_range": (1, 2),
                "bytes_per_pkt": (64, 256),
                "duration_range": (0.01, 0.08),
                "flags": "NONE",
                "is_outbound": False  # Usually targeted at internal DNS server (10.0.0.5)
            },
            # Profile 4: SSH Admin Session
            {
                "protocol": "TCP",
                "dst_port": 22,
                "packet_range": (50, 400),
                "bytes_per_pkt": (80, 250),
                "duration_range": (15.0, 180.0),
                "flags": "ACK",
                "is_outbound": False  # Internal admin to internal server
            },
            # Profile 5: Database Query
            {
                "protocol": "TCP",
                "dst_port": 5432,
                "packet_range": (15, 90),
                "bytes_per_pkt": (300, 1200),
                "duration_range": (0.1, 2.5),
                "flags": "ACK",
                "is_outbound": False
            }
        ]

        profile = random.choice(traffic_profiles)

        src_ip = random.choice(SYNTHETIC_INTERNAL_CLIENTS)
        if profile["is_outbound"]:
            dst_ip = random.choice(SYNTHETIC_EXTERNAL_IPS)
        else:
            dst_ip = random.choice(SYNTHETIC_INTERNAL_SERVERS)

        src_port = random.randint(49152, 65535)  # Ephemeral client port
        dst_port = profile["dst_port"]
        packets = random.randint(*profile["packet_range"])
        bytes_per_pkt = random.randint(*profile["bytes_per_pkt"])
        byte_count = packets * bytes_per_pkt
        duration = round(random.uniform(*profile["duration_range"]), 3)

        return {
            "timestamp": timestamp or self._random_timestamp(),
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": src_port,
            "destination_port": dst_port,
            "protocol": profile["protocol"],
            "packet_count": packets,
            "byte_count": byte_count,
            "duration": duration,
            "tcp_flags": profile["flags"],
            "is_synthetic": True,
            "simulation_label": "NORMAL"
        }

    def generate_port_scan_flow(
        self,
        scanner_ip: Optional[str] = None,
        target_ip: Optional[str] = None,
        target_port: Optional[int] = None,
        timestamp: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Simulates a Port Scan probe:
        An external reconnaissance scanner probing various ports on an internal server.
        Key features:
        - Exactly 1 to 2 packets per flow
        - Minimal packet size (40-64 bytes per packet; standard TCP SYN header with no data)
        - TCP flags: "SYN"
        - Microsecond/millisecond duration (0.001 - 0.05s)
        """
        src_ip = scanner_ip or random.choice(SYNTHETIC_EXTERNAL_IPS)
        dst_ip = target_ip or random.choice(SYNTHETIC_INTERNAL_SERVERS)

        # Scanners typically probe common ports or sequential blocks
        common_scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443]
        dst_port = target_port if target_port is not None else random.choice(common_scan_ports)
        src_port = random.randint(40000, 65535)

        packets = random.choice([1, 2])
        byte_count = packets * random.randint(40, 64)  # Minimal TCP header size
        duration = round(random.uniform(0.001, 0.05), 4)

        return {
            "timestamp": timestamp or self._random_timestamp(),
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": src_port,
            "destination_port": dst_port,
            "protocol": "TCP",
            "packet_count": packets,
            "byte_count": byte_count,
            "duration": duration,
            "tcp_flags": "SYN",
            "is_synthetic": True,
            "simulation_label": "PORT_SCAN"
        }

    def generate_port_scan_sequence(
        self,
        scanner_ip: Optional[str] = None,
        target_ip: Optional[str] = None,
        num_ports: int = 10,
        time_window_seconds: float = 20.0,
        start_time: Optional[datetime] = None,
        port_list: Optional[List[int]] = None
    ) -> List[Dict[str, Any]]:
        """
        Generates a realistic chronological sequence of vertical SYN probe flows:
        - Same source IP and target IP.
        - Multiple distinct destination ports.
        - Timestamps strictly within the configured time window.
        - Characteristic low packet counts (1-2) and minimal bytes (40-64 bytes per packet).
        """
        src_ip = scanner_ip or random.choice(SYNTHETIC_EXTERNAL_IPS)
        dst_ip = target_ip or random.choice(SYNTHETIC_INTERNAL_SERVERS)

        if port_list is not None:
            scan_ports = list(port_list)
        else:
            base_common_ports = [
                21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443, 9000
            ]
            if num_ports <= len(base_common_ports):
                scan_ports = random.sample(base_common_ports, num_ports)
            else:
                additional = list(range(10000, 10000 + (num_ports - len(base_common_ports))))
                scan_ports = base_common_ports + additional

        now = datetime.now(timezone.utc)
        base_start = start_time or (now - timedelta(seconds=time_window_seconds))
        interval = time_window_seconds / max(len(scan_ports), 1)

        sequence: List[Dict[str, Any]] = []
        for i, port in enumerate(scan_ports):
            flow_time = base_start + timedelta(seconds=i * interval)
            flow = self.generate_port_scan_flow(
                scanner_ip=src_ip,
                target_ip=dst_ip,
                target_port=port,
                timestamp=flow_time
            )
            sequence.append(flow)

        return sequence

    def generate_syn_flood_flow(
        self,
        target_ip: Optional[str] = None,
        target_port: Optional[int] = None,
        timestamp: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Simulates a SYN Flood (Denial of Service) attack flow:
        A surge of SYN requests sent at high packet rates to exhaust server connection state.
        Key features:
        - Disproportionately high packet count (500 to 5,000 packets)
        - Very small payload bytes (40-60 bytes/packet, pure SYN packets)
        - Extremely short duration (0.01 - 0.5s), resulting in huge packet-per-second rate
        - TCP flags: "SYN"
        """
        src_ip = random.choice(SYNTHETIC_EXTERNAL_IPS)
        dst_ip = target_ip or random.choice(SYNTHETIC_INTERNAL_SERVERS)
        dst_port = target_port if target_port is not None else random.choice([80, 443])
        src_port = random.randint(1024, 65535)

        packets = random.randint(500, 5000)
        bytes_per_pkt = random.randint(40, 60)
        byte_count = packets * bytes_per_pkt
        duration = round(random.uniform(0.01, 0.5), 3)

        return {
            "timestamp": timestamp or self._random_timestamp(),
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": src_port,
            "destination_port": dst_port,
            "protocol": "TCP",
            "packet_count": packets,
            "byte_count": byte_count,
            "duration": duration,
            "tcp_flags": "SYN",
            "is_synthetic": True,
            "simulation_label": "SYN_FLOOD"
        }

    def generate_data_exfiltration_flow(
        self,
        source_client_ip: Optional[str] = None,
        external_dest_ip: Optional[str] = None,
        timestamp: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Simulates Data Exfiltration / Unusual Data Transfer:
        A compromised internal host transferring an abnormally large volume of data out.
        Key features:
        - Massive byte count (5 MB to 50 MB in a single flow)
        - Sustained connection duration (15 to 120 seconds)
        - Packet size near Maximum Transmission Unit (MTU ~1400-1500 bytes per packet)
        - Outbound from internal client to external destination
        """
        src_ip = source_client_ip or random.choice(SYNTHETIC_INTERNAL_CLIENTS)
        dst_ip = external_dest_ip or random.choice(SYNTHETIC_EXTERNAL_IPS)
        src_port = random.randint(49152, 65535)
        dst_port = random.choice([443, 8080, 8443, 22])

        packets = random.randint(4000, 25000)
        bytes_per_pkt = random.randint(1300, 1500)  # Near standard Ethernet MTU
        byte_count = packets * bytes_per_pkt
        duration = round(random.uniform(15.0, 120.0), 2)

        return {
            "timestamp": timestamp or self._random_timestamp(),
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": src_port,
            "destination_port": dst_port,
            "protocol": "TCP",
            "packet_count": packets,
            "byte_count": byte_count,
            "duration": duration,
            "tcp_flags": "ACK",
            "is_synthetic": True,
            "simulation_label": "DATA_EXFILTRATION"
        }

    def generate_batch(
        self,
        total_flows: int = 100,
        anomaly_ratio: float = 0.15,
        target_attack_types: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Generates a realistic mixed batch of network flows.
        - `total_flows`: Number of flow records to generate.
        - `anomaly_ratio`: Proportion of anomalies (e.g., 0.15 = 15% anomalies).
        - `target_attack_types`: Attack categories to include ("PORT_SCAN", "SYN_FLOOD", "DATA_EXFILTRATION").

        Returns:
            List of flow dictionaries ready for database persistence or ML evaluation.
        """
        if target_attack_types is None:
            target_attack_types = ["PORT_SCAN", "SYN_FLOOD", "DATA_EXFILTRATION"]

        anomaly_count = int(total_flows * anomaly_ratio)
        normal_count = total_flows - anomaly_count

        flows: List[Dict[str, Any]] = []

        # 1. Generate normal baseline flows
        for _ in range(normal_count):
            flows.append(self.generate_normal_flow())

        # 2. Generate anomalous flows
        attack_generators = {
            "PORT_SCAN": self.generate_port_scan_flow,
            "SYN_FLOOD": self.generate_syn_flood_flow,
            "DATA_EXFILTRATION": self.generate_data_exfiltration_flow
        }

        # Filter valid generators
        active_generators = [
            attack_generators[atk] for atk in target_attack_types if atk in attack_generators
        ]
        if not active_generators:
            active_generators = [self.generate_port_scan_flow]

        for _ in range(anomaly_count):
            gen_func = random.choice(active_generators)
            flows.append(gen_func())

        # 3. Shuffle so normal and anomalous flows are interleaved chronologically
        random.shuffle(flows)

        # 4. Sort ascending by timestamp so they resemble realistic arrival times
        flows.sort(key=lambda x: x["timestamp"])

        return flows
