"""
Application configuration and network constants.
Defines database connection paths, reserved synthetic IP ranges, and common network services.
"""

from pathlib import Path
import os

# Base Directories
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

# SQLite Database Configuration
DATABASE_PATH = DATA_DIR / "nids.db"
DATABASE_URL = os.getenv("NIDS_DATABASE_URL", f"sqlite:///{DATABASE_PATH}")

# Synthetic Traffic IP Ranges (RFC 5737 Documentation & RFC 1918 Private Ranges)
# These ensure zero collision with actual internet hosts or sensitive networks.
SYNTHETIC_EXTERNAL_IPS = [
    "198.51.100.10", "198.51.100.25", "198.51.100.54", "198.51.100.99",
    "203.0.113.15", "203.0.113.42", "203.0.113.78", "203.0.113.120",
    "192.0.2.33", "192.0.2.77", "192.0.2.145", "192.0.2.210"
]

SYNTHETIC_INTERNAL_SERVERS = [
    "10.0.0.1",   # Core Gateway
    "10.0.0.5",   # DNS & Directory Server
    "10.0.0.10",  # Corporate Web Server
    "10.0.0.15",  # Database Server
    "10.0.0.20"   # File & Backup Server
]

SYNTHETIC_INTERNAL_CLIENTS = [
    f"192.168.1.{i}" for i in range(100, 120)  # Workstations 100-119
]

# Common Service Ports
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    123: "NTP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    8080: "HTTP-Proxy"
}
