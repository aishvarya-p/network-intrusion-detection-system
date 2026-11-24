# Network Intrusion Detection System (NIDS)
### Multi-Layer Defensive Network Security Monitoring & Anomaly Detection Dashboard

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18-61DAFB.svg)](https://react.dev/)
[![Scikit-Learn](https://img.shields.io/badge/scikit--learn-1.4%2B-F7931E.svg)](https://scikit-learn.org/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-3.4-38B2AC.svg)](https://tailwindcss.com/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

An open-source, defensive cybersecurity monitoring platform engineered to analyze structured network flow records, detect anomalous traffic patterns, and surface periodic telemetry refreshed through 15-second polling via an interactive Security Operations Center (SOC) dashboard.

The system implements a defense-in-depth **tri-engine detection architecture** combining:
1. **Unsupervised Machine Learning**: Scikit-Learn Isolation Forest trained on normal traffic baselines to flag statistical outliers.
2. **Stateless Heuristic Signatures**: Deterministic rule classifier identifying single-flow threat signatures (SYN probes, SYN flood DoS patterns, and large data transfers).
3. **Stateful Temporal Correlation**: Rolling-window detector identifying multi-flow vertical port scans across chronological time windows.

> [!NOTE]
> **Defensive & Analytical Scope**: This system operates strictly on **synthetic network flows** and **uploaded CSV flow datasets**. It does **not** perform promiscuous packet capture (`libpcap`/`WinPcap`), raw packet sniffing, or active network probing.

---

## Table of Contents

- [1. Project Overview](#1-project-overview)
- [2. Problem Statement](#2-problem-statement)
- [3. Key Features](#3-key-features)
- [4. System Architecture](#4-system-architecture)
- [5. Three Detection Layers](#5-three-detection-layers)
  - [Layer 1: Unsupervised Anomaly Detection (Isolation Forest)](#layer-1-unsupervised-anomaly-detection-isolation-forest)
  - [Layer 2: Stateless Heuristic Rule Classifier](#layer-2-stateless-heuristic-rule-classifier)
  - [Layer 3: Stateful Temporal Port Scan Detector](#layer-3-stateful-temporal-port-scan-detector)
- [6. Technology Stack](#6-technology-stack)
- [7. Windows Installation and Setup](#7-windows-installation-and-setup)
- [8. Configuration](#8-configuration)
- [9. Backend API Endpoints](#9-backend-api-endpoints)
- [10. React SOC Dashboard Features](#10-react-soc-dashboard-features)
- [11. CSV Dataset Format](#11-csv-dataset-format)
- [12. Testing and Synthetic Benchmark](#12-testing-and-synthetic-benchmark)
- [13. Limitations and Ethical Scope](#13-limitations-and-ethical-scope)
- [14. Project Directory Structure](#14-project-directory-structure)

---

## 1. Project Overview

Modern enterprise networks generate millions of flow records per hour. Security Operations Center (SOC) analysts face constant alert fatigue from noisy rule alerts while remaining vulnerable to novel anomalies that bypass traditional signature sets.

The **Network Intrusion Detection System (NIDS)** provides an end-to-end laboratory and analytical platform that demonstrates how machine learning and rule heuristics complement each other. Rather than relying on a single detection paradigm, NIDS pipes incoming network flows through three specialized evaluation engines, persists structured flow records and security alerts to an SQLite database, and serves high-density operational telemetry to a React SOC dashboard via a high-performance FastAPI REST API.

---

## 2. Problem Statement

Defending network boundaries against modern adversaries requires addressing three primary challenges:

1. **The Blind Spots of Pure Signature Rules**: Traditional signature systems (e.g., Snort, Suricata) excel at identifying known exploit patterns but struggle to detect novel behavioral anomalies that lack established signature patterns, non-standard port abuses, or subtle variations in traffic metrics.
2. **The Unexplainability of Pure Machine Learning**: Black-box ML models can flag anomalies but often lack actionable context, produce uncalibrated confidence scores, and fail to distinguish benign high-volume transfers from malicious activity without explicit domain rules.
3. **The Multi-Flow Correlation Gap**: Stateless inspection examines each flow in isolation. A vertical port scan consisting of individual probes spaced across seconds or minutes appears completely benign to a single-flow inspector. Detecting such activity requires temporal state tracking across sliding observation windows.

### The Solution: Multi-Layered Defense

NIDS reconciles these challenges by deploying three decoupled detection stages:
- **Statistical Outlier Detection**: Isolation Forest spots behavioral shifts in flow volume, duration, packet rates, and protocol ratios.
- **Immediate Signature Matching**: Stateless heuristics instantly categorize known high-risk flow shapes with explicit threat categories and severities.
- **Stateful Window Correlation**: Stateful engine aggregates flows by `(source_ip, destination_ip)` within rolling 60-second windows to catch distributed reconnaissance probes that evade single-flow inspection.

---

## 3. Key Features

- **Tri-Engine Detection Pipeline**: Independent execution of Isolation Forest ML, stateless heuristic rules, and stateful multi-flow correlation.
- **Dual Flow Ingestion Paths**:
  - *Synthetic Generator*: Generates realistic stochastic traffic batches with configurable volume and anomaly ratios.
  - *CSV Dataset Ingestion*: Validates, sanitizes, and ingests external flow logs via multipart upload (up to 5 MB / 5,000 rows).
- **Comprehensive Feature Engineering**: Extraction of 13 behavioral, volumetric, and protocol features from raw flow metadata during ingestion.
- **Cross-Batch Stateful Persistence**: Rolling 60-second sliding window with SQLite historical lookback to detect port scans spanning batch boundaries while suppressing duplicate alerts.
- **High-Performance REST API**: Built with FastAPI, featuring Pydantic v2 data validation, structured error responses, and interactive OpenAPI (Swagger) documentation.
- **Interactive React SOC Dashboard**: High-density analyst interface featuring 15-second telemetry polling, interactive SVG/Recharts visualizations, multi-criteria filtering, and modal detail inspection.
- **Safe & Non-Invasive**: Runs in user space without kernel drivers, privileged network hooks, or packet sniffing libraries.

---

## 4. System Architecture

```
                                    TRAFFIC INGESTION
                    ┌───────────────────────────────────────────────┐
                    │  • Synthetic Traffic Generator (/simulate)    │
                    │  • CSV Dataset Ingestor (/upload-csv)         │
                    └───────────────────────┬───────────────────────┘
                                            │
                                            ▼
                                ┌───────────────────────┐
                                │ Pydantic Sanitization │
                                │   & Schema Validation │
                                └───────────┬───────────┘
                                            │ Raw Flows
                                            ▼
                                ┌───────────────────────┐
                                │  Feature Extraction   │
                                │ (13-dim Vector Float) │
                                └───────────┬───────────┘
                                            │
                    ┌───────────────────────┼───────────────────────┐
                    ▼                       ▼                       ▼
        ┌───────────────────────┐ ┌───────────────────┐ ┌───────────────────────┐
        │  LAYER 1: ML ENGINE   │ │  LAYER 2: RULES   │ │  LAYER 3: STATEFUL    │
        │   Isolation Forest    │ │ Stateless Heur.   │ │ Rolling 60s Window    │
        │  • 100 Estimators     │ │ • SYN Probe       │ │ • (Src IP, Dst IP)    │
        │  • Normal baseline    │ │ • SYN Flood       │ │ • >= 5 Dst Ports      │
        │  • Relative score     │ │ • Data Transfer   │ │ • SQLite Lookback     │
        └───────────┬───────────┘ └─────────┬─────────┘ └───────────┬───────────┘
                    │                       │                       │
                    │ Normalized Score      │ Single-Flow Alert     │ Correlated Alert
                    └───────────────────────┼───────────────────────┘
                                            │
                                            ▼
                                ┌───────────────────────┐
                                │     FlowProcessor     │
                                │ • Consolidates Alerts │
                                │ • In-Place Updating   │
                                └───────────┬───────────┘
                                            │
                                            ▼
                                ┌───────────────────────┐
                                │   SQLite Database     │
                                │ (backend/data/nids.db)│
                                │ • TrafficFlows        │
                                │ • SecurityAlerts      │
                                └───────────┬───────────┘
                                            │
                                            ▼
                                ┌───────────────────────┐
                                │   FastAPI REST API    │
                                │  • /traffic  /alerts  │
                                │  • /stats    /health  │
                                └───────────┬───────────┘
                                            │ JSON Telemetry (15s Poll)
                                            ▼
                                ┌───────────────────────┐
                                │   React SOC Console   │
                                │  • KPI Metric Cards   │
                                │  • Recharts Visuals   │
                                │  • Log Search/Filter  │
                                └───────────────────────┘
```

---

## 5. Three Detection Layers

### Layer 1: Unsupervised Anomaly Detection (Isolation Forest)

The anomaly detection engine utilizes Scikit-Learn's `IsolationForest` to identify multidimensional outliers without requiring labeled attack datasets during training.

- **Model Parameters**:
  - `n_estimators`: `100` decision trees
  - `contamination`: `0.03` (3% expected anomaly prior)
  - `random_state`: `42`
  - `threshold`: `0.0` (decision boundary)
- **Baseline Training**:
  - Shipped model artifact: `backend/app/ml/model_store/isolation_forest.joblib` (trained on 200 normal synthetic baseline flows).
  - Dynamic fallback: If the artifact is missing, `backend/app/api/dependencies.py` automatically generates a clean baseline of 500 normal flows and fits a fresh model.
  - **Zero Attack Contamination**: The training corpus consists solely of benign traffic patterns (HTTP, HTTPS, DNS, SSH, NTP) to establish an authentic normality boundary.
- **13 Extracted Features**:
  1. `packet_count` (int): Total packets in the flow.
  2. `byte_count` (int): Total bytes transferred.
  3. `duration` (float): Flow duration in seconds.
  4. `packet_rate` (float): `packet_count / max(duration, 0.001)`.
  5. `byte_rate` (float): `byte_count / max(duration, 0.001)`.
  6. `avg_packet_size` (float): `byte_count / max(packet_count, 1)`.
  7. `is_tcp` (binary 0/1): `1.0` if protocol is TCP.
  8. `is_udp` (binary 0/1): `1.0` if protocol is UDP.
  9. `is_icmp` (binary 0/1): `1.0` if protocol is ICMP.
  10. `is_syn_flag` (binary 0/1): `1.0` if TCP flags contain `SYN`.
  11. `is_ack_flag` (binary 0/1): `1.0` if TCP flags contain `ACK`.
  12. `is_well_known_port` (binary 0/1): `1.0` if `destination_port < 1024` (standard system ports 0–1023).
  13. `destination_port_scaled` (float): `destination_port / 65535.0`.
- **Anomaly Score Transformation**:
  Raw decision function output from Isolation Forest is mapped to a normalized range $[0.0, 1.0]$ using a steep sigmoid transformation:
  $$\text{normalized\_score} = \frac{1.0}{1.0 + \exp(12.0 \times \text{raw\_score})}$$
  - A raw score $< 0.0$ yields a normalized score $> 0.50$, triggering an anomaly flag (`is_anomaly = True`).
  - **Important Interpretation**: The normalized score represents a **relative statistical distance metric**, not a calibrated mathematical probability of an attack. It reflects how isolated a sample is within feature space compared to baseline trees.

---

### Layer 2: Stateless Heuristic Rule Classifier

Implemented in `backend/app/ml/rule_classifier.py`, this engine evaluates each flow independently against deterministic, domain-specific thresholds for instant attribution.

| Threat Category | Exact Code Conditions | Severity | Confidence | Description |
| :--- | :--- | :--- | :--- | :--- |
| **SYN Probe** | Protocol == `TCP`<br>`SYN` in `tcp_flags`<br>`packet_count <= 2`<br>`byte_count <= 128`<br>`duration <= 0.1` | `MEDIUM` | `HIGH` | Isolated low-volume reconnaissance probe targeting a specific port. |
| **SYN Flood Pattern** | Protocol == `TCP`<br>`SYN` in `tcp_flags`<br>`(packet_count >= 300 or packet_rate >= 1000.0)`<br>`avg_packet_size <= 80.0`<br>`duration <= 1.0` | `HIGH` | `HIGH` | Volumetric burst of minimal SYN packets characteristic of DoS exhaustion. |
| **Unusual Large Data Transfer** | `byte_count >= 4_000_000` (4 MB)<br>`avg_packet_size >= 1100.0` | `HIGH` | `MEDIUM` | Massive payload volume with jumbo packet averages. *(Advisory alert indicating abnormal bulk transfer; not definitive proof of data exfiltration)*. |

If a flow does not meet any signature conditions, the classifier returns `category=None`, allowing benign flows to pass without alert generation.

---

### Layer 3: Stateful Temporal Port Scan Detector

Implemented in `backend/app/services/stateful_detector.py`, this engine detects coordinated vertical reconnaissance across time windows that stateless rules cannot identify.

- **Scope**: Focuses strictly on **vertical port scans** (a single source IP probing multiple distinct destination ports on a single destination IP). Horizontal sweeps (probing one port across a subnet) and distributed scans (multiple sources probing one target) are outside the current correlation scope.
- **Correlation Grouping**: Flows are grouped strictly by `(source_ip, destination_ip)`.
- **Sliding Window & Thresholds**:
  - Window Duration: `window_seconds = 60.0` seconds.
  - Port Threshold: `min_distinct_ports = 5` unique destination ports.
  - Probe Flow Filter: Only flows with `avg_bytes_per_packet <= 1000.0` qualify as scan probes, preventing bulk file transfers or web sessions from triggering false positives.
- **Window Merging Mechanics**:
  When a continuous port scan spans multiple overlapping 60-second observation intervals, adjacent qualifying windows are merged into a single consolidated incident **if and only if they share participating probe flows** (`flow_ids.intersection`). This prevents a sustained 120-second scan from generating fragmented, redundant alerts while strictly preventing two distinct scan bursts (separated in time without shared flows) from being erroneously linked.
- **Cross-Batch Statefulness & Lookback**:
  Network flows frequently arrive in separate API batches. To maintain continuity:
  1. The detector inspects the earliest timestamp $t_{\min}$ of an incoming batch and queries historical flows from SQLite within $[t_{\min} - 60\text{s}, t_{\min}]$.
  2. Historical flows serve purely as **correlation context** and are never re-inserted or duplicated in database queries.
  3. If an existing `Port Scan` alert for `(source_ip, destination_ip)` is already active within the window, the engine **updates the existing alert in-place** (refreshing port counts, target lists, and timestamps) rather than emitting duplicate alerts.
- **Confidence Assessment**:
  - `HIGH`: $\ge 50\%$ of the participating probe flows carry the `SYN` flag.
  - `MEDIUM`: $< 50\%$ of probe flows carry `SYN` (e.g. UDP probes or connect sweeps).

---

## 6. Technology Stack

### Backend
- **Python 3.10+** (Tested and verified on Python 3.10 through 3.14)
- **FastAPI**: Asynchronous web framework for high-throughput REST APIs.
- **Uvicorn**: ASGI web server implementation.
- **Pydantic v2**: High-performance data validation and schema enforcement.
- **SQLAlchemy 2.0**: Object-Relational Mapping (ORM) and connection pooling.
- **SQLite**: Self-contained relational database stored at `backend/data/nids.db`.

### Machine Learning & Data Processing
- **Scikit-Learn**: Isolation Forest unsupervised anomaly detection.
- **NumPy**: Vectorized numerical calculations and feature scaling.
- **Joblib**: Persistent model artifact serialization.

### Frontend
- **React 18**: Component-based UI library.
- **Vite**: Ultra-fast frontend build tooling and HMR dev server.
- **Tailwind CSS**: Utility-first styling for dark-themed SOC aesthetics.
- **Lucide React**: Modern icon set for cybersecurity dashboards.
- **Recharts**: Responsive SVG charting library (Donut, Bar, Area charts).

### Testing & Quality Assurance
- **Pytest**: Automated test suite with 43 unit and integration tests.
- **HTTPX**: In-process asynchronous HTTP client for FastAPI integration testing.

---

## 7. Windows Installation and Setup

Follow these step-by-step instructions in **Windows PowerShell** to set up and run the project locally.

### Prerequisites
- **Python**: Version 3.10 or higher installed and added to `PATH`.
- **Node.js**: Version 18 or higher with `npm` installed and added to `PATH`.
- **Git**: Installed for version control.

### Step 1: Clone the Repository
```powershell
git clone https://github.com/your-username/nids.git
cd nids
```

### Step 2: Configure the Backend Environment
From the project root directory (`D:\NIDS`):

```powershell
# 1. Create a Python virtual environment
python -m venv venv

# 2. Activate the virtual environment
.\venv\Scripts\Activate.ps1

# 3. Upgrade pip
python -m pip install --upgrade pip

# 4. Install backend dependencies
pip install -r backend/requirements.txt
```

> [!TIP]
> If PowerShell blocks script execution, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned` in your terminal session before activating the virtual environment.

### Step 3: Start the Backend Server
```powershell
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
- **API Base URL**: `http://127.0.0.1:8000`
- **Interactive Swagger UI**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **OpenAPI JSON Specification**: [http://127.0.0.1:8000/openapi.json](http://127.0.0.1:8000/openapi.json)

### Step 4: Configure and Start the React Frontend
Open a **new** Windows PowerShell window, navigate to the `frontend` folder, and start Vite:

```powershell
cd D:\NIDS\frontend

# 1. Install frontend packages
npm install

# 2. Start the development server
npm run dev
```
- **SOC Dashboard URL**: [http://localhost:5173](http://localhost:5173)

---

## 8. Configuration

### Database Settings
- **Default Database Path**: `backend/data/nids.db`
- **Environment Variable**: `NIDS_DATABASE_URL`
- By default, `backend/app/config.py` creates the SQLite database inside `backend/data/`. To specify a different SQLite path or connect to a PostgreSQL database:
  ```powershell
  $env:NIDS_DATABASE_URL="sqlite:///D:/custom_path/nids.db"
  ```

### CORS Configuration
Cross-Origin Resource Sharing (CORS) is configured directly in `backend/app/main.py`. The backend permits requests from a hardcoded local development whitelist:
```python
ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]
```

### Frontend API URL
The frontend connects to `http://127.0.0.1:8000` by default. You can configure this via `frontend/.env`:
```env
VITE_API_BASE_URL=http://127.0.0.1:8000
```

### Stateful Detector Defaults
Defined in `backend/app/services/stateful_detector.py`:
- `window_seconds`: `60.0` (rolling evaluation window)
- `min_distinct_ports`: `5` (minimum destination ports to trigger a vertical port scan alert)

---

## 9. Backend API Endpoints

| Method | Path | Summary | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/health` | System Health Check | Returns backend status, SQLite database connectivity, and ML model loaded flag. |
| `GET` | `/traffic` | Query Network Flows | Returns paginated flows with filtering by `protocol` (`TCP`, `UDP`, `ICMP`) and `is_suspicious` (`true`/`false`). |
| `GET` | `/alerts` | Query Security Alerts | Returns paginated security alerts with filtering by `severity` (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) and `is_resolved`. |
| `GET` | `/stats` | Aggregate SOC Statistics | Computes total flow counts, normal vs. suspicious distribution, alert severity breakdown, and protocol shares. |
| `POST` | `/simulate` | Ingest Synthetic Traffic | Generates and processes a batch of synthetic flows with configurable volume and anomaly ratio. |
| `POST` | `/upload-csv` | Ingest Flow CSV File | Validates, sanitizes, and runs detection on uploaded CSV flow logs (up to 5 MB, 5,000 rows). |

### Example API Requests

#### 1. System Health Check
```powershell
curl http://127.0.0.1:8000/health
```
```json
{
  "status": "healthy",
  "model_loaded": true,
  "database_status": "connected",
  "timestamp": "2026-11-24T05:45:00.123456Z",
  "version": "0.1.0"
}
```

#### 2. Run Synthetic Traffic Simulation
```powershell
curl -X POST http://127.0.0.1:8000/simulate `
  -H "Content-Type: application/json" `
  -d '{"total_flows": 25, "anomaly_ratio": 0.20}'
```
```json
{
  "status": "success",
  "generated_flows": 25,
  "anomaly_ratio": 0.2,
  "anomalies_detected": 5,
  "alerts_created": 3,
  "processed_at": "2026-11-24T05:46:12.789012Z"
}
```

#### 3. Upload a CSV Dataset
```powershell
curl -X POST http://127.0.0.1:8000/upload-csv `
  -F "file=@backend/data/samples/sample_network_traffic.csv"
```
```json
{
  "status": "success",
  "filename": "sample_network_traffic.csv",
  "rows_processed": 10,
  "anomalies_detected": 4,
  "alerts_created": 3,
  "processed_at": "2026-11-24T05:47:33.456789Z"
}
```

---

## 10. React SOC Dashboard Features

The frontend application provides a full-featured dark-mode SOC dashboard tailored for security analysts:

- **Automated Telemetry Polling**: Polls the `/stats` endpoint every **15 seconds** to refresh dashboard counters and charts on each polling interval.
- **Header Threat Indicator**:
  - `Threat Index`: Header badge displaying an aggregate percentage calculated as `(suspicious_flows / total_flows) * 100` with dynamic severity color-coding (Green < 10%, Amber 10–30%, Red ≥ 30%).
- **Primary KPI Cards Grid**:
  - `Total Flows Inspected`: Total count of network flow records processed and stored in the database.
  - `Normal Traffic`: Count and baseline compliance percentage of flows verifying as normal.
  - `Suspicious Activity`: Total count of flows flagged by ML anomaly scores or rule heuristic deviations.
  - `Security Alerts`: Total actionable incident records generated for operator investigation.
- **Dynamic Visualizations (Recharts)**:
  - *Protocol Distribution*: Donut chart illustrating TCP vs. UDP vs. ICMP traffic volume.
  - *Traffic Health Split*: Donut chart comparing normal vs. suspicious flow ratios.
  - *Alerts by Severity*: Categorical bar chart displaying alert distributions across `LOW`, `MEDIUM`, `HIGH`, and `CRITICAL`.
  - *Anomaly Score Timeline*: Area chart tracking anomaly score trajectories across recent flows.
- **Network Traffic Log Table**:
  - View detailed flow records with timestamps, IPs, ports, protocols, packet/byte counts, and calculated anomaly scores.
  - Interactive filters: Protocol (`ALL`, `TCP`, `UDP`, `ICMP`) and Suspicious filter (`ALL`, `Suspicious Only`, `Normal Only`).
  - Server-side pagination (50 flows per page).
- **Security Alerts Management**:
  - Triage alerts by Category (`SYN Probe`, `SYN Flood Pattern`, `Unusual Large Data Transfer`, `Port Scan`).
  - Filter by Severity (`ALL`, `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) and Resolution status.
  - Detailed modal view displaying participating source/dest IPs, port ranges, and confidence metrics.
- **Interactive Simulation Modal**:
  - Trigger synthetic traffic bursts directly from the UI with interactive sliders for `total_flows` (1 to 100) and `anomaly_ratio` (0.0 to 1.0).
- **CSV Ingestion Dropzone**:
  - Drag-and-drop CSV upload with instant client-side size checks, schema error warnings, and processing summaries.

---

## 11. CSV Dataset Format

The CSV ingestion endpoint (`POST /upload-csv`) accepts standard comma-separated network flow records.

### Constraints
- **File Extension**: Must end with `.csv`.
- **File Size**: Maximum `5 MB`.
- **Row Limit**: Maximum `5,000` rows per file.

### Column Specifications

| Column | Type | Required | Default | Allowed Values / Constraints |
| :--- | :--- | :--- | :--- | :--- |
| `source_ip` | String | **Yes** | — | Valid IPv4 address string (e.g. `192.168.1.100`) |
| `destination_ip` | String | **Yes** | — | Valid IPv4 address string (e.g. `10.0.0.10`) |
| `destination_port` | Integer | **Yes** | — | Integer between `0` and `65535` |
| `protocol` | String | **Yes** | — | `TCP`, `UDP`, or `ICMP` (case-insensitive) |
| `source_port` | Integer | No | `50000` | Integer between `0` and `65535` |
| `packet_count` | Integer | No | `1` | Integer $\ge 1$ |
| `byte_count` | Integer | No | `64` | Integer $\ge 1$ |
| `duration` | Float | No | `0.0` | Float $\ge 0.0$ (seconds) |
| `tcp_flags` | String | No | `NONE` | Comma or space separated TCP flags (`SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`, `NONE`) |
| `simulation_label` | String | No | `CSV_UPLOAD` | Stored as metadata for evaluation; **never** exposed to the ML model |

### Sample CSV Snippet
```csv
source_ip,destination_ip,source_port,destination_port,protocol,packet_count,byte_count,duration,tcp_flags
192.168.1.101,10.0.0.10,51234,443,TCP,45,28400,2.15,ACK
198.51.100.99,10.0.0.10,40112,22,TCP,1,48,0.005,SYN
203.0.113.120,10.0.0.10,61223,80,TCP,2500,120000,0.12,SYN
192.168.1.115,203.0.113.78,59821,8080,TCP,8500,12500000,45.2,ACK
192.168.1.102,10.0.0.5,52341,53,UDP,2,148,0.02,NONE
```

Pre-packaged sample datasets are available in `backend/data/samples/`:
- `sample_network_traffic.csv`: Balanced dataset containing benign traffic, SYN scans, floods, and large transfers.
- `malformed_traffic.csv`: Test dataset with invalid ports and missing columns for validating error handling.

---

## 12. Testing and Synthetic Benchmark

### Automated Test Suite
The project includes a comprehensive suite of **43 automated unit and integration tests** verifying all database models, traffic generation functions, feature extractors, machine learning classifiers, stateful correlation windows, and FastAPI endpoints.

Run the full test suite using PowerShell:
```powershell
python -m pytest backend/tests -v
```

All 43 tests execute against in-memory SQLite instances (`StaticPool`) ensuring complete test isolation with zero residual test data written to disk.

```
backend/tests/test_api_routes.py ......................... [ 58%]
backend/tests/test_database.py ....                       [ 67%]
backend/tests/test_generator.py ..                        [ 72%]
backend/tests/test_ml_detector.py ....                    [ 81%]
backend/tests/test_stateful_detector.py ........          [100%]
============================== 43 passed in 1.48s ==============================
```

### Stateful Evaluation Benchmark
A specialized evaluation script benchmarks the detection accuracy of the stateful correlation engine against an 830-flow synthetic ground-truth dataset.

Run the evaluation script:
```powershell
python -m backend.app.services.evaluate_stateful
```

#### Benchmark Dataset Composition (830 Total Flows):
- **600 Normal Baseline Flows**: Web browsing, DNS lookups, SSH administration, and streaming traffic.
- **100 SYN Flood Flows**: Rapid bursts of small SYN packets.
- **50 Large Data Transfers**: Bulk payload transfers ($> 4\text{ MB}$).
- **20 Isolated SYN Probes**: Single-packet scans targeting isolated ports ($< 5$ ports per source IP).
- **60 Vertical Port Scan Flows**: 5 separate scan campaigns targeting 8, 10, 12, 14, and 16 unique destination ports.

#### Benchmark Validation Results:
- **Precision**: `1.0000` (100.00%) — zero false positives on isolated single-port probes or background flows.
- **Recall**: `1.0000` (100.00%) — verifies complete detection across the 5 synthetic multi-port scan campaigns tested.
- **F1-Score**: `1.0000` across the synthetic evaluation corpus.

> [!IMPORTANT]
> **Synthetic Benchmark Notice**: These evaluation metrics are measured exclusively against a controlled synthetic dataset generated by `SyntheticTrafficGenerator`. They serve strictly to validate stateful correlation logic, threshold boundaries, and window-merging mechanics under unit testing conditions. They do **not** represent real-world detection efficacy or operational performance on live networks, where packet loss, transmission jitter, advanced evasion tactics, and diverse unmodeled background noise exist.

---

## 13. Limitations and Ethical Scope

### Ethical Scope & Permitted Use
This software is developed strictly for **educational, academic research, and defensive SOC training purposes**. It is designed to assist analysts and engineers in understanding how network flows are structured, how machine learning isolates outliers, and how signature rules identify malicious patterns.
- Do **not** attempt to adapt this code for offensive packet injection, unauthorized scanning, or network disruption.
- The software includes no attack exploitation capabilities.

### Technical Limitations
1. **Flow-Level vs. Packet-Level Inspection**: The system inspects structured flow summary metadata (packet counts, byte volumes, durations, protocol flags) rather than raw packet payloads. Deep Packet Inspection (DPI) of encrypted TLS payloads or application-layer commands is not supported.
2. **Synthetic and CSV Processing Only**: The system processes synthetic traffic generated by its internal simulator or structured CSV logs uploaded by users. It does not bind to network interfaces in promiscuous mode or execute live packet capture.
3. **Statistical Outlier Nature of Isolation Forest**: Isolation Forest detects statistical divergence from training baselines. High anomaly scores reflect unusual metrics—not verified malicious intent. Normal administrative tasks (e.g. large system backups or network stress testing) will naturally yield elevated anomaly scores.
4. **Advisory Heuristic Classifications**: Stateless rule alerts (such as `Unusual Large Data Transfer`) are advisory indicators based on metric thresholds and do not constitute legal proof of unauthorized data exfiltration.
5. **Vertical Port Scan Scope**: Stateful correlation currently identifies vertical scans (single source IP targeting multiple ports on one destination IP). Horizontal sweeps (targeting the same port across a `/24` subnet) and distributed port scans (botnet sweeps from multiple source IPs) are outside the current correlation window's grouping logic.

---

## 14. Project Directory Structure

```
D:\NIDS
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   ├── dependencies.py          # Database & ML model injection
│   │   │   └── routes.py                # FastAPI route endpoints
│   │   ├── models/
│   │   │   └── flow_models.py           # TrafficFlow & SecurityAlert ORM models
│   │   ├── schemas/
│   │   │   └── flow_schemas.py          # Pydantic schemas for flows, alerts, stats, & CSV
│   │   ├── ml/
│   │   │   ├── detector.py              # NetworkAnomalyDetector Isolation Forest wrapper
│   │   │   ├── evaluator.py             # ML classification & evaluation utilities
│   │   │   ├── feature_pipeline.py      # 13-feature extraction pipeline
│   │   │   ├── rule_classifier.py       # Stateless heuristic signature rules
│   │   │   └── model_store/             # Serialized .joblib model artifacts
│   │   ├── services/
│   │   │   ├── csv_service.py           # CSV validation & parsing service
│   │   │   ├── evaluate_stateful.py     # 830-flow stateful benchmark runner
│   │   │   ├── flow_processor.py        # Tri-engine pipeline coordinator
│   │   │   ├── stateful_detector.py     # Rolling 60s port scan detector
│   │   │   ├── stats_service.py         # SOC dashboard metrics aggregator
│   │   │   └── traffic_generator.py     # Stochastic synthetic flow generator
│   │   ├── config.py                    # Application settings & database path
│   │   ├── database.py                  # SQLAlchemy engine & sessionmaker
│   │   └── main.py                      # FastAPI app instance & CORS setup
│   ├── data/
│   │   ├── nids.db                      # Local SQLite database file
│   │   └── samples/                     # Sample CSV traffic datasets
│   │       ├── malformed_traffic.csv    # Negative test dataset for validation
│   │       └── sample_network_traffic.csv # Baseline sample dataset
│   ├── tests/
│   │   ├── conftest.py                  # Pytest fixtures & in-memory SQLite
│   │   ├── test_api_routes.py           # REST API endpoint tests
│   │   ├── test_database.py             # SQLAlchemy model & query tests
│   │   ├── test_generator.py            # Synthetic traffic generation tests
│   │   ├── test_ml_detector.py          # ML scoring & rule classifier tests
│   │   └── test_stateful_detector.py    # Sliding window & correlation tests
│   └── requirements.txt                 # Backend Python package requirements
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── charts/                  # ActivityTimeline, ProtocolChart, SeverityChart, ThreatSplitChart
│   │   │   ├── tables/                  # AlertsTable, RecentAlertsTable, TrafficTable
│   │   │   ├── MetricCard.jsx           # Reusable KPI metric card component
│   │   │   ├── Navbar.jsx               # Header navigation & system status pills
│   │   │   ├── Sidebar.jsx              # Navigation sidebar
│   │   │   └── SimulationModal.jsx      # Synthetic traffic generation modal
│   │   ├── pages/
│   │   │   ├── AlertsPage.jsx           # Security alerts triage page
│   │   │   ├── DashboardPage.jsx        # SOC dashboard overview page
│   │   │   ├── TrafficPage.jsx          # Network traffic flow explorer
│   │   │   └── UploadPage.jsx           # CSV dataset upload page
│   │   ├── services/
│   │   │   └── api.js                   # Axios API client & base URL
│   │   ├── App.jsx                      # React router & layout root
│   │   ├── index.css                    # Tailwind CSS directives
│   │   └── main.jsx                     # Vite entry point
│   ├── package.json                     # Frontend npm package dependencies
│   ├── tailwind.config.js               # Tailwind CSS theme configuration
│   └── vite.config.js                   # Vite dev server configuration
└── README.md                            # Comprehensive project documentation
```
