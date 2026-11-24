# NIDS — System Architecture & Data Flow

This document details the complete end-to-end architecture, component orchestration, and data flow of the Network Intrusion Detection System (NIDS).

---

## Architecture Diagram

```mermaid
flowchart TD
    subgraph FRONTEND["1. Presentation Layer (React + Vite)"]
        UI["React SOC Dashboard<br/>(Tailwind CSS + Recharts)"]
        VIEWS["Dashboard Metrics · Charts · Traffic Explorer<br/>Alerts Management · Simulation & Upload Modals"]
        UI --- VIEWS
    end

    subgraph API["2. API Layer (FastAPI REST API)"]
        APP["FastAPI Application"]
        READ_API["Read Endpoints<br/>GET /health · /traffic · /alerts · /stats"]
        INGEST_API["Ingestion Endpoints<br/>POST /simulate · POST /upload-csv"]
        APP --- READ_API
        APP --- INGEST_API
    end

    subgraph INGEST["3. Traffic Ingestion Pipeline"]
        GEN["Synthetic Traffic Generator<br/>(SyntheticTrafficGenerator)"]
        CSV_VAL["CSV Validation & Sanitization<br/>(parse_csv_stream)"]
    end

    subgraph CORE["4. Orchestration Layer"]
        FP["Flow Processor<br/>(process_and_store_flows)<br/>★ Central Orchestrator"]
    end

    subgraph DETECT["5. Detection Engines"]
        subgraph ML_PATH["Machine Learning Detection Engine"]
            NAD["Network Anomaly Detector<br/>(NetworkAnomalyDetector.predict)"]
            FE["Feature Engineering Pipeline<br/>(FeaturePipeline: 13 Features)"]
            IF["Isolation Forest Model<br/>(Scikit-Learn IsolationForest)"]
        end
        RULES["Stateless Rule Classifier<br/>(RuleBasedClassifier.classify_flow)"]
        STATEFUL["Stateful Port Scan Detector<br/>(StatefulPortScanDetector: 60s Window)"]
    end

    subgraph STORAGE["6. Data Persistence Layer (SQLite Database)"]
        DB[("SQLite Database<br/>backend/data/nids.db")]
        FLOW_TBL["TrafficFlow Records<br/>(Flow metrics, Anomaly score, Source)"]
        ALERT_TBL["SecurityAlert Records<br/>(Port scan, SYN flood, Data burst)"]
        DB --- FLOW_TBL
        DB --- ALERT_TBL
    end

    %% 1. Frontend to API Communication (Request & Response)
    UI -- "1a. Poll Stats (15s) / Query Flows & Alerts (HTTP GET)" --> READ_API
    READ_API -. "1b. Telemetry & Log JSON Responses" .-> UI

    UI -- "2a. Trigger Simulation / Upload CSV (HTTP POST)" --> INGEST_API
    INGEST_API -. "2b. Ingestion Result Summary JSON" .-> UI

    %% 2. API Ingestion Dispatch
    INGEST_API -- "POST /simulate: Invoke with (count, ratio)" --> GEN
    GEN -- "Generated Raw Flows" --> FP

    INGEST_API -- "POST /upload-csv: Multipart File Stream" --> CSV_VAL
    CSV_VAL -- "Validated Raw Flows (<= 5,000 rows)" --> FP

    %% 3. Database Read Operations (FastAPI Read Endpoints)
    READ_API -- "Query ORM Models (Read Only)" --> DB
    DB -. "Queried Rows (Flows, Alerts, Stats)" .-> READ_API

    %% 4. Historical Context Lookup for Stateful Detection
    FP -- "Query Historical Flows [t_min - 60s, t_min] (Read)" --> DB
    DB -. "Historical Flows Context" .-> FP
    FP -- "Historical + Current Raw Flows" --> STATEFUL

    %% 5. Complete Machine Learning Call Chain
    FP -- "Dispatch Raw Flows to predict()" --> NAD
    NAD -- "Extract Features" --> FE
    FE -- "13-Feature Vectors" --> IF
    IF -- "Raw Decision Scores" --> NAD
    NAD -- "Anomaly Scores & Outlier Flags" --> FP

    %% 6. Stateless Rule Classifier Path (Raw Flows)
    FP -- "Current Raw Flows" --> RULES
    RULES -- "Heuristic Signatures & Severities" --> FP

    %% 7. Stateful Port Scan Detection Return
    STATEFUL -- "Correlated Port Scan Incidents & Windows" --> FP

    %% 8. Database Write Operations (Sole Pipeline Persistence Writer)
    FP -- "Atomic Write: Persist Flows & Alerts (db.add_all / commit)" --> DB

    classDef frontend fill:#fce7f3,stroke:#db2777,color:#831843
    classDef api fill:#ede9fe,stroke:#7c3aed,color:#4c1d95
    classDef ingest fill:#dbeafe,stroke:#2563eb,color:#172554
    classDef core fill:#e0e7ff,stroke:#4f46e5,color:#312e81
    classDef detect fill:#d1fae5,stroke:#059669,color:#064e3b
    classDef storage fill:#fef3c7,stroke:#d97706,color:#78350f

    class UI,VIEWS frontend
    class APP,READ_API,INGEST_API api
    class GEN,CSV_VAL ingest
    class FP core
    class NAD,FE,IF,RULES,STATEFUL detect
    class DB,FLOW_TBL,ALERT_TBL storage
```

---

## Detailed Data Flow & Component Execution Walkthrough

### 1. Presentation & API Layer Interaction
- **Client-Side Request Initiation**: The React SOC Dashboard (`UI`) communicates with FastAPI (`APP`) exclusively via client-initiated HTTP requests (using Axios in `frontend/src/services/api.js`).
- **Telemetry Polling (Read Flow)**: Every 15 seconds, the dashboard issues an HTTP GET to `/stats` to refresh header KPIs and chart data. When the operator navigates to the Traffic Explorer or Alerts page, the frontend issues paginated GET requests to `/traffic` and `/alerts`.
- **Database Reads**: The read endpoints query SQLite (`backend/data/nids.db`) using SQLAlchemy ORM sessions (`Depends(get_db)`) and return serialized JSON payloads to the frontend.

### 2. Ingestion Triggering & Flow Sanitization
- **Simulation Ingestion**: When the operator clicks "Simulate Traffic" in the UI modal, the frontend issues an HTTP POST to `/simulate` with `total_flows` and `anomaly_ratio`. The endpoint invokes `SyntheticTrafficGenerator.generate_batch()` and forwards the generated raw flow dictionaries to the `Flow Processor`.
- **CSV Ingestion**: When the operator uploads a file, the frontend issues an HTTP POST with multipart form-data to `/upload-csv`. The endpoint routes the byte stream through `parse_csv_stream()` in `csv_service.py`, which validates required headers (`source_ip`, `destination_ip`, `destination_port`, `protocol`), enforces size boundaries ($\le 5\text{ MB}$, $\le 5,000\text{ rows}$), validates IP formatting, and forwards sanitized raw flow dictionaries to the `Flow Processor`.

### 3. Orchestration by Flow Processor
`process_and_store_flows()` in `backend/app/services/flow_processor.py` acts as the **central orchestrator** of the detection and storage pipeline:

1. **Historical Context Retrieval (Read)**:
   - Identifies the earliest timestamp $t_{\min}$ of the incoming batch.
   - Executes a bounded read query on SQLite: `TrafficFlow.timestamp >= (t_min - 60s)` and `TrafficFlow.timestamp <= t_min`.
   - Converts recent entities into historical dictionaries to establish correlation context across batch boundaries.
2. **Stateful Detection Dispatch**:
   - Passes incoming raw flows and historical context to `StatefulPortScanDetector.analyze_flows()`.
   - The detector operates strictly on raw flow metadata (`source_ip`, `destination_ip`, `destination_port`, `timestamp`, `byte_count`, `packet_count`) without touching engineered feature vectors.
   - Returns consolidated vertical port scan incidents.
3. **Machine Learning Dispatch (Complete ML Call Chain)**:
   - `Flow Processor` passes incoming raw flows to `NetworkAnomalyDetector.predict()`.
   - Inside the detector, `FeaturePipeline.transform()` extracts the 13 numerical and behavioral features (`packet_count`, `byte_count`, `duration`, `packet_rate`, `byte_rate`, `avg_packet_size`, protocol one-hot flags, TCP flags, `is_well_known_port`, and `destination_port_scaled`).
   - The resulting 13-dimensional NumPy array is passed to the Scikit-Learn `IsolationForest.decision_function()` model to compute raw decision scores.
   - `NetworkAnomalyDetector` maps the raw scores to normalized anomaly scores $[0.0, 1.0]$ via a sigmoid transformation, evaluates outlier flags (`is_suspicious`), and returns the prediction list to `Flow Processor`.
4. **Stateless Rule Dispatch**:
   - Evaluates each raw flow dictionary individually against `RuleBasedClassifier.classify_flow()` for immediate signature attribution (`SYN Probe`, `SYN Flood Pattern`, `Unusual Large Data Transfer`).
   - Evaluates raw flow keys directly, completely independent of the ML feature pipeline.
5. **Combined Attribution & Deduplication**:
   - Correlates verdicts across all three engines (`is_suspicious = ml_suspicious or rule_triggered or is_stateful_scan`).
   - Assigns detection source attribution (`ML_ISOLATION_FOREST`, `RULE_HEURISTIC`, `STATEFUL_CORRELATION`, or `HYBRID`).
   - For stateful port scan alerts, checks whether an active alert exists in SQLite for the `(source_ip, destination_ip)` pair within the sliding window. If found, updates the alert in-place; otherwise, creates a new `SecurityAlert` linked to the triggering flow.
6. **Atomic Persistence (Write)**:
   - `Flow Processor` is the **only component in the traffic-processing pipeline that persists `TrafficFlow` and `SecurityAlert` records** to SQLite (detection engines do not touch the database).
   - Executes `db.add_all(flows_to_insert)`, `db.add_all(all_new_alerts)`, and `db.commit()` in a single atomic transaction.
   - Returns the processing summary (flow counts, anomalies detected, alerts created) to the FastAPI endpoint, which returns it as JSON to the React frontend.
