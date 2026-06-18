# AegisAI – Autonomous Zero-Day Threat Investigation and Explainability Engine

## 1. Executive Summary

AegisAI is a proof-of-concept security analytics pipeline that ingests Windows Sysmon telemetry, detects statistically anomalous behavior using a deep learning autoencoder, reconstructs the anomaly into a human-readable incident timeline, and uses an LLM to generate a natural-language investigation report mapped to MITRE ATT&CK techniques with an associated risk score. The output is surfaced through a React/Tailwind dashboard for a SOC analyst.

The project is scoped intentionally as a **detection-assist and explainability layer**, not a production EDR/XDR replacement. Within a 2-month internship timeframe, the realistic goal is:

- A working offline/batch pipeline (not real-time streaming) that processes exported Sysmon logs.
- An autoencoder trained on a public or synthetically generated "benign" dataset (e.g., a subset of Sysmon logs from a lab VM) to flag reconstruction-error anomalies.
- A rule-assisted MITRE mapping (LLM-assisted, not purely LLM-hallucinated) using a curated lookup table to keep mappings grounded.
- A risk score combining model confidence, technique severity, and asset criticality (static, configurable).
- A dashboard showing timeline, anomaly score, LLM explanation, and ATT&CK tags.

**Explicitly out of scope** for this internship (called out so expectations are calibrated): real-time log streaming at enterprise scale, multi-host correlation across a live network, active response/remediation actions, and production-grade model retraining pipelines. These are noted as "Future Work" in the final report.

---

## 2. System Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                              CLIENT LAYER                                   │
│   React + TailwindCSS SPA  (Dashboard, Timeline View, Incident Detail)      │
└───────────────────────────────────┬────────────────────────────────────────┘
                                     │ REST (JSON)
┌───────────────────────────────────▼────────────────────────────────────────┐
│                         APPLICATION LAYER (FastAPI)                         │
│  ┌───────────────┐ ┌────────────────┐ ┌───────────────┐ ┌────────────────┐ │
│  │ Ingestion API │ │ Detection API   │ │ Investigation │ │ Dashboard/     │ │
│  │ (log upload)  │ │ (run inference) │ │ API (LLM)     │ │ Reporting API  │ │
│  └───────┬───────┘ └────────┬────────┘ └───────┬───────┘ └───────┬────────┘ │
└──────────┼──────────────────┼──────────────────┼─────────────────┼─────────┘
           │                  │                  │                 │
┌──────────▼──────────────────▼──────────────────▼─────────────────▼─────────┐
│                          PROCESSING / ML LAYER                              │
│  ┌─────────────────┐  ┌────────────────────┐  ┌────────────────────────┐   │
│  │ Feature                     │  │ TensorFlow                      │  │ MITRE Mapping Engine                    │
│  │ Engineering                 │→ │ Autoencoder                     │→ │ (lookup table +                         │
│  │ (pandas/sklearn)            │  │ (anomaly scoring)               │  │ LLM-assisted reasoning)                 │
│  │ → processed_events          │  │                                 │  │                                         │
│  └─────────────────┘  └─────────┬───────────┘  └───────────┬────────────┘   │
│                                  │                          │                │
│                       ┌──────────▼───────────┐   ┌──────────▼───────────┐   │
│                       │ Timeline Builder      │                │             OpenAI API             │   │
│                       │ (event correlation,   │            ──→│            (Investigation       │   │
│                       │ session windowing)    │   │ narrative generation)│   │
│                       └──────────┬────────────┘   └──────────┬───────────┘   │
│                                  │                            │              │
│                       ┌──────────▼────────────────────────────▼──────────┐   │
│                       │ Risk Scoring Module (weighted scoring function)  │   │
│                       └─────────────────────────┬─────────────────────────┘ │
└─────────────────────────────────────────────────┼───────────────────────────┘
                                                    │
┌───────────────────────────────────────────────────▼─────────────────────────┐
│                              DATA LAYER                                      │
│   MongoDB  (raw_logs, processed_events, anomalies, incidents, investigations,       │
│             attack_mappings, risk_scores, model_metadata, assets)                   │
│   Local Disk / Docker Volume (trained .h5/.keras model artifacts)            │
└────────────────────────────────────────────────────────────────────────────┘

           All services containerized via Docker Compose:
           [react-frontend] [fastapi-backend] [mongodb] [model-worker]
```

**Key architectural decisions:**

- **Batch-oriented, not streaming**: Sysmon logs are exported (EVTX → JSON/CSV) and uploaded/ingested in batches. This avoids needing Kafka/streaming infra, which is unrealistic for 2 months.
- **Autoencoder, not supervised classifier**: Since labeled zero-day attack data doesn't exist, unsupervised anomaly detection (reconstruction error thresholding) is the only honest approach.
- **LLM is an explainability layer, not a detector**: The autoencoder + rule-based MITRE lookup do the actual detection/mapping; the LLM's job is to turn structured findings into an analyst-readable narrative. This avoids over-claiming LLM capability and keeps mappings auditable.
- **Single FastAPI monolith with internal module separation** (not microservices) — appropriate for intern team size and timeline; structured so it *could* be split later.
- Architecture Note — MITRE Local Cache
MITRE ATT&CK reference data is stored locally in attack_lookup.json to avoid external API dependencies and ensure reliable offline demonstrations.

The MITRE Mapping Engine reads exclusively from this local cache rather than querying the live MITRE ATT&CK API/STIX feed at runtime.
---

## 3. Data Flow

**Stage 1 — Ingestion**
Sysmon EVTX logs exported → converted to structured JSON/CSV → uploaded via API → stored in `raw_logs` with ingestion metadata (host, timestamp range, source file).

**Stage 2 — Feature Engineering**
Raw event records (Event ID 1/3/7/11/13 etc.) parsed → features extracted: process creation frequency, parent-child process anomalies, network connection counts, registry/file write patterns, command-line entropy, time-of-day buckets → numerical feature vectors stored in processed_events, linked to raw_logs via reference ID.

**Stage 3 — Autoencoder Anomaly Detection**
Feature vectors (from processed_events) passed through pretrained TensorFlow autoencoder → reconstruction error computed per event/session window → error compared against a learned threshold (e.g., 95th/99th percentile of training reconstruction error) → events flagged anomalous are written to anomalies with score.

**Stage 4 — Incident Timeline Builder**
Anomalous events grouped by host + time-window (e.g., 10–30 min sliding window) and correlated by process lineage → ordered into a chronological incident timeline (process spawn → network connection → file write, etc.) → stored in `incidents`.

**Stage 5 — LLM Investigation Engine**
Incident timeline (structured JSON) sent to OpenAI API with a system prompt instructing it to: summarize the sequence, hypothesize intent, flag suspicious patterns in plain English → response stored in `investigations`, linked to `incidents`.

**Stage 6 — MITRE ATT&CK Mapping**
Structured timeline features (e.g., "process injection," "LOLBin usage," "outbound to rare IP") matched against a curated local MITRE technique lookup table; LLM is given the candidate techniques and timeline to select/justify the best-fit tactic/technique IDs (kept grounded — LLM ranks/explains, doesn't invent technique IDs) → stored in `attack_mappings`.

**Stage 7 — Risk Scoring**
Weighted function combines: anomaly score (from autoencoder), technique severity weight (from MITRE mapping), and asset/host criticality (static config value) → produces a 0–100 risk score and Low/Medium/High/Critical label → stored in `risk_scores`.

**Stage 8 — Dashboard**
React frontend polls/fetches incidents list (sortable by risk score), incident detail view renders timeline, LLM narrative, MITRE tags, and risk breakdown.

---

## 4. Folder Structure

```
aegisai/
├── docker-compose.yml
├── .env.example
├── README.md
│
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── app/
│   │   ├── main.py                      # FastAPI app entrypoint
│   │   ├── config.py                    # env config, model paths, thresholds
│   │   ├── api/
│   │   │   ├── ingestion_routes.py
│   │   │   ├── detection_routes.py
│   │   │   ├── investigation_routes.py
│   │   │   ├── incident_routes.py
│   │   │   └── dashboard_routes.py
│   │   ├── core/
│   │   │   ├── feature_engineering/
│   │   │   │   ├── parser.py            # EVTX/JSON Sysmon parsing
│   │   │   │   └── feature_builder.py
│   │   │   ├── ml/
│   │   │   │   ├── autoencoder_model.py
│   │   │   │   ├── train.py             # offline training script
│   │   │   │   └── inference.py
│   │   │   ├── timeline/
│   │   │   │   └── timeline_builder.py
│   │   │   ├── llm/
│   │   │   │   ├── prompts/
│   │   │   │   │   ├── investigation_prompt.txt
│   │   │   │   │   └── mitre_mapping_prompt.txt
│   │   │   │   └── llm_client.py
│   │   │   ├── mitre/
│   │   │   │   ├── attack_lookup.json   # curated technique reference table
│   │   │   │   └── mapper.py
│   │   │   └── risk/
│   │   │       └── risk_scoring.py
│   │   ├── db/
│   │   │   ├── mongo_client.py
│   │   │   └── repositories/            # one per collection
│   │   ├── models/                      # Pydantic schemas
│   │   └── utils/
│   ├── models_artifacts/                # saved .keras model + scaler.pkl
│   └── tests/
│
├── frontend/
│   ├── Dockerfile
│   ├── package.json
│   ├── tailwind.config.js
│   └── src/
│       ├── pages/
│       │   ├── Dashboard.jsx
│       │   ├── IncidentDetail.jsx
│       │   └── UploadLogs.jsx
│       ├── components/
│       │   ├── TimelineView.jsx
│       │   ├── RiskBadge.jsx
│       │   ├── AttackMatrixTag.jsx
│       │   └── InvestigationNarrative.jsx
│       ├── api/
│       │   └── client.js
│       └── App.jsx
│
├── data/
│   ├── sample_sysmon_logs/              # lab-generated sample data
│   ├── training_dataset/                # benign baseline for autoencoder
│   └── demo_scenarios/                  # deterministic attack scenarios for
demos/testing
│       ├── powershell_attack.json
│       ├── credential_dumping.json
│       └── suspicious_network_beacon.json

│
└── notebooks/
    ├── 01_feature_exploration.ipynb
    ├── 02_autoencoder_training.ipynb
    └── 03_threshold_tuning.ipynb
```

---

## 5. MongoDB Collections

| Collection | Purpose | Key Fields |
|---|---|---|
| **raw_logs** | Stores ingested Sysmon event batches | `_id`, `host`, `source_file`, `event_id`, `timestamp`, `raw_event` (JSON), `ingested_at` |
| **processed_events** | Engineered feature vectors per event/session | `_id`, `raw_log_ref`, `host`, `window_start`, `window_end`, `feature_vector` (array), `feature_names` |
| **anomalies** | Autoencoder output | `_id`, `feature_ref`, `host`, `reconstruction_error`, `threshold_used`, `is_anomalous`, `model_version`, `detected_at` |
| **incidents** | Correlated timeline of related anomalous events | `_id`, `host`, `start_time`, `end_time`, `event_sequence` (ordered array of refs), `status` (new/reviewed/closed), `created_at` |
| **investigations** | LLM-generated narrative per incident | `_id`, `incident_ref`, `narrative_text`, `llm_model_used`, `prompt_version`, `confidence_score` (0.0–1.0), `generated_at` |
| **attack_mappings** | MITRE technique mapping per incident | `_id`, `incident_ref`, `tactic_id`, `technique_id`, `technique_name`, `confidence`, `severity_level` (Low/Medium/High/Critical), `justification_text` |
| **risk_scores** | Final computed risk per incident | `_id`, `incident_ref`, `anomaly_component`, `technique_severity_component`, `asset_criticality_component`, `final_score`, `risk_label` |
| **model_metadata** | Versioning/audit for trained models | `_id`, `model_version`, `training_date`, `training_data_summary`, `threshold_value`, `metrics` (loss, val_loss) |
| **assets** (config) | Static host criticality reference | `_id`, `hostname`, `criticality_level`, `owner_team` |

---
Field Notes

investigations.confidence_score
Represents confidence in the generated investigation narrative (0.0–1.0).

attack_mappings.confidence reflects confidence in the MITRE technique match.

attack_mappings.severity_level
Static severity classification (Low/Medium/High/Critical) tied to the mapped MITRE technique.

Used later by the Risk Scoring Engine as the technique_severity_component.

## 6. API Endpoint Design

**Ingestion**
- `POST /api/v1/logs/upload` — Upload Sysmon export (JSON/CSV/EVTX-converted); triggers parsing into `raw_logs`
- `GET /api/v1/logs/{log_id}` — Retrieve a raw log batch's metadata

**Feature Engineering / Detection**
- `POST /api/v1/detection/run` — Trigger feature extraction + autoencoder inference on a log batch (sync for intern-scope demo; could be async/Celery if time permits)
- `GET /api/v1/detection/anomalies` — List anomalies (filterable by host, date range, score threshold)
- `GET /api/v1/detection/anomalies/{anomaly_id}` — Anomaly detail

**Incidents**
- `GET /api/v1/incidents` — List incidents (sortable/filterable by risk score, status, host)
- `GET /api/v1/incidents/{incident_id}` — Full incident detail: timeline + investigation + mapping + risk
- `PATCH /api/v1/incidents/{incident_id}/status` — Analyst marks incident reviewed/closed

**Investigation (LLM)**
- `POST /api/v1/investigation/{incident_id}/generate` — Trigger LLM narrative generation for an incident
- `GET /api/v1/investigation/{incident_id}` — Retrieve stored narrative

**MITRE Mapping**
- `POST /api/v1/mitre/{incident_id}/map` — Trigger MITRE technique mapping for an incident
- `GET /api/v1/mitre/{incident_id}` — Retrieve mapped tactics/techniques

**Risk Scoring**
- `GET /api/v1/risk/{incident_id}` — Retrieve risk score breakdown
- `POST /api/v1/risk/{incident_id}/recompute` — Recompute risk (e.g., after asset criticality config change)

**Dashboard / Aggregate**
- `GET /api/v1/dashboard/summary` — Aggregate stats: total incidents, by risk label, by host, trend over time
- `GET /api/v1/dashboard/attack-matrix` — Aggregated MITRE technique frequency for matrix-style visualization

**System**
- `GET /api/v1/health` — Health check (used by Docker healthcheck)
- `GET /api/v1/models/status` — Current loaded model version + threshold info
