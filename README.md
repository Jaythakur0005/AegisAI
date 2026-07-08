# AegisAI

**Autonomous Zero-Day Threat Investigation and Explainability Engine**

AegisAI is a cybersecurity investigation platform that processes Windows Sysmon telemetry through an end-to-end anomaly detection and threat investigation pipeline. It converts raw endpoint events into correlated incidents, MITRE ATT&CK mappings, risk scores, and investigation reports that can be explored through a React-based SOC dashboard.

## What AegisAI Does

Traditional rule-only detection can struggle with previously unseen or abnormal activity. AegisAI combines anomaly detection with incident correlation and explainability to help investigate suspicious Sysmon behaviour.

## Implemented Architecture

AegisAI currently contains seven connected backend processing stages:

1. **Log Ingestion** — parses and stores supported Sysmon event objects.
2. **Feature Engineering** — transforms stored telemetry into processed event windows and model features.
3. **Anomaly Detection** — scores processed data using the packaged anomaly detection model artifacts.
4. **Incident Building** — correlates anomalous activity into incidents.
5. **MITRE ATT&CK Mapping** — maps incident behaviour to ATT&CK tactics and techniques.
6. **Risk Scoring** — combines anomaly, technique severity, and asset criticality components.
7. **Investigation Reporting** — produces an investigation-oriented explanation for each scored incident.

The complete data flow is:

```text
Sysmon events
    -> raw_logs
    -> processed_events
    -> anomalies
    -> incidents
    -> MITRE mappings
    -> risk scores
    -> investigations
```

## Prerequisites

Before running AegisAI, install:

- Python 3
- MongoDB
- Node.js and npm

A local MongoDB instance must be available before the backend starts.

## Backend Setup

From the repository root:

```bash
cd backend

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt

cp .env.example .env
```

Review `backend/.env` before starting the application. The environment configuration controls application, MongoDB, model, pipeline, MITRE mapping, risk scoring, and logging behaviour.

Start the backend from the `backend` directory:

```bash
uvicorn app.main:app --reload --host 127.0.0.1 --port 8001
```

The backend API is available at `http://127.0.0.1:8001`.

Interactive FastAPI documentation is available at `http://127.0.0.1:8001/docs`.

## Frontend Setup

Open another terminal from the repository root:

```bash
cd frontend
npm install
npm run dev
```

Open the Vite development URL shown in the terminal.

## Running the Detection Pipeline

1. Start MongoDB.
2. Start the AegisAI backend.
3. Start the frontend.
4. Open the **Pipeline** page from the sidebar.
5. Select a Sysmon `.json`, `.jsonl`, or `.ndjson` file.
6. Run the pipeline.
7. Review the pipeline stage summary and diagnostics.
8. Open the Dashboard to inspect generated incidents.
9. Select an incident to review its risk data, MITRE ATT&CK mappings, and investigation report.

The Pipeline page uses a browser file picker. Local security datasets and demo samples do not need to be committed to the repository.

## Verified Integration Run

AegisAI has been exercised end-to-end using an APTSimulator/Cobalt Strike Sysmon sample containing 2,611 valid newline-delimited event objects.

The verified integration run produced:

| Pipeline result | Count |
| --- | ---: |
| Logs attempted | 2,611 |
| Raw logs inserted | 2,611 |
| Processed windows | 83 |
| Anomaly scores | 166 |
| Anomalies | 10 |
| Incidents | 2 |
| MITRE mappings | 6 |
| Risk scores | 2 |
| Investigations | 2 |

These figures demonstrate successful end-to-end pipeline integration. They are not presented as model accuracy, precision, recall, or F1-score measurements.

## Training and Dataset Utilities

The `training/scripts` directory contains supporting dataset utilities:

- `audit_sysmon_parser.py` audits compatible Sysmon events from external Security-Datasets archives against the AegisAI parser.
- `import_otrf_dataset.py` streams supported JSON, JSONL, or NDJSON events from ZIP archives into the existing ingestion service.

Large external datasets, extracted training data, and local sample logs are intentionally excluded from Git.

The current repository includes packaged model artifacts used by the anomaly detection service. The dataset utility scripts should not be described as a complete reproducible model-training pipeline.

## Current Limitations

- The current implementation is designed around supported Windows Sysmon telemetry.
- External datasets and local demo samples must be obtained separately.
- The packaged anomaly model is used by the runtime pipeline; full model-training reproducibility is outside the current repository scope.
- The project currently focuses on local development and internship demonstration rather than production-scale deployment.
- Automated backend and API test coverage remains future work.

## Project Status

The seven-stage backend pipeline, incident API integration, React SOC dashboard, incident detail workflow, and browser-driven pipeline execution interface are implemented.

Current development is focused on repository hardening, automated validation, final UI polish, and internship demonstration readiness.

## Disclaimer

AegisAI is an academic and cybersecurity research project. It should be used only with telemetry and systems that you are authorized to analyze.
