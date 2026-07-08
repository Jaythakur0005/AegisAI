import { useState } from "react";
import type { ChangeEvent } from "react";
import {
  Binary,
  BrainCircuit,
  CheckCircle2,
  ChevronRight,
  FileSearch,
  FileUp,
  GitBranch,
  Loader2,
  Map,
  ShieldCheck,
  TriangleAlert,
  Zap,
} from "lucide-react";
import { runPipeline } from "../lib/api";
import type { PipelineRunResponse } from "../types/api";

type PipelineState = "idle" | "ready" | "running" | "success" | "error";

const STAGES = [
  { id: 1, label: "Log Ingestion",           Icon: FileUp       },
  { id: 2, label: "Feature Engineering",     Icon: Binary       },
  { id: 3, label: "Anomaly Detection",       Icon: BrainCircuit },
  { id: 4, label: "Incident Building",       Icon: GitBranch    },
  { id: 5, label: "MITRE ATT&CK Mapping",   Icon: Map          },
  { id: 6, label: "Risk Scoring",            Icon: ShieldCheck  },
  { id: 7, label: "Investigation Reporting", Icon: FileSearch   },
] as const;

function parseLogText(text: string): Record<string, unknown>[] {
  const trimmed = text.trim();
  if (!trimmed) throw new Error("The selected file is empty.");

  try {
    const parsed: unknown = JSON.parse(trimmed);
    if (Array.isArray(parsed)) {
      if (parsed.length === 0) throw new Error("The JSON array contains no log events.");
      if (!parsed.every((item) => typeof item === "object" && item !== null && !Array.isArray(item)))
        throw new Error("Every JSON array item must be an event object.");
      return parsed as Record<string, unknown>[];
    }
    if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed))
      return [parsed as Record<string, unknown>];
  } catch (error) {
    if (error instanceof Error && !(error instanceof SyntaxError)) throw error;
  }

  const lines = trimmed.split(/\r?\n/).filter((l) => l.trim().length > 0);
  const events: Record<string, unknown>[] = [];
  for (let i = 0; i < lines.length; i++) {
    let pl: unknown;
    try { pl = JSON.parse(lines[i]); }
    catch { throw new Error(`Invalid JSON on line ${i + 1}.`); }
    if (typeof pl !== "object" || pl === null || Array.isArray(pl))
      throw new Error(`Line ${i + 1} is not a JSON event object.`);
    events.push(pl as Record<string, unknown>);
  }
  if (events.length === 0) throw new Error("No valid log events were found.");
  return events;
}

export default function PipelinePage() {
  const [logs, setLogs] = useState<Record<string, unknown>[]>([]);
  const [fileName, setFileName] = useState("");
  const [state, setState] = useState<PipelineState>("idle");
  const [message, setMessage] = useState("");
  const [result, setResult] = useState<PipelineRunResponse | null>(null);

  async function handleFileChange(event: ChangeEvent<HTMLInputElement>): Promise<void> {
    const file = event.target.files?.[0];
    if (!file) return;
    setResult(null);
    setFileName(file.name);
    try {
      const text = await file.text();
      const parsedLogs = parseLogText(text);
      setLogs(parsedLogs);
      setState("ready");
      setMessage(`${parsedLogs.length.toLocaleString()} events ready`);
    } catch (error) {
      setLogs([]);
      setState("error");
      setMessage(error instanceof Error ? error.message : "Failed to parse the log file.");
    }
  }

  async function handleRunPipeline(): Promise<void> {
    if (logs.length === 0 || state === "running") return;
    setState("running");
    setResult(null);
    setMessage(`Processing ${logs.length.toLocaleString()} events…`);
    try {
      const response = await runPipeline(logs);
      setResult(response);
      setState("success");
      setMessage("Pipeline completed.");
    } catch (error) {
      setState("error");
      setMessage(error instanceof Error ? error.message : "Pipeline execution failed.");
    }
  }

  const summaryEntries = result ? [
    ["Logs attempted",      result.summary.logs],
    ["Raw logs inserted",   result.summary.raw_logs_inserted],
    ["Processed windows",   result.summary.processed],
    ["Anomaly scores",      result.summary.anomaly_scores],
    ["Anomalies",           result.summary.anomalies],
    ["Incidents",           result.summary.incidents],
    ["MITRE mappings",      result.summary.attack_mappings],
    ["Risk scores",         result.summary.risk_scores],
    ["Investigations",      result.summary.investigations],
  ] : [];

  return (
    <div className="pipeline-page">

      {/* ── Header ─────────────────────────────────────────────── */}
      <div className="pipeline-intro">
        <h2 className="pipeline-intro-title">Detection Pipeline</h2>
        <p className="pipeline-intro-sub">
          Submit a Sysmon log file to execute all seven stages and surface correlated incidents.
        </p>
      </div>

      {/* ── Stage flow ─────────────────────────────────────────── */}
      <div className="stage-flow">
        {STAGES.map((stage, idx) => {
          const Icon = stage.Icon;
          const done    = state === "success";
          const running = state === "running";
          const last    = idx === STAGES.length - 1;
          return (
            <div key={stage.id} className="stage-flow-item">
              <div className={`stage-node${done ? " stage-node-done" : running ? " stage-node-running" : ""}`}>
                {done
                  ? <CheckCircle2 size={15} strokeWidth={2} />
                  : running
                    ? <Loader2 size={15} strokeWidth={2} className="spin" />
                    : <Icon size={15} strokeWidth={1.8} />
                }
                <span className="stage-label">{stage.label}</span>
              </div>
              {!last && (
                <ChevronRight size={13} strokeWidth={1.6} className="stage-connector" />
              )}
            </div>
          );
        })}
      </div>

      {/* ── Upload surface ─────────────────────────────────────── */}
      <section className="pipeline-panel">
        <label className="dropzone" htmlFor="pipeline-file">
          <div className="dropzone-icon">
            <FileUp size={22} strokeWidth={1.6} />
          </div>
          <div className="dropzone-copy">
            {fileName ? (
              <>
                <span className="dropzone-filename">{fileName}</span>
                {state === "ready" && (
                  <span className="dropzone-count">{message}</span>
                )}
              </>
            ) : (
              <>
                <span className="dropzone-primary">Choose a log file</span>
                <span className="dropzone-secondary">JSON · JSONL · NDJSON</span>
              </>
            )}
          </div>
          <span className="dropzone-browse">Browse</span>
          <input
            id="pipeline-file"
            type="file"
            accept=".json,.jsonl,.ndjson,application/json"
            disabled={state === "running"}
            onChange={handleFileChange}
            className="dropzone-input"
          />
        </label>

        {/* Status bar */}
        {(state === "running" || state === "error") && (
          <div className={`pipeline-statusbar pipeline-statusbar-${state}`}>
            {state === "running"
              ? <Loader2 size={13} strokeWidth={2} className="spin" />
              : <TriangleAlert size={13} strokeWidth={2} />
            }
            <span>{message}</span>
          </div>
        )}

        <button
          className="pipeline-run-btn"
          type="button"
          disabled={logs.length === 0 || state === "running"}
          onClick={handleRunPipeline}
        >
          {state === "running" ? (
            <>
              <Loader2 size={14} strokeWidth={2} className="spin" />
              Running Pipeline…
            </>
          ) : (
            <>
              <Zap size={14} strokeWidth={2} />
              Run Full Pipeline
            </>
          )}
        </button>
      </section>

      {/* ── Stage summary (preserved) ──────────────────────────── */}
      {result && (
        <>
          <section className="detail-section">
            <h3 className="detail-section-title">Stage Summary</h3>
            <div className="pipeline-summary-grid">
              {summaryEntries.map(([label, value]) => (
                <div className="pipeline-metric" key={label}>
                  <span className="detail-meta-label">{label}</span>
                  <span className="pipeline-metric-value">{value}</span>
                </div>
              ))}
            </div>
          </section>

          <section className="detail-section">
            <h3 className="detail-section-title">Run Diagnostics</h3>
            <div className="pipeline-summary-grid">
              <div className="pipeline-metric">
                <span className="detail-meta-label">Ingestion failures</span>
                <span className="pipeline-metric-value">{result.ingestion_failures.length}</span>
              </div>
              <div className="pipeline-metric">
                <span className="detail-meta-label">Skipped raw logs</span>
                <span className="pipeline-metric-value">{result.skipped_raw_logs.length}</span>
              </div>
              <div className="pipeline-metric">
                <span className="detail-meta-label">Skipped processed events</span>
                <span className="pipeline-metric-value">{result.skipped_processed_events.length}</span>
              </div>
              <div className="pipeline-metric">
                <span className="detail-meta-label">Skipped incident groups</span>
                <span className="pipeline-metric-value">{result.skipped_incident_groups.length}</span>
              </div>
            </div>
          </section>
        </>
      )}
    </div>
  );
}
