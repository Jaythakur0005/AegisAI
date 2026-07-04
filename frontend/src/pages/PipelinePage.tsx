import { useState } from "react";
import type { ChangeEvent } from "react";
import { runPipeline } from "../lib/api";
import type { PipelineRunResponse } from "../types/api";

type PipelineState = "idle" | "ready" | "running" | "success" | "error";

function parseLogText(text: string): Record<string, unknown>[] {
  const trimmed = text.trim();

  if (!trimmed) {
    throw new Error("The selected file is empty.");
  }

  try {
    const parsed: unknown = JSON.parse(trimmed);

    if (Array.isArray(parsed)) {
      if (parsed.length === 0) {
        throw new Error("The JSON array contains no log events.");
      }

      if (
        !parsed.every(
          (item) =>
            typeof item === "object" &&
            item !== null &&
            !Array.isArray(item),
        )
      ) {
        throw new Error("Every JSON array item must be an event object.");
      }

      return parsed as Record<string, unknown>[];
    }

    if (
      typeof parsed === "object" &&
      parsed !== null &&
      !Array.isArray(parsed)
    ) {
      return [parsed as Record<string, unknown>];
    }
  } catch (error) {
    if (
      error instanceof Error &&
      !(
        error instanceof SyntaxError
      )
    ) {
      throw error;
    }
  }

  const lines = trimmed
    .split(/\r?\n/)
    .filter((line) => line.trim().length > 0);

  const events: Record<string, unknown>[] = [];

  for (let index = 0; index < lines.length; index += 1) {
    let parsedLine: unknown;

    try {
      parsedLine = JSON.parse(lines[index]);
    } catch {
      throw new Error(`Invalid JSON on line ${index + 1}.`);
    }

    if (
      typeof parsedLine !== "object" ||
      parsedLine === null ||
      Array.isArray(parsedLine)
    ) {
      throw new Error(`Line ${index + 1} is not a JSON event object.`);
    }

    events.push(parsedLine as Record<string, unknown>);
  }

  if (events.length === 0) {
    throw new Error("No valid log events were found.");
  }

  return events;
}

export default function PipelinePage() {
  const [logs, setLogs] = useState<Record<string, unknown>[]>([]);
  const [fileName, setFileName] = useState("");
  const [state, setState] = useState<PipelineState>("idle");
  const [message, setMessage] = useState(
    "Select a JSON, JSONL, or NDJSON Sysmon log file.",
  );
  const [result, setResult] = useState<PipelineRunResponse | null>(null);

  async function handleFileChange(
    event: ChangeEvent<HTMLInputElement>,
  ): Promise<void> {
    const file = event.target.files?.[0];

    if (!file) {
      return;
    }

    setResult(null);
    setFileName(file.name);

    try {
      const text = await file.text();
      const parsedLogs = parseLogText(text);

      setLogs(parsedLogs);
      setState("ready");
      setMessage(`${parsedLogs.length} log events ready for processing.`);
    } catch (error) {
      setLogs([]);
      setState("error");
      setMessage(
        error instanceof Error ? error.message : "Failed to parse the log file.",
      );
    }
  }

  async function handleRunPipeline(): Promise<void> {
    if (logs.length === 0 || state === "running") {
      return;
    }

    setState("running");
    setResult(null);
    setMessage(`Running the full pipeline for ${logs.length} events…`);

    try {
      const response = await runPipeline(logs);
      setResult(response);
      setState("success");
      setMessage("Pipeline completed successfully.");
    } catch (error) {
      setState("error");
      setMessage(
        error instanceof Error ? error.message : "Pipeline execution failed.",
      );
    }
  }

  const summaryEntries = result
    ? [
        ["Logs attempted", result.summary.logs],
        ["Raw logs inserted", result.summary.raw_logs_inserted],
        ["Processed windows", result.summary.processed],
        ["Anomaly scores", result.summary.anomaly_scores],
        ["Anomalies", result.summary.anomalies],
        ["Incidents", result.summary.incidents],
        ["MITRE mappings", result.summary.attack_mappings],
        ["Risk scores", result.summary.risk_scores],
        ["Investigations", result.summary.investigations],
      ]
    : [];

  return (
    <div className="pipeline-page">
      <section className="pipeline-panel">
        <div className="pipeline-header">
          <div>
            <h2>Run Detection Pipeline</h2>
            <p>
              Process raw Sysmon events through the complete AegisAI workflow.
            </p>
          </div>
        </div>

        <div className="pipeline-upload">
          <label className="pipeline-file-label" htmlFor="pipeline-file">
            Select Sysmon log file
          </label>
          <input
            id="pipeline-file"
            className="pipeline-file-input"
            type="file"
            accept=".json,.jsonl,.ndjson,application/json"
            disabled={state === "running"}
            onChange={handleFileChange}
          />

          {fileName && (
            <span className="pipeline-file-name">{fileName}</span>
          )}
        </div>

        <div className={`pipeline-status pipeline-status-${state}`}>
          <span className="pipeline-status-label">Pipeline status</span>
          <span>{message}</span>
        </div>

        <button
          className="pipeline-run-btn"
          type="button"
          disabled={logs.length === 0 || state === "running"}
          onClick={handleRunPipeline}
        >
          {state === "running" ? "Running Pipeline…" : "Run Full Pipeline"}
        </button>
      </section>

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
                <span className="pipeline-metric-value">
                  {result.ingestion_failures.length}
                </span>
              </div>

              <div className="pipeline-metric">
                <span className="detail-meta-label">Skipped raw logs</span>
                <span className="pipeline-metric-value">
                  {result.skipped_raw_logs.length}
                </span>
              </div>

              <div className="pipeline-metric">
                <span className="detail-meta-label">
                  Skipped processed events
                </span>
                <span className="pipeline-metric-value">
                  {result.skipped_processed_events.length}
                </span>
              </div>

              <div className="pipeline-metric">
                <span className="detail-meta-label">
                  Skipped incident groups
                </span>
                <span className="pipeline-metric-value">
                  {result.skipped_incident_groups.length}
                </span>
              </div>
            </div>
          </section>
        </>
      )}
    </div>
  );
}
