import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  AlertTriangle,
  Binary,
  BrainCircuit,
  FileSearch,
  FileUp,
  GitBranch,
  Loader,
  Map,
  ServerCrash,
  ShieldCheck,
  ShieldOff,
} from "lucide-react";
import { getDashboardSummary, getIncidents, ApiError } from "../lib/api";
import type {
  DashboardSummaryResponse,
  IncidentListResponse,
  IncidentResponse,
} from "../types/api";
import SeverityBadge from "../components/SeverityBadge";

const PAGE_SIZE = 20;

function fmt(n: number): string {
  return new Intl.NumberFormat().format(n);
}

function fmtFloat(n: number, decimals = 4): string {
  return n.toFixed(decimals);
}

function fmtDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString(undefined, {
      year: "numeric",
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    });
  } catch {
    return iso;
  }
}

const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"] as const;

const FOOTPRINT_STAGES = [
  { label: "Raw Logs",       key: "raw_logs",         Icon: FileUp       },
  { label: "Processed",      key: "processed_events",  Icon: Binary       },
  { label: "Scored",         key: "anomaly_scores",    Icon: BrainCircuit },
  { label: "Incidents",      key: "incidents",         Icon: GitBranch    },
  { label: "MITRE Mappings", key: "attack_mappings",   Icon: Map          },
  { label: "Risk Scores",    key: "risk_scores",       Icon: ShieldCheck  },
  { label: "Investigations", key: "investigations",    Icon: FileSearch   },
] as const;

type FootprintKey = (typeof FOOTPRINT_STAGES)[number]["key"];

// ─── Sub-components ───────────────────────────────────────────────────────────

function StatCard({
  label,
  value,
  sub,
}: {
  label: string;
  value: string;
  sub?: string;
}) {
  return (
    <div className="db-stat-card">
      <span className="db-stat-label">{label}</span>
      <span className="db-stat-value">{value}</span>
      {sub && <span className="db-stat-sub">{sub}</span>}
    </div>
  );
}

function SectionHeading({ title }: { title: string }) {
  return <h3 className="db-section-title">{title}</h3>;
}

function SectionError({ message }: { message: string }) {
  return (
    <div className="db-section-error">
      <ServerCrash size={14} strokeWidth={1.8} />
      <span>{message}</span>
    </div>
  );
}

// ─── Section: Risk Posture ────────────────────────────────────────────────────

function RiskPostureSection({ summary }: { summary: DashboardSummaryResponse }) {
  const { risk_summary } = summary;
  return (
    <section className="db-section db-risk-band">
      <SectionHeading title="Risk Posture" />
      <div className="db-risk-scores">
        <div className="db-risk-primary">
          <span className="db-risk-score-value">
            {fmtFloat(risk_summary.average_final_score, 1)}
          </span>
          <span className="db-stat-label">Avg Risk Score (0–100)</span>
        </div>
        <div className="db-risk-secondary">
          <span className="db-risk-score-value db-risk-score-max">
            {fmtFloat(risk_summary.maximum_final_score, 1)}
          </span>
          <span className="db-stat-label">Max Risk Score</span>
        </div>
      </div>
      <div className="db-severity-pills">
        {SEVERITY_ORDER.map((sev) => {
          const count = risk_summary.severity_counts[sev] ?? 0;
          return (
            <div key={sev} className={`db-severity-pill db-severity-pill-${sev.toLowerCase()}`}>
              <span className="db-severity-pill-count">{fmt(count)}</span>
              <span className="db-severity-pill-label">{sev}</span>
            </div>
          );
        })}
      </div>
    </section>
  );
}

// ─── Section: Detection Activity ─────────────────────────────────────────────

function DetectionActivitySection({ summary }: { summary: DashboardSummaryResponse }) {
  const { counts, anomaly_summary } = summary;
  return (
    <section className="db-section">
      <SectionHeading title="Detection Activity" />
      <div className="db-stat-grid">
        <StatCard
          label="Events Scored"
          value={fmt(counts.anomaly_scores)}
        />
        <StatCard
          label="Anomalous"
          value={fmt(counts.anomalous)}
        />
        <StatCard
          label="Anomaly Rate"
          value={`${fmtFloat(anomaly_summary.anomaly_rate, 2)}%`}
        />
      </div>
      <div className="db-error-threshold-row" aria-label="Reconstruction error versus threshold">
        <div className="db-error-threshold-item">
          <span className="db-stat-label">Avg Reconstruction Error</span>
          <span className="db-error-value">{fmtFloat(anomaly_summary.average_reconstruction_error)}</span>
        </div>
        <div className="db-error-threshold-divider" aria-hidden="true" />
        <div className="db-error-threshold-item">
          <span className="db-stat-label">Max Reconstruction Error</span>
          <span className="db-error-value">{fmtFloat(anomaly_summary.maximum_reconstruction_error)}</span>
        </div>
        <div className="db-error-threshold-divider" aria-hidden="true" />
        <div className="db-error-threshold-item">
          <span className="db-stat-label">Avg Anomaly Threshold</span>
          <span className="db-threshold-value">{fmtFloat(anomaly_summary.average_threshold)}</span>
        </div>
      </div>
    </section>
  );
}

// ─── Section: System Footprint ────────────────────────────────────────────────

function SystemFootprintSection({ summary }: { summary: DashboardSummaryResponse }) {
  const { counts } = summary;
  return (
    <section className="db-section">
      <SectionHeading title="Seven-Stage System Footprint" />
      <div className="db-footprint-strip">
        {FOOTPRINT_STAGES.map((stage, idx) => {
          const Icon = stage.Icon;
          const count = counts[stage.key as FootprintKey];
          const last = idx === FOOTPRINT_STAGES.length - 1;
          return (
            <div key={stage.key} className="db-footprint-item">
              <div className="db-footprint-node">
                <Icon size={13} strokeWidth={1.8} />
                <span className="db-footprint-count">{fmt(count)}</span>
                <span className="db-footprint-label">{stage.label}</span>
              </div>
              {!last && (
                <span className="db-footprint-connector" aria-hidden="true">›</span>
              )}
            </div>
          );
        })}
      </div>
    </section>
  );
}

// ─── Section: Model Telemetry ─────────────────────────────────────────────────

function ModelTelemetrySection({ summary }: { summary: DashboardSummaryResponse }) {
  const { model } = summary;
  if (!model) {
    return (
      <section className="db-section">
        <SectionHeading title="Model Telemetry" />
        <p className="db-empty-notice">No model metadata available.</p>
      </section>
    );
  }
  return (
    <section className="db-section">
      <SectionHeading title="Model Telemetry" />
      <div className="db-stat-grid db-model-grid">
        <StatCard label="Model Version"   value={model.model_version} />
        <StatCard label="Training Date"   value={fmtDate(model.training_date)} />
        <StatCard label="Threshold Value" value={fmtFloat(model.threshold_value)} />
        <StatCard
          label="Training Loss (MSE)"
          value={fmtFloat(model.training_loss)}
        />
        <StatCard
          label="Validation Loss (MSE)"
          value={fmtFloat(model.validation_loss)}
        />
      </div>
    </section>
  );
}

// ─── Section: Host Exposure ───────────────────────────────────────────────────

function HostExposureSection({ summary }: { summary: DashboardSummaryResponse }) {
  const { hosts } = summary;
  const maxCount =
    hosts.top_anomalous_hosts.length > 0
      ? Math.max(...hosts.top_anomalous_hosts.map((h) => h.anomaly_count))
      : 1;

  return (
    <section className="db-section">
      <SectionHeading title="Host Exposure" />
      <div className="db-host-header">
        <StatCard
          label="Unique Scored Hosts"
          value={fmt(hosts.unique_scored_host_count)}
        />
      </div>
      {hosts.top_anomalous_hosts.length === 0 ? (
        <p className="db-empty-notice">No anomalous host data available.</p>
      ) : (
        <table className="db-host-table" aria-label="Top anomalous hosts">
          <thead>
            <tr>
              <th className="db-host-th">Host</th>
              <th className="db-host-th db-host-th-count">Anomalies</th>
              <th className="db-host-th db-host-th-bar" aria-label="Proportion"></th>
            </tr>
          </thead>
          <tbody>
            {hosts.top_anomalous_hosts.map((entry) => {
              const pct =
                maxCount > 0
                  ? Math.round((entry.anomaly_count / maxCount) * 100)
                  : 0;
              return (
                <tr key={entry.host} className="db-host-row">
                  <td className="host-cell db-host-name">{entry.host}</td>
                  <td className="db-host-count">{fmt(entry.anomaly_count)}</td>
                  <td className="db-host-bar-cell" aria-hidden="true">
                    <div className="db-host-bar-track">
                      <div
                        className="db-host-bar-fill"
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </section>
  );
}

// ─── Section: Investigation Queue ─────────────────────────────────────────────

function InvestigationQueueSection({
  data,
  loading,
  error,
  page,
  onPageChange,
  onRowClick,
  onRetry,
}: {
  data: IncidentListResponse | null;
  loading: boolean;
  error: string | null;
  page: number;
  onPageChange: (p: number) => void;
  onRowClick: (id: string) => void;
  onRetry: () => void;
}) {
  const incidents: IncidentResponse[] = data?.items ?? [];
  const pagination = data?.pagination;
  const totalPages = pagination?.total_pages ?? 1;
  const totalItems = pagination?.total_items ?? incidents.length;

  return (
    <section className="db-section">
      <SectionHeading title="Investigation Queue" />

      {loading && (
        <div className="state-container">
          <div className="state-icon-wrap">
            <Loader size={20} strokeWidth={1.8} />
          </div>
          <span className="state-title">Loading incidents</span>
        </div>
      )}

      {!loading && error !== null && (
        <div className="state-container">
          <div className="state-icon-wrap">
            <AlertTriangle size={20} strokeWidth={1.8} />
          </div>
          <span className="state-title">Failed to load incidents</span>
          <span className="error-detail">{error}</span>
          <button className="retry-btn" onClick={onRetry}>
            Retry
          </button>
        </div>
      )}

      {!loading && error === null && incidents.length === 0 && (
        <div className="state-container">
          <div className="state-icon-wrap">
            <ShieldOff size={20} strokeWidth={1.8} />
          </div>
          <span className="state-title">No incidents found</span>
          <span className="state-body">
            No correlated anomalous activity is currently available.
          </span>
        </div>
      )}

      {!loading && error === null && incidents.length > 0 && (
        <>
          <p className="db-queue-meta">
            {fmt(totalItems)} incident{totalItems !== 1 ? "s" : ""} across
            monitored hosts.
          </p>
          <div className="incident-table-wrap">
            <table className="incident-table">
              <thead>
                <tr>
                  <th>Host</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Start Time</th>
                </tr>
              </thead>
              <tbody>
                {incidents.map((incident) => (
                  <tr
                    key={incident.id}
                    className="incident-row"
                    role="button"
                    tabIndex={0}
                    onClick={() => onRowClick(incident.id)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        onRowClick(incident.id);
                      }
                    }}
                  >
                    <td className="host-cell">{incident.host}</td>
                    <td>
                      <SeverityBadge severity={incident.severity} />
                    </td>
                    <td>
                      <span className="status-chip">{incident.status}</span>
                    </td>
                    <td className="time-cell">{fmtDate(incident.start_time)}</td>
                  </tr>
                ))}
              </tbody>
            </table>

            {totalPages > 1 && pagination && (
              <div className="pagination-bar">
                <span>
                  Page {pagination.page} of {totalPages}
                </span>
                <div className="pagination-controls">
                  <button
                    className="page-btn"
                    disabled={pagination.page <= 1}
                    onClick={() => onPageChange(Math.max(1, page - 1))}
                  >
                    ← Prev
                  </button>
                  <button
                    className="page-btn"
                    disabled={pagination.page >= totalPages}
                    onClick={() => onPageChange(Math.min(totalPages, page + 1))}
                  >
                    Next →
                  </button>
                </div>
              </div>
            )}
          </div>
        </>
      )}
    </section>
  );
}

// ─── Root ─────────────────────────────────────────────────────────────────────

export default function DashboardPage() {
  const navigate = useNavigate();

  const [summary, setSummary] = useState<DashboardSummaryResponse | null>(null);
  const [summaryLoading, setSummaryLoading] = useState(true);
  const [summaryError, setSummaryError] = useState<string | null>(null);

  const [incidentData, setIncidentData] = useState<IncidentListResponse | null>(null);
  const [incidentLoading, setIncidentLoading] = useState(true);
  const [incidentError, setIncidentError] = useState<string | null>(null);
  const [incidentPage, setIncidentPage] = useState(1);

  const fetchSummary = useCallback(async () => {
    setSummaryLoading(true);
    setSummaryError(null);
    try {
      const data = await getDashboardSummary();
      setSummary(data);
    } catch (err) {
      if (err instanceof ApiError) {
        setSummaryError(`API ${err.status}: ${err.statusText}`);
      } else if (err instanceof Error) {
        setSummaryError(err.message);
      } else {
        setSummaryError("Failed to load dashboard summary.");
      }
    } finally {
      setSummaryLoading(false);
    }
  }, []);

  const fetchIncidents = useCallback(async (targetPage: number) => {
    setIncidentLoading(true);
    setIncidentError(null);
    try {
      const data = await getIncidents({ page: targetPage, page_size: PAGE_SIZE });
      setIncidentData(data);
    } catch (err) {
      if (err instanceof ApiError) {
        setIncidentError(`API ${err.status}: ${err.statusText}`);
      } else if (err instanceof Error) {
        setIncidentError(err.message);
      } else {
        setIncidentError("Failed to load incidents.");
      }
    } finally {
      setIncidentLoading(false);
    }
  }, []);

  useEffect(() => { void fetchSummary(); }, [fetchSummary]);
  useEffect(() => { void fetchIncidents(incidentPage); }, [incidentPage, fetchIncidents]);

  return (
    <div className="db-page">

      {/* ── Summary loading / error ───────────────────────────────────────── */}
      {summaryLoading && (
        <div className="state-container">
          <div className="state-icon-wrap">
            <Loader size={20} strokeWidth={1.8} />
          </div>
          <span className="state-title">Loading dashboard</span>
        </div>
      )}

      {!summaryLoading && summaryError !== null && (
        <div className="db-summary-error-banner">
          <SectionError message={`Dashboard summary unavailable: ${summaryError}`} />
          <button className="retry-btn" onClick={() => void fetchSummary()}>
            Retry
          </button>
        </div>
      )}

      {/* ── Summary sections (independent of incidents) ───────────────────── */}
      {!summaryLoading && summary !== null && (
        <>
          <RiskPostureSection summary={summary} />
          <DetectionActivitySection summary={summary} />
          <SystemFootprintSection summary={summary} />
          <ModelTelemetrySection summary={summary} />
          <HostExposureSection summary={summary} />
        </>
      )}

      {/* ── Investigation queue (independent of summary) ──────────────────── */}
      <InvestigationQueueSection
        data={incidentData}
        loading={incidentLoading}
        error={incidentError}
        page={incidentPage}
        onPageChange={setIncidentPage}
        onRowClick={(id) => navigate(`/incidents/${id}`)}
        onRetry={() => void fetchIncidents(incidentPage)}
      />
    </div>
  );
}