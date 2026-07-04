import { useEffect, useState } from "react";
import type { FC } from "react";
import { Link, useParams } from "react-router-dom";
import { getIncident } from "../lib/api";
import type { IncidentDetailResponse } from "../types/api";
import SeverityBadge from "../components/SeverityBadge";

type LoadState = "loading" | "error" | "ready";

function formatTimestamp(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function formatDecimal(value: number, digits: number): string {
  return value.toFixed(digits);
}

const IncidentDetailPage: FC = () => {
  const { incidentId } = useParams<{ incidentId: string }>();
  const [incident, setIncident] = useState<IncidentDetailResponse | null>(null);
  const [loadState, setLoadState] = useState<LoadState>("loading");
  const [errorMessage, setErrorMessage] = useState<string>("");

  useEffect(() => {
    if (!incidentId) {
      setLoadState("error");
      setErrorMessage("No incident ID was provided in the URL.");
      return;
    }

    const currentIncidentId = incidentId;
    let cancelled = false;

    async function loadIncident(): Promise<void> {
      setLoadState("loading");
      try {
        const response = await getIncident(currentIncidentId);
        if (cancelled) return;
        setIncident(response);
        setLoadState("ready");
      } catch (err) {
        if (cancelled) return;
        setErrorMessage(err instanceof Error ? err.message : "Failed to load incident.");
        setLoadState("error");
      }
    }

    void loadIncident();

    return () => {
      cancelled = true;
    };
  }, [incidentId]);

  if (loadState === "loading") {
    return (
      <div className="state-panel">
        <p className="state-panel-title">Loading incident…</p>
        <p className="state-panel-body">Fetching incident detail from the backend.</p>
      </div>
    );
  }

  if (loadState === "error") {
    return (
      <div className="state-panel state-panel-error">
        <p className="state-panel-title">Couldn't load incident</p>
        <p className="state-panel-body">{errorMessage}</p>
        <Link className="back-link" to="/">
          ← Back to Incidents
        </Link>
      </div>
    );
  }

  if (!incident) {
    return (
      <div className="state-panel state-panel-error">
        <p className="state-panel-title">Incident not found</p>
        <p className="state-panel-body">No incident data was returned.</p>
        <Link className="back-link" to="/">
          ← Back to Incidents
        </Link>
      </div>
    );
  }

  const { risk, mitre_mappings, investigation } = incident;

  return (
    <div className="incident-detail">
      <Link className="back-link" to="/">
        ← Back to Incidents
      </Link>

      <div className="detail-header">
        <div>
          <p className="app-header-eyebrow">Incident</p>
          <h2 className="detail-host">{incident.host}</h2>
        </div>
        <SeverityBadge severity={incident.severity} />
      </div>

      <div className="detail-meta">
        <div className="detail-meta-item">
          <span className="detail-meta-label">Status</span>
          <span className="detail-meta-value">{incident.status}</span>
        </div>
        <div className="detail-meta-item">
          <span className="detail-meta-label">Start time</span>
          <span className="detail-meta-value">{formatTimestamp(incident.start_time)}</span>
        </div>
        <div className="detail-meta-item">
          <span className="detail-meta-label">End time</span>
          <span className="detail-meta-value">{formatTimestamp(incident.end_time)}</span>
        </div>
        <div className="detail-meta-item">
          <span className="detail-meta-label">Event count</span>
          <span className="detail-meta-value">{incident.event_sequence.length}</span>
        </div>
      </div>

      <section className="detail-section">
        <h3 className="detail-section-title">Risk</h3>
        {risk ? (
          <div className="risk-grid">
            <div className="risk-metric">
              <span className="detail-meta-label">Final score</span>
              <span className="detail-meta-value">{formatDecimal(risk.final_score, 1)}</span>
            </div>
            <div className="risk-metric">
              <span className="detail-meta-label">Risk label</span>
              <span className="detail-meta-value">{risk.risk_label}</span>
            </div>
            <div className="risk-metric">
              <span className="detail-meta-label">Anomaly component</span>
              <span className="detail-meta-value">{formatDecimal(risk.anomaly_component, 1)}</span>
            </div>
            <div className="risk-metric">
              <span className="detail-meta-label">Technique severity component</span>
              <span className="detail-meta-value">{formatDecimal(risk.technique_severity_component, 1)}</span>
            </div>
            <div className="risk-metric">
              <span className="detail-meta-label">Asset criticality component</span>
              <span className="detail-meta-value">{formatDecimal(risk.asset_criticality_component, 1)}</span>
            </div>
          </div>
        ) : (
          <p className="empty-state-inline">No risk score has been computed for this incident.</p>
        )}
      </section>

      <section className="detail-section">
        <h3 className="detail-section-title">MITRE ATT&amp;CK Mappings</h3>
        {mitre_mappings.length > 0 ? (
          <ul className="mitre-list">
            {mitre_mappings.map((mapping, index) => (
              <li
                className="mitre-item"
                key={`${mapping.tactic_id}-${mapping.technique_id}-${index}`}
              >
                <div className="mitre-item-header">
                  <span className="mitre-technique">
                    {mapping.technique_id} — {mapping.technique_name}
                  </span>
                  <span className="mitre-tactic">{mapping.tactic_id}</span>
                </div>
                <div className="detail-meta">
                  <div className="detail-meta-item">
                    <span className="detail-meta-label">Confidence</span>
                    <span className="detail-meta-value">{formatDecimal(mapping.confidence, 2)}</span>
                  </div>
                  <div className="detail-meta-item">
                    <span className="detail-meta-label">Severity level</span>
                    <span className="detail-meta-value">{mapping.severity_level}</span>
                  </div>
                </div>
                <p className="mitre-justification">{mapping.justification_text}</p>
              </li>
            ))}
          </ul>
        ) : (
          <p className="empty-state-inline">
            No MITRE ATT&amp;CK techniques have been mapped for this incident.
          </p>
        )}
      </section>

      <section className="detail-section">
        <h3 className="detail-section-title">Investigation</h3>
        {investigation ? (
          <div className="investigation-block">
            <p className="investigation-narrative">{investigation.narrative_text}</p>
            <div className="detail-meta">
              <div className="detail-meta-item">
                <span className="detail-meta-label">Model</span>
                <span className="detail-meta-value">{investigation.llm_model_used}</span>
              </div>
              <div className="detail-meta-item">
                <span className="detail-meta-label">Prompt version</span>
                <span className="detail-meta-value">{investigation.prompt_version}</span>
              </div>
              <div className="detail-meta-item">
                <span className="detail-meta-label">Confidence score</span>
                <span className="detail-meta-value">{investigation.confidence_score}</span>
              </div>
              <div className="detail-meta-item">
                <span className="detail-meta-label">Generated at</span>
                <span className="detail-meta-value">
                  {formatTimestamp(investigation.generated_at)}
                </span>
              </div>
            </div>
          </div>
        ) : (
          <p className="empty-state-inline">
            No investigation report has been generated for this incident yet.
          </p>
        )}
      </section>
    </div>
  );
};

export default IncidentDetailPage;