import { useCallback, useEffect, useState } from "react";
import { getIncidents } from "../lib/api";
import type { IncidentResponse, IncidentListResponse } from "../types/api";
import { ApiError } from "../lib/api";
import SeverityBadge from "../components/SeverityBadge";

const PAGE_SIZE = 20;

function formatDateTime(iso: string): string {
  try {
    return new Date(iso).toLocaleString(undefined, {
      year:   "numeric",
      month:  "short",
      day:    "2-digit",
      hour:   "2-digit",
      minute: "2-digit",
      hour12: false,
    });
  } catch {
    return iso;
  }
}

export default function DashboardPage() {
  const [data, setData]       = useState<IncidentListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState<string | null>(null);
  const [page, setPage]       = useState(1);

  const fetchIncidents = useCallback(async (targetPage: number) => {
    setLoading(true);
    setError(null);

    try {
      const result = await getIncidents({ page: targetPage, page_size: PAGE_SIZE });
      setData(result);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(`API ${err.status}: ${err.statusText}`);
      } else if (err instanceof Error) {
        setError(err.message);
      } else {
        setError("An unexpected error occurred.");
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchIncidents(page);
  }, [page, fetchIncidents]);

  // ── Loading ──────────────────────────────────────────────────────────────
  if (loading) {
    return (
      <div className="state-container">
        <span className="state-icon">⏳</span>
        <span className="state-title">Loading incidents…</span>
      </div>
    );
  }

  // ── Error ────────────────────────────────────────────────────────────────
  if (error !== null) {
    return (
      <div className="state-container">
        <span className="state-icon">⚠️</span>
        <span className="state-title">Failed to load incidents</span>
        <span className="error-message">{error}</span>
        <button className="retry-btn" onClick={() => fetchIncidents(page)}>
          Retry
        </button>
      </div>
    );
  }

  const incidents: IncidentResponse[] = data?.items ?? [];
  const pagination = data?.pagination;

  // ── Empty ────────────────────────────────────────────────────────────────
  if (incidents.length === 0) {
    return (
      <>
        <div className="dashboard-header">
          <h2>Incident Overview</h2>
          <p>Detected anomalous activity, correlated into incidents.</p>
        </div>
        <div className="state-container">
          <span className="state-icon">🛡</span>
          <span className="state-title">No incidents found</span>
          <span className="state-body">
            No correlated anomalous activity is currently available.
          </span>
        </div>
      </>
    );
  }

  // ── Table ────────────────────────────────────────────────────────────────
  const totalPages = pagination?.total_pages ?? 1;
  const totalItems = pagination?.total_items ?? incidents.length;

  return (
    <>
      <div className="dashboard-header">
        <h2>Incident Overview</h2>
        <p>
          {totalItems} incident{totalItems !== 1 ? "s" : ""} detected
          across monitored hosts.
        </p>
      </div>

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
              <tr key={incident.id}>
                <td className="host-cell">{incident.host}</td>
                <td>
                  <SeverityBadge severity={incident.severity} />
                </td>
                <td>
                  <span className="status-chip">{incident.status}</span>
                </td>
                <td className="time-cell">
                  {formatDateTime(incident.start_time)}
                </td>
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
                onClick={() => setPage((p) => Math.max(1, p - 1))}
              >
                ← Prev
              </button>
              <button
                className="page-btn"
                disabled={pagination.page >= totalPages}
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              >
                Next →
              </button>
            </div>
          </div>
        )}
      </div>
    </>
  );
}
