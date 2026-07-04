// ─────────────────────────────────────────────────────────────────────────────
// AegisAI — typed API client
// All functions talk to the verified live backend contract only.
// No mock data, no invented fields.
// ─────────────────────────────────────────────────────────────────────────────

import type {
  IncidentDetailResponse,
  IncidentFilters,
  IncidentListResponse,
  InvestigationGenerateResponse,
  InvestigationResponse,
  PipelineRunRequest,
  PipelineRunResponse,
} from "../types/api";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const BASE_URL = "http://127.0.0.1:8001/api/v1";

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

export class ApiError extends Error {
  public readonly status: number;
  public readonly statusText: string;
  public readonly body: unknown;

  constructor(
    status: number,
    statusText: string,
    body: unknown,
  ) {
    super(`API error ${status} ${statusText}`);
    this.name = "ApiError";
    this.status = status;
    this.statusText = statusText;
    this.body = body;
  }
}

// ---------------------------------------------------------------------------
// Core fetch wrapper
// ---------------------------------------------------------------------------

async function request<T>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const url = `${BASE_URL}${path}`;

  const response = await fetch(url, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...init.headers,
    },
  });

  // Parse body regardless of status so error bodies are available.
  let body: unknown;
  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    body = await response.json();
  } else {
    body = await response.text();
  }

  if (!response.ok) {
    throw new ApiError(response.status, response.statusText, body);
  }

  return body as T;
}

// ---------------------------------------------------------------------------
// Query parameter encoding
// Omits undefined / null values. All values coerced to string.
// ---------------------------------------------------------------------------

function encodeParams(
  params: Record<string, string | number | boolean | null | undefined>,
): string {
  const searchParams = new URLSearchParams();

  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null) continue;
    searchParams.set(key, String(value));
  }

  const encoded = searchParams.toString();
  return encoded.length > 0 ? `?${encoded}` : "";
}

// ---------------------------------------------------------------------------
// Incidents
// ---------------------------------------------------------------------------

/**
 * GET /incidents
 * Returns a paginated, filtered list of incidents.
 * All filter fields are optional.
 */
export async function getIncidents(
  filters: IncidentFilters = {},
): Promise<IncidentListResponse> {
  const qs = encodeParams({
    page: filters.page,
    page_size: filters.page_size,
    host: filters.host,
    status: filters.status,
    severity: filters.severity,
  });

  return request<IncidentListResponse>(`/incidents${qs}`);
}

/**
 * GET /incidents/{incident_id}
 * Returns full incident detail including risk, MITRE mappings,
 * and investigation (all may be null/empty if not yet computed).
 */
export async function getIncident(
  id: string,
): Promise<IncidentDetailResponse> {
  return request<IncidentDetailResponse>(`/incidents/${encodeURIComponent(id)}`);
}

// ---------------------------------------------------------------------------
// Investigation
// ---------------------------------------------------------------------------

/**
 * GET /investigation/{incident_id}
 * Returns the stored investigation for an incident.
 * Throws ApiError with status 404 if no investigation exists yet —
 * callers should treat 404 as "not generated" rather than a hard error.
 */
export async function getInvestigation(
  incidentId: string,
): Promise<InvestigationResponse> {
  return request<InvestigationResponse>(
    `/investigation/${encodeURIComponent(incidentId)}`,
  );
}

/**
 * POST /investigation/{incident_id}/generate
 * Triggers investigation generation. No request body required.
 * May generate reports for multiple previously-unreported incidents
 * as a side effect (batch behaviour). Returns the report for the
 * requested incident plus a count of all reports generated.
 */
export async function generateInvestigation(
  incidentId: string,
): Promise<InvestigationGenerateResponse> {
  return request<InvestigationGenerateResponse>(
    `/investigation/${encodeURIComponent(incidentId)}/generate`,
    { method: "POST" },
  );
}

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------

/**
 * POST /pipeline/run
 * Executes the full AegisAI pipeline.
 * `logs` must contain at least 1 raw Sysmon event object (minItems: 1).
 */
export async function runPipeline(
  logs: PipelineRunRequest["logs"],
): Promise<PipelineRunResponse> {
  if (logs.length === 0) {
    throw new Error("Pipeline requires at least one log event.");
  }

  const body: PipelineRunRequest = { logs };

  return request<PipelineRunResponse>("/pipeline/run", {
    method: "POST",
    body: JSON.stringify(body),
  });
}