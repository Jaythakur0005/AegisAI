// ─────────────────────────────────────────────────────────────────────────────
// AegisAI — API type definitions
// Source: verified live contract only. No fields invented beyond what was
// confirmed via live HTTP / OpenAPI testing.
// ─────────────────────────────────────────────────────────────────────────────

// ---------------------------------------------------------------------------
// Primitives / enums
// ---------------------------------------------------------------------------

export type RiskLabel = "Low" | "Medium" | "High" | "Critical";

// Backend uses "new" | "reviewed" | "closed" per generated source, but
// kept as string-compatible per task instruction until live-verified.
export type IncidentStatus = string;

// ---------------------------------------------------------------------------
// Shared sub-objects
// ---------------------------------------------------------------------------

export interface RiskScoreDetail {
  anomaly_component: number;
  technique_severity_component: number;
  asset_criticality_component: number;
  final_score: number;
  risk_label: RiskLabel;
}

export interface AttackMappingDetail {
  tactic_id: string;
  technique_id: string;
  technique_name: string;
  confidence: number;
  severity_level: string;
  justification_text: string;
}

export interface InvestigationDetail {
  narrative_text: string;
  llm_model_used: string;
  prompt_version: string;
  confidence_score: number;
  generated_at: string;
}

// ---------------------------------------------------------------------------
// Incident
// ---------------------------------------------------------------------------

export interface IncidentResponse {
  id: string;
  host: string;
  start_time: string;
  end_time: string;
  event_sequence: string[];
  status: IncidentStatus;
  created_at: string;
  severity: string | null;
}

export interface IncidentDetailResponse extends IncidentResponse {
  risk: RiskScoreDetail | null;
  mitre_mappings: AttackMappingDetail[];
  investigation: InvestigationDetail | null;
}

// ---------------------------------------------------------------------------
// Incident list
// ---------------------------------------------------------------------------

export interface Pagination {
  page: number;
  page_size: number;
  total_items: number;
  total_pages: number;
}

export interface IncidentListResponse {
  items: IncidentResponse[];
  pagination: Pagination;
}

export interface IncidentFilters {
  page?: number;
  page_size?: number;
  host?: string;
  status?: IncidentStatus;
  severity?: string;
}

// ---------------------------------------------------------------------------
// Investigation
// ---------------------------------------------------------------------------

export interface InvestigationResponse {
  id: string;
  incident_ref: string;
  narrative_text: string;
  llm_model_used: string;
  prompt_version: string;
  confidence_score: number;
  generated_at: string;
}

export interface InvestigationGenerateResponse {
  investigation: InvestigationResponse;
  batch_reports_generated: number;
}

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------

export interface PipelineStageCounts {
  logs: number;
  raw_logs_inserted: number;
  processed: number;
  anomalies: number;
  anomaly_scores: number;
  incidents: number;
  attack_mappings: number;
  risk_scores: number;
  investigations: number;
}

export interface PipelineRunRequest {
  logs: Record<string, unknown>[];
}

export interface PipelineRunResponse {
  summary: PipelineStageCounts;
  raw_log_ids: string[];
  processed_event_ids: string[];
  anomaly_ids: string[];
  incident_ids: string[];
  attack_mapping_ids: string[];
  risk_score_ids: string[];
  investigation_ids: string[];
  ingestion_failures: Record<string, unknown>[];
  skipped_raw_logs: Record<string, unknown>[];
  skipped_processed_events: Record<string, unknown>[];
  skipped_incident_groups: Record<string, unknown>[];
}


