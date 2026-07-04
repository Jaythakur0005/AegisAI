"""
Pipeline orchestration service.

Connects the existing AegisAI processing stages into one executable
workflow:

    Sysmon events -> raw_logs -> processed_events -> anomalies -> incidents -> MITRE mappings -> risk scores -> investigations

The stage implementations remain in their dedicated service modules.
This module only coordinates them and returns a compact, API-friendly
summary of what each stage produced.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

from app.core.logging import get_logger
from app.services.anomaly_detector import (
    AnomalyDetectionResult,
    run_anomaly_detection,
)
from app.services.feature_engineering import (
    FeatureEngineeringResult,
    run_feature_engineering,
)
from app.services.incident_builder import (
    IncidentBuilderResult,
    run_incident_building,
)
from app.services.log_ingestion import IngestionResult, ingest_batch
from app.services.mitre_mapper import (
    MitreMappingResult,
    run_mitre_mapping,
)
from app.services.risk_scoring import (
    RiskScoringResult,
    run_risk_scoring,
)
from app.services.investigation_report_generator import (
    InvestigationReportResult,
    run_investigation_report_generation,
)

logger = get_logger(__name__)


class PipelineError(RuntimeError):
    """Raised when a pipeline stage fails and the workflow cannot continue."""

    def __init__(self, stage: str, reason: str) -> None:
        super().__init__(f"Pipeline failed during {stage}: {reason}")
        self.stage = stage
        self.reason = reason


@dataclass
class PipelineResult:
    """Structured result for one end-to-end pipeline run."""

    ingestion: IngestionResult
    feature_engineering: FeatureEngineeringResult
    anomaly_detection: AnomalyDetectionResult
    incident_building: IncidentBuilderResult
    mitre_mapping: MitreMappingResult
    risk_scoring: RiskScoringResult
    investigation_reporting: InvestigationReportResult

    @property
    def summary(self) -> Dict[str, int]:
        """Return the high-level counts most clients need."""
        return {
            "logs": self.ingestion.total,
            "raw_logs_inserted": self.ingestion.success_count,
            "processed": self.feature_engineering.windows_processed,
            "anomalies": self.anomaly_detection.anomalous_count,
            "anomaly_scores": self.anomaly_detection.total_scored,
            "incidents": self.incident_building.incidents_created,
            "attack_mappings": self.mitre_mapping.total_mappings_created,
            "risk_scores": self.risk_scoring.incidents_scored,
            "investigations": self.investigation_reporting.reports_generated,
        }


async def run_pipeline(events: List[Dict[str, Any]]) -> PipelineResult:
    """
    Run the full backend workflow for a batch of Sysmon JSON events.

    Args:
        events: Raw Sysmon event dictionaries in the shape accepted by
            `app.services.sysmon_parser`.

    Returns:
        A `PipelineResult` containing each stage's native result object.

    Raises:
        PipelineError: If any stage raises an infrastructure/model
            failure and the remaining stages cannot safely continue.
    """
    logger.info("Starting pipeline run", extra={"logs_received": len(events)})

    try:
        ingestion_result = await ingest_batch(events)
    except Exception as exc:  # noqa: BLE001 - stage boundary
        logger.exception("Pipeline ingestion stage failed")
        raise PipelineError("ingestion", str(exc)) from exc

    try:
        feature_result = await run_feature_engineering()
    except Exception as exc:  # noqa: BLE001 - stage boundary
        logger.exception("Pipeline feature engineering stage failed")
        raise PipelineError("feature_engineering", str(exc)) from exc

    try:
        anomaly_result = await run_anomaly_detection()
    except Exception as exc:  # noqa: BLE001 - stage boundary
        logger.exception("Pipeline anomaly detection stage failed")
        raise PipelineError("anomaly_detection", str(exc)) from exc

    try:
        incident_result = await run_incident_building()
    except Exception as exc:  # noqa: BLE001 - stage boundary
        logger.exception("Pipeline incident building stage failed")
        raise PipelineError("incident_building", str(exc)) from exc

    try:
        mitre_result = await run_mitre_mapping()
    except Exception as exc:  # noqa: BLE001 - stage boundary
        logger.exception("Pipeline MITRE mapping stage failed")
        raise PipelineError("mitre_mapping", str(exc)) from exc

    try:
        risk_result = await run_risk_scoring()
    except Exception as exc:  # noqa: BLE001 - stage boundary
        logger.exception("Pipeline risk scoring stage failed")
        raise PipelineError("risk_scoring", str(exc)) from exc

    try:
        investigation_result = await run_investigation_report_generation()
    except Exception as exc:  # noqa: BLE001 - stage boundary
        logger.exception("Pipeline investigation reporting stage failed")
        raise PipelineError("investigation_reporting", str(exc)) from exc

    result = PipelineResult(
        ingestion=ingestion_result,
        feature_engineering=feature_result,
        anomaly_detection=anomaly_result,
        incident_building=incident_result,
        mitre_mapping=mitre_result,
        risk_scoring=risk_result,
        investigation_reporting=investigation_result,
    )

    logger.info("Completed pipeline run", extra=result.summary)
    return result
