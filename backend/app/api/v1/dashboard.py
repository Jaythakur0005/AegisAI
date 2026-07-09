"""
Dashboard API routes.

Implements a single aggregate summary endpoint over the pipeline's
persisted collections:

    GET /api/v1/dashboard/summary

This module reads directly from MongoDB via
`app.db.mongo_client.get_database()`, consistent with the precedent
set by `app.api.v1.incidents`. No repository layer exists yet for any
of the collections queried here.

All figures are derived live from MongoDB at request time; nothing is
hardcoded. Aggregations are used for numeric summaries
(reconstruction error, threshold, risk score, per-host anomaly
counts); simple `count_documents` / `distinct` calls are used
elsewhere, matching the query style already used in
`app.api.v1.incidents`.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from pymongo.errors import PyMongoError

from app.core.logging import get_logger
from app.db.mongo_client import get_database
from app.models.risk_score import RiskLabel

logger = get_logger(__name__)

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

_RAW_LOGS_COLLECTION = "raw_logs"
_PROCESSED_EVENTS_COLLECTION = "processed_events"
_ANOMALIES_COLLECTION = "anomalies"
_INCIDENTS_COLLECTION = "incidents"
_ATTACK_MAPPINGS_COLLECTION = "attack_mappings"
_RISK_SCORES_COLLECTION = "risk_scores"
_INVESTIGATIONS_COLLECTION = "investigations"
_MODEL_METADATA_COLLECTION = "model_metadata"

_TOP_ANOMALOUS_HOSTS_LIMIT = 5


class CountsResponse(BaseModel):
    """Document counts across all pipeline collections."""

    raw_logs: int = Field(..., description="Total raw_logs documents.")
    processed_events: int = Field(
        ..., description="Total processed_events documents."
    )
    anomaly_scores: int = Field(
        ..., description="Total anomalies documents (scored windows)."
    )
    anomalous: int = Field(
        ..., description="Anomalies documents with is_anomalous=true."
    )
    incidents: int = Field(..., description="Total incidents documents.")
    attack_mappings: int = Field(
        ..., description="Total attack_mappings documents."
    )
    risk_scores: int = Field(..., description="Total risk_scores documents.")
    investigations: int = Field(
        ..., description="Total investigations documents."
    )


class AnomalySummaryResponse(BaseModel):
    """Aggregate statistics over the anomalies collection."""

    anomaly_rate: float = Field(
        ...,
        description=(
            "Percentage of scored windows flagged anomalous "
            "(anomalous / anomaly_scores * 100). 0 if no scored windows."
        ),
    )
    average_reconstruction_error: float = Field(
        ..., description="Mean reconstruction_error across all anomalies documents."
    )
    maximum_reconstruction_error: float = Field(
        ..., description="Maximum reconstruction_error across all anomalies documents."
    )
    average_threshold: float = Field(
        ..., description="Mean threshold_used across all anomalies documents."
    )


class RiskSummaryResponse(BaseModel):
    """Aggregate statistics over the risk_scores collection."""

    average_final_score: float = Field(
        ..., description="Mean final_score across all risk_scores documents."
    )
    maximum_final_score: float = Field(
        ..., description="Maximum final_score across all risk_scores documents."
    )
    severity_counts: Dict[str, int] = Field(
        ..., description="Count of risk_scores documents grouped by risk_label."
    )


class ModelSummaryResponse(BaseModel):
    """Most recently trained model version, by training_date descending."""

    model_version: str = Field(..., description="Trained model version identifier.")
    training_date: datetime = Field(
        ..., description="UTC timestamp at which this model version was trained."
    )
    threshold_value: float = Field(
        ..., description="Reconstruction-error threshold derived from training."
    )
    training_loss: float = Field(..., description="Final training-set loss.")
    validation_loss: float = Field(..., description="Final validation-set loss.")


class TopAnomalousHost(BaseModel):
    """A host ranked by number of anomalous detections."""

    host: str = Field(..., description="Hostname.")
    anomaly_count: int = Field(
        ..., description="Count of anomalies documents with is_anomalous=true for this host."
    )


class HostsSummaryResponse(BaseModel):
    """Host-level statistics derived from the anomalies collection."""

    unique_scored_host_count: int = Field(
        ..., description="Count of distinct host values in the anomalies collection."
    )
    top_anomalous_hosts: List[TopAnomalousHost] = Field(
        ...,
        description=(
            "Hosts ranked by anomalous detection count, descending, "
            f"limited to {_TOP_ANOMALOUS_HOSTS_LIMIT}."
        ),
    )


class DashboardSummaryResponse(BaseModel):
    """Top-level dashboard summary response."""

    counts: CountsResponse
    anomaly_summary: AnomalySummaryResponse
    risk_summary: RiskSummaryResponse
    model: Optional[ModelSummaryResponse]
    hosts: HostsSummaryResponse


async def _count_all_collections(db: Any) -> CountsResponse:
    """
    Count documents across all pipeline collections.

    Raises:
        HTTPException: 500 if any count query fails.
    """
    try:
        raw_logs = await db[_RAW_LOGS_COLLECTION].count_documents({})
        processed_events = await db[_PROCESSED_EVENTS_COLLECTION].count_documents({})
        anomaly_scores = await db[_ANOMALIES_COLLECTION].count_documents({})
        anomalous = await db[_ANOMALIES_COLLECTION].count_documents(
            {"is_anomalous": True}
        )
        incidents = await db[_INCIDENTS_COLLECTION].count_documents({})
        attack_mappings = await db[_ATTACK_MAPPINGS_COLLECTION].count_documents({})
        risk_scores = await db[_RISK_SCORES_COLLECTION].count_documents({})
        investigations = await db[_INVESTIGATIONS_COLLECTION].count_documents({})
    except PyMongoError as exc:
        logger.exception("Failed to count dashboard collections")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve dashboard counts.",
        ) from exc

    return CountsResponse(
        raw_logs=raw_logs,
        processed_events=processed_events,
        anomaly_scores=anomaly_scores,
        anomalous=anomalous,
        incidents=incidents,
        attack_mappings=attack_mappings,
        risk_scores=risk_scores,
        investigations=investigations,
    )


async def _fetch_anomaly_summary(
    db: Any, anomaly_scores: int, anomalous: int
) -> AnomalySummaryResponse:
    """
    Compute anomaly rate and reconstruction-error/threshold statistics.

    Raises:
        HTTPException: 500 if the aggregation query fails.
    """
    if anomaly_scores == 0:
        return AnomalySummaryResponse(
            anomaly_rate=0.0,
            average_reconstruction_error=0.0,
            maximum_reconstruction_error=0.0,
            average_threshold=0.0,
        )

    try:
        cursor = db[_ANOMALIES_COLLECTION].aggregate(
            [
                {
                    "$group": {
                        "_id": None,
                        "avg_error": {"$avg": "$reconstruction_error"},
                        "max_error": {"$max": "$reconstruction_error"},
                        "avg_threshold": {"$avg": "$threshold_used"},
                    }
                }
            ]
        )
        results = await cursor.to_list(length=1)
    except PyMongoError as exc:
        logger.exception("Failed to aggregate anomalies collection")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve anomaly summary.",
        ) from exc

    if not results:
        return AnomalySummaryResponse(
            anomaly_rate=0.0,
            average_reconstruction_error=0.0,
            maximum_reconstruction_error=0.0,
            average_threshold=0.0,
        )

    document = results[0]
    anomaly_rate = (anomalous / anomaly_scores) * 100

    return AnomalySummaryResponse(
        anomaly_rate=anomaly_rate,
        average_reconstruction_error=document.get("avg_error") or 0.0,
        maximum_reconstruction_error=document.get("max_error") or 0.0,
        average_threshold=document.get("avg_threshold") or 0.0,
    )


async def _fetch_risk_summary(db: Any, risk_scores: int) -> RiskSummaryResponse:
    """
    Compute final_score statistics and severity counts from risk_scores.

    Raises:
        HTTPException: 500 if either aggregation query fails.
    """
    if risk_scores == 0:
        return RiskSummaryResponse(
            average_final_score=0.0,
            maximum_final_score=0.0,
            severity_counts={},
        )

    try:
        score_cursor = db[_RISK_SCORES_COLLECTION].aggregate(
            [
                {
                    "$group": {
                        "_id": None,
                        "avg_score": {"$avg": "$final_score"},
                        "max_score": {"$max": "$final_score"},
                    }
                }
            ]
        )
        score_results = await score_cursor.to_list(length=1)

        severity_cursor = db[_RISK_SCORES_COLLECTION].aggregate(
            [
                {"$group": {"_id": "$risk_label", "count": {"$sum": 1}}}
            ]
        )
        severity_results = await severity_cursor.to_list(length=None)
    except PyMongoError as exc:
        logger.exception("Failed to aggregate risk_scores collection")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve risk summary.",
        ) from exc

    if score_results:
        average_final_score = score_results[0].get("avg_score") or 0.0
        maximum_final_score = score_results[0].get("max_score") or 0.0
    else:
        average_final_score = 0.0
        maximum_final_score = 0.0

    severity_counts: Dict[str, int] = {}
    for entry in severity_results:
        label = entry.get("_id")
        count = entry.get("count", 0)
        if label is None:
            continue
        severity_counts[str(label)] = count

    return RiskSummaryResponse(
        average_final_score=average_final_score,
        maximum_final_score=maximum_final_score,
        severity_counts=severity_counts,
    )


async def _fetch_latest_model(db: Any) -> Optional[ModelSummaryResponse]:
    """
    Fetch the most recently trained model version, by training_date
    descending.

    Returns:
        None if no model_metadata documents exist or the latest one is
        malformed.

    Raises:
        HTTPException: 500 if the query itself fails.
    """
    try:
        cursor = (
            db[_MODEL_METADATA_COLLECTION]
            .find()
            .sort("training_date", -1)
            .limit(1)
        )
        results = await cursor.to_list(length=1)
    except PyMongoError as exc:
        logger.exception("Failed to query model_metadata collection")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve model metadata.",
        ) from exc

    if not results:
        return None

    document = results[0]

    try:
        metrics = document["metrics"]
        return ModelSummaryResponse(
            model_version=document["model_version"],
            training_date=document["training_date"],
            threshold_value=document["threshold_value"],
            training_loss=metrics["loss"],
            validation_loss=metrics["val_loss"],
        )
    except (KeyError, TypeError):
        logger.warning(
            "Latest model_metadata document is malformed",
            extra={"model_metadata_id": str(document.get("_id"))},
        )
        return None


async def _fetch_hosts_summary(db: Any) -> HostsSummaryResponse:
    """
    Compute unique scored host count and top anomalous hosts.

    Raises:
        HTTPException: 500 if either query fails.
    """
    try:
        distinct_hosts = await db[_ANOMALIES_COLLECTION].distinct("host")

        cursor = db[_ANOMALIES_COLLECTION].aggregate(
            [
                {"$match": {"is_anomalous": True}},
                {"$group": {"_id": "$host", "anomaly_count": {"$sum": 1}}},
                {"$sort": {"anomaly_count": -1}},
                {"$limit": _TOP_ANOMALOUS_HOSTS_LIMIT},
            ]
        )
        top_host_documents = await cursor.to_list(length=_TOP_ANOMALOUS_HOSTS_LIMIT)
    except PyMongoError as exc:
        logger.exception("Failed to compute hosts summary from anomalies collection")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve hosts summary.",
        ) from exc

    top_anomalous_hosts = [
        TopAnomalousHost(
            host=entry["_id"],
            anomaly_count=entry.get("anomaly_count", 0),
        )
        for entry in top_host_documents
        if entry.get("_id") is not None
    ]

    return HostsSummaryResponse(
        unique_scored_host_count=len(distinct_hosts),
        top_anomalous_hosts=top_anomalous_hosts,
    )


@router.get(
    "/summary",
    response_model=DashboardSummaryResponse,
    summary="Dashboard summary",
    description=(
        "Aggregate summary of pipeline collections: document counts, "
        "anomaly statistics, risk statistics, latest model metadata, "
        "and host-level anomaly rankings."
    ),
)
async def get_dashboard_summary() -> DashboardSummaryResponse:
    """
    Build the dashboard summary from live MongoDB data.

    Raises:
        HTTPException: 500 if any underlying database query fails.
    """
    logger.info("Building dashboard summary")

    db = get_database()

    counts = await _count_all_collections(db)
    anomaly_summary = await _fetch_anomaly_summary(
        db, counts.anomaly_scores, counts.anomalous
    )
    risk_summary = await _fetch_risk_summary(db, counts.risk_scores)
    model_summary = await _fetch_latest_model(db)
    hosts_summary = await _fetch_hosts_summary(db)

    logger.info(
        "Built dashboard summary",
        extra={
            "anomaly_scores": counts.anomaly_scores,
            "anomalous": counts.anomalous,
            "incidents": counts.incidents,
            "has_model": model_summary is not None,
            "unique_scored_host_count": hosts_summary.unique_scored_host_count,
        },
    )

    return DashboardSummaryResponse(
        counts=counts,
        anomaly_summary=anomaly_summary,
        risk_summary=risk_summary,
        model=model_summary,
        hosts=hosts_summary,
    )