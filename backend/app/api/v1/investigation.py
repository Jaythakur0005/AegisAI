"""
Investigation API routes.

Implements the Investigation (LLM) endpoints from ARCHITECTURE_V2.md
Section 6:

    GET  /api/v1/investigation/{incident_id}           - Retrieve
                                                           stored
                                                           narrative
    POST /api/v1/investigation/{incident_id}/generate   - Trigger
                                                           narrative
                                                           generation

This module reads directly from the `investigations` collection via
`app.db.mongo_client.get_database()`, consistent with the precedent set
by every prior API/service module.


POST /api/v1/investigation/{incident_id}/generate

Generates or retrieves an investigation report for a
single incident using generate_investigation_for_incident().

The endpoint does not trigger batch investigation
generation and operates only on the requested incident.

"""

from __future__ import annotations

from typing import List, Optional

from bson import ObjectId
from bson.errors import InvalidId
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from pymongo.errors import PyMongoError

from app.core.logging import get_logger
from app.db.mongo_client import get_database
from app.models.incident import Incident
from app.models.investigation import Investigation
from app.services.investigation_report_generator import (
    InvestigationReportError,
    generate_investigation_for_incident,
)

logger = get_logger(__name__)

router = APIRouter(prefix="/investigation", tags=["Investigation"])

_INVESTIGATIONS_COLLECTION = "investigations"
_INCIDENTS_COLLECTION = "incidents"


class InvestigationResponse(BaseModel):
    """
    API response schema for a single investigation narrative.

    Mirrors `app.models.investigation.Investigation`, representing
    `id` and `incident_ref` as strings (rather than `PyObjectId`),
    appropriate for a JSON API response.
    """

    id: str = Field(..., description="Investigation document identifier.")
    incident_ref: str = Field(
        ..., description="Reference to the source document in `incidents`."
    )
    narrative_text: str = Field(
        ..., description="The generated investigation narrative."
    )
    llm_model_used: str = Field(
        ..., description="Identifier of the model/engine that generated this narrative."
    )
    prompt_version: str = Field(
        ..., description="Version identifier of the template/prompt used."
    )
    confidence_score: float = Field(
        ..., description="Confidence in the generated narrative (0.0-1.0)."
    )
    generated_at: str = Field(
        ..., description="UTC timestamp at which this narrative was generated, ISO 8601."
    )

    @classmethod
    def from_investigation(cls, investigation: Investigation) -> "InvestigationResponse":
        """Build an `InvestigationResponse` from an `Investigation` model instance."""
        return cls(
            id=str(investigation.id),
            incident_ref=str(investigation.incident_ref),
            narrative_text=investigation.narrative_text,
            llm_model_used=investigation.llm_model_used,
            prompt_version=investigation.prompt_version,
            confidence_score=investigation.confidence_score,
            generated_at=investigation.generated_at.isoformat(),
        )


class InvestigationGenerateResponse(BaseModel):
    """
    API response schema for a generation request.

    Includes `batch_reports_generated`, the total number of
    investigation reports created across ALL incidents during this
    request (see module docstring on the batch-generation side
    effect), so callers are never silently unaware that more than the
    requested incident may have been affected.
    """

    investigation: InvestigationResponse = Field(
        ..., description="The investigation narrative for the requested incident."
    )
    batch_reports_generated: int = Field(
        ...,
        description=(
            "Total number of investigation reports generated across "
            "ALL previously-unreported incidents during this request, "
            "including (but not limited to) the requested incident_id. "
            "See module docstring."
        ),
    )


def _parse_object_id(raw_id: str) -> ObjectId:
    """
    Parse a string into an `ObjectId`, raising an HTTP 400 if invalid.

    Args:
        raw_id: The string to parse.

    Returns:
        The parsed `ObjectId`.

    Raises:
        HTTPException: 400 if `raw_id` is not a valid ObjectId.
    """
    try:
        return ObjectId(raw_id)
    except (InvalidId, TypeError) as exc:
        logger.warning("Rejected invalid incident_id", extra={"incident_id": raw_id})
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid incident_id: {raw_id!r}",
        ) from exc


async def _fetch_incident(incident_id: str, object_id: ObjectId) -> Incident:
    """
    Fetch and parse an `Incident` document by `_id`, raising
    appropriate HTTP errors if it does not exist or is malformed.

    Raises:
        HTTPException: 404 if no matching incident exists, 500 if the
            database query fails or the stored document is malformed.
    """
    db = get_database()

    try:
        document = await db[_INCIDENTS_COLLECTION].find_one({"_id": object_id})
    except PyMongoError as exc:
        logger.exception(
            "Failed to query incidents collection",
            extra={"incident_id": incident_id},
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve incident.",
        ) from exc

    if document is None:
        logger.info("Incident not found", extra={"incident_id": incident_id})
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident not found: {incident_id}",
        )

    try:
        return Incident(**document)
    except Exception as exc:  # noqa: BLE001 - malformed stored document
        logger.exception(
            "Failed to parse incident document",
            extra={"incident_id": incident_id},
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Stored incident document is malformed.",
        ) from exc


async def _fetch_investigation_for_incident(
    object_id: ObjectId,
) -> Optional[Investigation]:
    """
    Fetch the `Investigation` document whose `incident_ref` matches
    `object_id`, if one exists.

    Returns None if no investigation has been generated for this
    incident, rather than raising.

    Raises:
        HTTPException: 500 if the database query fails or the stored
            document is malformed.
    """
    db = get_database()

    try:
        document = await db[_INVESTIGATIONS_COLLECTION].find_one(
            {"incident_ref": object_id}
        )
    except PyMongoError as exc:
        logger.exception(
            "Failed to query investigations collection",
            extra={"incident_id": str(object_id)},
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve investigation.",
        ) from exc

    if document is None:
        return None

    try:
        return Investigation(**document)
    except Exception as exc:  # noqa: BLE001 - malformed stored document
        logger.exception(
            "Failed to parse investigation document",
            extra={"incident_id": str(object_id)},
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Stored investigation document is malformed.",
        ) from exc


@router.get(
    "/{incident_id}",
    response_model=InvestigationResponse,
    summary="Get investigation narrative",
    description="Retrieve the stored investigation narrative for an incident.",
)
async def get_investigation(incident_id: str) -> InvestigationResponse:
    """
    Retrieve the stored investigation narrative for a single incident.

    Raises:
        HTTPException: 400 if `incident_id` is not a valid ObjectId,
            404 if the incident does not exist or has no investigation
            yet, 500 if the database query fails.
    """
    object_id = _parse_object_id(incident_id)

    logger.info("Fetching investigation", extra={"incident_id": incident_id})

    # Confirm the incident itself exists, so a 404 distinguishes
    # "incident not found" from "incident exists but has no report
    # yet" via the error detail message.
    await _fetch_incident(incident_id, object_id)

    investigation = await _fetch_investigation_for_incident(
        object_id
    )

    if investigation is None:
        logger.info(
            "No investigation found for incident",
            extra={"incident_id": incident_id},
        )

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"No investigation report exists yet for incident "
                f"{incident_id}. Use POST /investigation/{incident_id}/"
                f"generate to create one."
            ),
        )

    logger.info(
        "Retrieved investigation",
        extra={"incident_id": incident_id, "investigation_id": str(investigation.id)},
    )

    return InvestigationResponse.from_investigation(investigation)


@router.post(
    "/{incident_id}/generate",
    response_model=InvestigationGenerateResponse,
    summary="Generate investigation narrative",
    description=(
        "Trigger investigation narrative generation. NOTE: the "
        "underlying service only exposes batch generation across all "
        "unreported incidents, so this request may also generate "
        "reports for incidents other than incident_id. See "
        "batch_reports_generated in the response."
    ),
)
async def generate_investigation(incident_id: str) -> InvestigationGenerateResponse:
    """
    Trigger investigation narrative generation and return the result
    for the requested incident.

    Calls the underlying batch generation service
    (`run_investigation_report_generation`), which generates reports
    for every incident currently lacking one — not only `incident_id`.
    See module docstring for why this module does not call a
    per-incident generation function (none exists without reaching
    into the service's private internals).

    If an investigation already exists for `incident_id` prior to this
    call, that existing investigation is returned without triggering
    regeneration, since the underlying service already skips incidents
    that already have a report (per its own "skip already-reported
    incidents" behavior).

    Raises:
        HTTPException: 400 if `incident_id` is not a valid ObjectId,
            404 if the incident does not exist or no investigation
            could be produced for it, 500 if generation or the
            database query fails.
    """
    object_id = _parse_object_id(incident_id)

    logger.info(
        "Generation requested for incident", extra={"incident_id": incident_id}
    )

    await _fetch_incident(incident_id, object_id)

    existing_investigation = await _fetch_investigation_for_incident(object_id)
    if existing_investigation is not None:
        logger.info(
            "Investigation already exists for incident; returning existing "
            "report without triggering batch generation",
            extra={"incident_id": incident_id},
        )
        return InvestigationGenerateResponse(
            investigation=InvestigationResponse.from_investigation(
                existing_investigation
            ),
            batch_reports_generated=0,
        )

    logger.warning(
        "Triggering batch investigation generation as a side effect of "
        "single-incident request; other unreported incidents may also "
        "receive generated reports",
        extra={"incident_id": incident_id},
    )

    try:
        investigation = await generate_investigation_for_incident(
            incident_id
        )
    except InvestigationReportError as exc:
        logger.exception(
            "Investigation report generation failed",
            extra={"incident_id": incident_id},
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate investigation report.",
        ) from exc

    if investigation is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident not found: {incident_id}",
        )

    logger.info(
        "Generated investigation for incident",
        extra={
            "incident_id": incident_id,
            "investigation_id": str(investigation.id),
        },
    )

    return InvestigationGenerateResponse(
        investigation=InvestigationResponse.from_investigation(
            investigation
        ),
        batch_reports_generated=1,
    )