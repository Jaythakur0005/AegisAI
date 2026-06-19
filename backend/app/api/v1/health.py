"""
Health check route module.

Implements GET /api/v1/health as specified in ARCHITECTURE_V2.md
(Section 6 — System). Used by Docker Compose healthchecks and by
operators/monitoring to verify the API and its MongoDB dependency
are up.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Response, status
from pydantic import BaseModel

from app.core.config import get_settings
from app.core.logging import get_logger
from app.db.mongo_client import check_mongo_health

logger = get_logger(__name__)

router = APIRouter(tags=["System"])


class DependencyStatus(BaseModel):
    """Health status of a single upstream dependency."""

    name: str
    status: Literal["up", "down"]


class HealthResponse(BaseModel):
    """Response schema for the health check endpoint."""

    status: Literal["healthy", "degraded"]
    app_name: str
    app_env: str
    model_version: str
    timestamp: str
    dependencies: list[DependencyStatus]


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    description=(
        "Reports overall application status and the reachability of "
        "critical dependencies (MongoDB). Used by Docker Compose "
        "healthchecks."
    ),
)
async def get_health(response: Response) -> HealthResponse:
    """
    Return the current health of the API and its dependencies.

    The HTTP status code is 200 when healthy and 503 when any checked
    dependency is unreachable, so container orchestrators can act on
    it directly without parsing the body.
    """
    settings = get_settings()

    try:
        mongo_up = await check_mongo_health()
    except Exception:
        # Defensive: a health check must never itself raise and take
        # the endpoint down with it.
        logger.exception("Unexpected error while checking MongoDB health")
        mongo_up = False

    dependencies = [
        DependencyStatus(name="mongodb", status="up" if mongo_up else "down")
    ]

    overall_status: Literal["healthy", "degraded"] = (
        "healthy" if mongo_up else "degraded"
    )

    if overall_status == "degraded":
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        logger.warning(
            "Health check reporting degraded status",
            extra={"dependencies": [d.model_dump() for d in dependencies]},
        )
    else:
        logger.debug("Health check OK")

    return HealthResponse(
        status=overall_status,
        app_name=settings.app_name,
        app_env=settings.app_env,
        model_version=settings.model_version,
        timestamp=datetime.now(timezone.utc).isoformat(),
        dependencies=dependencies,
    )