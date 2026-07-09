"""
Top-level API router aggregation.

Combines all versioned sub-routers into a single router that main.py
mounts under the configured API prefix.
"""

from fastapi import APIRouter

from app.api.v1 import dashboard, health, incidents, investigation, pipeline
from app.core.logging import get_logger

logger = get_logger(__name__)

api_router = APIRouter()

api_router.include_router(health.router)
api_router.include_router(incidents.router)
api_router.include_router(investigation.router)
api_router.include_router(pipeline.router)
api_router.include_router(dashboard.router)

logger.debug(
    "API router initialized with sub-routers: health, incidents, "
    "investigation, pipeline, dashboard"
)