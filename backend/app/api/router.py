"""
Top-level API router aggregation.

Combines all versioned sub-routers (health, and — in future increments —
ingestion, detection, incidents, investigation, mitre, risk, dashboard,
per ARCHITECTURE_V2.md Section 6) into a single router that `main.py`
mounts under the configured API prefix.

This module intentionally does not import any ML, LLM, MITRE mapping,
timeline, or dashboard route modules yet — those are added here as they
are implemented, without requiring changes to main.py.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import health
from app.core.logging import get_logger

logger = get_logger(__name__)

api_router = APIRouter()

api_router.include_router(health.router)

logger.debug("API router initialized with sub-routers: health")