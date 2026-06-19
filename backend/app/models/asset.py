"""
Asset model module.

Defines the Pydantic V2 schema for the `assets` MongoDB collection, per
ARCHITECTURE_V2.md Section 5: a static, configurable reference table of
host criticality, consumed by the Risk Scoring Module as the source of
the asset_criticality_component.
"""

from __future__ import annotations

from enum import Enum

from bson import ObjectId
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.raw_log import PyObjectId


class CriticalityLevel(str, Enum):
    """Static criticality classification for a host/asset."""

    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class Asset(BaseModel):
    """
    Schema for a document in the `assets` collection.

    Represents a static, analyst-configured criticality rating for a
    single host, used by the Risk Scoring Module to compute the
    asset_criticality_component of an incident's final risk score.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str},
    )

    id: PyObjectId = Field(
        default_factory=lambda: PyObjectId(ObjectId()),
        alias="_id",
        description="MongoDB document identifier.",
    )
    hostname: str = Field(
        ...,
        min_length=1,
        description=(
            "Hostname of the asset, matched against `host` fields in "
            "raw_logs/processed_events/anomalies/incidents."
        ),
    )
    criticality_level: CriticalityLevel = Field(
        ...,
        description=(
            "Static criticality classification for this host "
            "(Low/Medium/High/Critical), configured by an analyst."
        ),
    )
    owner_team: str = Field(
        ...,
        min_length=1,
        description="Name of the team responsible for owning/operating this asset.",
    )

    @field_validator("hostname", "owner_team")
    @classmethod
    def _strip_and_validate_non_empty(cls, value: str) -> str:
        """Reject hostname/owner_team values that are empty or whitespace-only."""
        stripped = value.strip()
        if not stripped:
            raise ValueError("value must not be empty or whitespace-only")
        return stripped