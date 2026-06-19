"""
Anomaly model module.

Defines the Pydantic V2 schema for the `anomalies` MongoDB collection,
per ARCHITECTURE_V2.md Section 5: stores the autoencoder's per-event
reconstruction-error output and anomaly verdict.
"""

from __future__ import annotations

from datetime import datetime, timezone

from bson import ObjectId
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.raw_log import PyObjectId


class Anomaly(BaseModel):
    """
    Schema for a document in the `anomalies` collection.

    Represents the autoencoder's verdict for a single processed event:
    its reconstruction error, the threshold it was compared against,
    whether it was flagged anomalous, and which model version produced
    the score.
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
    feature_ref: PyObjectId = Field(
        ...,
        description="Reference to the source document in `processed_events`.",
    )
    host: str = Field(
        ...,
        min_length=1,
        description="Hostname this anomaly score pertains to.",
    )
    reconstruction_error: float = Field(
        ...,
        ge=0.0,
        description=(
            "Autoencoder reconstruction error for the associated "
            "feature vector. Higher values indicate the input deviates "
            "more from learned benign behavior."
        ),
    )
    threshold_used: float = Field(
        ...,
        ge=0.0,
        description=(
            "Reconstruction error threshold (e.g. 95th/99th percentile "
            "of training error) this score was compared against to "
            "determine `is_anomalous`."
        ),
    )
    is_anomalous: bool = Field(
        ...,
        description=(
            "True if reconstruction_error exceeded threshold_used at "
            "the time of detection."
        ),
    )
    model_version: str = Field(
        ...,
        min_length=1,
        description=(
            "Version identifier of the autoencoder model that produced "
            "this score, for audit and reproducibility."
        ),
    )
    detected_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp at which this anomaly score was computed.",
    )

    @field_validator("detected_at")
    @classmethod
    def _ensure_timezone_aware(cls, value: datetime) -> datetime:
        """Normalize naive datetimes to UTC-aware datetimes."""
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value