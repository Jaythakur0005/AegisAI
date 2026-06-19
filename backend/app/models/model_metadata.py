"""
Model metadata model module.

Defines the Pydantic V2 schema for the `model_metadata` MongoDB
collection, per ARCHITECTURE_V2.md Section 5: versioning and audit
records for trained autoencoder models, including training provenance,
the derived anomaly threshold, and training metrics.
"""

from __future__ import annotations

from datetime import datetime, timezone

from bson import ObjectId
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.raw_log import PyObjectId


class TrainingMetrics(BaseModel):
    """Training/validation loss metrics recorded for a model version."""

    model_config = ConfigDict(populate_by_name=True)

    loss: float = Field(
        ...,
        ge=0.0,
        description="Final training-set reconstruction loss.",
    )
    val_loss: float = Field(
        ...,
        ge=0.0,
        description="Final validation-set reconstruction loss.",
    )


class ModelMetadata(BaseModel):
    """
    Schema for a document in the `model_metadata` collection.

    Represents a single trained autoencoder model version, recording
    when and on what data it was trained, the reconstruction-error
    threshold derived from that training run, and the resulting
    loss/val_loss metrics — for versioning and audit purposes.
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
    model_version: str = Field(
        ...,
        min_length=1,
        description=(
            "Version identifier of the trained autoencoder model "
            "(e.g. 'v1.0.0'), referenced by `anomalies.model_version`."
        ),
    )
    training_date: datetime = Field(
        ...,
        description="UTC timestamp at which this model version was trained.",
    )
    training_data_summary: str = Field(
        ...,
        min_length=1,
        description=(
            "Human-readable summary of the training dataset used "
            "(e.g. source, size, time range, host(s))."
        ),
    )
    threshold_value: float = Field(
        ...,
        ge=0.0,
        description=(
            "Reconstruction-error threshold derived from this training "
            "run (e.g. 95th/99th percentile of training error), used "
            "by the inference pipeline to flag anomalies."
        ),
    )
    metrics: TrainingMetrics = Field(
        ...,
        description="Training and validation loss metrics for this model version.",
    )

    @field_validator("training_date")
    @classmethod
    def _ensure_timezone_aware(cls, value: datetime) -> datetime:
        """Normalize naive datetimes to UTC-aware datetimes."""
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value

    @field_validator("training_data_summary")
    @classmethod
    def _strip_and_validate_summary(cls, value: str) -> str:
        """Reject a summary that's empty or whitespace-only after stripping."""
        stripped = value.strip()
        if not stripped:
            raise ValueError(
                "training_data_summary must not be empty or whitespace-only"
            )
        return stripped