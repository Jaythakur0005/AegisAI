"""
Processed event model module.

Defines the Pydantic V2 schema for the `processed_events` MongoDB
collection, per ARCHITECTURE_V2.md Section 5: engineered feature vectors
derived from raw_logs, used as input to the autoencoder anomaly detector.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List

from bson import ObjectId
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models.raw_log import PyObjectId


class ProcessedEvent(BaseModel):
    """
    Schema for a document in the `processed_events` collection.

    Represents a numerical feature vector engineered from one or more
    raw log events within a host/time window, ready for autoencoder
    inference. `feature_names` provides positional labels for
    `feature_vector`, preserving interpretability.
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
    raw_log_ref: PyObjectId = Field(
        ...,
        description="Reference to the source document in `raw_logs`.",
    )
    host: str = Field(
        ...,
        min_length=1,
        description="Hostname this feature vector was derived from.",
    )
    window_start: datetime = Field(
        ...,
        description="UTC start of the time window this vector summarizes.",
    )
    window_end: datetime = Field(
        ...,
        description="UTC end of the time window this vector summarizes.",
    )
    feature_vector: List[float] = Field(
        ...,
        min_length=1,
        description=(
            "Numerical feature values (e.g. process creation frequency, "
            "parent-child process anomalies, network connection counts, "
            "registry/file write patterns, command-line entropy, "
            "time-of-day buckets) in the same order as `feature_names`."
        ),
    )
    feature_names: List[str] = Field(
        ...,
        min_length=1,
        description=(
            "Human-readable name for each position in `feature_vector`, "
            "used for interpretability and downstream explainability."
        ),
    )

    @field_validator("window_start", "window_end")
    @classmethod
    def _ensure_timezone_aware(cls, value: datetime) -> datetime:
        """Normalize naive datetimes to UTC-aware datetimes."""
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value

    @model_validator(mode="after")
    def _validate_window_and_lengths(self) -> "ProcessedEvent":
        """
        Cross-field validation:
        - `window_end` must not precede `window_start`.
        - `feature_vector` and `feature_names` must be the same length,
          since each vector position is positionally labeled by name.
        """
        if self.window_end < self.window_start:
            raise ValueError(
                "window_end must not be earlier than window_start"
            )
        if len(self.feature_vector) != len(self.feature_names):
            raise ValueError(
                "feature_vector and feature_names must have the same "
                f"length (got {len(self.feature_vector)} and "
                f"{len(self.feature_names)})"
            )
        return self