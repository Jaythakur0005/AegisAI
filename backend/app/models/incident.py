"""
Incident model module.

Defines the Pydantic V2 schema for the `incidents` MongoDB collection,
per ARCHITECTURE_V2.md Section 5 / Stage 4: a correlated, chronological
timeline of related anomalous events for a single host, grouped by a
host + time-window correlation step.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import List

from bson import ObjectId
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models.raw_log import PyObjectId


class IncidentStatus(str, Enum):
    """Analyst-managed lifecycle status for an incident."""

    NEW = "new"
    REVIEWED = "reviewed"
    CLOSED = "closed"


class Incident(BaseModel):
    """
    Schema for a document in the `incidents` collection.

    Represents anomalous events for a host, correlated by time window
    and process lineage, ordered into a chronological sequence
    (e.g. process spawn → network connection → file write).
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
    host: str = Field(
        ...,
        min_length=1,
        description="Hostname this incident's correlated events belong to.",
    )
    start_time: datetime = Field(
        ...,
        description="UTC timestamp of the earliest event in this incident.",
    )
    end_time: datetime = Field(
        ...,
        description="UTC timestamp of the latest event in this incident.",
    )
    event_sequence: List[PyObjectId] = Field(
        ...,
        min_length=1,
        description=(
            "Ordered references to the underlying anomalous events "
            "(`anomalies` documents) that make up this incident's "
            "chronological timeline."
        ),
    )
    status: IncidentStatus = Field(
        default=IncidentStatus.NEW,
        description=(
            "Analyst review status: 'new' (unreviewed), 'reviewed', or "
            "'closed'."
        ),
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp at which this incident was created.",
    )

    @field_validator("start_time", "end_time", "created_at")
    @classmethod
    def _ensure_timezone_aware(cls, value: datetime) -> datetime:
        """Normalize naive datetimes to UTC-aware datetimes."""
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value

    @model_validator(mode="after")
    def _validate_time_range(self) -> "Incident":
        """Ensure end_time does not precede start_time."""
        if self.end_time < self.start_time:
            raise ValueError("end_time must not be earlier than start_time")
        return self