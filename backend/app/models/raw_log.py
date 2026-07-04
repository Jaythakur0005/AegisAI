"""
Raw log model module.

Defines the Pydantic V2 schema for the `raw_logs` MongoDB collection, per
ARCHITECTURE_V2.md Section 5: stores ingested Sysmon event batches with
their source metadata and raw event payload.

Also defines `PyObjectId`, a shared MongoDB ObjectId type used across all
model modules (raw_log, processed_event, anomaly, and future models) for
consistent (de)serialization between BSON and JSON.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict

from bson import ObjectId
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    GetCoreSchemaHandler,
    field_validator,
)
from pydantic_core import core_schema


class PyObjectId(ObjectId):
    """
    Pydantic V2-compatible wrapper around BSON's ObjectId.

    Allows MongoDB's `_id` (and any reference field storing an ObjectId)
    to be validated and serialized correctly by Pydantic, accepting
    either an `ObjectId` instance or a valid 24-character hex string on
    input, and serializing to a plain string on output (e.g. for JSON
    API responses).
    """

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: GetCoreSchemaHandler
    ) -> core_schema.CoreSchema:
        return core_schema.json_or_python_schema(
            json_schema=core_schema.no_info_plain_validator_function(
                cls.validate
            ),
            python_schema=core_schema.union_schema(
                [
                    core_schema.is_instance_schema(ObjectId),
                    core_schema.no_info_plain_validator_function(
                        cls.validate
                    ),
                ]
            ),
            serialization=core_schema.plain_serializer_function_ser_schema(
                str,
                when_used="json",
            ),
        )

    @classmethod
    def validate(cls, value: Any) -> ObjectId:
        """Validate that `value` is a valid ObjectId or hex string."""
        if isinstance(value, ObjectId):
            return value
        if isinstance(value, str) and ObjectId.is_valid(value):
            return ObjectId(value)
        raise ValueError(f"Invalid ObjectId: {value!r}")


class RawLog(BaseModel):
    """
    Schema for a document in the `raw_logs` collection.

    Represents a single ingested Sysmon event, stored with provenance
    metadata (host, source file, ingestion time) and the original raw
    event payload as received from the export pipeline.
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
        description="Hostname of the machine that generated the event.",
    )
    source_file: str = Field(
        ...,
        min_length=1,
        description=(
            "Name or path of the original exported log file this event "
            "was parsed from (e.g. a converted EVTX/JSON/CSV export)."
        ),
    )
    event_id: int = Field(
        ...,
        ge=1,
        description=(
            "Sysmon Event ID (e.g. 1=process creation, 3=network "
            "connection, 7=image loaded, 11=file create, 13=registry "
            "value set)."
        ),
    )
    timestamp: datetime = Field(
        ...,
        description="UTC timestamp at which the original event occurred.",
    )
    raw_event: Dict[str, Any] = Field(
        ...,
        description=(
            "The raw, unmodified event payload as parsed from the "
            "source export, preserved for audit and re-processing."
        ),
    )
    ingested_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp at which this record was ingested.",
    )

    @field_validator("timestamp", "ingested_at")
    @classmethod
    def _ensure_timezone_aware(cls, value: datetime) -> datetime:
        """Normalize naive datetimes to UTC-aware datetimes."""
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value

    @field_validator("raw_event")
    @classmethod
    def _ensure_raw_event_not_empty(
        cls, value: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Reject an empty raw event payload — it carries no signal."""
        if not value:
            raise ValueError("raw_event must not be empty")
        return value