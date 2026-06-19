"""
Attack mapping model module.

Defines the Pydantic V2 schema for the `attack_mappings` MongoDB
collection, per ARCHITECTURE_V2.md Section 5 / Field Notes / Stage 6:
the MITRE ATT&CK tactic/technique mapping for a given incident, grounded
in the local attack_lookup.json reference table and justified by the LLM.
"""

from __future__ import annotations

from enum import Enum

from bson import ObjectId
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.raw_log import PyObjectId


class SeverityLevel(str, Enum):
    """
    Static severity classification tied to a mapped MITRE technique.

    Used downstream by the Risk Scoring Engine as the
    `technique_severity_component`.
    """

    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class AttackMapping(BaseModel):
    """
    Schema for a document in the `attack_mappings` collection.

    Represents a single MITRE ATT&CK tactic/technique match for an
    incident, selected from the curated local lookup table (kept
    grounded — the LLM ranks/explains candidates but does not invent
    technique IDs), along with the model's confidence and justification.
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
    incident_ref: PyObjectId = Field(
        ...,
        description="Reference to the source document in `incidents`.",
    )
    tactic_id: str = Field(
        ...,
        min_length=1,
        description=(
            "MITRE ATT&CK tactic identifier (e.g. 'TA0002'), sourced "
            "from the local attack_lookup.json cache."
        ),
    )
    technique_id: str = Field(
        ...,
        min_length=1,
        description=(
            "MITRE ATT&CK technique identifier (e.g. 'T1059'), sourced "
            "from the local attack_lookup.json cache."
        ),
    )
    technique_name: str = Field(
        ...,
        min_length=1,
        description=(
            "Human-readable name of the mapped technique (e.g. "
            "'Command and Scripting Interpreter')."
        ),
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence in this MITRE technique match, from 0.0 to 1.0.",
    )
    severity_level: SeverityLevel = Field(
        ...,
        description=(
            "Static severity classification tied to the mapped "
            "technique; consumed by the Risk Scoring Engine as the "
            "technique_severity_component."
        ),
    )
    justification_text: str = Field(
        ...,
        min_length=1,
        description=(
            "LLM-generated explanation justifying why this technique "
            "was selected as the best fit for the incident's timeline."
        ),
    )

    @field_validator("tactic_id")
    @classmethod
    def _validate_tactic_id_format(cls, value: str) -> str:
        """Validate tactic_id follows MITRE's 'TAxxxx' convention."""
        if not value.startswith("TA") or not value[2:].isdigit():
            raise ValueError(
                f"tactic_id must follow the 'TAxxxx' format, got {value!r}"
            )
        return value

    @field_validator("technique_id")
    @classmethod
    def _validate_technique_id_format(cls, value: str) -> str:
        """
        Validate technique_id follows MITRE's 'Txxxx' or sub-technique
        'Txxxx.xxx' convention.
        """
        base = value.split(".")[0]
        if not base.startswith("T") or not base[1:].isdigit():
            raise ValueError(
                f"technique_id must follow the 'Txxxx' or 'Txxxx.xxx' "
                f"format, got {value!r}"
            )
        return value

    @field_validator("justification_text")
    @classmethod
    def _strip_and_validate_justification(cls, value: str) -> str:
        """Reject justification text that's empty or whitespace-only after stripping."""
        stripped = value.strip()
        if not stripped:
            raise ValueError(
                "justification_text must not be empty or whitespace-only"
            )
        return stripped