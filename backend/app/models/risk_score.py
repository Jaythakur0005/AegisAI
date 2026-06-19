"""
Risk score model module.

Defines the Pydantic V2 schema for the `risk_scores` MongoDB collection,
per ARCHITECTURE_V2.md Section 5 / Stage 7: the final computed risk for
an incident, combining anomaly score, technique severity, and asset
criticality into a 0-100 score and risk label.
"""

from __future__ import annotations

from enum import Enum

from bson import ObjectId
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.models.raw_log import PyObjectId


class RiskLabel(str, Enum):
    """Risk classification label derived from the final 0-100 risk score."""

    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class RiskScore(BaseModel):
    """
    Schema for a document in the `risk_scores` collection.

    Represents the weighted-function output combining the autoencoder's
    anomaly score, the MITRE technique severity weight, and the static
    asset/host criticality value into a single 0-100 risk score and
    Low/Medium/High/Critical label for an incident.
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
    anomaly_component: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description=(
            "Contribution to the final score derived from the "
            "autoencoder's anomaly/reconstruction-error score, "
            "normalized to a 0-100 scale."
        ),
    )
    technique_severity_component: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description=(
            "Contribution to the final score derived from the mapped "
            "MITRE technique's severity_level, normalized to a 0-100 "
            "scale."
        ),
    )
    asset_criticality_component: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description=(
            "Contribution to the final score derived from the static, "
            "configurable criticality of the affected asset/host, "
            "normalized to a 0-100 scale."
        ),
    )
    final_score: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description=(
            "Final weighted risk score (0-100) combining the anomaly, "
            "technique severity, and asset criticality components."
        ),
    )
    risk_label: RiskLabel = Field(
        ...,
        description=(
            "Categorical risk classification derived from final_score "
            "(Low/Medium/High/Critical)."
        ),
    )

    @model_validator(mode="after")
    def _validate_label_matches_score(self) -> "RiskScore":
        """
        Ensure risk_label is consistent with final_score using the
        standard banding: Low [0-25), Medium [25-50), High [50-75),
        Critical [75-100].

        This guards against a caller persisting a label that was
        computed with different banding logic than the canonical
        scoring module, catching drift early.
        """
        score = self.final_score
        if score < 25.0:
            expected = RiskLabel.LOW
        elif score < 50.0:
            expected = RiskLabel.MEDIUM
        elif score < 75.0:
            expected = RiskLabel.HIGH
        else:
            expected = RiskLabel.CRITICAL

        if self.risk_label != expected:
            raise ValueError(
                f"risk_label {self.risk_label.value!r} is inconsistent "
                f"with final_score {score}; expected {expected.value!r} "
                "based on standard risk banding"
            )
        return self