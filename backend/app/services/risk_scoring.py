"""
Risk scoring service.

Implements Stage 7 (Risk Scoring) from ARCHITECTURE_V2.md: combines the
autoencoder's anomaly score, the mapped MITRE technique's severity
weight, and the static asset/host criticality value into a single
0-100 risk score and Low/Medium/High/Critical label per incident,
persisted into the `risk_scores` collection.

Weighted combination uses `Settings.risk_weight_anomaly`,
`Settings.risk_weight_technique_severity`, and
`Settings.risk_weight_asset_criticality` (Stage 7's "weighted function"),
applied to three normalized 0-100 components:

    final_score = (
        risk_weight_anomaly * anomaly_component
        + risk_weight_technique_severity * technique_severity_component
        + risk_weight_asset_criticality * asset_criticality_component
    )

Component derivation:

    - anomaly_component: `RiskScore` itself carries no anomaly data;
      this lives on `Anomaly` documents referenced by
      `Incident.event_sequence`. This module fetches an incident's
      constituent anomalies and derives anomaly_component from the
      maximum (reconstruction_error / threshold_used) ratio across
      them, normalized onto a 0-100 scale. This mirrors the ratio
      metric already used for severity calculation in
      `app.services.incident_builder.compute_incident_severity`,
      applied here to a continuous score rather than a discrete band.
    - technique_severity_component: derived from the highest-severity
      `AttackMapping` matched to the incident (an incident may have
      multiple one-to-many technique mappings, per
      `app.services.mitre_mapper`); each `SeverityLevel` is mapped to
      a fixed 0-100 point value.
    - asset_criticality_component: looked up from the `assets`
      collection by `Incident.host` matching `Asset.hostname`; each
      `CriticalityLevel` is mapped to a fixed 0-100 point value. If no
      matching asset record exists, a documented default is used
      (logged as a warning) rather than failing the incident's score
      entirely, since `assets` is described as a "(config)" reference
      table that may not yet cover every host.

risk_label banding is fixed to exactly match the cross-field validator
already enforced by `app.models.risk_score.RiskScore`
(`_validate_label_matches_score`): Low [0, 25), Medium [25, 50), High
[50, 75), Critical [75, 100]. This module's `_score_to_risk_label`
function must stay in lockstep with that validator, since
`RiskScore` construction will raise a `ValidationError` for any
score/label pair that doesn't match it, and that model cannot be
modified.

This module reads from and writes to MongoDB directly via
`app.db.mongo_client.get_database()`, consistent with the precedent set
by `app.services.log_ingestion`, `app.services.feature_engineering`,
`app.services.anomaly_detector`, `app.services.incident_builder`, and
`app.services.mitre_mapper` (no repository layer exists yet for
`incidents`/`attack_mappings`/`assets`/`anomalies`/`risk_scores`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from pymongo.errors import PyMongoError

from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.db.mongo_client import get_database
from app.models.anomaly import Anomaly
from app.models.asset import Asset, CriticalityLevel
from app.models.attack_mapping import AttackMapping, SeverityLevel
from app.models.incident import Incident
from app.models.risk_score import RiskLabel, RiskScore

logger = get_logger(__name__)

_ANOMALIES_COLLECTION = "anomalies"
_INCIDENTS_COLLECTION = "incidents"
_ATTACK_MAPPINGS_COLLECTION = "attack_mappings"
_ASSETS_COLLECTION = "assets"
_RISK_SCORES_COLLECTION = "risk_scores"

# Multiplier applied to an anomaly's threshold_used beyond which the
# anomaly_component reaches its maximum (100.0). A ratio of 1.0 means
# the error exactly equals the threshold (the minimum bar to have been
# flagged anomalous at all); this constant defines how far past that
# bar an anomaly must be to count as maximally severe for scoring
# purposes. Mirrors the multiplier already used in
# `app.services.incident_builder` for severity banding.
_ANOMALY_RATIO_AT_MAX_SCORE = 4.0

# Fixed point values for each MITRE technique severity level, on the
# same 0-100 scale as the other two components. Not specified
# numerically anywhere in ARCHITECTURE_V2.md beyond the qualitative
# Low/Medium/High/Critical labels already used elsewhere
# (e.g. RiskLabel, IncidentSeverity); chosen to align with this
# module's own final risk_label banding for internal consistency.
_SEVERITY_LEVEL_SCORES: Dict[SeverityLevel, float] = {
    SeverityLevel.LOW: 20.0,
    SeverityLevel.MEDIUM: 45.0,
    SeverityLevel.HIGH: 70.0,
    SeverityLevel.CRITICAL: 95.0,
}

# Fixed point values for each asset criticality level, on the same
# 0-100 scale. Same rationale as _SEVERITY_LEVEL_SCORES above.
_CRITICALITY_LEVEL_SCORES: Dict[CriticalityLevel, float] = {
    CriticalityLevel.LOW: 20.0,
    CriticalityLevel.MEDIUM: 45.0,
    CriticalityLevel.HIGH: 70.0,
    CriticalityLevel.CRITICAL: 95.0,
}

# Default asset_criticality_component applied when an incident's host
# has no matching `assets` document. Treated as "Medium" rather than
# "Low" or "Critical" so an unconfigured host neither silently
# suppresses nor silently inflates the final risk score.
_DEFAULT_CRITICALITY_SCORE = _CRITICALITY_LEVEL_SCORES[CriticalityLevel.MEDIUM]


class RiskScoringError(RuntimeError):
    """
    Raised for failures that prevent risk scoring from proceeding at
    all (e.g. the database is unreachable), as distinct from a single
    malformed incident document, which is skipped and logged rather
    than raised.
    """


@dataclass
class RiskScoringResult:
    """
    Outcome of a risk-scoring run.

    `inserted_ids` holds the Mongo `_id` of every `RiskScore` document
    successfully written. `skipped_incidents` records any incidents
    that could not be scored, each with a reason, without aborting the
    rest of the run.
    """

    inserted_ids: List[str] = field(default_factory=list)
    skipped_incidents: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def incidents_scored(self) -> int:
        """Number of RiskScore documents successfully persisted."""
        return len(self.inserted_ids)


def _score_to_risk_label(score: float) -> RiskLabel:
    """
    Map a final_score to a RiskLabel using the exact banding enforced
    by `RiskScore._validate_label_matches_score`.

    This function MUST stay in lockstep with that validator (Low
    [0, 25), Medium [25, 50), High [50, 75), Critical [75, 100]), since
    any divergence will cause `RiskScore` construction to raise a
    ValidationError for every incident whose score falls in the
    mismatched range.
    """
    if score < 25.0:
        return RiskLabel.LOW
    if score < 50.0:
        return RiskLabel.MEDIUM
    if score < 75.0:
        return RiskLabel.HIGH
    return RiskLabel.CRITICAL


async def _fetch_constituent_anomalies(incident: Incident) -> List[Anomaly]:
    """
    Fetch the `Anomaly` documents referenced by an incident's
    `event_sequence`.

    Malformed documents (failing `Anomaly` validation) are logged and
    skipped individually rather than aborting the fetch.

    Raises:
        RiskScoringError: If querying MongoDB fails.
    """
    if not incident.event_sequence:
        return []

    db = get_database()

    try:
        cursor = db[_ANOMALIES_COLLECTION].find(
            {"_id": {"$in": incident.event_sequence}}
        )
        anomalies: List[Anomaly] = []
        async for document in cursor:
            try:
                anomalies.append(Anomaly(**document))
            except Exception:  # noqa: BLE001 - isolate one bad document
                logger.warning(
                    "Skipping malformed anomalies document referenced "
                    "by incident",
                    extra={
                        "incident_id": str(incident.id),
                        "anomaly_id": str(document.get("_id")),
                    },
                )
    except PyMongoError as exc:
        logger.exception(
            "Failed to fetch constituent anomalies for incident",
            extra={"incident_id": str(incident.id)},
        )
        raise RiskScoringError(
            f"Failed to query anomalies for incident {incident.id}: {exc}"
        ) from exc

    return anomalies


async def _fetch_attack_mappings(incident: Incident) -> List[AttackMapping]:
    """
    Fetch the `AttackMapping` documents whose `incident_ref` matches
    this incident's own `_id`.

    Malformed documents (failing `AttackMapping` validation) are
    logged and skipped individually rather than aborting the fetch.

    Raises:
        RiskScoringError: If querying MongoDB fails.
    """
    db = get_database()

    try:
        cursor = db[_ATTACK_MAPPINGS_COLLECTION].find(
            {"incident_ref": incident.id}
        )
        mappings: List[AttackMapping] = []
        async for document in cursor:
            try:
                mappings.append(AttackMapping(**document))
            except Exception:  # noqa: BLE001 - isolate one bad document
                logger.warning(
                    "Skipping malformed attack_mappings document for "
                    "incident",
                    extra={
                        "incident_id": str(incident.id),
                        "attack_mapping_id": str(document.get("_id")),
                    },
                )
    except PyMongoError as exc:
        logger.exception(
            "Failed to fetch attack_mappings for incident",
            extra={"incident_id": str(incident.id)},
        )
        raise RiskScoringError(
            f"Failed to query attack_mappings for incident "
            f"{incident.id}: {exc}"
        ) from exc

    return mappings


async def _fetch_asset_for_host(host: str) -> Optional[Asset]:
    """
    Fetch the `Asset` document matching `host`, if one exists.

    Returns None (rather than raising) when no matching asset record
    is found, since `assets` is a "(config)" reference table that may
    not yet cover every host, per the module docstring.

    Raises:
        RiskScoringError: If querying MongoDB fails.
    """
    db = get_database()

    try:
        document = await db[_ASSETS_COLLECTION].find_one({"hostname": host})
    except PyMongoError as exc:
        logger.exception(
            "Failed to fetch asset document for host", extra={"host": host}
        )
        raise RiskScoringError(
            f"Failed to query assets for host {host}: {exc}"
        ) from exc

    if document is None:
        return None

    try:
        return Asset(**document)
    except Exception:  # noqa: BLE001 - isolate one bad document
        logger.warning(
            "Skipping malformed assets document for host",
            extra={"host": host, "asset_id": str(document.get("_id"))},
        )
        return None


def _compute_anomaly_component(anomalies: Sequence[Anomaly]) -> float:
    """
    Derive the anomaly_component (0-100) from an incident's
    constituent anomalies.

    Uses the maximum (reconstruction_error / threshold_used) ratio
    across the group, linearly scaled so a ratio of 1.0 (just over the
    anomalous threshold) maps to 0.0 and a ratio of
    `_ANOMALY_RATIO_AT_MAX_SCORE` or higher maps to 100.0.

    Returns 0.0 if `anomalies` is empty (an incident with no
    resolvable constituent anomalies contributes no anomaly signal,
    rather than raising).
    """
    if not anomalies:
        return 0.0

    max_ratio = max(
        (
            anomaly.reconstruction_error / anomaly.threshold_used
            if anomaly.threshold_used > 0
            else _ANOMALY_RATIO_AT_MAX_SCORE
        )
        for anomaly in anomalies
    )

    normalized = (max_ratio - 1.0) / (_ANOMALY_RATIO_AT_MAX_SCORE - 1.0)
    return max(0.0, min(normalized * 100.0, 100.0))


def _compute_technique_severity_component(
    mappings: Sequence[AttackMapping],
) -> float:
    """
    Derive the technique_severity_component (0-100) from an incident's
    matched MITRE techniques.

    An incident may have multiple one-to-many technique mappings; the
    highest-severity match drives the component, since the incident's
    overall technique-driven risk should reflect its most severe
    matched behavior, not an average that could dilute a single
    critical finding.

    Returns 0.0 if `mappings` is empty (an unmapped incident
    contributes no technique-severity signal, rather than raising).
    """
    if not mappings:
        return 0.0

    return max(
        _SEVERITY_LEVEL_SCORES[mapping.severity_level] for mapping in mappings
    )


def _compute_asset_criticality_component(asset: Optional[Asset]) -> float:
    """
    Derive the asset_criticality_component (0-100) from the incident
    host's asset record.

    Returns `_DEFAULT_CRITICALITY_SCORE` if `asset` is None (no
    matching `assets` document for this host), logged as a warning by
    the caller.
    """
    if asset is None:
        return _DEFAULT_CRITICALITY_SCORE
    return _CRITICALITY_LEVEL_SCORES[asset.criticality_level]


def _compute_final_score(
    settings: Settings,
    anomaly_component: float,
    technique_severity_component: float,
    asset_criticality_component: float,
) -> float:
    """
    Combine the three components into a single 0-100 final_score using
    the configured risk weights (Stage 7's "weighted function").
    """
    weighted_sum = (
        settings.risk_weight_anomaly * anomaly_component
        + settings.risk_weight_technique_severity * technique_severity_component
        + settings.risk_weight_asset_criticality * asset_criticality_component
    )
    return max(0.0, min(weighted_sum, 100.0))


async def _build_risk_score(
    settings: Settings, incident: Incident
) -> RiskScore:
    """
    Build a single `RiskScore` for one incident, fetching all required
    upstream data (constituent anomalies, attack mappings, asset
    record) and computing each weighted component.

    Raises:
        RiskScoringError: If any upstream fetch fails at the
            infrastructure level.
        Exception: If `RiskScore` construction itself fails (e.g. a
            label/score banding mismatch, which should not occur given
            `_score_to_risk_label`'s lockstep guarantee, but is not
            suppressed here so any future drift surfaces loudly).
    """
    anomalies = await _fetch_constituent_anomalies(incident)
    mappings = await _fetch_attack_mappings(incident)
    asset = await _fetch_asset_for_host(incident.host)

    if asset is None:
        logger.warning(
            "No assets record found for host; using default "
            "criticality component",
            extra={
                "incident_id": str(incident.id),
                "host": incident.host,
                "default_score": _DEFAULT_CRITICALITY_SCORE,
            },
        )

    anomaly_component = _compute_anomaly_component(anomalies)
    technique_severity_component = _compute_technique_severity_component(mappings)
    asset_criticality_component = _compute_asset_criticality_component(asset)

    final_score = _compute_final_score(
        settings,
        anomaly_component,
        technique_severity_component,
        asset_criticality_component,
    )
    risk_label = _score_to_risk_label(final_score)

    logger.info(
        "Computed risk score for incident",
        extra={
            "incident_id": str(incident.id),
            "host": incident.host,
            "anomaly_component": anomaly_component,
            "technique_severity_component": technique_severity_component,
            "asset_criticality_component": asset_criticality_component,
            "final_score": final_score,
            "risk_label": risk_label.value,
        },
    )

    return RiskScore(
        incident_ref=incident.id,
        anomaly_component=anomaly_component,
        technique_severity_component=technique_severity_component,
        asset_criticality_component=asset_criticality_component,
        final_score=final_score,
        risk_label=risk_label,
    )


async def _fetch_unscored_incidents() -> List[Incident]:
    """
    Fetch all `incidents` documents not yet referenced by an existing
    `risk_scores` document, parsed into `Incident` instances.

    Malformed documents (failing `Incident` validation) are logged and
    skipped individually rather than aborting the fetch.

    Raises:
        RiskScoringError: If querying MongoDB fails.
    """
    db = get_database()

    try:
        already_scored_refs = {
            doc["incident_ref"]
            async for doc in db[_RISK_SCORES_COLLECTION].find(
                {}, {"incident_ref": 1}
            )
        }
    except PyMongoError as exc:
        logger.exception("Failed to fetch existing risk_scores refs")
        raise RiskScoringError(
            f"Failed to query risk_scores: {exc}"
        ) from exc

    incidents: List[Incident] = []
    try:
        cursor = db[_INCIDENTS_COLLECTION].find({})
        async for document in cursor:
            if document.get("_id") in already_scored_refs:
                continue
            try:
                incidents.append(Incident(**document))
            except Exception:  # noqa: BLE001 - isolate one bad document
                logger.warning(
                    "Skipping malformed incidents document",
                    extra={"incident_id": str(document.get("_id"))},
                )
    except PyMongoError as exc:
        logger.exception("Failed to fetch incidents documents")
        raise RiskScoringError(
            f"Failed to query incidents: {exc}"
        ) from exc

    logger.info("Fetched unscored incidents", extra={"count": len(incidents)})
    return incidents


async def _insert_risk_scores(risk_scores: List[RiskScore]) -> List[str]:
    """
    Persist a list of `RiskScore` instances into `risk_scores`.

    Raises:
        RiskScoringError: If the insert operation fails.
    """
    if not risk_scores:
        return []

    db = get_database()
    documents = [
        risk_score.model_dump(by_alias=True, exclude={"id"})
        for risk_score in risk_scores
    ]

    try:
        if len(documents) == 1:
            result = await db[_RISK_SCORES_COLLECTION].insert_one(documents[0])
            inserted_ids = [str(result.inserted_id)]
        else:
            result = await db[_RISK_SCORES_COLLECTION].insert_many(
                documents, ordered=False
            )
            inserted_ids = [str(_id) for _id in result.inserted_ids]
    except PyMongoError as exc:
        logger.exception(
            "Failed to insert risk_scores documents",
            extra={"attempted_count": len(documents)},
        )
        raise RiskScoringError(
            f"Failed to persist {len(documents)} risk_scores "
            f"document(s): {exc}"
        ) from exc

    logger.info(
        "Inserted risk_scores documents",
        extra={"inserted_count": len(inserted_ids)},
    )
    return inserted_ids


async def run_risk_scoring() -> RiskScoringResult:
    """
    Run Stage 7 (Risk Scoring) end-to-end.

    Fetches all `incidents` documents not yet scored, computes each
    incident's anomaly_component, technique_severity_component, and
    asset_criticality_component from constituent anomalies, matched
    MITRE techniques, and the host's asset record respectively,
    combines them into a final_score and risk_label, and persists the
    resulting `RiskScore` documents with `incident_ref` set to the
    source incident's own `_id`.

    Supports batch processing: all unscored incidents in the database
    are processed in a single run, with per-incident failures isolated
    and reported rather than aborting the whole run.

    Returns:
        A `RiskScoringResult` summarizing every RiskScore inserted and
        every incident skipped.

    Raises:
        RiskScoringError: If fetching unscored incidents or persisting
            risk_scores fails at the infrastructure level.
    """
    settings = get_settings()

    logger.info("Starting risk scoring run")

    result = RiskScoringResult()

    incidents = await _fetch_unscored_incidents()
    if not incidents:
        logger.info("No unscored incidents found; nothing to score")
        return result

    risk_scores: List[RiskScore] = []

    for incident in incidents:
        try:
            risk_score = await _build_risk_score(settings, incident)
            risk_scores.append(risk_score)
        except RiskScoringError:
            logger.exception(
                "Skipping incident due to upstream fetch failure",
                extra={"incident_id": str(incident.id)},
            )
            result.skipped_incidents.append(
                {
                    "incident_id": str(incident.id),
                    "reason": "Failed to fetch upstream data for scoring",
                }
            )
        except Exception:  # noqa: BLE001 - isolate one bad incident
            logger.exception(
                "Failed to build risk score for incident",
                extra={"incident_id": str(incident.id)},
            )
            result.skipped_incidents.append(
                {
                    "incident_id": str(incident.id),
                    "reason": "Risk score construction failed",
                }
            )

    inserted_ids = await _insert_risk_scores(risk_scores)
    result.inserted_ids.extend(inserted_ids)

    logger.info(
        "Completed risk scoring run",
        extra={
            "incidents_scored": result.incidents_scored,
            "incidents_skipped": len(result.skipped_incidents),
        },
    )
    return result