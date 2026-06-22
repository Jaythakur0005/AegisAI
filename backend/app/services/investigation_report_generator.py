"""
Investigation report generator service.

ARCHITECTURE_V2.md Stage 5 describes the Investigation Engine as
sending an incident timeline to the OpenAI API to generate the
analyst-readable narrative. This module is an explicit, deterministic
substitute for that LLM call, per this task's requirement to produce
narratives with NO external LLM dependency. It persists into the same
`investigations` collection and satisfies the same `Investigation`
model contract, but every narrative is built entirely from template
text and the incident's own structured data (no model inference, no
network call). `Investigation.llm_model_used` is set to the literal
string "rule_based" to make this distinction visible and auditable in
every persisted record.

Report sections, each built deterministically from structured inputs:

    - Incident Summary: host, time range, constituent event count.
    - Timeline Summary: chronological description of the incident's
      duration and event density (this module does not re-fetch
      individual anomaly timestamps beyond what `Incident` itself
      stores — start_time/end_time/event_sequence length — since
      doing so would require reading `anomalies`, which is not in this
      task's assumed-existing/required-read list; see module note
      below).
    - MITRE ATT&CK Findings: enumerates every `AttackMapping` matched
      to the incident, with technique ID/name, tactic ID, severity,
      confidence, and its rule-based justification text.
    - Risk Assessment: the incident's `RiskScore` breakdown
      (component values, final_score, risk_label), if one exists.
    - Recommended Actions: deterministic, severity-driven action
      bullets selected by the incident's risk_label and matched
      technique severities.

Investigation.confidence_score derivation: with no LLM to self-report
confidence, this module derives a deterministic confidence value from
how complete the incident's supporting data is — full marks require
both at least one AttackMapping and a RiskScore to exist; a narrative
built from an incident with neither has its confidence_score reduced
accordingly, since a "no MITRE matches, no risk score" narrative is
necessarily a much thinner finding (see `_compute_confidence_score`).

This module reads from and writes to MongoDB directly via
`app.db.mongo_client.get_database()`, consistent with the precedent set
by `app.services.log_ingestion`, `app.services.feature_engineering`,
`app.services.anomaly_detector`, `app.services.incident_builder`,
`app.services.mitre_mapper`, and `app.services.risk_scoring` (no
repository layer exists yet for `incidents`/`attack_mappings`/
`risk_scores`/`investigations`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from bson import ObjectId
from bson.errors import InvalidId

from pymongo.errors import PyMongoError

from app.core.logging import get_logger
from app.db.mongo_client import get_database
from app.models.attack_mapping import AttackMapping, SeverityLevel
from app.models.incident import Incident
from app.models.investigation import Investigation
from app.models.risk_score import RiskLabel, RiskScore

logger = get_logger(__name__)

_INCIDENTS_COLLECTION = "incidents"
_ATTACK_MAPPINGS_COLLECTION = "attack_mappings"
_RISK_SCORES_COLLECTION = "risk_scores"
_INVESTIGATIONS_COLLECTION = "investigations"

# Identifies this module's deterministic generation logic for both the
# Investigation.llm_model_used field (per task requirement) and for
# versioning the template structure used to build narrative_text.
_LLM_MODEL_USED = "rule_based"
_PROMPT_VERSION = "rule_based_template_v1"

# Confidence score components: a complete narrative (with both MITRE
# mappings and a risk score available) earns the full score; each
# missing input subtracts a fixed, documented penalty. Values are this
# module's own reasonable choice, since no LLM self-reported
# confidence value exists to derive from.
_BASE_CONFIDENCE = 0.9
_MISSING_MITRE_PENALTY = 0.3
_MISSING_RISK_SCORE_PENALTY = 0.2

# Deterministic recommended-action templates, selected by risk_label.
_RECOMMENDED_ACTIONS_BY_LABEL: Dict[RiskLabel, List[str]] = {
    RiskLabel.LOW: [
        "Monitor the affected host for recurrence; no immediate "
        "action required.",
        "Log this incident for trend analysis across future detection "
        "runs.",
    ],
    RiskLabel.MEDIUM: [
        "Review the affected host's recent process and network "
        "activity for corroborating signals.",
        "Notify the asset's owning team for situational awareness.",
    ],
    RiskLabel.HIGH: [
        "Escalate to a SOC analyst for manual review within the "
        "current shift.",
        "Isolate or closely monitor the affected host pending further "
        "investigation.",
        "Cross-reference matched MITRE techniques against recent "
        "threat intelligence.",
    ],
    RiskLabel.CRITICAL: [
        "Escalate immediately to incident response; treat as an "
        "active compromise until ruled out.",
        "Isolate the affected host from the network pending forensic "
        "review.",
        "Preserve volatile evidence (memory, running processes, open "
        "connections) before remediation.",
        "Notify the asset's owning team and security leadership "
        "without delay.",
    ],
}

# Fallback action used only if an incident somehow has no resolvable
# risk_label-driven action set (defensive; should not occur given
# RiskLabel is a closed enum).
_DEFAULT_RECOMMENDED_ACTION = (
    "Review the incident manually; no risk-specific guidance is "
    "available."
)


class InvestigationReportError(RuntimeError):
    """
    Raised for failures that prevent report generation from proceeding
    at all (e.g. the database is unreachable), as distinct from a
    single malformed incident document, which is skipped and logged
    rather than raised.
    """


@dataclass
class InvestigationReportResult:
    """
    Outcome of an investigation-report generation run.

    `inserted_ids` holds the Mongo `_id` of every `Investigation`
    document successfully written. `skipped_incidents` records any
    incidents that could not be reported on, each with a reason,
    without aborting the rest of the run.
    """

    inserted_ids: List[str] = field(default_factory=list)
    skipped_incidents: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def reports_generated(self) -> int:
        """Number of Investigation documents successfully persisted."""
        return len(self.inserted_ids)


def _build_incident_summary_section(incident: Incident) -> str:
    """Build the 'Incident Summary' narrative section."""
    event_count = len(incident.event_sequence)
    return (
        f"Incident Summary: Host '{incident.host}' triggered {event_count} "
        f"correlated anomalous event(s) between "
        f"{incident.start_time.isoformat()} and "
        f"{incident.end_time.isoformat()}. Current review status: "
        f"'{incident.status.value}'."
    )


def _build_timeline_summary_section(incident: Incident) -> str:
    """
    Build the 'Timeline Summary' narrative section.

    Limited to the duration and event density derivable from
    `Incident` itself (start_time, end_time, event_sequence length),
    since per-event timestamps live on `anomalies`, which is outside
    this task's required read set (incidents, attack_mappings,
    risk_scores).
    """
    duration_seconds = (incident.end_time - incident.start_time).total_seconds()
    event_count = len(incident.event_sequence)

    if duration_seconds <= 0 or event_count <= 1:
        density_description = (
            "a single anomalous event with no measurable spread."
        )
    else:
        duration_minutes = duration_seconds / 60.0
        density_description = (
            f"{event_count} events spread across approximately "
            f"{duration_minutes:.1f} minute(s)"
        )

    return (
        f"Timeline Summary: The incident's correlated event sequence "
        f"spans {density_description}, beginning at "
        f"{incident.start_time.isoformat()} and concluding at "
        f"{incident.end_time.isoformat()}."
    )


def _build_mitre_findings_section(mappings: List[AttackMapping]) -> str:
    """Build the 'MITRE ATT&CK Findings' narrative section."""
    if not mappings:
        return (
            "MITRE ATT&CK Findings: No MITRE ATT&CK techniques have "
            "been matched to this incident."
        )

    lines = [
        f"MITRE ATT&CK Findings: {len(mappings)} technique match(es) "
        "identified for this incident:"
    ]
    for mapping in sorted(mappings, key=lambda m: m.confidence, reverse=True):
        lines.append(
            f"  - {mapping.technique_id} ({mapping.technique_name}), "
            f"tactic {mapping.tactic_id}, severity "
            f"{mapping.severity_level.value}, confidence "
            f"{mapping.confidence:.2f}. {mapping.justification_text}"
        )
    return "\n".join(lines)


def _build_risk_assessment_section(risk_score: Optional[RiskScore]) -> str:
    """Build the 'Risk Assessment' narrative section."""
    if risk_score is None:
        return (
            "Risk Assessment: No risk score has been computed for this "
            "incident yet."
        )

    return (
        f"Risk Assessment: Final risk score is "
        f"{risk_score.final_score:.1f}/100, classified as "
        f"'{risk_score.risk_label.value}'. Component breakdown - "
        f"anomaly: {risk_score.anomaly_component:.1f}, technique "
        f"severity: {risk_score.technique_severity_component:.1f}, "
        f"asset criticality: {risk_score.asset_criticality_component:.1f}."
    )


def _build_recommended_actions_section(
    risk_score: Optional[RiskScore],
) -> str:
    """Build the 'Recommended Actions' narrative section."""
    if risk_score is None:
        actions = [_DEFAULT_RECOMMENDED_ACTION]
    else:
        actions = _RECOMMENDED_ACTIONS_BY_LABEL.get(
            risk_score.risk_label, [_DEFAULT_RECOMMENDED_ACTION]
        )

    lines = ["Recommended Actions:"]
    lines.extend(f"  - {action}" for action in actions)
    return "\n".join(lines)


def _compute_confidence_score(
    mappings: List[AttackMapping], risk_score: Optional[RiskScore]
) -> float:
    """
    Derive a deterministic confidence_score (0.0-1.0) for the
    generated narrative.

    Starts from `_BASE_CONFIDENCE` and subtracts a fixed penalty for
    each major missing input (no MITRE mappings, no risk score), since
    a narrative built without those inputs is a strictly thinner
    finding than one with full supporting data.
    """
    confidence = _BASE_CONFIDENCE

    if not mappings:
        confidence -= _MISSING_MITRE_PENALTY
    if risk_score is None:
        confidence -= _MISSING_RISK_SCORE_PENALTY

    return max(0.0, min(confidence, 1.0))


def _build_narrative_text(
    incident: Incident,
    mappings: List[AttackMapping],
    risk_score: Optional[RiskScore],
) -> str:
    """
    Assemble the full narrative_text from all five required sections,
    in order: Incident Summary, Timeline Summary, MITRE ATT&CK
    Findings, Risk Assessment, Recommended Actions.
    """
    sections = [
        _build_incident_summary_section(incident),
        _build_timeline_summary_section(incident),
        _build_mitre_findings_section(mappings),
        _build_risk_assessment_section(risk_score),
        _build_recommended_actions_section(risk_score),
    ]
    return "\n\n".join(sections)


async def _fetch_attack_mappings(incident: Incident) -> List[AttackMapping]:
    """
    Fetch the `AttackMapping` documents whose `incident_ref` matches
    this incident's own `_id`.

    Malformed documents (failing `AttackMapping` validation) are
    logged and skipped individually rather than aborting the fetch.

    Raises:
        InvestigationReportError: If querying MongoDB fails.
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
        raise InvestigationReportError(
            f"Failed to query attack_mappings for incident "
            f"{incident.id}: {exc}"
        ) from exc

    return mappings


async def _fetch_risk_score(incident: Incident) -> Optional[RiskScore]:
    """
    Fetch the `RiskScore` document whose `incident_ref` matches this
    incident's own `_id`, if one exists.

    Returns None (rather than raising) when no risk score has been
    computed yet for this incident, since report generation can still
    proceed with a thinner Risk Assessment section.

    Raises:
        InvestigationReportError: If querying MongoDB fails.
    """
    db = get_database()

    try:
        document = await db[_RISK_SCORES_COLLECTION].find_one(
            {"incident_ref": incident.id}
        )
    except PyMongoError as exc:
        logger.exception(
            "Failed to fetch risk_score for incident",
            extra={"incident_id": str(incident.id)},
        )
        raise InvestigationReportError(
            f"Failed to query risk_scores for incident {incident.id}: {exc}"
        ) from exc

    if document is None:
        return None

    try:
        return RiskScore(**document)
    except Exception:  # noqa: BLE001 - isolate one bad document
        logger.warning(
            "Skipping malformed risk_scores document for incident",
            extra={
                "incident_id": str(incident.id),
                "risk_score_id": str(document.get("_id")),
            },
        )
        return None


async def _fetch_unreported_incidents() -> List[Incident]:
    """
    Fetch all `incidents` documents not yet referenced by an existing
    `investigations` document, parsed into `Incident` instances.

    Malformed documents (failing `Incident` validation) are logged and
    skipped individually rather than aborting the fetch.

    Raises:
        InvestigationReportError: If querying MongoDB fails.
    """
    db = get_database()

    try:
        already_reported_refs = {
            doc["incident_ref"]
            async for doc in db[_INVESTIGATIONS_COLLECTION].find(
                {}, {"incident_ref": 1}
            )
        }
    except PyMongoError as exc:
        logger.exception("Failed to fetch existing investigations refs")
        raise InvestigationReportError(
            f"Failed to query investigations: {exc}"
        ) from exc

    incidents: List[Incident] = []
    try:
        cursor = db[_INCIDENTS_COLLECTION].find({})
        async for document in cursor:
            if document.get("_id") in already_reported_refs:
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
        raise InvestigationReportError(
            f"Failed to query incidents: {exc}"
        ) from exc

    logger.info(
        "Fetched incidents without investigation reports",
        extra={"count": len(incidents)},
    )
    return incidents

async def _incident_already_has_report(
    incident_id: ObjectId,
) -> bool:
    """
    Check whether an incident already has an investigation report.
    """
    db = get_database()

    try:
        existing = await db[_INVESTIGATIONS_COLLECTION].find_one(
            {"incident_ref": incident_id}
        )
    except PyMongoError as exc:
        logger.exception(
            "Failed to check for existing investigation",
            extra={"incident_id": str(incident_id)},
        )
        raise InvestigationReportError(
            f"Failed to query investigation report: {exc}"
        ) from exc

    return existing is not None

async def _build_investigation(incident: Incident) -> Investigation:
    """
    Build a single `Investigation` document for one incident,
    fetching its MITRE mappings and risk score, assembling the
    five-section narrative, and computing a deterministic confidence
    score.

    Raises:
        InvestigationReportError: If any upstream fetch fails at the
            infrastructure level.
        Exception: If `Investigation` construction itself fails
            (e.g. an empty narrative, which should not occur given
            every section always returns non-empty template text).
    """
    mappings = await _fetch_attack_mappings(incident)
    risk_score = await _fetch_risk_score(incident)

    if not mappings:
        logger.warning(
            "No attack_mappings found for incident; MITRE Findings "
            "section will be thin",
            extra={"incident_id": str(incident.id)},
        )
    if risk_score is None:
        logger.warning(
            "No risk_score found for incident; Risk Assessment "
            "section will be thin",
            extra={"incident_id": str(incident.id)},
        )

    narrative_text = _build_narrative_text(incident, mappings, risk_score)
    confidence_score = _compute_confidence_score(mappings, risk_score)

    logger.info(
        "Generated investigation narrative for incident",
        extra={
            "incident_id": str(incident.id),
            "mitre_mapping_count": len(mappings),
            "has_risk_score": risk_score is not None,
            "confidence_score": confidence_score,
        },
    )

    return Investigation(
        incident_ref=incident.id,
        narrative_text=narrative_text,
        llm_model_used=_LLM_MODEL_USED,
        prompt_version=_PROMPT_VERSION,
        confidence_score=confidence_score,
        generated_at=datetime.now(timezone.utc),
    )

async def generate_investigation_for_incident(
    incident_id: str,
) -> Optional[Investigation]:
    """
    Generate and persist an investigation report
    for a single incident.
    """
    try:
        object_id = ObjectId(incident_id)
    except (InvalidId, TypeError) as exc:
        raise InvestigationReportError(
            f"Invalid incident_id: {incident_id}"
        ) from exc

    db = get_database()

    try:
        document = await db[_INCIDENTS_COLLECTION].find_one(
            {"_id": object_id}
        )
    except PyMongoError as exc:
        raise InvestigationReportError(
            f"Failed to fetch incident: {exc}"
        ) from exc

    if document is None:
        return None

    incident = Incident(**document)

    if await _incident_already_has_report(incident.id):
        existing = await db[_INVESTIGATIONS_COLLECTION].find_one(
            {"incident_ref": incident.id}
        )

        return (
            Investigation(**existing)
            if existing
            else None
        )

    investigation = await _build_investigation(
        incident
    )

    await _insert_investigations(
        [investigation]
    )

    return investigation

async def _insert_investigations(
    investigations: List[Investigation],
) -> List[str]:
    """
    Persist a list of `Investigation` instances into `investigations`.

    Raises:
        InvestigationReportError: If the insert operation fails.
    """
    if not investigations:
        return []

    db = get_database()
    documents = [
        investigation.model_dump(by_alias=True, exclude={"id"})
        for investigation in investigations
    ]

    try:
        if len(documents) == 1:
            result = await db[_INVESTIGATIONS_COLLECTION].insert_one(
                documents[0]
            )
            inserted_ids = [str(result.inserted_id)]
        else:
            result = await db[_INVESTIGATIONS_COLLECTION].insert_many(
                documents, ordered=False
            )
            inserted_ids = [str(_id) for _id in result.inserted_ids]
    except PyMongoError as exc:
        logger.exception(
            "Failed to insert investigations documents",
            extra={"attempted_count": len(documents)},
        )
        raise InvestigationReportError(
            f"Failed to persist {len(documents)} investigations "
            f"document(s): {exc}"
        ) from exc

    logger.info(
        "Inserted investigations documents",
        extra={"inserted_count": len(inserted_ids)},
    )
    return inserted_ids


async def run_investigation_report_generation() -> InvestigationReportResult:
    """
    Run deterministic investigation report generation end-to-end.

    Fetches all `incidents` documents not yet covered by an
    `investigations` document, builds a five-section narrative for
    each (Incident Summary, Timeline Summary, MITRE ATT&CK Findings,
    Risk Assessment, Recommended Actions) using only structured data
    already present in `attack_mappings` and `risk_scores` (no
    external LLM call), and persists the resulting `Investigation`
    documents with `incident_ref` set to the source incident's own
    `_id` and `llm_model_used="rule_based"`.

    Supports batch processing: all unreported incidents in the
    database are processed in a single run, with per-incident failures
    isolated and reported rather than aborting the whole run.

    Returns:
        An `InvestigationReportResult` summarizing every Investigation
        inserted and every incident skipped.

    Raises:
        InvestigationReportError: If fetching unreported incidents or
            persisting investigations fails at the infrastructure
            level.
    """
    logger.info("Starting investigation report generation run")

    result = InvestigationReportResult()

    incidents = await _fetch_unreported_incidents()
    if not incidents:
        logger.info(
            "No incidents without investigation reports found; "
            "nothing to generate"
        )
        return result

    investigations: List[Investigation] = []

    for incident in incidents:
        try:
            investigation = await _build_investigation(incident)
            investigations.append(investigation)
        except InvestigationReportError:
            logger.exception(
                "Skipping incident due to upstream fetch failure",
                extra={"incident_id": str(incident.id)},
            )
            result.skipped_incidents.append(
                {
                    "incident_id": str(incident.id),
                    "reason": "Failed to fetch upstream data for report",
                }
            )
        except Exception:  # noqa: BLE001 - isolate one bad incident
            logger.exception(
                "Failed to build investigation report for incident",
                extra={"incident_id": str(incident.id)},
            )
            result.skipped_incidents.append(
                {
                    "incident_id": str(incident.id),
                    "reason": "Investigation construction failed",
                }
            )

    inserted_ids = await _insert_investigations(investigations)
    result.inserted_ids.extend(inserted_ids)

    logger.info(
        "Completed investigation report generation run",
        extra={
            "reports_generated": result.reports_generated,
            "incidents_skipped": len(result.skipped_incidents),
        },
    )
    return result