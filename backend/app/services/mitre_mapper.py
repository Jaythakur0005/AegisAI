"""
MITRE ATT&CK mapping service.

Implements Stage 6 (MITRE ATT&CK Mapping) from ARCHITECTURE_V2.md: reads
incidents from the `incidents` collection, derives behavioral signals
from each incident's constituent anomalies (referenced via
`Incident.event_sequence`), matches those signals against a curated
local MITRE ATT&CK technique lookup table, and persists the resulting
tactic/technique matches as `AttackMapping` documents into
`attack_mappings`, with `incident_ref` set to the source incident's own
`_id` (per task requirement).

Per ARCHITECTURE_V2.md Section 2 ("Architecture Note — MITRE Local
Cache") and Stage 6, mapping is kept grounded: this module selects
candidate techniques only from the local `attack_lookup.json` cache via
rule-based signal matching. No LLM call is made here (LLM-assisted
ranking/justification, per Stage 6, is intentionally out of scope per
this task's "Do NOT generate: OpenAI integration") —
`justification_text` is populated with a deterministic, rule-based
explanation describing which signal(s) matched, keeping the field fully
auditable without an LLM dependency.

Behavioral signal source: `Incident` itself carries no behavioral
fields (only host, start_time, end_time, event_sequence, status,
created_at) — the actual behavior lives on the `Anomaly` documents
referenced by `event_sequence`. This module therefore fetches each
incident's constituent anomalies (by `_id`, via `event_sequence`) to
derive signals, then maps at the incident level. This read is a
necessary consequence of mapping incidents rather than anomalies
directly; without it there is no behavioral content to match against
MITRE techniques.

Expected `attack_lookup.json` shape (documented here since the dataset
file itself is out of scope for this module):

    [
      {
        "tactic_id": "TA0002",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "severity_level": "High",
        "signals": ["high_reconstruction_error", "anomalous_flag", ...]
      },
      ...
    ]

Each entry's "signals" list is a set of behavioral signal keys (defined
by `_derive_signals_from_incident` in this module) that, if present for
a given incident, make that technique a candidate match.

This module reads from and writes to MongoDB directly via
`app.db.mongo_client.get_database()`, consistent with the precedent set
by `app.services.log_ingestion`, `app.services.feature_engineering`,
`app.services.anomaly_detector`, and `app.services.incident_builder`
(no repository layer exists yet for `incidents`/`attack_mappings`).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Sequence, Set

from pymongo.errors import PyMongoError

from app.core.config import get_settings
from app.core.logging import get_logger
from app.db.mongo_client import get_database
from app.models.anomaly import Anomaly
from app.models.attack_mapping import AttackMapping, SeverityLevel
from app.models.incident import Incident

logger = get_logger(__name__)

_ANOMALIES_COLLECTION = "anomalies"
_INCIDENTS_COLLECTION = "incidents"
_ATTACK_MAPPINGS_COLLECTION = "attack_mappings"

# Behavioral signal keys this module knows how to derive from an
# incident's constituent Anomaly documents. A lookup table entry's
# "signals" list must use these exact keys to be matchable. Kept as an
# explicit, closed set so a typo in attack_lookup.json fails loudly
# rather than silently never matching.
_KNOWN_SIGNALS: FrozenSet[str] = frozenset(
    {
        "anomalous_flag",
        "high_reconstruction_error",
        "multi_event_incident",
        "multi_host_anomaly_burst",
    }
)

# Multiplier applied to an anomaly's threshold_used to qualify its
# reconstruction_error as "high" rather than merely anomalous. Kept as
# a module-level constant rather than a magic number, consistent with
# the threshold-multiplier pattern already used in the prior
# anomaly-centric version of this module.
_HIGH_ERROR_THRESHOLD_MULTIPLIER = 1.5

# An incident with at least this many constituent anomalies is
# considered to exhibit a multi-step behavioral pattern, distinct from
# a single isolated anomalous event.
_MULTI_EVENT_INCIDENT_MIN_COUNT = 3

# Confidence assigned when exactly one candidate signal matches a
# lookup entry. Scales up (never down) as more of the entry's declared
# signals are matched.
_BASE_SIGNAL_CONFIDENCE = 0.6

# Maximum confidence achievable through rule-based signal matching,
# reserving headroom below 1.0 since this module performs no
# LLM-assisted verification (per Stage 6, that step is intentionally
# out of scope here).
_MAX_RULE_BASED_CONFIDENCE = 0.9


class MitreMappingError(RuntimeError):
    """
    Raised for failures that prevent MITRE mapping from proceeding at
    all (e.g. the lookup table can't be loaded, or the database is
    unreachable), as distinct from a single malformed incident
    document, which is skipped and logged rather than raised.
    """


@dataclass
class MitreMappingResult:
    """
    Outcome of a MITRE mapping run.

    `inserted_ids` holds the Mongo `_id` of every `AttackMapping`
    document successfully written. Since one incident may yield
    multiple technique matches (one-to-many), `mapped_incident_count`
    tracks distinct incidents mapped, separately from the total
    mapping documents inserted.
    """

    inserted_ids: List[str] = field(default_factory=list)
    skipped_incidents: List[Dict[str, Any]] = field(default_factory=list)
    mapped_incident_count: int = 0
    unmatched_incident_count: int = 0

    @property
    def total_mappings_created(self) -> int:
        """Total number of AttackMapping documents inserted."""
        return len(self.inserted_ids)


def _load_lookup_table(lookup_path: str) -> List[Dict[str, Any]]:
    """
    Load and validate the curated local MITRE technique lookup table.

    Args:
        lookup_path: Path to the JSON lookup file (per
            `Settings.mitre_lookup_path`).

    Returns:
        A list of lookup entries, each with at least `tactic_id`,
        `technique_id`, `technique_name`, `severity_level`, and
        `signals`.

    Raises:
        MitreMappingError: If the file does not exist, is not valid
            JSON, or does not match the expected shape.
    """
    path = Path(lookup_path)
    if not path.is_file():
        raise MitreMappingError(
            f"MITRE lookup table not found at path: {lookup_path}"
        )

    try:
        with path.open("r", encoding="utf-8") as handle:
            raw_data = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise MitreMappingError(
            f"Failed to load MITRE lookup table from {lookup_path}: {exc}"
        ) from exc

    if not isinstance(raw_data, list):
        raise MitreMappingError(
            f"MITRE lookup table at {lookup_path} must be a JSON array, "
            f"got {type(raw_data).__name__}"
        )

    validated_entries: List[Dict[str, Any]] = []
    required_keys = {
        "tactic_id",
        "technique_id",
        "technique_name",
        "severity_level",
        "signals",
    }

    for index, entry in enumerate(raw_data):
        if not isinstance(entry, dict):
            logger.warning(
                "Skipping malformed MITRE lookup entry at index %d: not "
                "an object",
                index,
            )
            continue

        missing_keys = required_keys - entry.keys()
        if missing_keys:
            logger.warning(
                "Skipping malformed MITRE lookup entry at index %d: "
                "missing key(s) %s",
                index,
                sorted(missing_keys),
            )
            continue

        unknown_signals = set(entry["signals"]) - _KNOWN_SIGNALS
        if unknown_signals:
            logger.warning(
                "MITRE lookup entry %s (%s) references unknown signal "
                "key(s) %s; those signals will never match",
                entry.get("technique_id"),
                entry.get("technique_name"),
                sorted(unknown_signals),
            )

        validated_entries.append(entry)

    logger.info(
        "Loaded MITRE lookup table",
        extra={
            "lookup_path": lookup_path,
            "entry_count": len(validated_entries),
        },
    )
    return validated_entries


async def _fetch_constituent_anomalies(incident: Incident) -> List[Anomaly]:
    """
    Fetch the `Anomaly` documents referenced by an incident's
    `event_sequence`.

    Malformed documents (failing `Anomaly` validation) are logged and
    skipped individually rather than aborting the fetch.

    Raises:
        MitreMappingError: If querying MongoDB fails.
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
        raise MitreMappingError(
            f"Failed to query anomalies for incident {incident.id}: {exc}"
        ) from exc

    return anomalies


def _derive_signals_from_incident(
    incident: Incident, anomalies: Sequence[Anomaly]
) -> Set[str]:
    """
    Derive behavioral signal keys from an incident and its constituent
    anomalies.

    Args:
        incident: The incident being mapped.
        anomalies: The Anomaly documents referenced by
            `incident.event_sequence`.

    Returns:
        The set of signal keys (drawn from `_KNOWN_SIGNALS`) present
        for this incident.
    """
    signals: Set[str] = set()

    if not anomalies:
        return signals

    if any(anomaly.is_anomalous for anomaly in anomalies):
        signals.add("anomalous_flag")

    if any(
        anomaly.reconstruction_error
        > anomaly.threshold_used * _HIGH_ERROR_THRESHOLD_MULTIPLIER
        for anomaly in anomalies
        if anomaly.threshold_used > 0
    ):
        signals.add("high_reconstruction_error")

    if len(anomalies) >= _MULTI_EVENT_INCIDENT_MIN_COUNT:
        signals.add("multi_event_incident")

    distinct_hosts = {anomaly.host for anomaly in anomalies}
    if len(distinct_hosts) > 1:
        signals.add("multi_host_anomaly_burst")

    return signals


def _score_candidate(matched_signals: Set[str], entry_signals: Set[str]) -> float:
    """
    Compute a confidence score for one candidate lookup entry, given
    the signals matched between the incident and that entry.

    Confidence scales with the proportion of the entry's declared
    signals that were matched, anchored at `_BASE_SIGNAL_CONFIDENCE`
    for a single match and capped at `_MAX_RULE_BASED_CONFIDENCE`,
    since this is a rule-based match with no LLM-assisted
    verification step.

    Returns:
        A confidence value in [0.0, _MAX_RULE_BASED_CONFIDENCE], or
        0.0 if there is no overlap at all.
    """
    if not entry_signals:
        return 0.0

    overlap = matched_signals & entry_signals
    if not overlap:
        return 0.0

    match_ratio = len(overlap) / len(entry_signals)
    confidence = _BASE_SIGNAL_CONFIDENCE + (
        (_MAX_RULE_BASED_CONFIDENCE - _BASE_SIGNAL_CONFIDENCE)
        * (match_ratio - 1.0 / len(entry_signals))
    )
    return max(_BASE_SIGNAL_CONFIDENCE, min(confidence, _MAX_RULE_BASED_CONFIDENCE))


def _build_justification(matched_signals: Set[str], technique_name: str) -> str:
    """
    Build a rule-based, auditable justification string for a match.

    Since this module performs no LLM call (per task scope), the
    justification is a deterministic description of which signals
    triggered the match rather than free-text LLM reasoning.
    """
    signal_list = ", ".join(sorted(matched_signals))
    return (
        f"Matched technique '{technique_name}' based on observed "
        f"behavioral signal(s) across the incident's constituent "
        f"events: {signal_list}."
    )


def _map_incident_to_techniques(
    incident: Incident,
    matched_signals: Set[str],
    lookup_table: List[Dict[str, Any]],
) -> List[AttackMapping]:
    """
    Map a single incident to zero or more candidate MITRE techniques.

    Supports one-to-many mapping: every lookup entry with at least one
    matching signal produces its own `AttackMapping` document, each
    with its own confidence score. `incident_ref` is set to the
    incident's own `_id`, per task requirement.

    Returns:
        A list of `AttackMapping` instances (possibly empty, if no
        lookup entry's signals matched this incident at all).
    """
    if not matched_signals:
        return []

    mappings: List[AttackMapping] = []

    for entry in lookup_table:
        entry_signals = set(entry["signals"])
        confidence = _score_candidate(matched_signals, entry_signals)

        if confidence <= 0.0:
            continue

        overlap = matched_signals & entry_signals
        technique_name = str(entry["technique_name"])

        try:
            severity_level = SeverityLevel(entry["severity_level"])
        except ValueError:
            logger.warning(
                "Skipping MITRE lookup entry %s: invalid severity_level "
                "%r",
                entry.get("technique_id"),
                entry.get("severity_level"),
            )
            continue

        try:
            mapping = AttackMapping(
                incident_ref=incident.id,
                tactic_id=str(entry["tactic_id"]),
                technique_id=str(entry["technique_id"]),
                technique_name=technique_name,
                confidence=confidence,
                severity_level=severity_level,
                justification_text=_build_justification(overlap, technique_name),
            )
            mappings.append(mapping)
        except Exception:  # noqa: BLE001 - isolate one bad candidate
            logger.exception(
                "Failed to construct AttackMapping for incident %s and "
                "technique %s",
                str(incident.id),
                entry.get("technique_id"),
            )

    return mappings


async def _fetch_unmapped_incidents() -> List[Incident]:
    """
    Fetch all `incidents` documents not yet referenced by an existing
    `attack_mappings` document, parsed into `Incident` instances.

    Malformed documents (failing `Incident` validation) are logged and
    skipped individually rather than aborting the fetch.

    Raises:
        MitreMappingError: If querying MongoDB fails.
    """
    db = get_database()

    try:
        already_mapped_refs = {
            doc["incident_ref"]
            async for doc in db[_ATTACK_MAPPINGS_COLLECTION].find(
                {}, {"incident_ref": 1}
            )
        }
    except PyMongoError as exc:
        logger.exception("Failed to fetch existing attack_mappings refs")
        raise MitreMappingError(
            f"Failed to query attack_mappings: {exc}"
        ) from exc

    incidents: List[Incident] = []
    try:
        cursor = db[_INCIDENTS_COLLECTION].find({})
        async for document in cursor:
            if document.get("_id") in already_mapped_refs:
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
        raise MitreMappingError(
            f"Failed to query incidents: {exc}"
        ) from exc

    logger.info("Fetched unmapped incidents", extra={"count": len(incidents)})
    return incidents


async def _insert_attack_mappings(mappings: List[AttackMapping]) -> List[str]:
    """
    Persist a list of `AttackMapping` instances into `attack_mappings`.

    Raises:
        MitreMappingError: If the insert operation fails.
    """
    if not mappings:
        return []

    db = get_database()
    documents = [
        mapping.model_dump(by_alias=True, exclude={"id"}) for mapping in mappings
    ]

    try:
        if len(documents) == 1:
            result = await db[_ATTACK_MAPPINGS_COLLECTION].insert_one(documents[0])
            inserted_ids = [str(result.inserted_id)]
        else:
            result = await db[_ATTACK_MAPPINGS_COLLECTION].insert_many(
                documents, ordered=False
            )
            inserted_ids = [str(_id) for _id in result.inserted_ids]
    except PyMongoError as exc:
        logger.exception(
            "Failed to insert attack_mappings documents",
            extra={"attempted_count": len(documents)},
        )
        raise MitreMappingError(
            f"Failed to persist {len(documents)} attack_mappings "
            f"document(s): {exc}"
        ) from exc

    logger.info(
        "Inserted attack_mappings documents",
        extra={"inserted_count": len(inserted_ids)},
    )
    return inserted_ids


async def run_mitre_mapping() -> MitreMappingResult:
    """
    Run Stage 6 (MITRE ATT&CK Mapping) end-to-end.

    Loads the local MITRE lookup table, fetches all `incidents`
    documents not yet mapped, derives behavioral signals per incident
    from its constituent anomalies, matches against lookup entries
    (supporting one-to-many technique matches per incident), and
    persists the resulting `AttackMapping` documents with
    `incident_ref` set to the source incident's own `_id`.

    Returns:
        A `MitreMappingResult` summarizing every AttackMapping
        inserted, every incident skipped, and counts of mapped versus
        unmatched incidents.

    Raises:
        MitreMappingError: If loading the lookup table, querying
            MongoDB, or persisting attack_mappings fails at the
            infrastructure level.
    """
    settings = get_settings()

    logger.info(
        "Starting MITRE mapping run",
        extra={"lookup_path": settings.mitre_lookup_path},
    )

    result = MitreMappingResult()

    lookup_table = _load_lookup_table(settings.mitre_lookup_path)
    if not lookup_table:
        logger.warning(
            "MITRE lookup table loaded but contains no valid entries; "
            "no incidents can be mapped"
        )
        return result

    incidents = await _fetch_unmapped_incidents()
    if not incidents:
        logger.info("No unmapped incidents found; nothing to map")
        return result

    all_mappings: List[AttackMapping] = []

    for incident in incidents:
        try:
            anomalies = await _fetch_constituent_anomalies(incident)
            matched_signals = _derive_signals_from_incident(incident, anomalies)
            mappings = _map_incident_to_techniques(
                incident, matched_signals, lookup_table
            )
        except MitreMappingError:
            # Infrastructure-level failure fetching this incident's
            # anomalies; treat as a skip for this incident rather than
            # aborting the whole run, consistent with the
            # per-document isolation used elsewhere in this module.
            logger.exception(
                "Skipping incident due to anomaly fetch failure",
                extra={"incident_id": str(incident.id)},
            )
            result.skipped_incidents.append(
                {
                    "incident_id": str(incident.id),
                    "reason": "Failed to fetch constituent anomalies",
                }
            )
            continue
        except Exception:  # noqa: BLE001 - isolate one bad incident
            logger.exception(
                "Failed to map incident to MITRE techniques",
                extra={"incident_id": str(incident.id)},
            )
            result.skipped_incidents.append(
                {
                    "incident_id": str(incident.id),
                    "reason": "Mapping logic raised an unexpected error",
                }
            )
            continue

        if mappings:
            all_mappings.extend(mappings)
            result.mapped_incident_count += 1
        else:
            result.unmatched_incident_count += 1
            logger.debug(
                "No MITRE technique matched incident",
                extra={"incident_id": str(incident.id)},
            )

    inserted_ids = await _insert_attack_mappings(all_mappings)
    result.inserted_ids.extend(inserted_ids)

    logger.info(
        "Completed MITRE mapping run",
        extra={
            "mapped_incident_count": result.mapped_incident_count,
            "unmatched_incident_count": result.unmatched_incident_count,
            "total_mappings_created": result.total_mappings_created,
            "skipped_count": len(result.skipped_incidents),
        },
    )
    return result