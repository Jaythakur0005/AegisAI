"""
MITRE ATT&CK mapping service.

Implements Stage 6 (MITRE ATT&CK Mapping) from ARCHITECTURE_V2.md: reads
incidents from the `incidents` collection, reconstructs compact Sysmon
evidence by traversing `Incident.event_sequence` -> `Anomaly` ->
`ProcessedEvent` -> matching `RawLog` window events, matches those
evidence rules against a curated local MITRE ATT&CK technique lookup
table, and persists the resulting tactic/technique matches as
`AttackMapping` documents into `attack_mappings`, with `incident_ref`
set to the source incident's own `_id` (per task requirement).

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
created_at). The actual auditable behavior lives on raw Sysmon events,
so this module reconstructs evidence through the required chain:
incident.event_sequence -> anomaly.feature_ref -> processed_event ->
raw_logs matching processed_event.host and
[processed_event.window_start, processed_event.window_end). The
processed_event.raw_log_ref fallback is used only when the full window
query returns no raw logs.

Expected `attack_lookup.json` shape (documented here since the dataset
file itself is out of scope for this module):

    [
      {
        "tactic_id": "TA0002",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "severity_level": "High",
        "signals": ["powershell_encoded_command", "external_network_connection", ...]
      },
      ...
    ]

Each entry's "signals" list is a set of Sysmon evidence signal keys
(defined by `_derive_rule_matches_from_evidence` in this module) that,
if present for a given incident, make that technique a candidate match.

This module reads from and writes to MongoDB directly via
`app.db.mongo_client.get_database()`, consistent with the precedent set
by `app.services.log_ingestion`, `app.services.feature_engineering`,
`app.services.anomaly_detector`, and `app.services.incident_builder`
(no repository layer exists yet for `incidents`/`attack_mappings`).
"""

from __future__ import annotations

import ipaddress
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
from app.models.processed_event import ProcessedEvent
from app.models.raw_log import RawLog

logger = get_logger(__name__)

_ANOMALIES_COLLECTION = "anomalies"
_PROCESSED_EVENTS_COLLECTION = "processed_events"
_RAW_LOGS_COLLECTION = "raw_logs"
_INCIDENTS_COLLECTION = "incidents"
_ATTACK_MAPPINGS_COLLECTION = "attack_mappings"

# Behavioral signal keys this module knows how to derive from raw
# Sysmon evidence. A lookup table entry's "signals" list must use these
# exact keys to be matchable. Kept as an explicit, closed set so a typo
# in attack_lookup.json fails loudly rather than silently never
# matching.
_KNOWN_SIGNALS: FrozenSet[str] = frozenset(
    {
        "powershell_encoded_command",
        "script_lolbin_execution",
        "external_network_connection",
        "lsass_access",
        "registry_run_key_persistence",
        "suspicious_file_drop",
        "process_injection_access",
    }
)

# Confidence assigned when exactly one candidate signal matches a
# lookup entry. Scales up (never down) as more of the entry's declared
# signals are matched.
_BASE_SIGNAL_CONFIDENCE = 0.6

# Maximum confidence achievable through rule-based signal matching,
# reserving headroom below 1.0 since this module performs no
# LLM-assisted verification (per Stage 6, that step is intentionally
# out of scope here).
_MAX_RULE_BASED_CONFIDENCE = 0.9

_SYSMON_PROCESS_CREATE = 1
_SYSMON_NETWORK_CONNECTION = 3
_SYSMON_PROCESS_ACCESS = 10
_SYSMON_FILE_CREATE = 11
_SYSMON_REGISTRY_SET = 13

_SCRIPT_LOLBINS = frozenset(
    {
        "cmd.exe",
        "cscript.exe",
        "mshta.exe",
        "powershell.exe",
        "pwsh.exe",
        "regsvr32.exe",
        "rundll32.exe",
        "wscript.exe",
    }
)

_PRIVATE_OR_LOCAL_IP_PREFIXES = (
    "10.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
    "192.168.",
    "127.",
    "::1",
)


@dataclass(frozen=True)
class SysmonEvidence:
    """One raw Sysmon event plus the reference chain used to retrieve it."""

    anomaly_ref: Any
    processed_event_ref: Any
    raw_log: RawLog
    used_raw_log_ref_fallback: bool = False


@dataclass(frozen=True)
class RuleMatch:
    """A compact, explainable Sysmon rule hit."""

    signal: str
    reason: str
    event_id: int
    raw_log_ref: Any


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


async def _fetch_processed_events(
    incident: Incident, anomalies: Sequence[Anomaly]
) -> Dict[Any, ProcessedEvent]:
    """
    Fetch ProcessedEvent documents referenced by anomaly.feature_ref.

    This is the middle hop in the required evidence chain:
    incident.event_sequence -> anomaly.feature_ref -> processed_event.
    """
    if not anomalies:
        return {}

    feature_refs = [anomaly.feature_ref for anomaly in anomalies]
    db = get_database()

    try:
        cursor = db[_PROCESSED_EVENTS_COLLECTION].find(
            {"_id": {"$in": feature_refs}}
        )
        processed_events: Dict[Any, ProcessedEvent] = {}
        async for document in cursor:
            try:
                processed_event = ProcessedEvent(**document)
                processed_events[processed_event.id] = processed_event
            except Exception:  # noqa: BLE001 - isolate one bad document
                logger.warning(
                    "Skipping malformed processed_events document "
                    "referenced by anomaly",
                    extra={
                        "incident_id": str(incident.id),
                        "processed_event_id": str(document.get("_id")),
                    },
                )
    except PyMongoError as exc:
        logger.exception(
            "Failed to fetch processed_events for incident",
            extra={"incident_id": str(incident.id)},
        )
        raise MitreMappingError(
            f"Failed to query processed_events for incident {incident.id}: {exc}"
        ) from exc

    return processed_events


async def _fetch_raw_logs_for_processed_event(
    processed_event: ProcessedEvent,
) -> tuple[List[RawLog], bool]:
    """
    Fetch raw Sysmon logs for one processed event's host/window.

    The primary query uses processed_event.host and the half-open
    [window_start, window_end) timestamp range. processed_event.raw_log_ref
    is used only if that full window query returns no raw logs.
    """
    db = get_database()

    try:
        cursor = db[_RAW_LOGS_COLLECTION].find(
            {
                "host": processed_event.host,
                "timestamp": {
                    "$gte": processed_event.window_start,
                    "$lt": processed_event.window_end,
                },
            }
        )
        raw_logs: List[RawLog] = []
        async for document in cursor:
            try:
                raw_logs.append(RawLog(**document))
            except Exception:  # noqa: BLE001 - isolate one bad document
                logger.warning(
                    "Skipping malformed raw_logs document in processed "
                    "event window",
                    extra={
                        "processed_event_id": str(processed_event.id),
                        "raw_log_id": str(document.get("_id")),
                    },
                )
    except PyMongoError as exc:
        logger.exception(
            "Failed to fetch raw_logs window for processed_event",
            extra={"processed_event_id": str(processed_event.id)},
        )
        raise MitreMappingError(
            f"Failed to query raw_logs for processed_event "
            f"{processed_event.id}: {exc}"
        ) from exc

    if raw_logs:
        return raw_logs, False

    try:
        document = await db[_RAW_LOGS_COLLECTION].find_one(
            {
                "_id": processed_event.raw_log_ref,
                "host": processed_event.host,
            }
        )
    except PyMongoError as exc:
        logger.exception(
            "Failed to fetch raw_log_ref fallback for processed_event",
            extra={"processed_event_id": str(processed_event.id)},
        )
        raise MitreMappingError(
            f"Failed to query raw_log_ref fallback for processed_event "
            f"{processed_event.id}: {exc}"
        ) from exc

    if not document:
        return [], True

    try:
        return [RawLog(**document)], True
    except Exception:  # noqa: BLE001 - isolate one bad fallback document
        logger.warning(
            "Skipping malformed raw_log_ref fallback document",
            extra={
                "processed_event_id": str(processed_event.id),
                "raw_log_id": str(document.get("_id")),
            },
        )
        return [], True


async def _fetch_sysmon_evidence(incident: Incident) -> List[SysmonEvidence]:
    """
    Reconstruct auditable Sysmon evidence for an incident.

    Required traversal:
    incident.event_sequence -> anomaly.feature_ref -> processed_event ->
    raw_logs matching processed_event.host and
    [processed_event.window_start, processed_event.window_end).
    """
    anomalies = await _fetch_constituent_anomalies(incident)
    processed_events = await _fetch_processed_events(incident, anomalies)
    evidence: List[SysmonEvidence] = []
    seen_raw_log_ids: Set[Any] = set()

    for anomaly in anomalies:
        processed_event = processed_events.get(anomaly.feature_ref)
        if not processed_event:
            logger.warning(
                "Skipping anomaly with unresolved feature_ref during "
                "MITRE evidence reconstruction",
                extra={
                    "incident_id": str(incident.id),
                    "anomaly_id": str(anomaly.id),
                    "feature_ref": str(anomaly.feature_ref),
                },
            )
            continue

        raw_logs, used_fallback = await _fetch_raw_logs_for_processed_event(
            processed_event
        )
        for raw_log in raw_logs:
            if raw_log.id in seen_raw_log_ids:
                continue
            seen_raw_log_ids.add(raw_log.id)
            evidence.append(
                SysmonEvidence(
                    anomaly_ref=anomaly.id,
                    processed_event_ref=processed_event.id,
                    raw_log=raw_log,
                    used_raw_log_ref_fallback=used_fallback,
                )
            )

    return sorted(evidence, key=lambda item: item.raw_log.timestamp)


def _extract_raw_event_field(raw_event: Dict[str, Any], *candidates: str) -> str:
    """Return the first non-empty raw_event field from possible exporter names."""
    for key in candidates:
        value = raw_event.get(key)
        if value is not None and str(value).strip():
            return str(value)
    return ""


def _basename_lower(path: str) -> str:
    """Return a lowercase executable/file basename from a Windows or POSIX path."""
    normalized = path.replace("\\", "/").strip().lower()
    return normalized.rsplit("/", maxsplit=1)[-1]


def _looks_public_ip(ip_address: str) -> bool:
    """Return True only for globally routable IP addresses."""
    value = ip_address.strip()
    if not value:
        return False

    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def _derive_rule_matches_from_evidence(
    evidence_items: Sequence[SysmonEvidence],
) -> List[RuleMatch]:
    """
    Apply compact, explainable Sysmon evidence rules.

    These rules intentionally look only at raw Sysmon fields. They do
    not use reconstruction_error or is_anomalous.
    """
    matches: List[RuleMatch] = []

    for evidence in evidence_items:
        raw_log = evidence.raw_log
        raw_event = raw_log.raw_event
        image = _extract_raw_event_field(raw_event, "Image", "image", "ProcessImage")
        image_name = _basename_lower(image)
        command_line = _extract_raw_event_field(
            raw_event, "CommandLine", "command_line", "ProcessCommandLine"
        )
        command_line_lower = command_line.lower()

        if raw_log.event_id == _SYSMON_PROCESS_CREATE:
            if image_name in {"powershell.exe", "pwsh.exe"} and any(
                token in command_line_lower
                for token in ("-enc", "-encodedcommand", "frombase64string")
            ):
                matches.append(
                    RuleMatch(
                        signal="powershell_encoded_command",
                        reason=(
                            "Sysmon Event ID 1 process creation shows "
                            "PowerShell with encoded command indicators."
                        ),
                        event_id=raw_log.event_id,
                        raw_log_ref=raw_log.id,
                    )
                )

            if image_name in _SCRIPT_LOLBINS and any(
                token in command_line_lower
                for token in (
                    "http://",
                    "https://",
                    "javascript:",
                    "vbscript:",
                    ".sct",
                    "downloadstring",
                    "regsvr32",
                    "rundll32",
                )
            ):
                matches.append(
                    RuleMatch(
                        signal="script_lolbin_execution",
                        reason=(
                            "Sysmon Event ID 1 process creation shows a "
                            "script-capable Windows binary with remote or "
                            "script-loading command-line content."
                        ),
                        event_id=raw_log.event_id,
                        raw_log_ref=raw_log.id,
                    )
                )

        if raw_log.event_id == _SYSMON_NETWORK_CONNECTION:
            destination_ip = _extract_raw_event_field(
                raw_event, "DestinationIp", "destination_ip", "dest_ip"
            )
            destination_port = _extract_raw_event_field(
                raw_event, "DestinationPort", "destination_port", "dest_port"
            )
            if _looks_public_ip(destination_ip) and destination_port:
                matches.append(
                    RuleMatch(
                        signal="external_network_connection",
                        reason=(
                            "Sysmon Event ID 3 network connection targets "
                            f"external address {destination_ip}:{destination_port}."
                        ),
                        event_id=raw_log.event_id,
                        raw_log_ref=raw_log.id,
                    )
                )

        if raw_log.event_id == _SYSMON_PROCESS_ACCESS:
            target_image = _extract_raw_event_field(
                raw_event, "TargetImage", "target_image"
            ).lower()
            granted_access = _extract_raw_event_field(
                raw_event, "GrantedAccess", "granted_access"
            ).lower()
            if target_image.endswith("lsass.exe"):
                matches.append(
                    RuleMatch(
                        signal="lsass_access",
                        reason=(
                            "Sysmon Event ID 10 process access targets "
                            f"LSASS with GrantedAccess={granted_access or 'unknown'}."
                        ),
                        event_id=raw_log.event_id,
                        raw_log_ref=raw_log.id,
                    )
                )
            elif granted_access in {"0x1fffff", "0x1f0fff", "0x143a", "0x1410"}:
                matches.append(
                    RuleMatch(
                        signal="process_injection_access",
                        reason=(
                            "Sysmon Event ID 10 process access uses access "
                            f"mask {granted_access}, consistent with remote "
                            "process manipulation."
                        ),
                        event_id=raw_log.event_id,
                        raw_log_ref=raw_log.id,
                    )
                )

        if raw_log.event_id == _SYSMON_REGISTRY_SET:
            target_object = _extract_raw_event_field(
                raw_event, "TargetObject", "target_object"
            ).lower()
            if "\\currentversion\\run" in target_object:
                matches.append(
                    RuleMatch(
                        signal="registry_run_key_persistence",
                        reason=(
                            "Sysmon Event ID 13 registry value set touches "
                            "a CurrentVersion\\Run persistence location."
                        ),
                        event_id=raw_log.event_id,
                        raw_log_ref=raw_log.id,
                    )
                )

        if raw_log.event_id == _SYSMON_FILE_CREATE:
            target_filename = _extract_raw_event_field(
                raw_event, "TargetFilename", "target_filename"
            ).lower()
            if any(
                path_fragment in target_filename
                for path_fragment in ("\\temp\\", "\\appdata\\", "\\startup\\")
            ) and target_filename.endswith((".exe", ".dll", ".ps1", ".vbs", ".js")):
                matches.append(
                    RuleMatch(
                        signal="suspicious_file_drop",
                        reason=(
                            "Sysmon Event ID 11 file creation writes an "
                            "executable or script into a temp, appdata, or "
                            "startup path."
                        ),
                        event_id=raw_log.event_id,
                        raw_log_ref=raw_log.id,
                    )
                )

    deduped: Dict[str, RuleMatch] = {}
    for match in matches:
        deduped.setdefault(match.signal, match)
    return list(deduped.values())


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


def _build_justification(
    matched_rules: Sequence[RuleMatch], technique_name: str
) -> str:
    """
    Build a rule-based, auditable justification string for a match.

    Since this module performs no LLM call (per task scope), the
    justification is a deterministic description of which Sysmon
    evidence rule(s) triggered the match rather than free-text LLM
    reasoning.
    """
    signal_list = ", ".join(sorted(match.signal for match in matched_rules))
    event_list = "; ".join(
        f"{match.signal}: {match.reason} raw_log_ref={match.raw_log_ref}"
        for match in matched_rules
    )
    return (
        f"Matched technique '{technique_name}' based on observed "
        f"Sysmon evidence signal(s): {signal_list}. Evidence: {event_list}"
    )


def _map_incident_to_techniques(
    incident: Incident,
    rule_matches: Sequence[RuleMatch],
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
    matched_signals = {match.signal for match in rule_matches}
    if not matched_signals:
        return []

    matches_by_signal = {match.signal: match for match in rule_matches}
    mappings: List[AttackMapping] = []

    for entry in lookup_table:
        entry_signals = set(entry["signals"])
        confidence = _score_candidate(matched_signals, entry_signals)

        if confidence <= 0.0:
            continue

        overlap = matched_signals & entry_signals
        matched_rules = [
            matches_by_signal[signal] for signal in sorted(overlap)
        ]
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
                justification_text=_build_justification(
                    matched_rules, technique_name
                ),
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
    documents not yet mapped, reconstructs raw Sysmon evidence through
    anomaly.feature_ref and processed_events, derives compact evidence
    rule matches, matches against lookup entries (supporting one-to-many
    technique matches per incident), and persists the resulting
    `AttackMapping` documents with
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
            evidence = await _fetch_sysmon_evidence(incident)
            rule_matches = _derive_rule_matches_from_evidence(evidence)
            mappings = _map_incident_to_techniques(
                incident, rule_matches, lookup_table
            )
        except MitreMappingError:
            # Infrastructure-level failure fetching this incident's
            # evidence chain; treat as a skip for this incident rather
            # than aborting the whole run, consistent with the
            # per-document isolation used elsewhere in this module.
            logger.exception(
                "Skipping incident due to MITRE evidence fetch failure",
                extra={"incident_id": str(incident.id)},
            )
            result.skipped_incidents.append(
                {
                    "incident_id": str(incident.id),
                    "reason": "Failed to fetch Sysmon evidence chain",
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
