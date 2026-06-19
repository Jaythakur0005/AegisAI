"""
Sysmon JSON parser service.

Implements the JSON-parsing portion of Stage 1 (Ingestion) from
ARCHITECTURE_V2.md: takes raw Sysmon event records (already converted
from EVTX to JSON upstream, per the architecture's "EVTX → JSON/CSV"
note) and maps each one to a validated `RawLog` model instance, ready
for persistence into the `raw_logs` collection.

This module performs parsing and validation only. It does not write to
MongoDB — that is the responsibility of the ingestion repository/route
layer, which should call `parse_sysmon_event` / `parse_sysmon_batch` and
then persist the resulting `RawLog` instances.

Expected input shape (per event), based on standard Sysmon JSON exports:

    {
        "host": "WIN-LAB01",
        "source_file": "sysmon_export_2026-06-18.json",
        "event_id": 1,
        "timestamp": "2026-06-18T14:32:10.123Z",
        ... (remaining Sysmon fields, preserved verbatim in raw_event)
    }

Malformed events (missing required fields, wrong types, unparsable
timestamps) are skipped individually with a logged reason rather than
aborting the entire batch, since a single corrupt record should not
block ingestion of an otherwise-valid export.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List

from pydantic import ValidationError

from app.core.logging import get_logger
from app.models.raw_log import RawLog

logger = get_logger(__name__)

# Fields that must be present (and non-null) on every raw Sysmon event
# record for it to be considered parseable. `raw_event` is constructed
# from the full payload, not required as a literal input key.
_REQUIRED_FIELDS: tuple[str, ...] = (
    "host",
    "source_file",
    "event_id",
    "timestamp",
)

# Accepted ISO-8601 timestamp suffix used by many Sysmon JSON exporters
# to denote UTC when the trailing offset is 'Z' rather than '+00:00'.
_ZULU_SUFFIX = "Z"


class SysmonParseError(ValueError):
    """
    Raised for a single malformed Sysmon event.

    Carries enough context (the offending raw payload and a human
    -readable reason) for the caller to log/quarantine the record
    without needing to re-derive why it failed.
    """

    def __init__(self, reason: str, raw_payload: Any) -> None:
        super().__init__(reason)
        self.reason = reason
        self.raw_payload = raw_payload


@dataclass
class SysmonParseResult:
    """
    Aggregate result of parsing a batch of Sysmon events.

    Keeps successfully parsed `RawLog` instances separate from the
    raw payloads that failed validation, along with their failure
    reasons, so callers can persist the former and report/quarantine
    the latter.
    """

    parsed: List[RawLog] = field(default_factory=list)
    failed: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def total(self) -> int:
        """Total number of events attempted (parsed + failed)."""
        return len(self.parsed) + len(self.failed)

    @property
    def success_count(self) -> int:
        """Number of events successfully parsed into RawLog instances."""
        return len(self.parsed)

    @property
    def failure_count(self) -> int:
        """Number of events that failed parsing/validation."""
        return len(self.failed)


def _normalize_timestamp(value: Any) -> datetime:
    """
    Coerce a raw timestamp value into a `datetime` instance.

    Accepts `datetime` instances directly, or ISO-8601 strings
    (including the trailing 'Z' UTC suffix commonly emitted by Sysmon
    JSON exporters, which `datetime.fromisoformat` does not natively
    accept on its own).

    Raises:
        SysmonParseError: If `value` cannot be interpreted as a
            datetime.
    """
    if isinstance(value, datetime):
        return value

    if isinstance(value, str):
        candidate = value.strip()
        if candidate.endswith(_ZULU_SUFFIX):
            candidate = f"{candidate[:-1]}+00:00"
        try:
            return datetime.fromisoformat(candidate)
        except ValueError as exc:
            raise SysmonParseError(
                f"Unparsable timestamp string: {value!r} ({exc})",
                value,
            ) from exc

    raise SysmonParseError(
        f"timestamp must be a string or datetime, got {type(value).__name__}",
        value,
    )


def _validate_required_fields(event: Dict[str, Any]) -> None:
    """
    Verify all required top-level fields are present and non-null.

    Raises:
        SysmonParseError: If any required field is missing or null.
    """
    missing = [
        field_name
        for field_name in _REQUIRED_FIELDS
        if field_name not in event or event[field_name] is None
    ]
    if missing:
        raise SysmonParseError(
            f"Missing required field(s): {', '.join(missing)}",
            event,
        )


def parse_sysmon_event(event: Dict[str, Any]) -> RawLog:
    """
    Parse and validate a single raw Sysmon JSON event into a `RawLog`.

    Args:
        event: A single Sysmon event record as a dict (already
            converted from EVTX to JSON upstream of this function).

    Returns:
        A validated `RawLog` instance, with `raw_event` set to the
        full original payload (preserved verbatim for audit and
        re-processing, per the `raw_logs` schema).

    Raises:
        SysmonParseError: If the event is missing required fields,
            has an unparsable timestamp, or otherwise fails `RawLog`
            validation.
    """
    if not isinstance(event, dict):
        raise SysmonParseError(
            f"Event must be a JSON object (dict), got {type(event).__name__}",
            event,
        )

    _validate_required_fields(event)

    try:
        timestamp = _normalize_timestamp(event["timestamp"])
    except SysmonParseError:
        raise

    try:
        event_id_raw = event["event_id"]
        event_id = int(event_id_raw)
    except (TypeError, ValueError) as exc:
        raise SysmonParseError(
            f"event_id must be an integer, got {event['event_id']!r}",
            event,
        ) from exc

    try:
        raw_log = RawLog(
            host=str(event["host"]),
            source_file=str(event["source_file"]),
            event_id=event_id,
            timestamp=timestamp,
            raw_event=event,
        )
    except ValidationError as exc:
        raise SysmonParseError(
            f"RawLog validation failed: {exc}",
            event,
        ) from exc

    logger.debug(
        "Parsed Sysmon event",
        extra={
            "host": raw_log.host,
            "event_id": raw_log.event_id,
            "source_file": raw_log.source_file,
        },
    )
    return raw_log


def parse_sysmon_batch(events: List[Dict[str, Any]]) -> SysmonParseResult:
    """
    Parse a batch of raw Sysmon JSON events.

    Each event is parsed independently: a malformed event is logged
    and recorded in `SysmonParseResult.failed` without aborting
    processing of the remaining events in the batch.

    Args:
        events: List of raw Sysmon event dicts.

    Returns:
        A `SysmonParseResult` containing all successfully parsed
        `RawLog` instances and all failed payloads with reasons.
    """
    result = SysmonParseResult()

    if not isinstance(events, list):
        logger.error(
            "parse_sysmon_batch expected a list of events, got %s",
            type(events).__name__,
        )
        raise SysmonParseError(
            f"events must be a list, got {type(events).__name__}",
            events,
        )

    logger.info("Starting Sysmon batch parse", extra={"batch_size": len(events)})

    for index, event in enumerate(events):
        try:
            raw_log = parse_sysmon_event(event)
            result.parsed.append(raw_log)
        except SysmonParseError as exc:
            logger.warning(
                "Skipping malformed Sysmon event at index %d: %s",
                index,
                exc.reason,
                extra={"event_index": index, "reason": exc.reason},
            )
            result.failed.append(
                {
                    "index": index,
                    "reason": exc.reason,
                    "raw_payload": exc.raw_payload,
                }
            )
        except Exception as exc:  # noqa: BLE001 - defensive batch boundary
            # Any unexpected (non-SysmonParseError) failure must not
            # crash the whole batch; quarantine it and keep going.
            logger.exception(
                "Unexpected error parsing Sysmon event at index %d", index
            )
            result.failed.append(
                {
                    "index": index,
                    "reason": f"Unexpected error: {exc}",
                    "raw_payload": event,
                }
            )

    logger.info(
        "Finished Sysmon batch parse",
        extra={
            "total": result.total,
            "success_count": result.success_count,
            "failure_count": result.failure_count,
        },
    )
    return result