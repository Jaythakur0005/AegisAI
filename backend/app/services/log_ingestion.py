"""
Log ingestion service.

Orchestrates Stage 1 (Ingestion) from ARCHITECTURE_V2.md: takes raw
Sysmon JSON event payloads, delegates parsing/validation to
`app.services.sysmon_parser`, and persists successfully parsed
`RawLog` documents into the `raw_logs` MongoDB collection via the
existing Motor connection layer (`app.db.mongo_client`).

This module is the boundary between parsing (sysmon_parser) and
persistence (MongoDB). It contains no parsing logic of its own and no
FastAPI route definitions — those belong in `app/api/`.

Supports two entry points:
    - `ingest_single_event`: ingest one raw Sysmon event dict.
    - `ingest_batch`: ingest a list of raw Sysmon event dicts
      (e.g. an uploaded log export containing many events).

Both return a structured `IngestionResult` so callers (API routes) can
report partial success without the entire request failing because a
handful of malformed events were present in an otherwise-valid upload.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from pymongo.errors import PyMongoError

from app.core.logging import get_logger
from app.db.mongo_client import get_database
from app.models.raw_log import RawLog
from app.services.sysmon_parser import (
    SysmonParseError,
    SysmonParseResult,
    parse_sysmon_batch,
    parse_sysmon_event,
)

logger = get_logger(__name__)

_RAW_LOGS_COLLECTION = "raw_logs"


class LogIngestionError(RuntimeError):
    """
    Raised for a failure that prevents ingestion from proceeding at
    all (e.g. the database is unreachable), as opposed to a per-event
    parsing failure, which is reported in `IngestionResult.failed`
    rather than raised.
    """


@dataclass
class IngestionResult:
    """
    Outcome of an ingestion run (single-event or batch).

    Mirrors `SysmonParseResult` but reflects post-persistence state:
    `inserted_ids` holds the Mongo `_id` of every `RawLog` that was
    successfully written, while `failed` carries every event (parse
    failures and any individual insert failures) that did not make it
    into `raw_logs`, each with a reason.
    """

    inserted_ids: List[str] = field(default_factory=list)
    failed: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def total(self) -> int:
        """Total number of events attempted (inserted + failed)."""
        return len(self.inserted_ids) + len(self.failed)

    @property
    def success_count(self) -> int:
        """Number of events successfully persisted to raw_logs."""
        return len(self.inserted_ids)

    @property
    def failure_count(self) -> int:
        """Number of events that failed parsing or persistence."""
        return len(self.failed)


async def _insert_raw_logs(raw_logs: List[RawLog]) -> List[str]:
    """
    Persist a list of validated `RawLog` instances into `raw_logs`.

    Uses a single `insert_many` for batches greater than one document,
    which is both faster and avoids partially-applied per-document
    error handling diverging from the parse-stage's "skip and
    continue" semantics — if the database call itself fails, that is
    an infrastructure problem (see `LogIngestionError`), not a
    per-event data problem.

    Args:
        raw_logs: Validated `RawLog` instances to persist. Must be
            non-empty.

    Returns:
        The string-encoded MongoDB `_id` of each inserted document,
        in insertion order.

    Raises:
        LogIngestionError: If the insert operation fails.
    """
    if not raw_logs:
        return []

    db = get_database()
    documents = [
        raw_log.model_dump(by_alias=True, exclude={"id"})
        for raw_log in raw_logs
    ]

    try:
        if len(documents) == 1:
            result = await db[_RAW_LOGS_COLLECTION].insert_one(documents[0])
            inserted_ids = [str(result.inserted_id)]
        else:
            result = await db[_RAW_LOGS_COLLECTION].insert_many(
                documents, ordered=False
            )
            inserted_ids = [str(_id) for _id in result.inserted_ids]
    except PyMongoError as exc:
        logger.exception(
            "Failed to insert raw_logs documents",
            extra={"attempted_count": len(documents)},
        )
        raise LogIngestionError(
            f"Failed to persist {len(documents)} raw_logs document(s): {exc}"
        ) from exc

    logger.info(
        "Inserted raw_logs documents",
        extra={"inserted_count": len(inserted_ids)},
    )
    return inserted_ids


async def ingest_single_event(event: Dict[str, Any]) -> IngestionResult:
    """
    Parse and persist a single raw Sysmon JSON event.

    Args:
        event: A single raw Sysmon event dict.

    Returns:
        An `IngestionResult` with either one entry in `inserted_ids`
        (on success) or one entry in `failed` (on parse or insert
        failure) — never both, and never empty.

    Raises:
        LogIngestionError: If the database insert itself fails after
            the event was successfully parsed (i.e. an infrastructure
            failure, not a data-quality failure).
    """
    logger.info("Starting single-event ingestion")
    result = IngestionResult()

    try:
        raw_log = parse_sysmon_event(event)
    except SysmonParseError as exc:
        logger.warning(
            "Single-event ingestion: event failed parsing: %s", exc.reason
        )
        result.failed.append({"index": 0, "reason": exc.reason, "raw_payload": event})
        return result

    inserted_ids = await _insert_raw_logs([raw_log])
    result.inserted_ids.extend(inserted_ids)

    logger.info(
        "Completed single-event ingestion",
        extra={
            "success_count": result.success_count,
            "failure_count": result.failure_count,
        },
    )
    return result


async def ingest_batch(events: List[Dict[str, Any]]) -> IngestionResult:
    """
    Parse and persist a batch of raw Sysmon JSON events.

    Delegates parsing to `sysmon_parser.parse_sysmon_batch`, which
    already isolates malformed events without aborting the batch.
    Only successfully parsed events are persisted; parse failures are
    carried straight through into the returned `IngestionResult`
    without ever reaching the database.

    Args:
        events: List of raw Sysmon event dicts (e.g. the contents of
            an uploaded log export).

    Returns:
        An `IngestionResult` summarizing every event in the batch:
        successfully inserted documents' `_id`s, and every failed
        event (parse or insert failure) with a reason.

    Raises:
        LogIngestionError: If the database insert step fails for the
            batch of successfully parsed events. Note that events
            which failed *parsing* are still reported in
            `failed` even when this is raised, since that information
            was already determined before the database call — but the
            caller will not receive the partial `IngestionResult` in
            that case, since the exception propagates. Callers who
            need partial-result-on-db-failure semantics should catch
            `LogIngestionError` and reconstruct failed parse entries
            via `sysmon_parser.parse_sysmon_batch` themselves.
    """
    logger.info("Starting batch ingestion", extra={"batch_size": len(events)})

    result = IngestionResult()

    parse_result: SysmonParseResult = parse_sysmon_batch(events)

    for failure in parse_result.failed:
        result.failed.append(failure)

    if parse_result.parsed:
        inserted_ids = await _insert_raw_logs(parse_result.parsed)
        result.inserted_ids.extend(inserted_ids)
    else:
        logger.warning(
            "Batch ingestion: no events passed parsing; skipping insert",
            extra={"batch_size": len(events)},
        )

    logger.info(
        "Completed batch ingestion",
        extra={
            "total": result.total,
            "success_count": result.success_count,
            "failure_count": result.failure_count,
        },
    )
    return result