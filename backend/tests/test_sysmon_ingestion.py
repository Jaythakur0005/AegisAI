from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from bson import ObjectId
from pymongo.errors import PyMongoError

from app.services import log_ingestion
from app.services.log_ingestion import LogIngestionError
from app.services.sysmon_parser import (
    SysmonParseError,
    parse_sysmon_batch,
    parse_sysmon_event,
)


def native_event() -> dict:
    return {
        "host": "WIN-LAB01",
        "source_file": "sample.json",
        "event_id": 1,
        "timestamp": "2026-06-18T14:32:10.123Z",
        "Image": r"C:\Windows\System32\cmd.exe",
    }


def otrf_event() -> dict:
    return {
        "SourceName": "Microsoft-Windows-Sysmon",
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Hostname": "WORKSTATION5",
        "TimeCreated": "2021-06-11T09:07:15.635Z",
        "EventID": 1,
        "Image": r"C:\Windows\System32\PING.EXE",
    }


def test_parse_native_sysmon_event() -> None:
    event = native_event()

    parsed = parse_sysmon_event(event)

    assert parsed.host == "WIN-LAB01"
    assert parsed.source_file == "sample.json"
    assert parsed.event_id == 1
    assert parsed.timestamp == datetime(
        2026, 6, 18, 14, 32, 10, 123000, tzinfo=timezone.utc
    )
    assert parsed.raw_event == event


def test_parse_otrf_sysmon_event() -> None:
    event = otrf_event()

    parsed = parse_sysmon_event(event)

    assert parsed.host == "WORKSTATION5"
    assert parsed.source_file == "sysmon_dataset.json"
    assert parsed.event_id == 1
    assert parsed.timestamp.tzinfo is not None
    assert parsed.raw_event == event


@pytest.mark.parametrize(
    ("event", "reason_fragment"),
    [
        ({"timestamp": "2026-01-01T00:00:00Z"}, "event_id/EventID"),
        ({"event_id": 1}, "timestamp/TimeCreated"),
        (
            {"event_id": "not-an-int", "timestamp": "2026-01-01T00:00:00Z"},
            "must be an integer",
        ),
        (
            {"event_id": 1, "timestamp": "not-a-date"},
            "Unparsable timestamp string",
        ),
    ],
)
def test_parse_rejects_malformed_events(
    event: dict,
    reason_fragment: str,
) -> None:
    with pytest.raises(SysmonParseError) as exc_info:
        parse_sysmon_event(event)

    assert reason_fragment in exc_info.value.reason


def test_parse_rejects_non_object_event() -> None:
    with pytest.raises(SysmonParseError, match="JSON object"):
        parse_sysmon_event(["not", "an", "object"])  # type: ignore[arg-type]


def test_parse_batch_keeps_valid_events_and_quarantines_invalid() -> None:
    result = parse_sysmon_batch(
        [
            native_event(),
            {"event_id": 1},
            otrf_event(),
        ]
    )

    assert result.total == 3
    assert result.success_count == 2
    assert result.failure_count == 1
    assert result.failed[0]["index"] == 1
    assert "timestamp/TimeCreated" in result.failed[0]["reason"]


def test_parse_batch_rejects_non_list_input() -> None:
    with pytest.raises(SysmonParseError, match="events must be a list"):
        parse_sysmon_batch({"event_id": 1})  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_ingest_single_event_inserts_parsed_document(monkeypatch) -> None:
    inserted_id = ObjectId()
    collection = SimpleNamespace(
        insert_one=AsyncMock(
            return_value=SimpleNamespace(inserted_id=inserted_id)
        )
    )
    database = {"raw_logs": collection}

    monkeypatch.setattr(log_ingestion, "get_database", lambda: database)

    result = await log_ingestion.ingest_single_event(native_event())

    assert result.total == 1
    assert result.success_count == 1
    assert result.failure_count == 0
    assert result.inserted_ids == [str(inserted_id)]
    collection.insert_one.assert_awaited_once()


@pytest.mark.asyncio
async def test_ingest_single_event_returns_parse_failure_without_insert(
    monkeypatch,
) -> None:
    get_database = AsyncMock()
    monkeypatch.setattr(log_ingestion, "get_database", get_database)

    result = await log_ingestion.ingest_single_event({"event_id": 1})

    assert result.total == 1
    assert result.success_count == 0
    assert result.failure_count == 1
    assert "timestamp/TimeCreated" in result.failed[0]["reason"]
    get_database.assert_not_called()


@pytest.mark.asyncio
async def test_ingest_batch_inserts_only_valid_events(monkeypatch) -> None:
    inserted_ids = [ObjectId(), ObjectId()]
    collection = SimpleNamespace(
        insert_many=AsyncMock(
            return_value=SimpleNamespace(inserted_ids=inserted_ids)
        )
    )
    database = {"raw_logs": collection}

    monkeypatch.setattr(log_ingestion, "get_database", lambda: database)

    result = await log_ingestion.ingest_batch(
        [
            native_event(),
            {"event_id": 1},
            otrf_event(),
        ]
    )

    assert result.total == 3
    assert result.success_count == 2
    assert result.failure_count == 1
    assert result.inserted_ids == [str(value) for value in inserted_ids]
    collection.insert_many.assert_awaited_once()

    inserted_documents = collection.insert_many.await_args.args[0]
    assert len(inserted_documents) == 2
    assert all("_id" not in document for document in inserted_documents)


@pytest.mark.asyncio
async def test_ingest_batch_skips_database_when_all_events_fail(
    monkeypatch,
) -> None:
    get_database = AsyncMock()
    monkeypatch.setattr(log_ingestion, "get_database", get_database)

    result = await log_ingestion.ingest_batch(
        [
            {"event_id": 1},
            {"timestamp": "2026-01-01T00:00:00Z"},
        ]
    )

    assert result.total == 2
    assert result.success_count == 0
    assert result.failure_count == 2
    get_database.assert_not_called()


@pytest.mark.asyncio
async def test_database_failure_becomes_log_ingestion_error(
    monkeypatch,
) -> None:
    collection = SimpleNamespace(
        insert_one=AsyncMock(
            side_effect=PyMongoError("database unavailable")
        )
    )
    database = {"raw_logs": collection}

    monkeypatch.setattr(log_ingestion, "get_database", lambda: database)

    with pytest.raises(
        LogIngestionError,
        match="Failed to persist 1 raw_logs document",
    ):
        await log_ingestion.ingest_single_event(native_event())
