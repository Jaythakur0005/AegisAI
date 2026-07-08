"""
Import an OTRF Security-Datasets NDJSON ZIP into AegisAI.

The importer streams newline-delimited JSON events from a ZIP archive
and delegates parsing and persistence to the existing AegisAI
ingestion service.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import zipfile
from pathlib import Path
from typing import Any, Dict, List


PROJECT_ROOT = Path(__file__).resolve().parents[2]
BACKEND_ROOT = PROJECT_ROOT / "backend"

if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))


from app.db.mongo_client import (  # noqa: E402
    close_mongo_connection,
    connect_to_mongo,
)
from app.services.log_ingestion import ingest_batch  # noqa: E402


DEFAULT_BATCH_SIZE = 500


async def ingest_events(
    zip_path: Path,
    batch_size: int,
) -> None:
    total_lines = 0
    total_inserted = 0
    total_failed = 0

    await connect_to_mongo()

    try:
        with zipfile.ZipFile(zip_path) as archive:
            json_files = [
                name
                for name in archive.namelist()
                if name.lower().endswith(
                    (".json", ".jsonl", ".ndjson")
                )
            ]

            if not json_files:
                raise RuntimeError(
                    "No JSON/JSONL/NDJSON file found in ZIP archive."
                )

            print(f"Archive: {zip_path}")
            print(f"Dataset files: {len(json_files)}")
            print(f"Batch size: {batch_size}")

            for json_name in json_files:
                print(f"\nReading: {json_name}")

                batch: List[Dict[str, Any]] = []

                with archive.open(json_name) as dataset_file:
                    for raw_line in dataset_file:
                        total_lines += 1

                        line = raw_line.decode(
                            "utf-8-sig"
                        ).strip()

                        if not line:
                            continue

                        try:
                            event = json.loads(line)
                        except json.JSONDecodeError as exc:
                            total_failed += 1
                            print(
                                "Invalid JSON at line "
                                f"{total_lines}: {exc}"
                            )
                            continue

                        if not isinstance(event, dict):
                            total_failed += 1
                            print(
                                "Skipping non-object JSON at line "
                                f"{total_lines}"
                            )
                            continue

                        event["_source_file"] = json_name
                        batch.append(event)

                        if len(batch) >= batch_size:
                            result = await ingest_batch(batch)

                            total_inserted += result.success_count
                            total_failed += result.failure_count

                            print(
                                f"Processed={total_lines} "
                                f"Inserted={total_inserted} "
                                f"Failed={total_failed}"
                            )

                            batch.clear()

                if batch:
                    result = await ingest_batch(batch)

                    total_inserted += result.success_count
                    total_failed += result.failure_count

                    print(
                        f"Processed={total_lines} "
                        f"Inserted={total_inserted} "
                        f"Failed={total_failed}"
                    )

        print("\n=== OTRF IMPORT COMPLETE ===")
        print(f"Lines read: {total_lines}")
        print(f"Inserted: {total_inserted}")
        print(f"Failed: {total_failed}")

    finally:
        await close_mongo_connection()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Stream an OTRF NDJSON ZIP into AegisAI raw_logs."
        )
    )

    parser.add_argument(
        "zip_path",
        type=Path,
        help="Path to the OTRF dataset ZIP archive.",
    )

    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help=(
            "Number of events passed to ingest_batch per batch "
            f"(default: {DEFAULT_BATCH_SIZE})."
        ),
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    zip_path = args.zip_path.expanduser().resolve()

    if not zip_path.is_file():
        raise FileNotFoundError(
            f"Dataset ZIP does not exist: {zip_path}"
        )

    if args.batch_size <= 0:
        raise ValueError("--batch-size must be greater than zero")

    asyncio.run(
        ingest_events(
            zip_path=zip_path,
            batch_size=args.batch_size,
        )
    )


if __name__ == "__main__":
    main()
