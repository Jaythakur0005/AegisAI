from collections import Counter
import json
from pathlib import Path
import zipfile

from app.services.sysmon_parser import (
    SysmonParseError,
    parse_sysmon_event,
)


DATASET_ROOT = Path("../Security-Datasets/datasets")


def is_sysmon_event(event):
    source = str(
        event.get("SourceName")
        or event.get("source_name")
        or event.get("ProviderName")
        or event.get("Provider")
        or ""
    )

    channel = str(event.get("Channel") or "")

    return (
        "sysmon" in source.lower()
        or "sysmon" in channel.lower()
    )


def decode_json_member(raw_bytes):
    if raw_bytes.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw_bytes.decode("utf-16")

    try:
        return raw_bytes.decode("utf-8-sig")
    except UnicodeDecodeError:
        pass

    try:
        return raw_bytes.decode("utf-16-le")
    except UnicodeDecodeError:
        pass

    return raw_bytes.decode("utf-16-be")


def main():
    zips = sorted(DATASET_ROOT.rglob("*.zip"))

    records = 0
    sysmon = 0
    parsed = 0
    failed = 0
    json_files = 0
    json_decode_failures = 0
    member_decode_failures = 0

    reasons = Counter()
    ids = Counter()
    parsed_ids = Counter()
    failed_ids = Counter()

    compatible = set()
    failed_zips = set()
    samples = []
    json_failure_samples = []
    decode_failure_samples = []

    print("=== AEGISAI FULL SYSMON PARSER AUDIT ===")
    print("ZIP FILES FOUND:", len(zips))

    for i, zp in enumerate(zips, 1):
        zip_sysmon = 0
        zip_failed = 0

        try:
            with zipfile.ZipFile(zp) as zf:
                json_names = [
                    name
                    for name in zf.namelist()
                    if name.lower().endswith(".json")
                    and not name.endswith("/")
                ]

                for name in json_names:
                    json_files += 1

                    with zf.open(name) as fh:
                        raw_bytes = fh.read()

                    try:
                        decoded = decode_json_member(raw_bytes)
                    except UnicodeDecodeError as exc:
                        member_decode_failures += 1

                        if len(decode_failure_samples) < 20:
                            decode_failure_samples.append(
                                (
                                    zp,
                                    name,
                                    type(exc).__name__,
                                    str(exc),
                                    len(raw_bytes),
                                    raw_bytes[:32].hex(),
                                )
                            )

                        continue

                    for line_no, raw in enumerate(
                        decoded.splitlines(),
                        1,
                    ):
                        raw = raw.strip()

                        if not raw:
                            continue

                        records += 1

                        try:
                            event = json.loads(raw)
                        except json.JSONDecodeError as exc:
                            json_decode_failures += 1

                            if len(json_failure_samples) < 20:
                                json_failure_samples.append(
                                    (
                                        zp,
                                        name,
                                        line_no,
                                        str(exc),
                                        raw[:300],
                                    )
                                )

                            continue

                        if (
                            not isinstance(event, dict)
                            or not is_sysmon_event(event)
                        ):
                            continue

                        sysmon += 1
                        zip_sysmon += 1

                        eid = (
                            event.get("event_id")
                            if event.get("event_id") is not None
                            else event.get("EventID")
                        )

                        key = str(eid)
                        ids[key] += 1

                        try:
                            parse_sysmon_event(event)
                            parsed += 1
                            parsed_ids[key] += 1

                        except SysmonParseError as exc:
                            failed += 1
                            zip_failed += 1
                            reasons[exc.reason] += 1
                            failed_ids[key] += 1

                            if len(samples) < 20:
                                samples.append(
                                    (
                                        zp,
                                        name,
                                        line_no,
                                        eid,
                                        exc.reason,
                                        list(event.keys()),
                                    )
                                )

            if zip_sysmon:
                if zip_failed == 0:
                    compatible.add(str(zp))
                else:
                    failed_zips.add(str(zp))

        except Exception as exc:
            print(
                f"[ZIP ERROR] {zp}: "
                f"{type(exc).__name__}: {exc}"
            )

        if i % 25 == 0 or i == len(zips):
            print(
                f"Scanned {i}/{len(zips)} ZIPs | "
                f"Records={records} | "
                f"Sysmon={sysmon} | "
                f"Parsed={parsed} | "
                f"Failed={failed} | "
                f"JSONDecodeFailures={json_decode_failures} | "
                f"MemberDecodeFailures={member_decode_failures}"
            )

    print("\n========================================")
    print("=== FINAL PARSER COMPATIBILITY RESULT ===")
    print("========================================")

    print("ZIP FILES SCANNED:", len(zips))
    print("JSON FILES SEEN:", json_files)
    print("RECORDS READ:", records)
    print("SYSMON EVENTS:", sysmon)
    print("PARSED:", parsed)
    print("FAILED:", failed)

    print(
        "PARSER COVERAGE:",
        f"{(parsed / sysmon * 100 if sysmon else 0):.4f}%",
    )

    print(
        "FULLY COMPATIBLE SYSMON ZIPS:",
        len(compatible),
    )

    print(
        "ZIPS WITH PARSE FAILURES:",
        len(failed_zips),
    )

    print(
        "JSON DECODE FAILURES:",
        json_decode_failures,
    )

    print(
        "MEMBER DECODE FAILURES:",
        member_decode_failures,
    )

    print("\n=== EVENT ID DISTRIBUTION ===")

    for eid, count in ids.most_common():
        print(
            f"EVENT ID {eid}: "
            f"TOTAL={count} "
            f"PARSED={parsed_ids[eid]} "
            f"FAILED={failed_ids[eid]}"
        )

    print("\n=== TOP FAILURE REASONS ===")

    if reasons:
        for reason, count in reasons.most_common(20):
            print(f"{count}x | {reason}")
    else:
        print("NO PARSE FAILURES")

    print("\n=== FAILURE SAMPLES ===")

    if samples:
        for index, sample in enumerate(samples, 1):
            print(f"\n[{index}] ZIP: {sample[0]}")
            print("FILE:", sample[1])
            print("LINE:", sample[2])
            print("EVENT ID:", sample[3])
            print("REASON:", sample[4])
            print("KEYS:", sample[5])
    else:
        print("NO FAILURE SAMPLES")

    print("\n=== JSON DECODE FAILURE SAMPLES ===")

    if json_failure_samples:
        for index, sample in enumerate(
            json_failure_samples,
            1,
        ):
            print(f"\n[{index}] ZIP: {sample[0]}")
            print("FILE:", sample[1])
            print("LINE:", sample[2])
            print("REASON:", sample[3])
            print("RAW SAMPLE:", repr(sample[4]))
    else:
        print("NO JSON DECODE FAILURES")

    print("\n=== MEMBER DECODE FAILURE SAMPLES ===")

    if decode_failure_samples:
        for index, sample in enumerate(
            decode_failure_samples,
            1,
        ):
            print(f"\n[{index}] ZIP: {sample[0]}")
            print("FILE:", sample[1])
            print("ERROR TYPE:", sample[2])
            print("REASON:", sample[3])
            print("BYTE LENGTH:", sample[4])
            print("FIRST 32 BYTES HEX:", sample[5])
    else:
        print("NO MEMBER DECODE FAILURES")

    print("\n=== ZIPS WITH PARSE FAILURES ===")

    if failed_zips:
        print("\n".join(sorted(failed_zips)))
    else:
        print("NONE")


if __name__ == "__main__":
    main()
