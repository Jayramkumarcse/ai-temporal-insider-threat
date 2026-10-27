#!/usr/bin/env python3
"""Verify CERT r4.2 answer-key event IDs against raw activity logs."""

import csv
import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data/cert/r4.2"
ANSWERS = ROOT / "data/cert/answer_key/answers"
INDEX = ANSWERS / "insiders.csv"
LOGS = ("logon.csv", "device.csv", "file.csv", "email.csv", "http.csv")
TIMESTAMP_FORMAT = "%m/%d/%Y %H:%M:%S"


def parse_timestamp(value):
    return datetime.strptime(value.strip(), TIMESTAMP_FORMAT)


def main():
    csv.field_size_limit(min(sys.maxsize, 20 * 1024 * 1024))

    answer_events = {}
    duplicate_answer_ids = 0
    non_target_events = 0
    answer_by_type = Counter()

    with INDEX.open("r", encoding="utf-8-sig", newline="") as f:
        records = [
            row for row in csv.DictReader(f)
            if row.get("dataset", "").strip() == "4.2"
        ]

    for record in records:
        scenario = record["scenario"].strip()
        target_user = record["user"].strip()
        detail_file = record["details"].strip()
        path = ANSWERS / f"r4.2-{scenario}" / detail_file

        if not path.is_file():
            raise FileNotFoundError(path)

        with path.open("r", encoding="utf-8-sig", newline="") as f:
            for row in csv.reader(f):
                if len(row) < 5:
                    raise ValueError(f"Short answer-key row in {path}")

                event_type, event_id, date_text, event_user = (
                    row[0].strip().lower(),
                    row[1].strip(),
                    row[2].strip(),
                    row[3].strip(),
                )

                item = {
                    "scenario": scenario,
                    "target_user": target_user,
                    "event_type": event_type,
                    "timestamp": parse_timestamp(date_text),
                    "event_user": event_user,
                }

                if event_id in answer_events:
                    duplicate_answer_ids += 1
                else:
                    answer_events[event_id] = item

                answer_by_type[event_type] += 1
                non_target_events += int(event_user != target_user)

    matched_ids = set()
    duplicates_in_raw = set()
    source_matches = Counter()
    type_mismatches = 0
    timestamp_mismatches = 0
    user_mismatches = 0
    scanned_rows = Counter()

    for filename in LOGS:
        path = RAW / filename
        if not path.is_file():
            raise FileNotFoundError(path)

        source_type = filename.removesuffix(".csv")
        print(f"Scanning {filename} ...", flush=True)

        with path.open("r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)

            for row_number, row in enumerate(reader, start=1):
                scanned_rows[source_type] += 1
                event_id = (row.get("id") or "").strip()

                if event_id not in answer_events:
                    continue

                if event_id in matched_ids:
                    duplicates_in_raw.add(event_id)
                    continue

                matched_ids.add(event_id)
                expected = answer_events[event_id]
                source_matches[source_type] += 1

                if expected["event_type"] != source_type:
                    type_mismatches += 1

                try:
                    raw_timestamp = parse_timestamp(row.get("date") or "")
                except ValueError:
                    timestamp_mismatches += 1
                else:
                    if raw_timestamp != expected["timestamp"]:
                        timestamp_mismatches += 1

                if (row.get("user") or "").strip() != expected["event_user"]:
                    user_mismatches += 1

                if row_number % 1_000_000 == 0:
                    print(
                        f"  {source_type}: {row_number:,} rows scanned; "
                        f"{len(matched_ids):,} answer IDs matched",
                        flush=True,
                    )

    missing_ids = set(answer_events) - matched_ids
    summary = {
        "dataset": "CERT r4.2",
        "global_scenarios": len(records),
        "answer_event_rows": sum(answer_by_type.values()),
        "unique_answer_event_ids": len(answer_events),
        "duplicate_answer_ids": duplicate_answer_ids,
        "events_whose_user_differs_from_target": non_target_events,
        "raw_rows_scanned_by_source": dict(scanned_rows),
        "matched_unique_event_ids": len(matched_ids),
        "missing_event_ids": len(missing_ids),
        "matched_ids_by_raw_source": dict(source_matches),
        "source_type_mismatches": type_mismatches,
        "timestamp_mismatches": timestamp_mismatches,
        "event_user_mismatches": user_mismatches,
        "duplicate_ids_in_raw_logs": len(duplicates_in_raw),
        "matched_ids_by_answer_type": dict(answer_by_type),
    }

    output = ROOT / "data/interim/cert_r42_answer_event_audit.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    print("\n===== ANSWER EVENT AUDIT =====")
    print(json.dumps(summary, indent=2))
    print(f"\nSaved audit summary: {output}")


if __name__ == "__main__":
    main()
