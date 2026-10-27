#!/usr/bin/env python3
"""Streaming user-day feature extraction for CERT r4.2."""

from __future__ import annotations

import argparse
import csv
import sqlite3
import sys
import tempfile
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = ROOT / "data" / "cert" / "r4.2"
ANSWER_FILE = ROOT / "data" / "cert" / "answer_key" / "answers" / "insiders.csv"

SOURCES = ("logon.csv", "device.csv", "file.csv", "email.csv", "http.csv")

NUMERIC_COLUMNS = (
    "event_count",
    "logon_event_count",
    "login_count",
    "logout_count",
    "device_event_count",
    "device_connect_count",
    "device_disconnect_count",
    "file_event_count",
    "email_count",
    "email_bytes",
    "email_attachment_count",
    "http_event_count",
    "night_activity_count",
    "off_hours_activity_count",
    "weekend_activity_count",
)

OUTPUT_COLUMNS = (
    "user_id",
    "date",
    *NUMERIC_COLUMNS,
    "active_span_seconds",
    "events_per_hour",
    "ground_truth",
    "scenario_types",
)


def parse_timestamp(value: str) -> datetime:
    """Parse CERT's MM/DD/YYYY HH:MM:SS timestamp without timezone conversion."""
    return datetime.strptime(value.strip(), "%m/%d/%Y %H:%M:%S")


def build_interval_labels() -> dict[tuple[str, str], set[str]]:
    """Label every user-day intersecting a global r4.2 incident interval."""
    labels: dict[tuple[str, str], set[str]] = defaultdict(set)

    with ANSWER_FILE.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            if row.get("dataset", "").strip() != "4.2":
                continue

            user = row.get("user", "").strip()
            scenario = row.get("scenario", "").strip()
            start = parse_timestamp(row["start"])
            end = parse_timestamp(row["end"])

            if not user or not scenario or end < start:
                raise ValueError(f"Invalid r4.2 answer-key row: {row}")

            day = start.date()
            while day <= end.date():
                labels[(user, day.isoformat())].add(scenario)
                day += timedelta(days=1)

    if not labels:
        raise ValueError(f"No r4.2 incident intervals found in {ANSWER_FILE}")

    return labels


def create_database(connection: sqlite3.Connection) -> None:
    metric_sql = ",\n".join(
        f"{name} INTEGER NOT NULL DEFAULT 0"
        for name in NUMERIC_COLUMNS
    )

    connection.execute(
        f"""
        CREATE TABLE daily_features (
            user_id TEXT NOT NULL,
            event_date TEXT NOT NULL,
            {metric_sql},
            first_ts TEXT NOT NULL,
            last_ts TEXT NOT NULL,
            PRIMARY KEY (user_id, event_date)
        )
        """
    )
    connection.commit()


def flush_batch(
    connection: sqlite3.Connection,
    batch: dict[tuple[str, str], dict],
) -> None:
    if not batch:
        return

    columns = [
        "user_id",
        "event_date",
        *NUMERIC_COLUMNS,
        "first_ts",
        "last_ts",
    ]

    placeholders = ", ".join("?" for _ in columns)
    updates = [
        f"{name}=daily_features.{name}+excluded.{name}"
        for name in NUMERIC_COLUMNS
    ]
    updates.extend(
        [
            "first_ts=MIN(daily_features.first_ts, excluded.first_ts)",
            "last_ts=MAX(daily_features.last_ts, excluded.last_ts)",
        ]
    )

    sql = (
        f"INSERT INTO daily_features ({', '.join(columns)}) "
        f"VALUES ({placeholders}) "
        f"ON CONFLICT(user_id, event_date) DO UPDATE SET "
        f"{', '.join(updates)}"
    )

    values = []
    for (user, event_date), stats in batch.items():
        values.append(
            (
                user,
                event_date,
                *(stats[name] for name in NUMERIC_COLUMNS),
                stats["first_ts"],
                stats["last_ts"],
            )
        )

    connection.executemany(sql, values)
    connection.commit()
    batch.clear()


def process_source(
    connection: sqlite3.Connection,
    filename: str,
    max_rows: int | None,
    chunk_rows: int,
) -> dict[str, int]:
    path = RAW_DIR / filename
    if not path.is_file():
        raise FileNotFoundError(f"Required CERT log not found: {path}")

    source_type = filename.removesuffix(".csv")
    batch: dict[tuple[str, str], dict] = {}

    rows_read = 0
    valid_rows = 0
    skipped_rows = 0

    csv.field_size_limit(min(sys.maxsize, 10 * 1024 * 1024))

    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        required = {"id", "date", "user", "pc"}

        if not reader.fieldnames or not required.issubset(reader.fieldnames):
            raise ValueError(
                f"Unexpected columns in {filename}: {reader.fieldnames}"
            )

        if source_type in {"logon", "device"} and "activity" not in reader.fieldnames:
            raise ValueError(f"Missing activity column in {filename}")

        if source_type == "http" and "url" not in reader.fieldnames:
            raise ValueError(f"Missing URL column in {filename}")

        if source_type == "email" and not {"size", "attachments"}.issubset(
            reader.fieldnames
        ):
            raise ValueError(f"Missing email size/attachments columns in {filename}")

        for row in reader:
            if max_rows is not None and rows_read >= max_rows:
                break

            rows_read += 1

            user = (row.get("user") or "").strip()
            timestamp_text = (row.get("date") or "").strip()

            try:
                if not user:
                    raise ValueError("missing user")
                timestamp = parse_timestamp(timestamp_text)
            except (ValueError, TypeError):
                skipped_rows += 1
                continue

            event_date = timestamp.date().isoformat()
            key = (user, event_date)

            if key not in batch:
                batch[key] = {name: 0 for name in NUMERIC_COLUMNS}
                batch[key]["first_ts"] = timestamp.isoformat(sep=" ")
                batch[key]["last_ts"] = timestamp.isoformat(sep=" ")

            stats = batch[key]
            stats["event_count"] += 1
            activity = (row.get("activity") or "").strip().lower()

            if source_type == "logon":
                stats["logon_event_count"] += 1
                if activity in {"logon", "login"}:
                    stats["login_count"] += 1
                elif activity in {"logoff", "logout"}:
                    stats["logout_count"] += 1

            elif source_type == "device":
                stats["device_event_count"] += 1
                if activity == "connect":
                    stats["device_connect_count"] += 1
                elif activity == "disconnect":
                    stats["device_disconnect_count"] += 1

            elif source_type == "file":
                stats["file_event_count"] += 1

            elif source_type == "email":
                stats["email_count"] += 1
                try:
                    stats["email_bytes"] += max(0, int(row.get("size") or 0))
                    stats["email_attachment_count"] += max(
                        0, int(row.get("attachments") or 0)
                    )
                except ValueError:
                    skipped_rows += 1
                    # The event remains counted; unavailable email metrics add zero.

            if source_type == "http":
                stats["http_event_count"] += 1

            if timestamp.hour < 6:
                stats["night_activity_count"] += 1

            if timestamp.hour < 8 or timestamp.hour >= 18:
                stats["off_hours_activity_count"] += 1

            if timestamp.weekday() >= 5:
                stats["weekend_activity_count"] += 1

            timestamp_iso = timestamp.isoformat(sep=" ")
            stats["first_ts"] = min(stats["first_ts"], timestamp_iso)
            stats["last_ts"] = max(stats["last_ts"], timestamp_iso)
            valid_rows += 1

            if rows_read % chunk_rows == 0:
                flush_batch(connection, batch)
                print(
                    f"  {filename}: processed {rows_read:,} rows "
                    f"({valid_rows:,} valid)",
                    flush=True,
                )

        flush_batch(connection, batch)

    return {
        "rows_read": rows_read,
        "valid_rows": valid_rows,
        "skipped_rows": skipped_rows,
    }


def write_features(
    connection: sqlite3.Connection,
    output_path: Path,
    labels: dict[tuple[str, str], set[str]],
) -> dict[str, int]:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    positive_rows = 0
    total_rows = 0

    query_columns = [
        "user_id",
        "event_date",
        *NUMERIC_COLUMNS,
        "first_ts",
        "last_ts",
    ]
    query = (
        f"SELECT {', '.join(query_columns)} FROM daily_features "
        "ORDER BY user_id, event_date"
    )

    with output_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=OUTPUT_COLUMNS)
        writer.writeheader()

        for row in connection.execute(query):
            user = row["user_id"]
            event_date = row["event_date"]
            scenarios = sorted(labels.get((user, event_date), set()))

            first = datetime.fromisoformat(row["first_ts"])
            last = datetime.fromisoformat(row["last_ts"])
            span = max(0.0, (last - first).total_seconds())

            event_count = row["event_count"]
            events_per_hour = (
                (event_count - 1) / (span / 3600.0)
                if span > 0 and event_count > 1
                else 0.0
            )

            label = int(bool(scenarios))
            positive_rows += label
            total_rows += 1

            output = {
                "user_id": user,
                "date": event_date,
                **{name: row[name] for name in NUMERIC_COLUMNS},
                "active_span_seconds": round(span, 3),
                "events_per_hour": round(events_per_hour, 6),
                "ground_truth": label,
                "scenario_types": ";".join(scenarios),
            }
            writer.writerow(output)

    return {"user_days": total_rows, "positive_user_days": positive_rows}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build CERT r4.2 user-day features using streaming CSV reads."
    )
    parser.add_argument(
        "--max-rows-per-log",
        type=int,
        default=None,
        help="Optional per-file row limit for a smoke test; omit for full processing.",
    )
    parser.add_argument(
        "--chunk-rows",
        type=int,
        default=50_000,
        help="Rows between SQLite batch writes (default: 50000).",
    )
    parser.add_argument(
        "--output",
        default="data/processed/cert_r42_user_day.csv",
        help="Output path, relative to project root unless absolute.",
    )
    args = parser.parse_args()

    if args.max_rows_per_log is not None and args.max_rows_per_log < 1:
        parser.error("--max-rows-per-log must be positive")
    if args.chunk_rows < 1:
        parser.error("--chunk-rows must be positive")

    if not ANSWER_FILE.is_file():
        parser.error(f"Answer key not found: {ANSWER_FILE}")

    labels = build_interval_labels()
    print(f"Loaded r4.2 interval labels: {len(labels)} user-day keys")

    output_path = Path(args.output)
    if not output_path.is_absolute():
        output_path = ROOT / output_path

    scratch_dir = ROOT / "data" / "interim"
    scratch_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(
        prefix="cert_r42_", dir=scratch_dir
    ) as temp_dir:
        database_path = Path(temp_dir) / "aggregates.sqlite3"

        with sqlite3.connect(database_path) as connection:
            connection.row_factory = sqlite3.Row
            create_database(connection)

            for filename in SOURCES:
                print(f"\nProcessing {filename} ...", flush=True)
                summary = process_source(
                    connection,
                    filename,
                    args.max_rows_per_log,
                    args.chunk_rows,
                )
                print(
                    f"Rows read={summary['rows_read']:,}, "
                    f"valid={summary['valid_rows']:,}, "
                    f"skipped/metric issues={summary['skipped_rows']:,}",
                    flush=True,
                )

            summary = write_features(connection, output_path, labels)

    print("\n===== COMPLETE =====")
    print(f"Output: {output_path}")
    print(f"User-days: {summary['user_days']:,}")
    print(f"Positive interval-labelled user-days: {summary['positive_user_days']:,}")
    print("Note: ground_truth uses incident date intervals, not event-level labels.")
    print("Note: timestamps use CERT's recorded clock; no timezone conversion applied.")


if __name__ == "__main__":
    main()
