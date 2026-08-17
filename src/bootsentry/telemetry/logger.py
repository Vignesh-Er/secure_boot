"""Interruption-safe atomic JSONL telemetry logger."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

from bootsentry.telemetry.record import BootRecord


def log_boot_record(record: BootRecord, file_path: Path | str) -> None:
    """Append a single BootRecord to a JSONL dataset file safely."""
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    line = record.to_json() + "\n"
    with open(path, "a", encoding="utf-8") as f:
        f.write(line)
        f.flush()


def read_boot_records(file_path: Path | str) -> list[BootRecord]:
    """Read all BootRecords from a JSONL file."""
    path = Path(file_path)
    if not path.exists():
        return []

    records = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if stripped:
                try:
                    data = json.loads(stripped)
                    records.append(BootRecord.from_dict(data))
                except json.JSONDecodeError:
                    continue
    return records


def iter_boot_records(file_path: Path | str) -> Iterator[BootRecord]:
    """Iterate over BootRecords line-by-line for streaming memory-efficient processing."""
    path = Path(file_path)
    if not path.exists():
        return

    with open(path, encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if stripped:
                try:
                    data = json.loads(stripped)
                    yield BootRecord.from_dict(data)
                except json.JSONDecodeError:
                    continue
