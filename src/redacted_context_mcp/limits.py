"""Shared bounded-operation helpers."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path


class OperationLimitError(SystemExit):
    """Raised when a configured operation budget is exceeded."""


@dataclass
class OperationBudget:
    max_files: int | None = None
    max_raw_bytes_per_file: int | None = None
    max_total_raw_bytes: int | None = None
    max_entries: int | None = None
    max_output_chars: int | None = None
    deadline: float | None = None

    files_seen: int = 0
    raw_bytes_seen: int = 0
    entries_seen: int = 0

    @classmethod
    def from_seconds(
        cls,
        *,
        max_files: int | None = None,
        max_raw_bytes_per_file: int | None = None,
        max_total_raw_bytes: int | None = None,
        max_entries: int | None = None,
        max_output_chars: int | None = None,
        seconds: float | None = None,
    ) -> "OperationBudget":
        deadline = time.monotonic() + seconds if seconds is not None else None
        return cls(
            max_files=max_files,
            max_raw_bytes_per_file=max_raw_bytes_per_file,
            max_total_raw_bytes=max_total_raw_bytes,
            max_entries=max_entries,
            max_output_chars=max_output_chars,
            deadline=deadline,
        )

    def check_deadline(self) -> None:
        if self.deadline is not None and time.monotonic() > self.deadline:
            raise OperationLimitError("Operation deadline exceeded.")

    def consume_entry(self) -> None:
        self.check_deadline()
        self.entries_seen += 1
        if self.max_entries is not None and self.entries_seen > self.max_entries:
            raise OperationLimitError("Traversal entry limit exceeded.")

    def consume_file(self, path: Path) -> int:
        self.check_deadline()
        self.files_seen += 1
        if self.max_files is not None and self.files_seen > self.max_files:
            raise OperationLimitError("File limit exceeded.")
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise OperationLimitError("Could not inspect file size.") from exc
        self.consume_raw_bytes(size)
        return size

    def consume_raw_bytes(self, size: int) -> None:
        self.check_deadline()
        if self.max_raw_bytes_per_file is not None and size > self.max_raw_bytes_per_file:
            raise OperationLimitError("Raw file byte limit exceeded.")
        next_total = self.raw_bytes_seen + size
        if self.max_total_raw_bytes is not None and next_total > self.max_total_raw_bytes:
            raise OperationLimitError("Total raw byte limit exceeded.")
        self.raw_bytes_seen = next_total

    def check_output_chars(self, count: int) -> None:
        self.check_deadline()
        if self.max_output_chars is not None and count > self.max_output_chars:
            raise OperationLimitError("Output character limit exceeded.")
