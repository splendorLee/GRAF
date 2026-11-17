from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import uuid
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Optional

from .model import stable_json, to_jsonable


JOURNAL_SCHEMA = "graf-enterprise-journal/v1"


class EnterpriseJournal:
    """Append-only, process-safe-enough JSONL journal with monotonic sequence IDs.

    One GRAF process owns a journal.  Thread locking prevents interleaved writes;
    O_APPEND keeps each encoded event contiguous at the OS boundary.  Optional
    fsync trades throughput for crash durability.
    """

    def __init__(self, path: str | Path, *, run_id: str = "", fsync: bool = False) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.run_id = run_id or f"run-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{uuid.uuid4().hex[:8]}"
        self.fsync = fsync
        self._sequence = 0
        self._lock = threading.Lock()
        self.counters: Counter[str] = Counter()

    def emit(self, event: str, **payload: Any) -> dict[str, Any]:
        with self._lock:
            self._sequence += 1
            self.counters[event] += 1
            record = {
                "schema": JOURNAL_SCHEMA,
                "run_id": self.run_id,
                "sequence": self._sequence,
                "timestamp_unix_ms": int(time.time() * 1000),
                "event": event,
                **{key: to_jsonable(value) for key, value in payload.items()},
            }
            encoded = (json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
            descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
            try:
                view = memoryview(encoded)
                while view:
                    written = os.write(descriptor, view)
                    view = view[written:]
                if self.fsync:
                    os.fsync(descriptor)
            finally:
                os.close(descriptor)
            return record

    def summary(self) -> dict[str, Any]:
        return {
            "schema": "graf-enterprise-summary/v1",
            "run_id": self.run_id,
            "journal": str(self.path),
            "events": self._sequence,
            "counts": dict(sorted(self.counters.items())),
        }

    def write_summary(self, path: str | Path, **payload: Any) -> Path:
        """Atomically publish a machine-readable terminal run summary."""

        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        document = self.summary()
        document.update({key: to_jsonable(value) for key, value in payload.items()})
        encoded = (json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
        temporary = destination.with_name(f".{destination.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
        try:
            view = memoryview(encoded)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, destination)
        try:
            directory_fd = os.open(destination.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            # Some filesystems do not support directory fsync.  The file was
            # still written and atomically renamed successfully.
            pass
        return destination


class ArtifactStore:
    """Content-addressed evidence store with atomic writes and deduplication."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def save(self, category: str, payload: Mapping[str, Any]) -> tuple[Path, bool]:
        body = stable_json(payload).encode("utf-8")
        digest = hashlib.sha256(body).hexdigest()
        safe_category = "".join(char if char.isalnum() or char in "-_" else "_" for char in category) or "uncategorized"
        directory = self.root / safe_category / digest[:2]
        final_path = directory / f"{digest}.json"
        with self._lock:
            if final_path.exists():
                return final_path, False
            directory.mkdir(parents=True, exist_ok=True)
            temporary = directory / f".{digest}.{os.getpid()}.{threading.get_ident()}.tmp"
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
            try:
                os.write(descriptor, body)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temporary, final_path)
        return final_path, True
