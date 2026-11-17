"""Durable, bounded evidence bundles for abnormal target executions.

The executor owns target-specific replay rendering.  This module owns the
portable evidence contract and crash-safe publication of a complete case
directory.  A bundle is assembled in a private sibling directory and becomes
visible only after every file has been flushed and the directory is renamed.
"""

from __future__ import annotations

import datetime as _datetime
import hashlib
import json
import os
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence


ABNORMAL_CASE_SCHEMA = "graf-enterprise-abnormal-case/v1"
DEFAULT_DIAGNOSTIC_FIELD_BYTES = 256 * 1024
DEFAULT_DIAGNOSTIC_WINDOW_BYTES = 2 * 1024 * 1024


class EpochLedger:
    """Durable, append-only record of target submissions within one graph epoch.

    Every record is synced before the next database request.  The full record
    stays on disk; diagnostic windows in memory may be bounded independently.
    """

    def __init__(self, root: str | Path, sequence: int, reason: str):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / f"epoch_{sequence:06d}.jsonl"
        descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
        os.close(descriptor)
        directory_fd = os.open(self.root, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        self.append("epoch_started", sequence=sequence, reason=reason)

    def append(self, event: str, **fields: Any) -> None:
        record = {"event": event, "at": utc_now(), **_json_safe(fields)}
        body = (json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
        descriptor = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
        try:
            offset = 0
            while offset < len(body):
                offset += os.write(descriptor, body[offset:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def snapshot(self) -> tuple[str, list[dict[str, Any]]]:
        body = self.path.read_text(encoding="utf-8")
        records = []
        for line_number, line in enumerate(body.splitlines(), 1):
            try:
                item = json.loads(line)
            except (ValueError, TypeError) as exc:
                raise ValueError(f"corrupt epoch ledger line {line_number}: {exc}") from exc
            if not isinstance(item, dict):
                raise ValueError(f"invalid epoch ledger record at line {line_number}")
            records.append(item)
        return body, records


def utc_now() -> str:
    return (
        _datetime.datetime.now(_datetime.timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def sha256_text(value: str) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def _safe_component(value: str, fallback: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value or "")).strip("._")
    return safe or fallback


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]
    if hasattr(value, "to_dict"):
        return _json_safe(value.to_dict())
    if hasattr(value, "__dict__"):
        return _json_safe(vars(value))
    return str(value)


def _bounded_diagnostic(value: Any, max_bytes: int, path: str = "$") -> tuple[Any, list[dict[str, Any]]]:
    """Bound diagnostic strings without truncating replay-critical SQL/Cypher.

    Trigger, seed, and replay statements are stored in dedicated files and are
    deliberately excluded from this function.  It is used for driver errors,
    log tails, and auxiliary fuzzer metadata where a pathological line must not
    create an unbounded artifact.
    """

    truncations: list[dict[str, Any]] = []
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        if len(encoded) <= max_bytes:
            return value, truncations
        prefix = encoded[:max_bytes].decode("utf-8", errors="ignore")
        truncations.append(
            {
                "path": path,
                "original_bytes": len(encoded),
                "retained_bytes": len(prefix.encode("utf-8")),
                "sha256": hashlib.sha256(encoded).hexdigest(),
            }
        )
        return prefix, truncations
    if isinstance(value, Mapping):
        bounded: dict[str, Any] = {}
        for key, item in value.items():
            child, child_truncations = _bounded_diagnostic(item, max_bytes, f"{path}.{key}")
            bounded[str(key)] = child
            truncations.extend(child_truncations)
        return bounded, truncations
    if isinstance(value, (list, tuple, set)):
        bounded_items = []
        for index, item in enumerate(value):
            child, child_truncations = _bounded_diagnostic(item, max_bytes, f"{path}[{index}]")
            bounded_items.append(child)
            truncations.extend(child_truncations)
        return bounded_items, truncations
    return _json_safe(value), truncations


def _bounded_text_window(
    values: Sequence[str],
    max_item_bytes: int,
    max_total_bytes: int,
) -> tuple[list[str], list[dict[str, Any]]]:
    """Retain the newest diagnostic strings under a deterministic byte cap."""

    retained_reversed: list[str] = []
    truncations: list[dict[str, Any]] = []
    retained_bytes = 0
    for reverse_index, value in enumerate(reversed([str(item) for item in values])):
        original_index = len(values) - reverse_index - 1
        bounded, item_truncations = _bounded_diagnostic(
            value,
            max_item_bytes,
            f"$.diagnostic_query_history[{original_index}]",
        )
        encoded = str(bounded).encode("utf-8")
        if retained_bytes + len(encoded) > max_total_bytes:
            truncations.append(
                {
                    "path": "$.diagnostic_query_history",
                    "omitted_oldest_items": original_index + 1,
                    "retained_total_bytes": retained_bytes,
                    "maximum_total_bytes": max_total_bytes,
                }
            )
            break
        retained_reversed.append(str(bounded))
        retained_bytes += len(encoded)
        truncations.extend(item_truncations)
    return list(reversed(retained_reversed)), truncations


@dataclass(frozen=True)
class ReplayWindow:
    """Accounting for history retained since the last graph reset."""

    successful_total: int
    successful_retained: int
    successful_evicted: int
    state_changes_total: int
    state_changes_retained: int
    state_changes_evicted: int
    seed_available: bool = True
    uncertain_prior_writes: int = 0

    @property
    def state_replay_complete(self) -> bool:
        return self.state_changes_evicted == 0 and self.seed_available and self.uncertain_prior_writes == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "successful_total": self.successful_total,
            "successful_retained": self.successful_retained,
            "successful_evicted": self.successful_evicted,
            "state_changes_total": self.state_changes_total,
            "state_changes_retained": self.state_changes_retained,
            "state_changes_evicted": self.state_changes_evicted,
            "seed_available": self.seed_available,
            "uncertain_prior_writes": self.uncertain_prior_writes,
            "state_replay_complete": self.state_replay_complete,
        }


@dataclass(frozen=True)
class AbnormalCase:
    target: str
    classification: str
    message: str
    trigger_query: str
    seed_script: str
    seed_statements: Sequence[str]
    state_change_history: Sequence[Mapping[str, Any]]
    diagnostic_query_history: Sequence[str]
    replay_window: ReplayWindow
    execution_context: Mapping[str, Any]
    evidence: Mapping[str, Any]
    graph_reset_sequence: int
    graph_context_started_at: str
    graph_context_reason: str
    managed_seed: bool
    reproduction_extension: str
    reproduction_text: str
    extra_files: Mapping[str, str] = field(default_factory=dict)
    diagnostic_field_bytes: int = DEFAULT_DIAGNOSTIC_FIELD_BYTES
    diagnostic_window_bytes: int = DEFAULT_DIAGNOSTIC_WINDOW_BYTES

    def validate(self) -> None:
        if not self.target.strip():
            raise ValueError("abnormal evidence target must not be empty")
        if not self.classification.strip():
            raise ValueError("abnormal evidence classification must not be empty")
        if not self.trigger_query.strip():
            raise ValueError("abnormal evidence trigger query must not be empty")
        if self.graph_reset_sequence < 0:
            raise ValueError("graph reset sequence must be non-negative")
        if self.diagnostic_field_bytes < 1024:
            raise ValueError("diagnostic field budget must be at least 1024 bytes")
        if self.diagnostic_window_bytes < self.diagnostic_field_bytes:
            raise ValueError("diagnostic window budget must be at least one field budget")


@dataclass(frozen=True)
class PublishedCase:
    case_id: str
    case_dir: Path
    reproduction_path: Path
    manifest_path: Path


class AbnormalCaseBundleWriter:
    """Publish one abnormal case as an atomically visible directory."""

    def __init__(self, root: str | Path):
        self.root = Path(root)

    @staticmethod
    def _write_bytes(path: Path, body: bytes) -> None:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
        try:
            offset = 0
            while offset < len(body):
                offset += os.write(descriptor, body[offset:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @classmethod
    def _write_text(cls, path: Path, value: str) -> None:
        text = str(value or "")
        if text and not text.endswith("\n"):
            text += "\n"
        cls._write_bytes(path, text.encode("utf-8"))

    @classmethod
    def _write_json(cls, path: Path, value: Any) -> None:
        body = json.dumps(
            _json_safe(value),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            separators=(",", ": "),
        ) + "\n"
        cls._write_bytes(path, body.encode("utf-8"))

    @staticmethod
    def _file_record(path: Path) -> dict[str, Any]:
        body = path.read_bytes()
        return {
            "bytes": len(body),
            "sha256": hashlib.sha256(body).hexdigest(),
        }

    def publish(self, case: AbnormalCase) -> PublishedCase:
        case.validate()
        observed_at = utc_now()
        timestamp = observed_at.replace("-", "").replace(":", "").replace(".", "")
        timestamp = timestamp.replace("Z", "Z")
        case_id = (
            f"{_safe_component(case.classification.lower(), 'abnormal')}_"
            f"{timestamp}_{uuid.uuid4().hex[:8]}"
        )
        self.root.mkdir(parents=True, exist_ok=True)
        temporary = self.root / f".{case_id}.{os.getpid()}.tmp"
        destination = self.root / case_id
        temporary.mkdir(mode=0o750)

        try:
            bounded_message, message_truncations = _bounded_diagnostic(
                str(case.message or ""), case.diagnostic_field_bytes, "$.message"
            )
            bounded_context, context_truncations = _bounded_diagnostic(
                _json_safe(case.execution_context), case.diagnostic_field_bytes, "$.execution_context"
            )
            bounded_evidence, evidence_truncations = _bounded_diagnostic(
                _json_safe(case.evidence), case.diagnostic_field_bytes, "$.evidence"
            )
            seed_script = str(case.seed_script or "")
            seed_statements = [str(statement) for statement in case.seed_statements]
            state_history = []
            state_truncations: list[dict[str, Any]] = []
            for index, item in enumerate(case.state_change_history):
                safe_item = _json_safe(item)
                if not isinstance(safe_item, Mapping):
                    continue
                bounded_summary, summary_truncations = _bounded_diagnostic(
                    str(safe_item.get("summary", "")),
                    case.diagnostic_field_bytes,
                    f"$.graph_context.state_change_history[{index}].summary",
                )
                state_history.append(
                    {
                        **safe_item,
                        # Query text is replay-critical and therefore exact.
                        "query": str(safe_item.get("query", "")),
                        "summary": bounded_summary,
                    }
                )
                state_truncations.extend(summary_truncations)
            query_history, query_history_truncations = _bounded_text_window(
                case.diagnostic_query_history,
                case.diagnostic_field_bytes,
                case.diagnostic_window_bytes,
            )

            state_replay = "\n".join(
                str(item.get("query", "")).strip()
                for item in state_history
                if isinstance(item, Mapping) and str(item.get("query", "")).strip()
            )
            diagnostic_history = "\n".join(query.strip() for query in query_history if query.strip())
            files: dict[str, str] = {
                "seed.cypher": seed_script,
                "replay_state_changes.cypher": state_replay,
                "successful_query_window.cypher": diagnostic_history,
                "trigger.cypher": case.trigger_query,
                f"reproduce.{_safe_component(case.reproduction_extension, 'txt')}": case.reproduction_text,
            }
            for name, content in case.extra_files.items():
                safe_name = Path(str(name)).name
                if safe_name in files or safe_name == "manifest.json":
                    raise ValueError(f"duplicate or reserved evidence filename: {safe_name}")
                files[safe_name] = str(content or "")

            context_payload = {
                "schema": ABNORMAL_CASE_SCHEMA,
                "case_id": case_id,
                "observed_at": observed_at,
                "target": case.target,
                "classification": case.classification,
                "message": bounded_message,
                "capture_order": "evidence_committed_before_recovery_or_reset",
                "trigger": {
                    "query": case.trigger_query,
                    "sha256": sha256_text(case.trigger_query),
                },
                "graph_context": {
                    "managed_seed": case.managed_seed,
                    "seed_capture_status": (
                        "exact_managed_seed"
                        if case.managed_seed
                        else "unavailable_external_reuse_graph"
                    ),
                    "reset_sequence": case.graph_reset_sequence,
                    "started_at": case.graph_context_started_at,
                    "reason": case.graph_context_reason,
                    "seed_script": seed_script,
                    "seed_script_sha256": sha256_text(seed_script),
                    "seed_statement_count": len(seed_statements),
                    "seed_statements": seed_statements,
                    "state_change_history": state_history,
                    "replay_window": case.replay_window.to_dict(),
                    "epoch_query_history_file": "epoch_queries.jsonl",
                },
                "diagnostic_query_history": query_history,
                "execution_context": bounded_context,
                "evidence": bounded_evidence,
                "diagnostic_truncations": (
                    message_truncations
                    + context_truncations
                    + evidence_truncations
                    + state_truncations
                    + query_history_truncations
                ),
            }
            self._write_json(temporary / "context.json", context_payload)
            for name, content in files.items():
                self._write_text(temporary / name, content)

            file_inventory = {
                path.name: self._file_record(path)
                for path in sorted(temporary.iterdir())
                if path.is_file()
            }
            reproduction_name = f"reproduce.{_safe_component(case.reproduction_extension, 'txt')}"
            manifest = {
                "schema": ABNORMAL_CASE_SCHEMA,
                "case_id": case_id,
                "observed_at": observed_at,
                "target": case.target,
                "classification": case.classification,
                "capture_order": "evidence_committed_before_recovery_or_reset",
                "reproduction_file": reproduction_name,
                "context_file": "context.json",
                "state_replay_complete": case.replay_window.state_replay_complete,
                "epoch_query_history_file": "epoch_queries.jsonl",
                "files": file_inventory,
            }
            self._write_json(temporary / "manifest.json", manifest)

            directory_fd = os.open(temporary, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            os.replace(temporary, destination)
            try:
                parent_fd = os.open(self.root, os.O_RDONLY)
                try:
                    os.fsync(parent_fd)
                finally:
                    os.close(parent_fd)
            except OSError:
                pass
        except Exception:
            # The temporary directory is intentionally left hidden for
            # post-mortem inspection if publication itself fails.
            raise

        return PublishedCase(
            case_id=case_id,
            case_dir=destination,
            reproduction_path=destination / reproduction_name,
            manifest_path=destination / "manifest.json",
        )

