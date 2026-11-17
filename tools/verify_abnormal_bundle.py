#!/usr/bin/env python3
"""Verify integrity and replay completeness of a GRAF abnormal-case bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from graf.evidence import ABNORMAL_CASE_SCHEMA, sha256_text  # noqa: E402


REQUIRED_FILES = {
    "context.json",
    "seed.cypher",
    "replay_state_changes.cypher",
    "successful_query_window.cypher",
    "trigger.cypher",
    "epoch_queries.jsonl",
}


def _load_json(path: Path, errors: list[str]) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{path.name}: invalid JSON: {type(exc).__name__}: {exc}")
        return {}
    if not isinstance(value, dict):
        errors.append(f"{path.name}: root must be an object")
        return {}
    return value


def verify_bundle(case_path: Path, require_complete_replay: bool = False) -> dict[str, Any]:
    case_dir = case_path.resolve()
    if case_dir.is_file():
        case_dir = case_dir.parent
    errors: list[str] = []
    manifest_path = case_dir / "manifest.json"
    context_path = case_dir / "context.json"
    if not manifest_path.is_file():
        errors.append("manifest.json is missing")
    if not context_path.is_file():
        errors.append("context.json is missing")
    if errors:
        return {"valid": False, "case_dir": str(case_dir), "errors": errors}

    manifest = _load_json(manifest_path, errors)
    context = _load_json(context_path, errors)
    if manifest.get("schema") != ABNORMAL_CASE_SCHEMA:
        errors.append(f"manifest schema must be {ABNORMAL_CASE_SCHEMA}")
    if context.get("schema") != ABNORMAL_CASE_SCHEMA:
        errors.append(f"context schema must be {ABNORMAL_CASE_SCHEMA}")
    if manifest.get("case_id") != context.get("case_id"):
        errors.append("manifest/context case_id mismatch")

    reproduction_file = str(manifest.get("reproduction_file", ""))
    required = set(REQUIRED_FILES)
    if reproduction_file:
        required.add(reproduction_file)
    else:
        errors.append("manifest reproduction_file is missing")

    inventory = manifest.get("files")
    if not isinstance(inventory, dict):
        errors.append("manifest files inventory must be an object")
        inventory = {}
    for filename in sorted(required):
        if filename not in inventory:
            errors.append(f"required file is not inventoried: {filename}")

    for filename, expected in inventory.items():
        if Path(filename).name != filename:
            errors.append(f"unsafe inventory filename: {filename}")
            continue
        path = case_dir / filename
        if not path.is_file():
            errors.append(f"inventoried file is missing: {filename}")
            continue
        if not isinstance(expected, dict):
            errors.append(f"invalid inventory record: {filename}")
            continue
        body = path.read_bytes()
        actual_hash = hashlib.sha256(body).hexdigest()
        if expected.get("bytes") != len(body):
            errors.append(f"byte length mismatch: {filename}")
        if expected.get("sha256") != actual_hash:
            errors.append(f"SHA-256 mismatch: {filename}")

    graph_context = context.get("graph_context", {})
    trigger = context.get("trigger", {})
    if not isinstance(graph_context, dict):
        errors.append("context graph_context must be an object")
        graph_context = {}
    if not isinstance(trigger, dict):
        errors.append("context trigger must be an object")
        trigger = {}
    if sha256_text(str(graph_context.get("seed_script", ""))) != graph_context.get("seed_script_sha256"):
        errors.append("context seed_script digest mismatch")
    if sha256_text(str(trigger.get("query", ""))) != trigger.get("sha256"):
        errors.append("context trigger digest mismatch")

    replay_window = graph_context.get("replay_window", {})
    if not isinstance(replay_window, dict):
        errors.append("context replay_window must be an object")
        replay_window = {}
    state_history = graph_context.get("state_change_history", [])
    if not isinstance(state_history, list):
        errors.append("context state_change_history must be an array")
        state_history = []
    if replay_window.get("state_changes_retained") != len(state_history):
        errors.append("retained state-change count does not match history length")
    replay_complete = bool(replay_window.get("state_replay_complete"))
    expected_complete = (
        int(replay_window.get("state_changes_evicted", 0) or 0) == 0
        and bool(replay_window.get("seed_available", True))
        and int(replay_window.get("uncertain_prior_writes", 0) or 0) == 0
    )
    if replay_complete != expected_complete:
        errors.append("state_replay_complete contradicts seed, write uncertainty, or eviction count")
    if require_complete_replay and not replay_complete:
        errors.append("state replay is incomplete")

    if "epoch_queries.jsonl" in inventory:
        try:
            records = [json.loads(line) for line in (case_dir / "epoch_queries.jsonl").read_text(encoding="utf-8").splitlines()]
            if not records or records[0].get("event") != "epoch_started":
                errors.append("epoch history has no start marker")
            committed = sum(item.get("event") == "state_change_committed" for item in records)
            if committed != len(state_history):
                errors.append("epoch history state-change count mismatch")
            starts = [item for item in records if item.get("event") == "query_started"]
            if starts and context.get("capture_order") == "evidence_committed_before_recovery_or_reset":
                trigger_query = str(trigger.get("query", "")).strip()
                if starts[-1].get("query", "").strip() != trigger_query:
                    errors.append("last submitted query differs from trigger")
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            errors.append(f"invalid epoch query history: {type(exc).__name__}: {exc}")

    return {
        "valid": not errors,
        "case_dir": str(case_dir),
        "case_id": context.get("case_id"),
        "target": context.get("target"),
        "classification": context.get("classification"),
        "managed_seed": graph_context.get("managed_seed"),
        "seed_capture_status": graph_context.get("seed_capture_status"),
        "state_replay_complete": replay_complete,
        "inventoried_files": len(inventory),
        "errors": errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", type=Path, help="Case directory or a file inside it")
    parser.add_argument(
        "--require-complete-replay",
        action="store_true",
        help="Fail if state-changing history was evicted",
    )
    args = parser.parse_args()
    result = verify_bundle(args.case, require_complete_replay=args.require_complete_replay)
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

