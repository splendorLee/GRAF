"""Version-pinned target-native admission of LLM skeleton candidates.

No candidate can enter the certified pool without an accepted concrete
EXPLAIN. Deterministic target rejection, inconclusive target failure and
suspected crash are separate outcomes with durable evidence.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import tempfile
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

from .skeleton_lexical import check_skeleton
from .target_validation import TargetCheckResult, TargetCheckStatus

ADMISSION_VERSION = 5
TARGETS = {"memgraph", "neo4j", "falkordb", "kuzu", "nebula"}


def load_candidates(path: Path, *, input_format: str = "lines") -> list[str]:
    """Read one complete skeleton per physical line, with optional semicolon."""
    data = path.read_text(encoding="utf-8")
    if input_format == "lines":
        # Each nonempty physical line is one complete query. Adding a final
        # terminator preserves downstream normalization and catches accidental
        # multiple statements on a line in the mechanical gate.
        return [line.strip() if line.strip().endswith(";") else line.strip() + ";"
                for line in data.splitlines() if line.strip()]
    raise ValueError("admission accepts only one skeleton per physical line")


def _atomic_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".admission-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, default=str) + "\n").encode("utf-8")


def context_digest(schema: Any, state: Any) -> str:
    payload = {
        "labels": sorted(schema.labels),
        "topology": {str(k): sorted(list(v)) for k, v in sorted(schema.topology.items())},
        "properties": schema.properties,
        "property_values": getattr(schema, "property_values", {}),
        "graph": vars(state),
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()


@dataclass(frozen=True)
class AdmissionConfig:
    target: str
    build_id: str
    samples: int = 3
    seed: int = 20260627
    timeout_seconds: int = 15

    def __post_init__(self) -> None:
        if self.target not in TARGETS or not self.build_id.strip():
            raise ValueError("target must be supported and build_id must pin the target binary/image")
        if self.samples < 1 or self.timeout_seconds < 1:
            raise ValueError("samples and timeout_seconds must both be positive")


def admit_candidates(
    candidates: Iterable[str], *, config: AdmissionConfig,
    schema: Any, state: Any, checker: Any,
    instantiate: Callable[..., tuple[str, list[str]]],
    progress: Callable[[int, dict[str, int]], None] | None = None,
    on_record: Callable[[dict[str, Any]], None] | None = None,
) -> tuple[list[str], list[dict[str, Any]], dict[str, int]]:
    """Accept a successful binding only if no sampled infrastructure fails.

    Instantiation failures are deferred for repair. A target compile timeout,
    disconnect or worker death never becomes evidence of unsupported syntax.
    """
    if not callable(getattr(checker, "check", None)):
        raise TypeError("admission requires an isolated checker exposing typed check()")
    accepted: list[str] = []
    evidence: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    seen: dict[str, int] = {}

    def emit(record: dict[str, Any]) -> None:
        evidence.append(record)
        if on_record is not None:
            on_record(record)
        if progress is not None:
            progress(record["index"], dict(counts))

    for index, candidate in enumerate(candidates, 1):
        mechanical = check_skeleton(candidate)
        if not mechanical.accepted:
            counts["mechanical_rejected"] += 1
            emit({"index": index, "status": "mechanical_rejected",
                  "reason": mechanical.reason, "skeleton": candidate})
            continue
        if mechanical.normalized in seen:
            counts["duplicate"] += 1
            emit({"index": index, "status": "duplicate",
                  "reason": f"identical skeleton to input {seen[mechanical.normalized]}",
                  "skeleton": candidate})
            continue
        seen[mechanical.normalized] = index
        samples = []
        statuses: list[TargetCheckStatus] = []
        for sample_index in range(config.samples):
            started = time.monotonic()
            # Isolate each binding's RNG from the campaign and make replay
            # independent of prior candidates or targets.
            rng = random.getstate()
            material = f"{config.seed}:{index}:{sample_index}:{mechanical.normalized}"
            random.seed(int.from_bytes(hashlib.sha256(material.encode()).digest()[:8], "big"))
            try:
                statement, errors = instantiate(mechanical.normalized, schema, state,
                                                target_engine=config.target,
                                                allow_target_dialect=True)
            except Exception as exc:
                statement, errors = "", [f"{type(exc).__name__}: {exc}"]
            finally:
                random.setstate(rng)
            if errors or not statement or "$" in statement:
                samples.append({"sample": sample_index, "status": "instantiation_deferred",
                                "reason": "; ".join(errors)[:500] if errors else "unresolved placeholder",
                                "query": statement[:2000],
                                "elapsed_ms": round((time.monotonic() - started) * 1000, 2)})
                continue
            try:
                result: TargetCheckResult = checker.check(statement)
            except Exception as exc:
                result = TargetCheckResult(TargetCheckStatus.INFRASTRUCTURE,
                                           f"checker exception: {type(exc).__name__}: {exc}")
            statuses.append(result.status)
            samples.append({"sample": sample_index, "status": result.status.value,
                            "reason": result.message[:500], "query": statement[:2000],
                            "elapsed_ms": round((time.monotonic() - started) * 1000, 2)})
        if TargetCheckStatus.CRASH_SUSPECTED in statuses:
            status = "crash_suspected"
        elif TargetCheckStatus.TIMEOUT in statuses:
            status = "timeout_deferred"
        elif TargetCheckStatus.INFRASTRUCTURE in statuses:
            status = "infrastructure_deferred"
        elif TargetCheckStatus.ACCEPTED in statuses:
            status = "accepted"
            accepted.append(mechanical.normalized)
        elif any(sample["status"] == "instantiation_deferred" for sample in samples):
            status = "instantiation_deferred"
        else:
            status = "target_rejected"
        counts[status] += 1
        emit({"index": index, "status": status,
              "skeleton": mechanical.normalized, "samples": samples})
    return accepted, evidence, dict(counts)


def publish_admission(
    *, source: Path, output: Path, candidates: list[str], config: AdmissionConfig,
    schema: Any, state: Any, checker: Any,
    instantiate: Callable[..., tuple[str, list[str]]],
    progress: Callable[[int, dict[str, int]], None] | None = None,
    on_record: Callable[[dict[str, Any]], None] | None = None,
    progress_path: Path | None = None,
    input_format: str = "lines",
    campaign_seed: int | None = None,
    seed_profile_name: str | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    output.parent.mkdir(parents=True, exist_ok=True)
    if progress_path is None:
        progress_path = Path(f"{output}.evidence.{time.strftime('%Y%m%dT%H%M%S', time.gmtime())}"
                             f".{os.getpid()}.inprogress.jsonl")
    with progress_path.open("x", encoding="utf-8") as stream:
        def persist(record: dict[str, Any]) -> None:
            stream.write(json.dumps(record, ensure_ascii=False) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
            if on_record is not None:
                on_record(record)

        accepted, evidence, counts = admit_candidates(
            candidates, config=config, schema=schema, state=state,
            checker=checker, instantiate=instantiate, progress=progress,
            on_record=persist)
    pool_bytes = ("\n".join(accepted) + ("\n" if accepted else "")).encode("utf-8")
    target_reasons = Counter(
        next((sample.get("reason", "") for sample in row.get("samples", [])
              if sample.get("status") == "rejected"), "unknown target rejection")
        for row in evidence if row["status"] == "target_rejected"
    )
    result = {
        "status": "CERTIFIED" if accepted else "NO_ACCEPTED_CANDIDATES",
        "pool_published": bool(accepted),
        "admission_version": ADMISSION_VERSION, "target": config.target,
        "duplicate_policy": "exact_skeleton_after_optional_final_semicolon/v1",
        "input_format": input_format,
        "target_build_id": config.build_id, "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "source_file": source.name if source.parent.resolve() == output.parent.resolve()
                       else str(source.resolve()),
        "pool_sha256": hashlib.sha256(pool_bytes).hexdigest(),
        "context_sha256": context_digest(schema, state),
        "samples_per_skeleton": config.samples, "seed": config.seed,
        "campaign_seed": campaign_seed, "initial_seed_profile": seed_profile_name,
        "compile_timeout_seconds": config.timeout_seconds,
        "admission_wall_seconds": round(time.monotonic() - started, 3),
        "input_count": len(candidates), "accepted": len(accepted), "counts": counts,
        "context_summary": {
            "labels": len(schema.labels), "edge_types": len(schema.topology),
            "observed_topology_pairs": sum(len(pairs) for pairs in schema.topology.values()),
            "nodes": state.total_nodes, "edges": state.total_edges,
        },
        "top_target_rejection_reasons": [[reason, count] for reason, count
                                         in target_reasons.most_common(20)],
        "evidence_file": output.name + ".evidence.jsonl",
        "gate": "three independent live-context instantiations + target-native EXPLAIN; at least one accepted and no sampled target exception",
    }
    evidence_bytes = ("\n".join(json.dumps(row, ensure_ascii=False) for row in evidence) + "\n").encode()
    result["evidence_sha256"] = hashlib.sha256(evidence_bytes).hexdigest()
    if not accepted:
        # A failed re-admission must never erase an already certified pool,
        # evidence or manifest. Preserve this run's diagnosis separately.
        stem = progress_path.name.removesuffix(".inprogress.jsonl")
        failed_path = progress_path.with_name(stem + ".failed.jsonl")
        if failed_path.exists():
            raise FileExistsError(f"failed admission evidence already exists: {failed_path}")
        os.rename(progress_path, failed_path)
        result["evidence_file"] = failed_path.name
        result["diagnostic_manifest_file"] = failed_path.name + ".admission.json"
        _atomic_bytes(Path(str(failed_path) + ".admission.json"), _json_bytes(result))
        return result
    # Publish the manifest last: interrupted writes cannot appear certified.
    _atomic_bytes(output, pool_bytes)
    _atomic_bytes(Path(str(output) + ".evidence.jsonl"), evidence_bytes)
    _atomic_bytes(Path(str(output) + ".admission.json"), _json_bytes(result))
    progress_path.unlink()
    return result


def verify_admission(path: Path, target: str, build_id: str | None = None) -> dict[str, Any]:
    manifest_path = Path(str(path) + ".admission.json")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if (manifest.get("status") != "CERTIFIED" or
            manifest.get("admission_version") != ADMISSION_VERSION or
            manifest.get("target") != target or
            (build_id is not None and manifest.get("target_build_id") != build_id) or
            not manifest.get("target_build_id") or int(manifest.get("accepted", 0)) < 1 or
            manifest.get("samples_per_skeleton") != 3):
        raise ValueError("target pool is not certified for this target/build or three samples")
    if hashlib.sha256(path.read_bytes()).hexdigest() != manifest.get("pool_sha256"):
        raise ValueError("target pool differs from its certified hash")
    source_file = manifest.get("source_file")
    if not source_file:
        raise ValueError("admission manifest has no raw source file")
    source = Path(source_file)
    if not source.is_absolute():
        source = path.parent / source
    if not source.is_file() or hashlib.sha256(source.read_bytes()).hexdigest() != manifest.get("source_sha256"):
        raise ValueError("raw skeleton source is missing or differs from the admitted source")
    evidence = Path(str(path) + ".evidence.jsonl")
    if (not evidence.is_file() or hashlib.sha256(evidence.read_bytes()).hexdigest()
            != manifest.get("evidence_sha256")):
        raise ValueError("target admission evidence is missing or modified")
    if len(load_candidates(path, input_format="lines")) != manifest["accepted"]:
        raise ValueError("target pool has a different statement count")
    return manifest
