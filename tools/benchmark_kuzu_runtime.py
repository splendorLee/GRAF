#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import statistics
import sys
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from GraphInitializer import KuzuSeedGenerator
from graf.kuzu_runtime import KuzuWorkerSupervisor
from graf.seed_profiles import seed_profile


SCHEMA = "graf-kuzu-runtime-benchmark/v1"
QUERY = "MATCH (n) RETURN count(n)"


def _summary(samples_ms: list[float]) -> dict[str, float | int]:
    ordered = sorted(samples_ms)
    count = len(ordered)

    def percentile(fraction: float) -> float:
        if not ordered:
            return 0.0
        return ordered[int((count - 1) * fraction)]

    total_ms = sum(ordered)
    return {
        "iterations": count,
        "total_ms": round(total_ms, 3),
        "mean_ms": round(statistics.mean(ordered), 3) if ordered else 0.0,
        "p50_ms": round(percentile(0.50), 3),
        "p95_ms": round(percentile(0.95), 3),
        "operations_per_second": round(count / (total_ms / 1000.0), 3) if total_ms else 0.0,
    }


def _persistent(db_path: str, iterations: int, timeout_seconds: float) -> tuple[dict, dict]:
    runtime = KuzuWorkerSupervisor(db_path)
    samples: list[float] = []
    try:
        runtime.request("ping", timeout_seconds=timeout_seconds)
        for _ in range(iterations):
            started = time.perf_counter()
            compiled = runtime.request(
                "compile",
                query=QUERY,
                timeout_seconds=timeout_seconds,
            )
            executed = runtime.request(
                "execute",
                query=QUERY,
                timeout_seconds=timeout_seconds,
            )
            if not compiled.success or not executed.success:
                raise RuntimeError(
                    f"persistent benchmark failed: compile={compiled.status}, execute={executed.status}"
                )
            samples.append((time.perf_counter() - started) * 1000.0)
    finally:
        runtime.close()
    telemetry = runtime.snapshot()
    return _summary(samples), telemetry


def _cold_worker(db_path: str, iterations: int, timeout_seconds: float) -> tuple[dict, int]:
    samples: list[float] = []
    starts = 0
    for _ in range(iterations):
        started = time.perf_counter()
        runtime = KuzuWorkerSupervisor(db_path)
        try:
            compiled = runtime.request(
                "compile",
                query=QUERY,
                timeout_seconds=timeout_seconds,
            )
            executed = runtime.request(
                "execute",
                query=QUERY,
                timeout_seconds=timeout_seconds,
            )
            if not compiled.success or not executed.success:
                raise RuntimeError(
                    f"cold benchmark failed: compile={compiled.status}, execute={executed.status}"
                )
            starts += runtime.snapshot()["worker_starts"]
        finally:
            runtime.close()
        samples.append((time.perf_counter() - started) * 1000.0)
    return _summary(samples), starts


def run_benchmark(iterations: int, timeout_seconds: float) -> dict:
    iterations = max(1, int(iterations))
    timeout_seconds = max(0.1, float(timeout_seconds))
    with tempfile.TemporaryDirectory(prefix="graf-kuzu-benchmark-") as directory:
        db_path = str(Path(directory) / "db")
        generator = KuzuSeedGenerator(db_path, seed_spec=seed_profile("baseline"))
        generator.reset_and_initialize(reset=True)

        persistent, telemetry = _persistent(db_path, iterations, timeout_seconds)
        cold, cold_starts = _cold_worker(db_path, iterations, timeout_seconds)

    speedup = (
        cold["mean_ms"] / persistent["mean_ms"]
        if persistent["mean_ms"]
        else 0.0
    )
    return {
        "schema": SCHEMA,
        "query": QUERY,
        "iterations": iterations,
        "persistent_runtime": persistent,
        "cold_worker_per_iteration": cold,
        "mean_latency_speedup": round(speedup, 3),
        "worker_starts": {
            "persistent": telemetry["worker_starts"],
            "cold": cold_starts,
        },
        "persistent_telemetry": telemetry,
        "interpretation": (
            "cold mode approximates repeated process/database ownership; "
            "it intentionally excludes the removed SyncManager overhead"
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Benchmark persistent versus per-iteration Kuzu worker lifecycle",
    )
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--assert-min-speedup",
        type=float,
        default=0.0,
        help="Exit non-zero when mean latency speedup is below this value",
    )
    args = parser.parse_args(argv)

    report = run_benchmark(args.iterations, args.timeout)
    encoded = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    sys.stdout.write(encoded)
    if args.assert_min_speedup > 0 and report["mean_latency_speedup"] < args.assert_min_speedup:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
