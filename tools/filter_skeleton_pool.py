#!/usr/bin/env python3
"""Admit raw LLM skeletons by three seeded bindings and target-native EXPLAIN."""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from graf.skeleton_paths import DEFAULT_GENERATED_DIR, pool_path, raw_path, target_name


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generated-dir", type=Path, default=DEFAULT_GENERATED_DIR)
    parser.add_argument("--input", type=Path, help="Default: generated_skeletons/<GDBMS>_skeletons")
    parser.add_argument("--output", type=Path, help="Default: generated_skeletons/<GDBMS>_skeleton_pool")
    parser.add_argument("--target", required=True,
                        help="Neo4j, Memgraph, FalkorDB, KuzuDB, or NebulaGraph")
    parser.add_argument("--target-build-id", default=os.environ.get("GRAF_TARGET_BUILD_ID"),
                        help="Exact target image digest or binary build ID (pass to GRAF for an exact match)")
    parser.add_argument("--compile-check-timeout", type=int, default=15)
    parser.add_argument("--seed", type=int, default=20260627)
    parser.add_argument("--campaign-seed", type=int, default=20260627,
                        help="Select the same initial seed graph as GRAF --seed (default: 20260627)")
    parser.add_argument("--print-rejections", action="store_true",
                        help="Print every rejected/deferred candidate with its concrete query; full evidence is always saved as JSONL")
    parser.add_argument("--initialize-graph", action="store_true",
                        help="Explicitly clear and seed a dedicated test graph with the campaign's initial graph profile")
    parser.add_argument("--memgraph-uri", default="bolt://localhost:7687")
    parser.add_argument("--memgraph-user", default=os.environ.get("GRAF_MEMGRAPH_USER", ""))
    parser.add_argument("--memgraph-password", default=os.environ.get("GRAF_MEMGRAPH_PASSWORD", ""))
    parser.add_argument("--neo4j-uri", default="bolt://localhost:7687")
    parser.add_argument("--neo4j-user", default="neo4j")
    parser.add_argument("--neo4j-password", default=os.environ.get("NEO4J_PASSWORD", ""))
    parser.add_argument("--neo4j-database", default="neo4j")
    parser.add_argument("--falkordb-host", default=os.environ.get("GRAF_FALKORDB_HOST", "127.0.0.1"))
    parser.add_argument("--falkordb-port", type=int, default=6380)
    parser.add_argument("--falkordb-password", default=os.environ.get("GRAF_FALKORDB_PASSWORD", ""))
    parser.add_argument("--falkordb-graph", default=os.environ.get("GRAF_FALKORDB_GRAPH", "graf_fuzz"))
    parser.add_argument("--kuzu-db-path", default=os.environ.get("GRAF_KUZU_DB_PATH", "./kuzu_fuzz_test"))
    parser.add_argument("--nebula-host", default=os.environ.get("GRAF_NEBULA_HOST", "127.0.0.1"))
    parser.add_argument("--nebula-port", type=int, default=9669)
    parser.add_argument("--nebula-user", default=os.environ.get("GRAF_NEBULA_USER", "root"))
    parser.add_argument("--nebula-password", default=os.environ.get("GRAF_NEBULA_PASSWORD", "nebula"))
    parser.add_argument("--nebula-space", default=os.environ.get("GRAF_NEBULA_SPACE", "graf_fuzz"))
    parser.add_argument("--self-check", action="store_true", help="Check project layout/imports without a target")
    return parser


def connection(args):
    from GraphContext import (MemgraphContextExtractor, Neo4jContextExtractor,
                              FalkorDBContextExtractor, KuzuContextExtractor,
                              NebulaContextExtractor)
    if args.target == "memgraph":
        return (MemgraphContextExtractor(args.memgraph_uri, args.memgraph_user, args.memgraph_password),
                {"kind": "bolt", "target": "memgraph", "uri": args.memgraph_uri,
                 "auth": (args.memgraph_user, args.memgraph_password)})
    if args.target == "neo4j":
        return (Neo4jContextExtractor(args.neo4j_uri, args.neo4j_user, args.neo4j_password,
                                      args.neo4j_database),
                {"kind": "bolt", "target": "neo4j", "uri": args.neo4j_uri,
                 "auth": (args.neo4j_user, args.neo4j_password), "database": args.neo4j_database,
                 "server_timeout": args.compile_check_timeout})
    if args.target == "falkordb":
        return (FalkorDBContextExtractor(args.falkordb_host, args.falkordb_port,
                                         args.falkordb_password, args.falkordb_graph),
                {"kind": "falkordb", "target": "falkordb", "host": args.falkordb_host,
                 "port": args.falkordb_port, "password": args.falkordb_password,
                 "graph_name": args.falkordb_graph})
    if args.target == "kuzu":
        return (KuzuContextExtractor(args.kuzu_db_path),
                {"kind": "kuzu", "target": "kuzu", "db_path": args.kuzu_db_path})
    return (NebulaContextExtractor(args.nebula_host, args.nebula_port, args.nebula_user,
                                   args.nebula_password, args.nebula_space),
            {"kind": "nebula", "target": "nebula", "host": args.nebula_host,
             "port": args.nebula_port, "user": args.nebula_user,
             "password": args.nebula_password, "space": args.nebula_space})


def initialize_graph(args) -> None:
    from GraphInitializer import (MemgraphSeedGenerator, Neo4jSeedGenerator,
                                  FalkorDBSeedGenerator, KuzuSeedGenerator, NebulaSeedGenerator)
    from graf.seed_profiles import SeedPortfolioScheduler
    spec = SeedPortfolioScheduler(args.campaign_seed).select(0).profile
    constructors = {
        "memgraph": lambda: MemgraphSeedGenerator(args.memgraph_uri, args.memgraph_user,
                                                     args.memgraph_password, seed_spec=spec),
        "neo4j": lambda: Neo4jSeedGenerator(args.neo4j_uri, args.neo4j_user,
                                             args.neo4j_password, args.neo4j_database, seed_spec=spec),
        "falkordb": lambda: FalkorDBSeedGenerator(args.falkordb_host, args.falkordb_port,
                                                   args.falkordb_password, args.falkordb_graph,
                                                   seed_spec=spec),
        "kuzu": lambda: KuzuSeedGenerator(args.kuzu_db_path, seed_spec=spec),
        "nebula": lambda: NebulaSeedGenerator(args.nebula_host, args.nebula_port,
                                               args.nebula_user, args.nebula_password,
                                               args.nebula_space, seed_spec=spec),
    }
    generator = constructors[args.target]()
    try:
        generator.reset_and_initialize(reset=True)
    finally:
        generator.close()


def main(argv=None) -> int:
    logging.getLogger("neo4j.notifications").setLevel(logging.ERROR)
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.target = target_name(args.target)[0]
    except ValueError as exc:
        parser.error(str(exc))
    for name in ("Instantiator.py", "graf/admission.py", "graf/target_validation.py"):
        if not (ROOT / name).is_file():
            parser.error(f"Incomplete GRAF source tree: missing {name}")
    if args.self_check:
        from Instantiator import compile_and_instantiate  # noqa: F401
        from graf.admission import AdmissionConfig  # noqa: F401
        print(f"GRAF self-check OK root={ROOT} package=graf")
        return 0
    if not args.target_build_id:
        parser.error("--target-build-id is required to pin the target binary/image")
    if args.target == "neo4j":
        if not args.neo4j_user.strip():
            parser.error("--neo4j-user must not be empty")
        if not args.neo4j_password.strip():
            parser.error(
                "Neo4j password is empty: set/export NEO4J_PASSWORD or pass a nonempty "
                "--neo4j-password; an empty value produces a basic auth token without credentials"
            )
    from Instantiator import compile_and_instantiate
    from graf.admission import AdmissionConfig, load_candidates, publish_admission
    from graf.target_validation import IsolatedTargetCompileChecker, TargetCheckConfig
    config = AdmissionConfig(args.target, args.target_build_id, 3,
                             args.seed, args.compile_check_timeout)
    from graf.seed_profiles import SeedPortfolioScheduler
    initial_spec = SeedPortfolioScheduler(args.campaign_seed).select(0).profile
    source = args.input or raw_path(args.target, args.generated_dir)
    output = args.output or pool_path(args.target, args.generated_dir)
    if source.resolve() == output.resolve():
        parser.error("input and output must be different paths")
    if not source.is_file():
        parser.error(f"raw skeleton file not found: {source}")
    input_format = "lines"
    candidates = load_candidates(source, input_format="lines")
    if not candidates:
        parser.error("input pool is empty")
    if args.initialize_graph:
        initialize_graph(args)
    extractor, payload = connection(args)
    try:
        try:
            schema, state = extractor.extract_context()
        except Exception as exc:
            if args.target == "neo4j":
                from neo4j.exceptions import AuthError
                if isinstance(exc, AuthError):
                    parser.error(
                        "Neo4j authentication failed; check --neo4j-uri, --neo4j-user "
                        "and NEO4J_PASSWORD against the selected instance"
                    )
            raise
    finally:
        extractor.close()
    if not schema.labels or state.total_nodes <= 0:
        parser.error("target graph has no labeled seed nodes; initialize the dedicated test graph before admission")
    checker = IsolatedTargetCompileChecker(payload,
                                           TargetCheckConfig(required=True, timeout_seconds=config.timeout_seconds))
    try:
        progress_path = Path(
            f"{output}.evidence.{time.strftime('%Y%m%dT%H%M%S', time.gmtime())}"
            f".{os.getpid()}.inprogress.jsonl"
        )
        print(f"[admission] streaming per-candidate evidence to {progress_path}", flush=True)
        shown = Counter()

        def report_record(record):
            status = record["status"]
            if status in {"accepted", "duplicate"}:
                return
            shown[status] += 1
            if not args.print_rejections and shown[status] > 3:
                return
            sample = next((item for item in record.get("samples", [])
                           if item["status"] != "accepted"), {})
            reason = record.get("reason") or sample.get("reason", "")
            reason = " ".join(str(reason).split())[:240]
            print(f"[admission:{status}] #{record['index']} {reason}", flush=True)
            if args.print_rejections:
                query = sample.get("query") or record["skeleton"]
                print(f"[admission:{status}] query={json.dumps(query, ensure_ascii=False)}", flush=True)

        def progress(index, counts):
            if index % 100 == 0 or index == len(candidates):
                print(f"[admission] {index}/{len(candidates)} accepted={counts.get('accepted', 0)} "
                      f"rejected={counts.get('target_rejected', 0)} "
                      f"deferred={sum(value for key, value in counts.items() if key.endswith('_deferred'))} "
                      f"mechanical_rejected={counts.get('mechanical_rejected', 0)} "
                      f"duplicate={counts.get('duplicate', 0)} "
                      f"crash_suspected={counts.get('crash_suspected', 0)}",
                      flush=True)

        summary = publish_admission(source=source, output=output, candidates=candidates,
                                    config=config, schema=schema, state=state,
                                    checker=checker, instantiate=compile_and_instantiate,
                                    progress=progress, on_record=report_record,
                                    progress_path=progress_path, input_format=input_format,
                                    campaign_seed=args.campaign_seed,
                                    seed_profile_name=initial_spec.name)
    finally:
        checker.close()
    print(json.dumps({"output": str(output), **summary}, ensure_ascii=False, indent=2))
    if not summary["pool_published"]:
        print(f"[admission] no certified pool published; inspect {output.parent / summary['evidence_file']}",
              file=sys.stderr, flush=True)
    return 0 if summary["accepted"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
