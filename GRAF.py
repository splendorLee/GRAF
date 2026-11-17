import math
import sys
import os
import time
import traceback
import argparse  
import textwrap  
import random
import subprocess
import logging
import hashlib
import re
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Set, Tuple, List


logging.getLogger("neo4j.notifications").setLevel(logging.ERROR)

current_dir = os.path.dirname(os.path.abspath(__file__))
antlr_path = os.path.join(current_dir, "antlr4_cypher", "antlr4_cypher")
if antlr_path not in sys.path:
    sys.path.insert(0, antlr_path)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="GRAF Fuzzer - 跨引擎图数据库漏洞挖掘系统")
    parser.add_argument(
        "--target",
        type=str,
        required=True,
        help="指定目标引擎，可选值: 'memgraph', 'neo4j', 'falkordb', 'kuzu', 'nebula'",
    )
    parser.add_argument("--skeleton-pool", help="覆盖默认的按目标准入的骨架池路径（需要相应准入清单）")
    parser.add_argument("--target-build-id", default=os.environ.get("GRAF_TARGET_BUILD_ID"),
                        help="验证准入时所用的目标版本/镜像摘要；默认验证目标和骨架池摘要")
    parser.add_argument("--max-iterations", type=int, default=0, help="最大循环次数；0 表示持续运行")
    parser.add_argument("--context-refresh-interval", type=int, default=500, help="重新提取图上下文的间隔轮数")
    parser.add_argument("--seed", type=int, help="固定随机种子，便于复现测试")
    parser.add_argument("--crash-policy", choices=["legacy", "strict"], default="strict", help="Crash classification policy: legacy follows the uploaded project; strict reduces false positives")
    parser.add_argument("--init-mode", choices=["reset", "reuse"], default="reset", help="Startup database initialization mode. reset clears and seeds; reuse only checks connectivity")
    parser.add_argument(
        "--reseed-interval",
        type=int,
        default=500,
        help=(
            "Queries per automatically selected seed-graph epoch; "
            "0 disables rotation without exposing individual graph profiles"
        ),
    )
    parser.add_argument("--init-delete-batch-size", type=int, default=1000, help="Nodes deleted per batch during Memgraph/Neo4j initialization and recovery")
    parser.add_argument("--init-delete-max-batches", type=int, default=1000, help="Maximum delete batches before aborting Memgraph/Neo4j initialization")
    parser.add_argument(
        "--query-timeout", type=int, default=None, metavar="SECONDS",
        help="Query execution limit for the selected target in seconds (default: 120; 0 disables the GRAF limit)",
    )
    parser.add_argument("--memgraph-uri", default="bolt://localhost:7687", help="Memgraph Bolt URI")
    parser.add_argument("--memgraph-user", default=os.environ.get("GRAF_MEMGRAPH_USER", ""), help="Memgraph username; defaults to GRAF_MEMGRAPH_USER")
    parser.add_argument("--memgraph-password", default=os.environ.get("GRAF_MEMGRAPH_PASSWORD", ""), help="Memgraph password; defaults to GRAF_MEMGRAPH_PASSWORD")
    parser.add_argument("--memgraph-container", default="memgraph_fuzz_target", help="Memgraph Docker container name")
    parser.add_argument("--memgraph-ready-timeout", type=int, default=60, help="Seconds to wait for Memgraph Bolt readiness after restart")
    parser.add_argument("--memgraph-recovery-retries", type=int, default=3, help="Memgraph container restart/reconnect attempts after crash-like disconnects")
    parser.add_argument("--memgraph-query-timeout", type=int, default=None, help="Deprecated alias for --query-timeout when --target memgraph")
    parser.add_argument("--neo4j-uri", default="bolt://localhost:7687", help="Neo4j Bolt URI")
    parser.add_argument("--neo4j-user", default="neo4j", help="Neo4j username")
    parser.add_argument("--neo4j-password", default="testpassword", help="Neo4j password")
    parser.add_argument("--neo4j-database", default="neo4j", help="Neo4j database name")
    parser.add_argument("--neo4j-container", default="neo4j_fuzz_target", help="Neo4j Docker container name")
    parser.add_argument("--neo4j-ready-timeout", type=int, default=90, help="Seconds to wait for Neo4j Bolt readiness after startup/restart")
    parser.add_argument("--neo4j-recovery-retries", type=int, default=3, help="Neo4j container restart/reconnect attempts after crash-like disconnects")
    parser.add_argument("--neo4j-query-timeout", type=int, default=None, help="Deprecated alias for --query-timeout when --target neo4j")
    parser.add_argument("--falkordb-host", default=os.environ.get("GRAF_FALKORDB_HOST", "127.0.0.1"), help="FalkorDB host; defaults to GRAF_FALKORDB_HOST or 127.0.0.1")
    parser.add_argument("--falkordb-port", type=int, default=os.environ.get("GRAF_FALKORDB_PORT", "6380"), help="FalkorDB port; defaults to GRAF_FALKORDB_PORT or 6380")
    parser.add_argument("--falkordb-password", default=os.environ.get("GRAF_FALKORDB_PASSWORD", ""), help="FalkorDB password; defaults to GRAF_FALKORDB_PASSWORD")
    parser.add_argument("--falkordb-graph", default=os.environ.get("GRAF_FALKORDB_GRAPH", "graf_fuzz"), help="FalkorDB graph name")
    parser.add_argument("--falkordb-container", default=os.environ.get("GRAF_FALKORDB_CONTAINER", "falkordb_fuzz_target"), help="FalkorDB Docker container name")
    parser.add_argument("--falkordb-query-timeout", type=int, default=None, help="Deprecated alias for --query-timeout when --target falkordb")
    parser.add_argument("--kuzu-db-path", default=os.environ.get("GRAF_KUZU_DB_PATH", "./kuzu_fuzz_test"), help="Kùzu database path")
    parser.add_argument("--kuzu-query-timeout", type=int, default=None, help="Deprecated alias for --query-timeout when --target kuzu")
    parser.add_argument(
        "--kuzu-compile-cache-capacity",
        type=int,
        default=10000,
        help="Epoch-scoped Kùzu EXPLAIN result cache entries; 0 disables caching",
    )
    parser.add_argument("--nebula-host", default=os.environ.get("GRAF_NEBULA_HOST", "127.0.0.1"), help="NebulaGraph host")
    parser.add_argument("--nebula-port", type=int, default=os.environ.get("GRAF_NEBULA_PORT", "9669"), help="NebulaGraph port")
    parser.add_argument("--nebula-user", default=os.environ.get("GRAF_NEBULA_USER", "root"), help="NebulaGraph username")
    parser.add_argument("--nebula-password", default=os.environ.get("GRAF_NEBULA_PASSWORD", "nebula"), help="NebulaGraph password; defaults to GRAF_NEBULA_PASSWORD")
    parser.add_argument("--nebula-space", default=os.environ.get("GRAF_NEBULA_SPACE", "graf_fuzz"), help="NebulaGraph space")
    parser.add_argument("--nebula-container", default=os.environ.get("GRAF_NEBULA_CONTAINER", "nebula-docker-compose-graphd-1"), help="NebulaGraph graphd container name")
    parser.add_argument("--nebula-recovery-retries", type=int, default=5, help="NebulaGraph reconnect attempts after a lost connection")
    parser.add_argument("--nebula-recovery-delay", type=float, default=2.0, help="Seconds between NebulaGraph reconnect attempts")
    parser.add_argument("--nebula-query-timeout", type=int, default=None, help="Deprecated alias for --query-timeout when --target nebula")
    parser.add_argument("--run-dir", help="Run directory; defaults to runs/graf-enterprise-<target>-<UTC timestamp>")
    parser.add_argument("--mutation-attempts", type=int, default=12, help="Maximum validated candidates tried for one parent query")
    parser.add_argument("--mutation-max-path-bound", type=int, default=12, help="Absolute path-bound budget for depth mutation")
    parser.add_argument("--mutation-max-limit", type=int, default=10000, help="Absolute LIMIT/range volume budget")
    parser.add_argument(
        "--target-compile-check",
        choices=["required", "best-effort", "off"],
        default="required",
        help="Use side-effect-free target EXPLAIN before parent/child execution",
    )
    parser.add_argument("--compile-check-timeout", type=int, default=15, help="Target EXPLAIN timeout in seconds")
    parser.add_argument("--mutation-noop-policy", choices=["execute-parent", "skip"], default="execute-parent")
    parser.add_argument("--evolved-seed-capacity", type=int, default=10000, help="Maximum concrete lineage seeds retained in memory")
    parser.add_argument("--lineage-interval", type=int, default=4, help="Use one evolved seed every N rounds")
    parser.add_argument("--journal-fsync", action="store_true", help="fsync every audit event for crash durability")
    parser.add_argument(
        "--context-refresh-on-write",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Refresh schema/topology/value context immediately after successful writes",
    )
    return parser


QUERY_TIMEOUT_TARGETS = ("memgraph", "neo4j", "falkordb", "kuzu", "nebula")


def resolve_query_timeout(args: argparse.Namespace, parser: argparse.ArgumentParser) -> tuple[int, str]:
    """Choose one explicit timeout source; never silently ignore a target option."""

    target = str(args.target or "").lower()
    general = args.query_timeout
    target_value = getattr(args, f"{target}_query_timeout", None)
    for option_target in QUERY_TIMEOUT_TARGETS:
        option_value = getattr(args, f"{option_target}_query_timeout", None)
        if option_value is not None and option_target != target:
            parser.error(
                f"--{option_target}-query-timeout requires --target {option_target}"
            )
        if option_value is not None and option_value < 0:
            parser.error(f"--{option_target}-query-timeout must be >= 0")
    if general is not None and general < 0:
        parser.error("--query-timeout must be >= 0")
    if general is not None and target_value is not None:
        parser.error(f"--query-timeout conflicts with --{target}-query-timeout")
    if target_value is not None:
        return target_value, f"--{target}-query-timeout"
    if general is not None:
        return general, "--query-timeout"
    return 120, "default"


def resolve_docker_bolt_uri(container_name: str, container_port: int = 7687) -> str:
    try:
        result = subprocess.run(
            ["docker", "port", container_name, str(container_port)],
            check=True,
            capture_output=True,
            text=True,
        )
    except Exception as exc:
        raise RuntimeError(f"无法通过 docker port 解析 {container_name}:{container_port}: {exc}") from exc

    mappings = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not mappings:
        raise RuntimeError(f"容器 {container_name} 没有暴露端口 {container_port}")

    host_mapping = mappings[-1]
    host, port = host_mapping.rsplit(":", 1)
    if host in {"0.0.0.0", "::", "[::]"}:
        host = "localhost"
    return f"bolt://{host}:{port}"


if any(arg in ("-h", "--help") for arg in sys.argv[1:]):
    build_arg_parser().parse_args()


try:
    from antlr4 import InputStream, CommonTokenStream
except ImportError as exc:
    raise SystemExit(
        "Missing dependency: antlr4-python3-runtime. "
        "Install it with `pip install antlr4-python3-runtime` before running GRAF."
    ) from exc

from CypherLexer import CypherLexer
from CypherParser import CypherParser
from CypherParserVisitor import CypherParserVisitor

from GraphInitializer import MemgraphSeedGenerator, Neo4jSeedGenerator, FalkorDBSeedGenerator, KuzuSeedGenerator, NebulaSeedGenerator
from Instantiator import compile_and_instantiate
from FeedbackMonitor import FeedbackMonitor, FeedbackVector, ExecStatus, estimate_result_scale

from GraphContext import MemgraphContextExtractor, Neo4jContextExtractor, FalkorDBContextExtractor, KuzuContextExtractor, NebulaContextExtractor
from DB_Executor import EvidencePersistenceError, UnsafeTargetStateError, ExecutionOutcome, MemgraphFuzzExecutor, Neo4jFuzzExecutor, FalkorDBFuzzExecutor, KuzuFuzzExecutor, NebulaFuzzExecutor
from graf.engine import EnterpriseMutationEngine, MutationEngineConfig
from graf.journal import ArtifactStore, EnterpriseJournal
from graf.model import GraphStats, MutationStatus, SchemaView, query_digest, to_jsonable
from graf.seed_profiles import SeedPortfolioScheduler, seed_profile
from graf.target_validation import TargetCheckConfig, build_target_compile_checker
from graf.skeleton_paths import pool_path
from graf.admission import load_candidates, verify_admission
from graf.validation import ValidationPipeline, ValidationPolicy


class SeedRotationError(RuntimeError):
    """Fail-closed campaign error raised when graph rotation cannot be verified."""


def completed_execution_metrics(
    submitted: int,
    passed: int,
    failed: int,
    crashes: int,
    resource_exhaustions: int,
) -> Dict[str, float | int]:
    """Return settled target metrics without counting an in-flight request."""

    completed = max(0, int(passed) + int(failed) + int(crashes) + int(resource_exhaustions))
    return {
        "submitted": max(0, int(submitted)),
        "completed": completed,
        "in_flight": max(0, int(submitted) - completed),
        "pass_rate_percent": (float(passed) / completed * 100.0) if completed else 0.0,
    }


class FuzzDashboard:
    def __init__(self, target_name, log_path=""):
        self.start_time = time.time()
        self.target_name = target_name
        self.log_path = log_path or f"fuzz_verbose_{target_name.lower()}.log"
        self.crashes_record = 0
        self.current_query_display = self._format_query("等待初始化...") 

    def _format_query(self, query):
        if not query:
            query = ""
            
        wrapped_lines = textwrap.wrap(query, width=54, break_long_words=True)
        
        if len(wrapped_lines) > 5:
            wrapped_lines = wrapped_lines[:5]
            wrapped_lines[4] = wrapped_lines[4][:50] + "..."
            
        display_lines = []
        for i in range(5):
            text = wrapped_lines[i] if i < len(wrapped_lines) else ""
            if i == 0:
                display_lines.append(f"当前执行 : {text}")
            else:
                display_lines.append(f"           {text}")
                
        return "\n".join(display_lines)

    def update(self, drawn, filtered, executed, passed, exec_failed, crashes, resource_exhaustions=0, current_q=None):
        if current_q:
            self.current_query_display = self._format_query(current_q)

        self.crashes_record = crashes

        # `executed` is a submission counter and advances before the blocking
        # target call.  Derive the denominator from terminal outcomes so an
        # in-flight query cannot make the displayed pass rate oscillate.
        progress = completed_execution_metrics(
            executed,
            passed,
            exec_failed,
            crashes,
            resource_exhaustions,
        )
        completed = progress["completed"]
        in_flight = progress["in_flight"]
        pass_rate = progress["pass_rate_percent"]
        elapsed = int(time.time() - self.start_time)
        
        screen = f"""\033[2J\033[H
===================================================================
                           GRAF Fuzzer
===================================================================
攻击目标 : {self.target_name}
运行时间 : {elapsed} 秒
已提交   : {executed} 次
已完成   : {completed} 次
执行中   : {in_flight} 次
-------------------------------------------------------------------
执行成功 : {passed} 次 
执行失败 : {exec_failed} 次 
完成通过率: {pass_rate:.2f}%
发现崩溃 : {crashes} 次 
资源耗尽 : {resource_exhaustions} 次
-------------------------------------------------------------------
{self.current_query_display}
===================================================================
(按 Ctrl+C 随时安全退出，详细日志保存在 {self.log_path})
"""
        sys.stdout.write(screen)
        sys.stdout.flush()


def load_skeletons_from_file(filepath: str) -> List[str]:
    """Read the same one-skeleton-per-line format certified by admission."""
    path = Path(filepath)
    if not path.is_file():
        raise FileNotFoundError(f"找不到骨架池文件: {filepath}")
    return load_candidates(path, input_format="lines")

def deterministic_mutation_seed(base_seed: int, round_idx: int, seed_id: str) -> int:
    material = f"{base_seed}:{round_idx}:{seed_id}".encode("utf-8")
    return int.from_bytes(hashlib.sha256(material).digest()[:8], "big", signed=False)


def effective_seed_rotation_interval(init_mode: str, configured_interval: int) -> int:
    """External reuse graphs are never cleared by portfolio rotation."""

    return 0 if init_mode == "reuse" else int(configured_interval)


def should_rotate_seed_graph(
    epoch_executed: int,
    reseed_interval: int,
    round_idx: int,
    max_iterations: int,
) -> bool:
    """Return true only after a full graph-local execution epoch.

    ``epoch_executed`` is reset whenever recovery actually rebuilds the graph,
    unlike a global modulo counter that can immediately rotate a freshly
    recovered database.  The final finite-campaign query does not trigger a
    destructive reset that nobody will use.
    """

    return (
        reseed_interval > 0
        and epoch_executed >= reseed_interval
        and (not max_iterations or round_idx < max_iterations)
    )


def is_write_query(query: str) -> bool:
    return bool(
        re.search(
            r"\b(?:CREATE|MERGE|SET|DELETE|DETACH|REMOVE|DROP|LOAD|FOREACH|"
            r"INSERT|UPDATE|UPSERT|ALTER|COPY|TRUNCATE|CLEAR|REBUILD|SUBMIT|"
            r"GRANT|REVOKE)\b",
            query,
            re.IGNORECASE,
        )
    )


def build_enterprise_mutation_runtime(target, real_schema, real_state, executor, args):
    schema_view = SchemaView.from_legacy(real_schema, real_state)
    graph_stats = GraphStats.from_legacy(real_state)
    check_mode = args.target_compile_check
    checker = build_target_compile_checker(
        executor,
        target,
        TargetCheckConfig(
            enabled=check_mode != "off",
            required=check_mode == "required",
            timeout_seconds=args.compile_check_timeout,
        ),
    )
    validator = ValidationPipeline(
        target,
        schema_view,
        policy=ValidationPolicy(target_compile_required=check_mode == "required"),
        target_check=checker,
    )
    engine = EnterpriseMutationEngine(
        target=target,
        schema=schema_view,
        graph=graph_stats,
        validator=validator,
        config=MutationEngineConfig(
            max_attempts=args.mutation_attempts,
            max_path_bound=args.mutation_max_path_bound,
            max_limit=args.mutation_max_limit,
            validate_parent=True,
            fail_closed=True,
        ),
    )
    return schema_view, graph_stats, validator, engine


if __name__ == "__main__":
    parser = build_arg_parser()
    args = parser.parse_args()

    non_negative_options = {
        "--max-iterations": args.max_iterations,
        "--context-refresh-interval": args.context_refresh_interval,
        "--reseed-interval": args.reseed_interval,
        "--kuzu-compile-cache-capacity": args.kuzu_compile_cache_capacity,
        "--compile-check-timeout": args.compile_check_timeout,
    }
    for option, value in non_negative_options.items():
        if value < 0:
            parser.error(f"{option} must be >= 0")
    positive_options = {
        "--mutation-attempts": args.mutation_attempts,
        "--mutation-max-path-bound": args.mutation_max_path_bound,
        "--mutation-max-limit": args.mutation_max_limit,
        "--evolved-seed-capacity": args.evolved_seed_capacity,
        "--lineage-interval": args.lineage_interval,
        "--nebula-recovery-retries": args.nebula_recovery_retries,
    }
    for option, value in positive_options.items():
        if value <= 0:
            parser.error(f"{option} must be > 0")
    if args.nebula_recovery_delay < 0:
        parser.error("--nebula-recovery-delay must be >= 0")
    for option, value in {"--falkordb-port": args.falkordb_port, "--nebula-port": args.nebula_port}.items():
        if not 1 <= value <= 65535:
            parser.error(f"{option} must be between 1 and 65535")

    TARGET_ENGINE = args.target.lower()
    seed_was_supplied = args.seed is not None
    
    if TARGET_ENGINE not in ["memgraph", "neo4j", "falkordb", "kuzu", "nebula"]:
        print(f"致命错误: 不支持的目标引擎 '{args.target}'。请使用 'memgraph', 'neo4j', 'falkordb', 'kuzu', 'nebula'。")
        sys.exit(1)
    query_timeout_seconds, query_timeout_source = resolve_query_timeout(args, parser)

    POOL_FILE = args.skeleton_pool or str(pool_path(TARGET_ENGINE))
    try:
        admission_record = verify_admission(Path(POOL_FILE), TARGET_ENGINE, args.target_build_id)
    except (FileNotFoundError, ValueError, KeyError, TypeError) as exc:
        parser.error(f"目标骨架池准入验证失败：{exc}。先运行 tools/filter_skeleton_pool.py --target {TARGET_ENGINE}。")
    if args.seed is None:
        args.seed = (admission_record.get("campaign_seed")
                     if isinstance(admission_record.get("campaign_seed"), int)
                     else int.from_bytes(os.urandom(8), "big", signed=False))
    if args.init_mode == "reset" and admission_record.get("initial_seed_profile"):
        selected_profile = SeedPortfolioScheduler(args.seed).select(0).profile.name
        if selected_profile != admission_record["initial_seed_profile"]:
            parser.error(
                f"当前 --seed 选中的初始图 {selected_profile} 与准入时的 "
                f"{admission_record['initial_seed_profile']} 不同；请使用准入清单中的 "
                f"campaign_seed={admission_record['campaign_seed']}，或对该种子图重新准入。"
            )
    random.seed(args.seed)

    run_stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    RUN_DIR = Path(args.run_dir or f"runs/graf-enterprise-{TARGET_ENGINE}-{run_stamp}").resolve()
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    VERBOSE_LOG_FILE = str(RUN_DIR / f"fuzz_verbose_{TARGET_ENGINE}.log")
    with open(VERBOSE_LOG_FILE, "w", encoding="utf-8") as f:
        f.write(f"=== GRAF Fuzzer 详细运行日志 (Target: {TARGET_ENGINE.upper()}) ===\n\n")

    def log_verbose(msg):
        with open(VERBOSE_LOG_FILE, "a", encoding="utf-8") as file:
            file.write(msg + "\n")

    log_verbose(f"🚀 [GRAF Fuzzer] 目标引擎已设定为: {TARGET_ENGINE.upper()}")
    log_verbose(
        f"[查询超时] target={TARGET_ENGINE} seconds={query_timeout_seconds} "
        f"source={query_timeout_source} (0 disables the GRAF query limit)"
    )
    print(
        f"[GRAF] {TARGET_ENGINE} query timeout: {query_timeout_seconds}s "
        f"(source: {query_timeout_source})", flush=True,
    )

    journal = EnterpriseJournal(RUN_DIR / "journal.jsonl", fsync=args.journal_fsync)
    artifact_store = ArtifactStore(RUN_DIR / "artifacts")
    seed_scheduler = SeedPortfolioScheduler(args.seed)
    managed_seed_graph = args.init_mode == "reset"
    initial_seed_selection = seed_scheduler.select(0) if managed_seed_graph else None
    seed_runtime = {"selection": initial_seed_selection}
    selected_seed_spec = (
        initial_seed_selection.profile if initial_seed_selection is not None else seed_profile("baseline")
    )
    configured_reseed_interval = args.reseed_interval
    args.reseed_interval = effective_seed_rotation_interval(args.init_mode, args.reseed_interval)
    if not managed_seed_graph and configured_reseed_interval > 0:
        log_verbose(
            "[种子图组合] init-mode=reuse：现有图由用户管理，已自动禁用周期清库与图组合轮换。"
        )
    if initial_seed_selection is not None:
        log_verbose(
            f"[种子图组合] 自动选择 epoch=0 profile={selected_seed_spec.name} "
            f"fingerprint={selected_seed_spec.fingerprint}"
        )
        journal.emit(
            "seed_profile_initialization_started",
            seed_graph=initial_seed_selection.to_dict(),
        )
    else:
        journal.emit("external_graph_reuse_started", target=TARGET_ENGINE)

    if TARGET_ENGINE == "memgraph":
        URI = args.memgraph_uri
        USER = args.memgraph_user
        PASSWORD = args.memgraph_password
        generator = MemgraphSeedGenerator(
            URI,
            USER,
            PASSWORD,
            ready_timeout_s=args.memgraph_ready_timeout,
            delete_batch_size=args.init_delete_batch_size,
            delete_max_batches=args.init_delete_max_batches,
            seed_spec=selected_seed_spec,
        )
        generator.reset_and_initialize(reset=args.init_mode == "reset")
        seed_cypher_text = getattr(generator, 'seed_cypher', '')
        generator.close()
        extractor = MemgraphContextExtractor(URI, USER, PASSWORD)
        executor = MemgraphFuzzExecutor(
            URI,
            USER,
            PASSWORD,
            seed_cypher=seed_cypher_text,
            log_file=str(RUN_DIR / "fuzzer_memgraph.log"),
            container_name=args.memgraph_container,
            ready_timeout_s=args.memgraph_ready_timeout,
            recovery_retries=args.memgraph_recovery_retries,
            delete_batch_size=args.init_delete_batch_size,
            delete_max_batches=args.init_delete_max_batches,
            query_timeout_s=query_timeout_seconds,
            crash_policy=args.crash_policy,
        )

    elif TARGET_ENGINE == "neo4j":
        neo4j_auto_uri = args.neo4j_uri == "auto"
        URI = resolve_docker_bolt_uri(args.neo4j_container) if neo4j_auto_uri else args.neo4j_uri
        print(f"[Neo4j] Bolt URI: {URI}")
        USER = args.neo4j_user
        PASSWORD = args.neo4j_password
        DATABASE = args.neo4j_database
        generator = Neo4jSeedGenerator(
            URI,
            USER,
            PASSWORD,
            database=DATABASE,
            ready_timeout_s=args.neo4j_ready_timeout,
            delete_batch_size=args.init_delete_batch_size,
            delete_max_batches=args.init_delete_max_batches,
            seed_spec=selected_seed_spec,
        )
        generator.reset_and_initialize(reset=args.init_mode == "reset")
        seed_cypher_text = getattr(generator, 'seed_cypher', '')
        generator.close()
        extractor = Neo4jContextExtractor(URI, USER, PASSWORD, database=DATABASE)
        executor = Neo4jFuzzExecutor(
            URI,
            USER,
            PASSWORD,
            database=DATABASE,
            seed_cypher=seed_cypher_text,
            log_file=str(RUN_DIR / "fuzzer_neo4j.log"),
            container_name=args.neo4j_container,
            ready_timeout_s=args.neo4j_ready_timeout,
            auto_resolve_uri=neo4j_auto_uri,
            recovery_retries=args.neo4j_recovery_retries,
            delete_batch_size=args.init_delete_batch_size,
            delete_max_batches=args.init_delete_max_batches,
            query_timeout_s=query_timeout_seconds,
            crash_policy=args.crash_policy,
        )
        
    elif TARGET_ENGINE == "falkordb":
        HOST = args.falkordb_host
        PORT = args.falkordb_port
        PASSWORD = args.falkordb_password
        GRAPH_NAME = args.falkordb_graph
        generator = FalkorDBSeedGenerator(
            host=HOST,
            port=PORT,
            password=PASSWORD,
            graph_name=GRAPH_NAME,
            seed_spec=selected_seed_spec,
        )
        generator.reset_and_initialize(reset=args.init_mode == "reset")
        seed_cypher_text = getattr(generator, 'seed_cypher', '')
        extractor = FalkorDBContextExtractor(host=HOST, port=PORT, password=PASSWORD, graph_name=GRAPH_NAME)
        executor = FalkorDBFuzzExecutor(
            host=HOST,
            port=PORT,
            password=PASSWORD,
            graph_name=GRAPH_NAME,
            seed_cypher=seed_cypher_text,
            log_file=str(RUN_DIR / "fuzzer_falkordb.log"),
            query_timeout_s=query_timeout_seconds,
            container_name=args.falkordb_container,
            crash_policy=args.crash_policy,
        )
        executor.initializer = generator if managed_seed_graph else None

    elif TARGET_ENGINE == "kuzu":
        DB_PATH = args.kuzu_db_path
        generator = KuzuSeedGenerator(db_path=DB_PATH, seed_spec=selected_seed_spec)
        generator.reset_and_initialize(reset=args.init_mode == "reset")
        seed_cypher_text = getattr(generator, 'seed_cypher', '')
        generator.close()
        executor = KuzuFuzzExecutor(
            db_path=DB_PATH,
            seed_cypher=seed_cypher_text,
            log_file=str(RUN_DIR / "fuzzer_kuzu.log"),
            query_timeout_s=query_timeout_seconds,
            crash_policy=args.crash_policy,
            compile_cache_capacity=args.kuzu_compile_cache_capacity,
        )
        # Kuzu is embedded: context inspection, EXPLAIN and execution must be
        # serialized through the same persistent owner process. Opening the
        # database again in the orchestrator would reintroduce file-lock and
        # catalog-open overhead on every refresh.
        extractor = KuzuContextExtractor(query_runner=executor.query_rows)

    elif TARGET_ENGINE == "nebula":
        HOST = args.nebula_host
        PORT = args.nebula_port
        USER = args.nebula_user
        PASSWORD = args.nebula_password
        SPACE = args.nebula_space
        generator = NebulaSeedGenerator(
            host=HOST,
            port=PORT,
            user=USER,
            password=PASSWORD,
            space=SPACE,
            seed_spec=selected_seed_spec,
        )
        generator.reset_and_initialize(reset=args.init_mode == "reset")
        seed_cypher_text = getattr(generator, 'seed_cypher', '')
        generator.close()
        extractor = NebulaContextExtractor(host=HOST, port=PORT, user=USER, password=PASSWORD, space=SPACE)
        executor = NebulaFuzzExecutor(
            host=HOST,
            port=PORT,
            user=USER,
            password=PASSWORD,
            space=SPACE,
            seed_cypher=seed_cypher_text,
            log_file=str(RUN_DIR / "fuzzer_nebula.log"),
            container_name=args.nebula_container,
            recovery_retries=args.nebula_recovery_retries,
            recovery_delay_s=args.nebula_recovery_delay,
            query_timeout_s=query_timeout_seconds,
            crash_policy=args.crash_policy,
        )

    if managed_seed_graph:
        executor.set_seed_spec(
            selected_seed_spec,
            generator.seed_cypher,
            getattr(generator, "seed_statements", ()),
        )
        seed_cypher_text = generator.seed_cypher
    else:
        # Reuse mode must never turn a reconnect into an implicit destructive
        # reset of data that GRAF does not own.
        executor.set_seed_spec(None, "", ())
        seed_cypher_text = ""
        if TARGET_ENGINE == "falkordb":
            generator.close()

    # Diagnostic read history remains a small rolling window, while the
    # state-changing replay window is sized to one complete managed graph
    # epoch.  This makes the default 500-query epoch exactly reproducible.
    executor.configure_context_retention(args.reseed_interval)

    log_verbose("正在提取运行时图上下文约束...")
    real_schema, real_state = extractor.extract_context()
    extractor.close()
    
    monitor = FeedbackMonitor(seed_cypher=seed_cypher_text)
    schema_view, graph_stats, validation_pipeline, mutation_engine = build_enterprise_mutation_runtime(
        TARGET_ENGINE,
        real_schema,
        real_state,
        executor,
        args,
    )
    if callable(getattr(executor, "on_context_refreshed", None)):
        executor.on_context_refreshed(schema_view.to_snapshot())
    evolved_seeds = deque(maxlen=max(1, args.evolved_seed_capacity))
    initial_context_path, _initial_context_created = artifact_store.save(
        "contexts",
        {
            "schema": schema_view.to_snapshot(),
            "graph": graph_stats,
            "reason": "startup",
            "seed_graph": initial_seed_selection.to_dict() if initial_seed_selection else {
                "management": "external_reuse"
            },
        },
    )
    initial_seed_manifest_path = None
    if initial_seed_selection is not None:
        initial_seed_manifest_path, _ = artifact_store.save(
            "seed_manifests", initial_seed_selection.to_dict()
        )
        journal.emit(
            "seed_profile_selected",
            seed_graph=initial_seed_selection.to_dict(),
            artifact=str(initial_seed_manifest_path),
        )
    journal.emit(
        "run_started",
        target=TARGET_ENGINE,
        seed=args.seed,
        seed_source="command_line" if seed_was_supplied else "admission_manifest",
        skeleton_pool=str(Path(POOL_FILE).resolve()),
        mutation_config={
            "attempts": args.mutation_attempts,
            "max_path_bound": args.mutation_max_path_bound,
            "max_limit": args.mutation_max_limit,
            "target_compile_check": args.target_compile_check,
            "kuzu_compile_cache_capacity": (
                args.kuzu_compile_cache_capacity if TARGET_ENGINE == "kuzu" else None
            ),
            "noop_policy": args.mutation_noop_policy,
        },
        execution_policy={
            "query_timeout_seconds": getattr(executor, "query_timeout_s", 0),
            "query_timeout_source": query_timeout_source,
            "timeout_zero_means_unlimited": True,
            "runtime_model": (
                "persistent_killable_single_owner"
                if TARGET_ENGINE == "kuzu"
                else "persistent_killable_bolt_worker"
                if TARGET_ENGINE in {"memgraph", "neo4j"}
                else "target_adapter_default"
            ),
            "diagnostic_query_history_limit": executor.history_limit,
            "state_replay_history_limit": executor.state_history_limit,
            "reseed_interval": args.reseed_interval,
        },
        seed_graph=(
            {
                **initial_seed_selection.to_dict(),
                "manifest_artifact": str(initial_seed_manifest_path),
                "rotation_interval": args.reseed_interval,
                "selection_mode": "automatic_deterministic_portfolio",
            }
            if initial_seed_selection is not None
            else {
                "management": "external_reuse",
                "rotation_interval": 0,
                "selection_mode": "disabled_for_reuse",
            }
        ),
        context={
            "labels": len(schema_view.labels),
            "relationships": len(schema_view.edges),
            "nodes": graph_stats.node_count,
            "edges": graph_stats.edge_count,
            "observed_properties": len(schema_view.observed_values),
            "artifact": str(initial_context_path),
        },
    )
    
    log_verbose("\n启动无限循环图变异测试...\n")
    
    dashboard = FuzzDashboard(TARGET_ENGINE.upper(), VERBOSE_LOG_FILE)
    stats_drawn = 0           
    stats_filtered = 0        
    stats_executed = 0        
    stats_passed = 0          
    stats_exec_failed = 0     
    stats_crashes = 0         
    stats_resource_exhaustions = 0
    stats_parent_rejected = 0
    stats_mutation_rejected = 0
    stats_mutation_noop = 0
    stats_internal_errors = 0
    last_submitted_query = None
    recorded_oob_disconnects = set()
    epoch_executed = 0

    def install_context(schema, state, reason="refresh"):
        nonlocal_schema = SchemaView.from_legacy(schema, state)
        nonlocal_graph = GraphStats.from_legacy(state)
        if callable(getattr(executor, "on_context_refreshed", None)):
            executor.on_context_refreshed(nonlocal_schema.to_snapshot())
        mutation_engine.refresh_context(nonlocal_schema, nonlocal_graph)
        active_selection = seed_runtime["selection"]
        context_path, _context_created = artifact_store.save(
            "contexts",
            {
                "schema": nonlocal_schema.to_snapshot(),
                "graph": nonlocal_graph,
                "reason": reason,
                "seed_graph": (
                    active_selection.to_dict()
                    if active_selection is not None
                    else {"management": "external_reuse"}
                ),
            },
        )
        journal.emit(
            "context_refreshed",
            reason=reason,
            labels=len(nonlocal_schema.labels),
            relationships=len(nonlocal_schema.edges),
            nodes=nonlocal_graph.node_count,
            edges=nonlocal_graph.edge_count,
            observed_properties=len(nonlocal_schema.observed_values),
            artifact=str(context_path),
            seed_graph=(active_selection.to_dict() if active_selection is not None else None),
        )
        return nonlocal_schema, nonlocal_graph

    def refresh_context_once():
        if TARGET_ENGINE == "memgraph":
            return MemgraphContextExtractor(URI, USER, PASSWORD)
        if TARGET_ENGINE == "neo4j":
            current_uri = getattr(executor, "uri", URI)
            return Neo4jContextExtractor(current_uri, USER, PASSWORD, database=DATABASE)
        if TARGET_ENGINE == "falkordb":
            return FalkorDBContextExtractor(host=HOST, port=PORT, password=PASSWORD, graph_name=GRAPH_NAME)
        if TARGET_ENGINE == "kuzu":
            return KuzuContextExtractor(query_runner=executor.query_rows)
        if TARGET_ENGINE == "nebula":
            return NebulaContextExtractor(host=HOST, port=PORT, user=USER, password=PASSWORD, space=SPACE)
        raise RuntimeError(f"Unsupported target for context refresh: {TARGET_ENGINE}")

    def periodic_reseed_and_refresh():
        if not hasattr(executor, "reset_to_seed"):
            raise SeedRotationError(f"{TARGET_ENGINE} does not expose reset_to_seed")
        current_selection = seed_runtime["selection"]
        if current_selection is None:
            raise SeedRotationError("automatic seed rotation is unavailable in reuse mode")
        next_selection = seed_scheduler.select(current_selection.epoch + 1)
        generator.set_seed_spec(next_selection.profile)
        executor.set_seed_spec(
            next_selection.profile,
            generator.seed_cypher,
            getattr(generator, "seed_statements", ()),
        )
        journal.emit(
            "seed_profile_rotation_started",
            previous_seed_graph=current_selection.to_dict(),
            next_seed_graph=next_selection.to_dict(),
            executed=stats_executed,
        )
        log_verbose(
            f"[种子图组合] 自动轮换 epoch={current_selection.epoch}->{next_selection.epoch} "
            f"profile={next_selection.profile.name}，开始清空并重灌。"
        )
        try:
            executor.reset_to_seed()
        except Exception as reset_exc:
            try:
                if TARGET_ENGINE not in {"neo4j", "memgraph", "falkordb"}:
                    raise reset_exc
                log_verbose(
                    f"[种子图组合] 轻量重置失败，按相同 profile 尝试恢复。\n"
                    f"{traceback.format_exc()}"
                )
                if hasattr(executor, "_reconnect_and_reseed"):
                    executor._reconnect_and_reseed()
                elif hasattr(executor, "_recover_container_and_seed"):
                    executor._recover_container_and_seed()
                else:
                    raise reset_exc
            except Exception as recovery_exc:
                journal.emit(
                    "seed_profile_rotation_failed",
                    previous_seed_graph=current_selection.to_dict(),
                    next_seed_graph=next_selection.to_dict(),
                    error=f"{type(recovery_exc).__name__}: {recovery_exc}",
                )
                raise SeedRotationError(
                    f"seed profile {next_selection.profile.name} could not be installed: "
                    f"{type(recovery_exc).__name__}: {recovery_exc}"
                ) from recovery_exc

        if TARGET_ENGINE == "neo4j":
            globals()["URI"] = getattr(executor, "uri", URI)

        temp_extractor = None
        try:
            temp_extractor = refresh_context_once()
            refreshed_schema, refreshed_state = temp_extractor.extract_context()
            observed_graph = GraphStats.from_legacy(refreshed_state)
            if (
                observed_graph.node_count != len(next_selection.profile.nodes)
                or observed_graph.edge_count != len(next_selection.profile.edges)
            ):
                raise SeedRotationError(
                    f"post-rotation context mismatch for {next_selection.profile.name}: "
                    f"expected {len(next_selection.profile.nodes)}/{len(next_selection.profile.edges)} "
                    f"nodes/edges, observed {observed_graph.node_count}/{observed_graph.edge_count}"
                )
            seed_runtime["selection"] = next_selection
            evolved_seeds.clear()
            seen_evolved_queries.clear()
            manifest_path, _ = artifact_store.save("seed_manifests", next_selection.to_dict())
            journal.emit(
                "seed_profile_selected",
                seed_graph=next_selection.to_dict(),
                artifact=str(manifest_path),
                executed=stats_executed,
            )
            log_verbose(
                f"[种子图组合] 轮换成功 profile={next_selection.profile.name} "
                f"fingerprint={next_selection.profile.fingerprint}；旧图 lineage 已隔离。"
            )
            return refreshed_schema, refreshed_state
        except SeedRotationError:
            raise
        except Exception as exc:
            journal.emit(
                "seed_profile_rotation_failed",
                previous_seed_graph=current_selection.to_dict(),
                next_seed_graph=next_selection.to_dict(),
                error=f"{type(exc).__name__}: {exc}",
            )
            raise SeedRotationError(
                f"seed profile {next_selection.profile.name} was installed but verification failed: "
                f"{type(exc).__name__}: {exc}"
            ) from exc
        finally:
            if temp_extractor:
                temp_extractor.close()

    def record_out_of_band_disconnect(phase: str, exc: Exception, suspected_query: str, executed_count: int):
        if not suspected_query:
            return None
        if not all(hasattr(executor, name) for name in ("_collect_crash_evidence", "_looks_confirmed_crash", "_write_crash_artifact", "_set_execution_result")):
            return None

        dedupe_key = (phase, executed_count, suspected_query)
        if dedupe_key in recorded_oob_disconnects:
            return None
        recorded_oob_disconnects.add(dedupe_key)

        msg = f"{phase}: {type(exc).__name__}: {exc}"
        evidence = executor._collect_crash_evidence({
            "detection_phase": phase,
            "driver_error": msg,
            "trigger_confidence": "suspected_last_submitted_query",
            "executed_count_at_detection": str(executed_count),
        })
        outcome = ExecutionOutcome.CONFIRMED_CRASH if executor._looks_confirmed_crash(evidence) else ExecutionOutcome.CRASH_LIKE
        artifact_path = executor._write_crash_artifact(outcome, suspected_query, msg, evidence)
        if hasattr(executor, "error_ledger"):
            executor.error_ledger[outcome.value] += 1
        if hasattr(executor, "bug_reports"):
            executor.bug_reports.append({
                "query": suspected_query,
                "artifact": artifact_path,
                "outcome": outcome.value,
                "detection_phase": phase,
            })
        result = executor._set_execution_result(
            outcome,
            suspected_query,
            msg,
            output="DATABASE DISCONNECT DETECTED OUTSIDE QUERY EXECUTION",
            error_type=type(exc).__name__,
            health=evidence,
            artifact_path=artifact_path,
        )
        log_verbose(f"[异步断连] {phase} 检测到目标断连，按 {outcome.value} 记录。疑似触发语句: {suspected_query}")
        log_verbose(f"[异步断连] 证据文件: {artifact_path}")
        return result
    
    termination_reason = "unhandled_exception"
    try:
        skeletons = load_skeletons_from_file(POOL_FILE)
        if not skeletons:
            raise RuntimeError(f"骨架池为空: {POOL_FILE}")
        seen_evolved_queries = OrderedDict()

        def remember_evolved(digest: str) -> None:
            seen_evolved_queries[digest] = None
            seen_evolved_queries.move_to_end(digest)
            maximum = max(1_000, args.evolved_seed_capacity * 5)
            while len(seen_evolved_queries) > maximum:
                seen_evolved_queries.popitem(last=False)
        
        round_idx = 0                  
        CONTEXT_REFRESH_INTERVAL = args.context_refresh_interval 
        
        while True:
            if args.max_iterations and round_idx >= args.max_iterations:
                log_verbose(f"[停止] 达到最大循环次数: {args.max_iterations}")
                termination_reason = "max_iterations"
                break

            round_idx += 1
            stats_drawn += 1
            
            if CONTEXT_REFRESH_INTERVAL > 0 and round_idx % CONTEXT_REFRESH_INTERVAL == 0:
                log_verbose("[环境同步] 正在重新提取数据库真实状态与规模...")

                temp_extractor = None
                try:
                    temp_extractor = refresh_context_once()
                    real_schema, real_state = temp_extractor.extract_context()
                    schema_view, graph_stats = install_context(real_schema, real_state)
                except Exception as refresh_exc:
                    oob_result = record_out_of_band_disconnect(
                        "context_refresh",
                        refresh_exc,
                        last_submitted_query,
                        stats_executed,
                    )
                    if oob_result is not None:
                        stats_crashes += 1
                    log_verbose(f"[环境同步] {TARGET_ENGINE} 上下文刷新失败。\n{traceback.format_exc()}")
                    journal.emit(
                        "context_refresh_failed",
                        round=round_idx,
                        phase="periodic",
                        error=f"{type(refresh_exc).__name__}: {refresh_exc}",
                    )
                    try:
                        if temp_extractor:
                            temp_extractor.close()
                        temp_extractor = None
                        reset_sequence_before_recovery = executor.graph_reset_sequence
                        if hasattr(executor, "_reconnect_and_reseed"):
                            log_verbose(f"[环境同步] {TARGET_ENGINE} 尝试重连并重灌种子图。")
                            executor._reconnect_and_reseed()
                        elif hasattr(executor, "_recover_container_and_seed"):
                            log_verbose(f"[环境同步] {TARGET_ENGINE} 尝试恢复容器并重灌种子图。")
                            executor._recover_container_and_seed()
                        else:
                            raise RuntimeError("target executor does not expose an automatic recovery hook")
                        if executor.graph_reset_sequence != reset_sequence_before_recovery:
                            epoch_executed = 0
                        if TARGET_ENGINE in {"neo4j", "memgraph"}:
                            URI = getattr(executor, "uri", URI)
                        temp_extractor = refresh_context_once()
                        real_schema, real_state = temp_extractor.extract_context()
                        schema_view, graph_stats = install_context(real_schema, real_state)
                        log_verbose(f"[环境同步] {TARGET_ENGINE} 恢复后上下文刷新成功")
                    except Exception as recovery_exc:
                        log_verbose(
                            f"[环境同步] {TARGET_ENGINE} 自动恢复不可用或恢复后仍无法刷新；"
                            f"继续使用上一版本上下文。\n{traceback.format_exc()}"
                        )
                        journal.emit(
                            "context_recovery_failed",
                            round=round_idx,
                            phase="periodic",
                            error=f"{type(recovery_exc).__name__}: {recovery_exc}",
                        )
                finally:
                    if temp_extractor:
                        temp_extractor.close()

            try:
                # Concrete high-value children use a dedicated queue. A configurable share
                # of rounds is reserved for lineage exploration so new roots
                # cannot be starved by successful descendants.
                use_evolved_seed = bool(evolved_seeds) and round_idx % max(1, args.lineage_interval) == 0
                if use_evolved_seed:
                    envelope = evolved_seeds.popleft()
                    skeleton = envelope.get("skeleton", "<evolved-concrete-seed>")
                    formatted_base = envelope["query"].strip()
                    lineage_seed_id = envelope["seed_id"]
                    instantiation_errors = []
                    journal.emit(
                        "evolved_seed_selected",
                        round=round_idx,
                        seed_id=lineage_seed_id,
                        generation=envelope.get("generation", 0),
                        query=formatted_base,
                    )
                else:
                    current_idx = (round_idx - 1) % len(skeletons)
                    skeleton = skeletons[current_idx]
                    executable_query, instantiation_errors = compile_and_instantiate(
                        skeleton,
                        real_schema,
                        real_state,
                        target_engine=TARGET_ENGINE,
                        allow_target_dialect=True,
                    )
                    formatted_base = executable_query.strip()
                    lineage_seed_id = query_digest(formatted_base)

                log_verbose(f"基础查询 (Q0): {formatted_base}")
                if instantiation_errors:
                    journal.emit(
                        "instantiation_diagnostics",
                        round=round_idx,
                        seed_id=lineage_seed_id,
                        errors=instantiation_errors,
                        parent_query=formatted_base,
                    )
                    stats_filtered += 1
                    log_verbose(f"[实例化拒绝] {instantiation_errors}")
                    continue

                strategy = monitor.plan_for(formatted_base, lineage_seed_id)
                mutation_seed = deterministic_mutation_seed(args.seed or 0, round_idx, lineage_seed_id)
                mutation_result = mutation_engine.mutate(
                    formatted_base,
                    seed=mutation_seed,
                    directive=strategy.directive,
                    weights=strategy.operator_weights,
                    enabled=strategy.enabled_operators,
                    seed_id=lineage_seed_id,
                )
                monitor.record_mutation(mutation_result)
                journal.emit(
                    "mutation_result",
                    round=round_idx,
                    mutation=mutation_result,
                    mutation_seed=mutation_seed,
                )

                if mutation_result.status in {MutationStatus.REJECTED, MutationStatus.ERROR}:
                    rejection_stage = mutation_result.metadata.get("rejection_stage", "mutation")
                    category = "parent_rejected" if rejection_stage.startswith("parent") else "mutation_rejected"
                    if category == "parent_rejected":
                        stats_parent_rejected += 1
                    else:
                        stats_mutation_rejected += 1
                    artifact_path, _created = artifact_store.save(
                        category,
                        {
                            "round": round_idx,
                            "target": TARGET_ENGINE,
                            "skeleton": skeleton,
                            "instantiation_errors": instantiation_errors,
                            "mutation": mutation_result,
                            "seed_graph": (
                                seed_runtime["selection"].to_dict()
                                if seed_runtime["selection"] is not None
                                else {"management": "external_reuse"}
                            ),
                        },
                    )
                    log_verbose(f"[{category}] 已阻止执行，证据: {artifact_path}")
                    dashboard.update(stats_drawn, stats_filtered, stats_executed, stats_passed, stats_exec_failed, stats_crashes, stats_resource_exhaustions)
                    continue

                if mutation_result.status == MutationStatus.NO_MATCH:
                    stats_mutation_noop += 1
                    if args.mutation_noop_policy == "skip":
                        log_verbose("[变异无匹配] 按策略跳过父查询执行")
                        continue
                    formatted_mut = formatted_base
                    log_verbose("[变异无匹配] 执行已通过双门禁的父查询")
                else:
                    formatted_mut = mutation_result.query.strip()
                    log_verbose(
                        f"AST变异 (Q_mut, operator={mutation_result.operator.value}, action={mutation_result.action}): {formatted_mut}"
                    )

                query_to_log = formatted_mut if formatted_mut.endswith(';') else f"{formatted_mut};"
                try:
                    with open(RUN_DIR / f"fuzzing_execution_trace_{TARGET_ENGINE}.cypher", "a", encoding="utf-8") as trace_file:
                        trace_file.write(f"{query_to_log}\n")
                except Exception:
                    pass

                stats_executed += 1
                epoch_executed += 1
                
                dashboard.update(stats_drawn, stats_filtered, stats_executed, stats_passed, stats_exec_failed, stats_crashes, stats_resource_exhaustions, current_q=formatted_mut)
                
                start_time = time.time()
                last_submitted_query = formatted_mut
                if hasattr(executor, "set_execution_context"):
                    executor.set_execution_context(
                        target=TARGET_ENGINE,
                        round_idx=round_idx,
                        stats_drawn=stats_drawn,
                        stats_executed=stats_executed,
                        epoch_query_index=epoch_executed,
                        graph_reset_sequence=executor.graph_reset_sequence,
                        seed=args.seed,
                        skeleton=skeleton,
                        base_query=formatted_base,
                        mutated_query=formatted_mut,
                        mutation_result=mutation_result.to_dict(),
                        context_refresh_interval=args.context_refresh_interval,
                        reseed_interval=args.reseed_interval,
                        query_timeout_seconds=getattr(executor, "query_timeout_s", 0),
                        mutation_strategy=to_jsonable(strategy),
                        seed_graph=(
                            seed_runtime["selection"].to_dict()
                            if seed_runtime["selection"] is not None
                            else {"management": "external_reuse"}
                        ),
                    )
                journal.emit(
                    "execution_started",
                    round=round_idx,
                    seed_id=mutation_result.seed_id,
                    mutation_id=mutation_result.mutation_id,
                    operator=mutation_result.operator,
                    action=mutation_result.action,
                    query=formatted_mut,
                    seed_graph=(
                        seed_runtime["selection"].to_dict()
                        if seed_runtime["selection"] is not None
                        else None
                    ),
                    executor_telemetry=(
                        executor.runtime_telemetry()
                        if callable(getattr(executor, "runtime_telemetry", None))
                        else None
                    ),
                )
                reset_sequence_before_execution = executor.graph_reset_sequence
                is_success, msg, execution_output = executor.execute_single(formatted_mut)
                graph_reset_during_execution = (
                    executor.graph_reset_sequence != reset_sequence_before_execution
                )
                if graph_reset_during_execution:
                    journal.emit(
                        "graph_recovered_during_execution",
                        round=round_idx,
                        query=formatted_mut,
                        previous_reset_sequence=reset_sequence_before_execution,
                        current_graph_context=executor.graph_context_metadata(),
                    )
                    epoch_executed = 0
                if TARGET_ENGINE == "neo4j":
                    URI = getattr(executor, "uri", URI)
                exec_time_ms = (time.time() - start_time) * 1000

                execution_result = getattr(executor, "last_execution", None)
                if execution_result is not None:
                    msg = execution_result.status_message()
                    execution_output = execution_result.output
                    if execution_result.outcome == ExecutionOutcome.SUCCESS:
                        status = ExecStatus.SUCCESS
                    elif execution_result.outcome == ExecutionOutcome.REJECTED:
                        status = ExecStatus.REJECTED
                    elif execution_result.outcome == ExecutionOutcome.TIMEOUT:
                        status = ExecStatus.TIMEOUT
                    elif execution_result.outcome == ExecutionOutcome.RESOURCE_EXHAUSTION:
                        status = ExecStatus.RESOURCE_EXHAUSTION
                    elif execution_result.outcome in {ExecutionOutcome.CRASH_LIKE, ExecutionOutcome.CONFIRMED_CRASH}:
                        status = ExecStatus.CRASH
                    else:
                        status = ExecStatus.ERROR
                else:
                    status = ExecStatus.SUCCESS
                    if not is_success:
                        msg_lower = msg.lower()
                        if msg.startswith(("CRASH_LIKE:", "CRASH:", "CONFIRMED_CRASH:")):
                            status = ExecStatus.CRASH
                        elif msg.startswith("RESOURCE_EXHAUSTION:"):
                            status = ExecStatus.RESOURCE_EXHAUSTION
                        elif msg.startswith("TIMEOUT:"):
                            status = ExecStatus.TIMEOUT
                        elif msg.startswith("REJECTED:"):
                            status = ExecStatus.REJECTED
                        elif msg.startswith("RUNTIME_ERROR:"):
                            status = ExecStatus.ERROR
                        elif any(err in msg_lower for err in ["clienterror", "parsing error", "syntax error", "extraneous input"]):
                            status = ExecStatus.ERROR
                        else:
                            status = ExecStatus.ERROR

                # Commit the terminal accounting immediately after the target
                # result is classified.  Downstream feedback/journal failures
                # must not leave a completed target call looking in-flight.
                if status == ExecStatus.CRASH:
                    stats_crashes += 1
                    log_verbose(f"触发引擎崩溃: {msg}")
                elif status == ExecStatus.RESOURCE_EXHAUSTION:
                    stats_resource_exhaustions += 1
                    log_verbose(f"触发资源耗尽候选: {msg}")
                elif is_success:
                    stats_passed += 1
                    log_verbose(f"执行状态: Success ({exec_time_ms:.2f}ms)")
                else:
                    stats_exec_failed += 1
                    log_verbose(f"执行失败: {msg}")

                scale_r = estimate_result_scale(execution_output)
            
                feedback_vec = FeedbackVector(
                    execution_time_ms=exec_time_ms,
                    result_scale=scale_r,
                    status=status,
                    raw_query=formatted_mut,
                    seed_id=mutation_result.seed_id,
                    error_code=getattr(execution_result, "error_type", "") if execution_result else "",
                )
                
                new_strategy, is_interesting = monitor.process_feedback(feedback_vec, mutation_result)
                journal.emit(
                    "execution_finished",
                    round=round_idx,
                    seed_id=mutation_result.seed_id,
                    mutation_id=mutation_result.mutation_id,
                    operator=mutation_result.operator,
                    action=mutation_result.action,
                    status=status,
                    execution_time_ms=exec_time_ms,
                    result_scale=scale_r,
                    message=msg,
                    artifact_path=(execution_result.artifact_path if execution_result else ""),
                    execution_health=(execution_result.health if execution_result else {}),
                    executor_telemetry=(
                        executor.runtime_telemetry()
                        if callable(getattr(executor, "runtime_telemetry", None))
                        else None
                    ),
                    graph_reset_during_execution=graph_reset_during_execution,
                    graph_context=executor.graph_context_metadata(),
                    interesting=is_interesting,
                    next_strategy=to_jsonable(new_strategy),
                )

                concrete_digest = query_digest(formatted_mut)
                if monitor.should_promote_seed(feedback_vec, is_interesting, mutation_result) and concrete_digest not in seen_evolved_queries:
                    monitor.inherit_seed_policy(mutation_result.seed_id, mutation_result.mutation_id)
                    evolved_seeds.append(
                        {
                            "query": formatted_mut,
                            "seed_id": mutation_result.mutation_id,
                            "generation": strategy.generation + 1,
                            "skeleton": skeleton,
                        }
                    )
                    remember_evolved(concrete_digest)
                    log_verbose("[种子池进化] 高价值具体查询进入独立 lineage 队列")
                elif is_interesting:
                    log_verbose(f"[反馈路由] 高延迟/异常候选进入专用反馈路径: {monitor.classify_latency(feedback_vec).value}")

                localization_seed = monitor.pop_localization_seed()
                if localization_seed:
                    localization_seed_id = localization_seed.get("mutation_id") or localization_seed["seed_id"]
                    monitor.inherit_seed_policy(localization_seed["seed_id"], localization_seed_id)
                    evolved_seeds.appendleft(
                        {
                            "query": localization_seed["query"],
                            "seed_id": localization_seed_id,
                            "generation": strategy.generation + 1,
                            "skeleton": skeleton,
                        }
                    )
                
                if not is_success:
                    artifact_store.save(
                        "execution_failures",
                        {
                            "round": round_idx,
                            "target": TARGET_ENGINE,
                            "status": status,
                            "message": msg,
                            "base_query": formatted_base,
                            "mutated_query": formatted_mut,
                            "mutation": mutation_result,
                            "execution_context": getattr(executor, "execution_context", {}),
                            "artifact_path": (
                                execution_result.artifact_path if execution_result else ""
                            ),
                            "graph_context": executor.graph_context_metadata(),
                            "seed_graph": (
                                seed_runtime["selection"].to_dict()
                                if seed_runtime["selection"] is not None
                                else {"management": "external_reuse"}
                            ),
                        },
                    )

                if is_success and args.context_refresh_on_write and is_write_query(formatted_mut):
                    temp_extractor = None
                    try:
                        temp_extractor = refresh_context_once()
                        real_schema, real_state = temp_extractor.extract_context()
                        schema_view, graph_stats = install_context(real_schema, real_state)
                        log_verbose("[写后同步] 图上下文已刷新")
                    except Exception as refresh_exc:
                        # The query has already completed successfully.  A
                        # telemetry refresh failure must not be reclassified as
                        # an execution or mutator failure; retain the last
                        # known-good context and leave an auditable event.
                        log_verbose(
                            f"[写后同步] 上下文刷新失败，继续使用上一版本: "
                            f"{type(refresh_exc).__name__}: {refresh_exc}"
                        )
                        journal.emit(
                            "context_refresh_failed",
                            round=round_idx,
                            phase="post_write",
                            query=formatted_mut,
                            error=f"{type(refresh_exc).__name__}: {refresh_exc}",
                        )
                    finally:
                        if temp_extractor:
                            temp_extractor.close()

                if should_rotate_seed_graph(
                    epoch_executed,
                    args.reseed_interval,
                    round_idx,
                    args.max_iterations,
                ):
                    real_schema, real_state = periodic_reseed_and_refresh()
                    epoch_executed = 0
                    schema_view, graph_stats = install_context(
                        real_schema, real_state, reason="automatic_seed_rotation"
                    )

                log_verbose("-" * 60 + "\n")
                
                dashboard.update(stats_drawn, stats_filtered, stats_executed, stats_passed, stats_exec_failed, stats_crashes, stats_resource_exhaustions)
                    
            except SeedRotationError as rotation_exc:
                stats_internal_errors += 1
                termination_reason = "seed_rotation_failed"
                log_verbose(
                    f"[种子图组合] 轮换失败，图状态不可证明，按 fail-closed 终止：{rotation_exc}"
                )
                journal.emit(
                    "campaign_aborted",
                    round=round_idx,
                    reason="seed_rotation_failed",
                    error=f"{type(rotation_exc).__name__}: {rotation_exc}",
                )
                break
            except EvidencePersistenceError as evidence_exc:
                stats_internal_errors += 1
                termination_reason = "evidence_persistence_failed"
                log_verbose(f"[证据写入失败] 停止测试，避免继续执行而丢失上下文：{evidence_exc}")
                break
            except UnsafeTargetStateError as target_exc:
                stats_internal_errors += 1
                termination_reason = "target_state_unsafe"
                log_verbose(f"[目标状态不可验证] 停止测试：{target_exc}")
                journal.emit(
                    "campaign_aborted", round=round_idx,
                    reason="target_state_unsafe", error=str(target_exc),
                )
                break
            except Exception:
                stats_internal_errors += 1
                log_verbose(f"严重内部崩溃发生！\n{traceback.format_exc()}\n" + "-" * 60 + "\n")
                journal.emit(
                    "internal_error",
                    round=round_idx,
                    traceback=traceback.format_exc(),
                    last_query=last_submitted_query,
                )
                dashboard.update(stats_drawn, stats_filtered, stats_executed, stats_passed, stats_exec_failed, stats_crashes, stats_resource_exhaustions)

    except KeyboardInterrupt:
        termination_reason = "keyboard_interrupt"
        print("\n\n测试终止 (Ctrl+C)！")        
    finally:
        runtime_counts = {
            "drawn": stats_drawn,
            "filtered": stats_filtered,
            "executed": stats_executed,
            "passed": stats_passed,
            "execution_failed": stats_exec_failed,
            "crashes": stats_crashes,
            "resource_exhaustions": stats_resource_exhaustions,
            "parent_rejected": stats_parent_rejected,
            "mutation_rejected": stats_mutation_rejected,
            "mutation_no_match": stats_mutation_noop,
            "internal_errors": stats_internal_errors,
        }
        runtime_counts["completed"] = (
            stats_passed
            + stats_exec_failed
            + stats_crashes
            + stats_resource_exhaustions
        )
        runtime_counts["in_flight"] = max(
            0,
            stats_executed - runtime_counts["completed"],
        )
        runtime_counts["completed_pass_rate_percent"] = (
            round(stats_passed / runtime_counts["completed"] * 100.0, 6)
            if runtime_counts["completed"]
            else 0.0
        )
        final_seed_state = (
            {
                **seed_runtime["selection"].to_dict(),
                "profiles_completed_or_active": seed_runtime["selection"].epoch + 1,
                "selection_mode": "automatic_deterministic_portfolio",
            }
            if seed_runtime["selection"] is not None
            else {"management": "external_reuse", "selection_mode": "disabled_for_reuse"}
        )
        final_graph_context = executor.graph_context_metadata()
        shutdown_errors = []
        target_checker = getattr(validation_pipeline, "target_check", None)
        if hasattr(target_checker, "close"):
            try:
                target_checker.close()
            except Exception as close_exc:
                shutdown_errors.append(
                    f"target_checker: {type(close_exc).__name__}: {close_exc}"
                )
        try:
            executor.close()
        except Exception as close_exc:
            shutdown_errors.append(
                f"executor: {type(close_exc).__name__}: {close_exc}"
            )
        final_executor_telemetry = None
        if callable(getattr(executor, "runtime_telemetry", None)):
            try:
                final_executor_telemetry = executor.runtime_telemetry()
            except Exception as telemetry_exc:
                shutdown_errors.append(
                    f"executor_telemetry: {type(telemetry_exc).__name__}: {telemetry_exc}"
                )
        try:
            journal.emit(
                "run_finished",
                termination=termination_reason,
                runtime_counts=runtime_counts,
                feedback=monitor.snapshot(),
                seed_graph=final_seed_state,
                epoch_query_count=epoch_executed,
                graph_context=final_graph_context,
                executor_telemetry=final_executor_telemetry,
                shutdown_errors=shutdown_errors,
            )
            summary_path = journal.write_summary(
                RUN_DIR / "run_summary.json",
                termination=termination_reason,
                target=TARGET_ENGINE,
                runtime_counts=runtime_counts,
                feedback=monitor.snapshot(),
                seed_graph=final_seed_state,
                epoch_query_count=epoch_executed,
                graph_context=final_graph_context,
                executor_telemetry=final_executor_telemetry,
                shutdown_errors=shutdown_errors,
            )
            log_verbose(f"[收尾] 运行摘要: {summary_path}")
            print(f"\n运行产物目录: {RUN_DIR}")
        except Exception:
            log_verbose(f"[收尾] 写入运行摘要失败:\n{traceback.format_exc()}")
