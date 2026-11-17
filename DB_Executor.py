import time
import datetime
import os
import multiprocessing
import uuid
import json
import re
import hashlib
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Tuple, List, Dict, Optional, Any
import sys
import subprocess

from graf.target_queries import prepare_target_query
from graf.evidence import (
    AbnormalCase,
    AbnormalCaseBundleWriter,
    EpochLedger,
    ReplayWindow,
)
from graf.kuzu_runtime import (
    KuzuRuntimeError,
    KuzuRuntimeResponse,
    KuzuWorkerCrashed,
    KuzuWorkerStartError,
    KuzuWorkerSupervisor,
    KuzuWorkerTimeout,
)
from graf.memgraph_runtime import (
    MemgraphQueryRuntime,
    MemgraphWorkerExited,
    MemgraphWorkerTimeout,
)
from graf.neo4j_runtime import (
    Neo4jQueryRuntime,
    Neo4jWorkerExited,
    Neo4jWorkerTimeout,
    snapshot_graph_state,
)

try:
    import redis
    RedisConnectionError = redis.exceptions.ConnectionError
    RedisTimeoutError = redis.exceptions.TimeoutError
except ImportError:
    redis = None

    class _MissingRedisException(Exception):
        pass

    RedisConnectionError = _MissingRedisException
    RedisTimeoutError = _MissingRedisException

try:
    from neo4j import GraphDatabase, Query
    from neo4j.exceptions import (
        CypherSyntaxError,
        CypherTypeError,
        ClientError,
        DatabaseError,
        ServiceUnavailable,
        SessionExpired,
        TransientError,
    )
except ImportError:
    pass

try:
    from falkordb import FalkorDB
except ImportError:
    pass

try:
    from nebula3.gclient.net import ConnectionPool
    from nebula3.Config import Config
    from nebula3.Exception import (
        IOErrorException,
        InValidHostname,
        NoValidSessionException,
        NotValidConnectionException,
        SessionException,
    )
    NebulaConnectionErrors = (
        IOErrorException,
        InValidHostname,
        NoValidSessionException,
        NotValidConnectionException,
        SessionException,
    )
    _NEBULA_IMPORT_ERROR = None
except ImportError as exc:
    ConnectionPool = None
    Config = None

    class _MissingNebulaException(Exception):
        pass

    NebulaConnectionErrors = (_MissingNebulaException,)
    _NEBULA_IMPORT_ERROR = exc


class ExecutionOutcome(Enum):
    SUCCESS = "SUCCESS"
    REJECTED = "REJECTED"
    RUNTIME_ERROR = "RUNTIME_ERROR"
    REPORTABLE_RUNTIME_BUG = "REPORTABLE_RUNTIME_BUG"
    TIMEOUT = "TIMEOUT"
    RESOURCE_EXHAUSTION = "RESOURCE_EXHAUSTION"
    CRASH_LIKE = "CRASH_LIKE"
    CONFIRMED_CRASH = "CONFIRMED_CRASH"


class EvidencePersistenceError(RuntimeError):
    """Stop the campaign when the ordered evidence stream cannot be trusted."""


class UnsafeTargetStateError(RuntimeError):
    """Stop when an interrupted write may still be running on the target."""


class _MemgraphRemoteError(Exception):
    def __init__(self, response):
        self.code = response.get("code", "")
        self.message = response.get("message", "")
        self.remote_type = response.get("error_type", "RemoteError")
        super().__init__(f"{self.remote_type}: {self.message}")


class _MemgraphRemoteClientError(_MemgraphRemoteError):
    pass


class _MemgraphRemoteDatabaseError(_MemgraphRemoteError):
    pass


class _MemgraphRemoteConnectionError(_MemgraphRemoteError):
    pass


class _Neo4jRemoteError(Exception):
    def __init__(self, response):
        self.code = response.get("code", "")
        self.message = response.get("message", "")
        self.remote_type = response.get("error_type", "RemoteError")
        super().__init__(f"{self.remote_type}: {self.message}")


class _Neo4jRemoteClientError(_Neo4jRemoteError):
    pass


class _Neo4jRemoteTransientError(_Neo4jRemoteError):
    pass


class _Neo4jRemoteDatabaseError(_Neo4jRemoteError):
    pass


class _Neo4jRemoteConnectionError(_Neo4jRemoteError):
    pass


@dataclass
class ExecutionResult:
    target: str
    outcome: ExecutionOutcome
    query: str
    message: str
    output: str = ""
    elapsed_ms: float = 0.0
    error_type: str = ""
    health: Dict[str, Any] = field(default_factory=dict)
    artifact_path: str = ""

    @property
    def is_success(self) -> bool:
        return self.outcome == ExecutionOutcome.SUCCESS

    def status_message(self) -> str:
        if self.outcome == ExecutionOutcome.SUCCESS:
            return f"Success ({self.elapsed_ms:.2f}ms)"
        prefix = {
            ExecutionOutcome.REJECTED: "REJECTED",
            ExecutionOutcome.RUNTIME_ERROR: "RUNTIME_ERROR",
            ExecutionOutcome.REPORTABLE_RUNTIME_BUG: "REPORTABLE_RUNTIME_BUG",
            ExecutionOutcome.TIMEOUT: "TIMEOUT",
            ExecutionOutcome.RESOURCE_EXHAUSTION: "RESOURCE_EXHAUSTION",
            ExecutionOutcome.CRASH_LIKE: "CRASH_LIKE",
            ExecutionOutcome.CONFIRMED_CRASH: "CONFIRMED_CRASH",
        }[self.outcome]
        artifact_suffix = f" | ARTIFACT: {self.artifact_path}" if self.artifact_path else ""
        return f"{prefix}: {self.message}{artifact_suffix}"


class BaseFuzzExecutor:
    def __init__(
        self,
        target_name: str,
        log_file: str,
        seed_cypher: str,
        history_limit: int = 200,
        state_history_limit: int = 500,
        crash_policy: str = "strict",
    ):
        self.target_name = target_name
        self.seed_cypher = seed_cypher
        self.seed_spec = None
        self.seed_statements = []
        self.managed_seed = False
        self.history_limit = max(1, int(history_limit))
        self.state_history_limit = max(1, int(state_history_limit))
        self.crash_policy = crash_policy
        
        current_dir = os.path.dirname(os.path.abspath(__file__))
        self.log_file = log_file if os.path.isabs(log_file) else os.path.join(current_dir, log_file)
        self.output_root = os.path.dirname(os.path.abspath(self.log_file))
        os.makedirs(self.output_root, exist_ok=True)
        
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(f"\n{'='*80}\n")
            f.write(f"[GRAF Fuzzer - {self.target_name}] Session Started at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"{'='*80}\n")
        
        self.stats = {"total_executed": 0, "passed": 0, "failed": 0, "total_time_ms": 0.0}
        self.error_ledger = defaultdict(int)
        self.bug_reports = []  
        self.runtime_bug_reports = []
        self.global_query_history = []
        self.state_changing_success_history = []
        self.successful_queries_since_reset = 0
        self.state_changes_since_reset = 0
        self.global_query_history_evicted = 0
        self.state_change_history_evicted = 0
        self.graph_reset_sequence = 0
        self.graph_context_started_at = self._utc_now()
        self.graph_context_reason = "startup_seed_or_external_graph"
        self.execution_context: Dict[str, Any] = {}
        self.last_execution: Optional[ExecutionResult] = None
        self._pending_query: Optional[str] = None
        self.epoch_ledger = EpochLedger(
            os.path.join(self.output_root, "epoch_history"),
            self.graph_reset_sequence,
            self.graph_context_reason,
        )

    @staticmethod
    def _utc_now() -> str:
        return (
            datetime.datetime.now(datetime.timezone.utc)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z")
        )

    def configure_context_retention(self, reseed_interval: int) -> None:
        """Keep replay history complete for a normal managed graph epoch.

        Diagnostic history remains a small rolling window.  State-changing
        history gets an epoch-sized budget because it is required to rebuild
        the exact graph state that preceded an abnormal query.  Rotation being
        disabled is represented honestly through eviction counters in the
        bundle instead of claiming an incomplete replay is complete.
        """

        interval = max(0, int(reseed_interval))
        if interval > 0:
            self.state_history_limit = max(self.history_limit, interval)

    def graph_context_metadata(self) -> Dict[str, Any]:
        return {
            "reset_sequence": self.graph_reset_sequence,
            "started_at": self.graph_context_started_at,
            "reason": self.graph_context_reason,
            "successful_queries_since_reset": self.successful_queries_since_reset,
            "state_changes_since_reset": self.state_changes_since_reset,
            "diagnostic_history_retained": len(self.global_query_history),
            "diagnostic_history_evicted": self.global_query_history_evicted,
            "state_history_retained": len(self.state_changing_success_history),
            "state_history_evicted": self.state_change_history_evicted,
            "state_history_note": "memory_window_only; complete committed history is in epoch_history",
        }

    def set_seed_spec(self, seed_spec, seed_cypher: str, seed_statements=None):
        """Atomically install the seed used by resets, recovery, and PoCs."""
        self.seed_spec = seed_spec
        self.seed_cypher = str(seed_cypher or "")
        self.seed_statements = list(seed_statements or [])
        self.managed_seed = seed_spec is not None
        self._append_epoch(
            "seed_selected",
            managed=self.managed_seed,
            statement_count=len(self.seed_statements),
            seed_sha256=hashlib.sha256(self.seed_cypher.encode("utf-8")).hexdigest(),
        )

    def _run_driver_seed(self, session):
        if self.seed_statements:
            for statement in self.seed_statements:
                session.run(statement).consume()
        elif self.seed_cypher:
            session.run(self.seed_cypher).consume()

    def _verify_driver_seed(self, session, engine: str):
        if self.seed_spec is None:
            return
        from GraphInitializer import verify_driver_seed

        verify_driver_seed(session, self.seed_spec, engine)

    def _write_log(self, content: str):
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(content + "\n")

    def set_execution_context(self, **context):
        self.execution_context = self._json_safe(context)

    def _append_epoch(self, event: str, **fields):
        try:
            self.epoch_ledger.append(event, **fields)
        except (OSError, ValueError) as exc:
            raise EvidencePersistenceError(f"epoch history write failed: {exc}") from exc

    def _begin_query(self, query: str, wire_query: Optional[str] = None):
        if self._pending_query is not None:
            raise RuntimeError("previous target query has no terminal evidence record")
        self._append_epoch(
            "query_started", query=self._normalize_cypher(query),
            wire_query=wire_query or query, context=self.execution_context,
        )
        self._pending_query = query

    def _epoch_snapshot(self):
        try:
            return self.epoch_ledger.snapshot()
        except (OSError, ValueError) as exc:
            raise EvidencePersistenceError(f"epoch history read failed: {exc}") from exc

    def _record_query(self, query: str, summary: str = "", state_changing: Optional[bool] = None):
        self.successful_queries_since_reset += 1
        self.global_query_history.append(query)
        if len(self.global_query_history) > self.history_limit:
            evicted = len(self.global_query_history) - self.history_limit
            del self.global_query_history[:evicted]
            self.global_query_history_evicted += evicted
        if state_changing is None:
            state_changing = self._looks_state_changing_query(query)
        if state_changing:
            self.state_changes_since_reset += 1
            self.state_changing_success_history.append({
                "query": self._normalize_cypher(query),
                "summary": str(summary or ""),
                "recorded_at": self._utc_now(),
            })
            self._append_epoch("state_change_committed", **self.state_changing_success_history[-1])
            if len(self.state_changing_success_history) > self.state_history_limit:
                evicted = len(self.state_changing_success_history) - self.state_history_limit
                del self.state_changing_success_history[:evicted]
                self.state_change_history_evicted += evicted

    def _clear_recorded_history(self, reason: str = "graph_reset_or_reseed"):
        if self._pending_query is not None:
            # A recovery reset can happen while the triggering call is still
            # unwinding.  Its terminal event belongs to the previous epoch.
            self._finish_epoch_pending("recovered_before_result", self._pending_query)
        self._append_epoch("epoch_ended", reason=reason)
        self.global_query_history.clear()
        self.state_changing_success_history.clear()
        self.successful_queries_since_reset = 0
        self.state_changes_since_reset = 0
        self.global_query_history_evicted = 0
        self.state_change_history_evicted = 0
        self.graph_reset_sequence += 1
        self.graph_context_started_at = self._utc_now()
        self.graph_context_reason = str(reason or "graph_reset_or_reseed")
        self.epoch_ledger = EpochLedger(
            os.path.join(self.output_root, "epoch_history"),
            self.graph_reset_sequence,
            self.graph_context_reason,
        )

    def _finish_epoch_pending(self, outcome: str, query: str):
        if self._pending_query is None:
            return
        self._append_epoch("query_finished", query=self._normalize_cypher(query), outcome=outcome)
        self._pending_query = None

    def _use_legacy_crash_policy(self) -> bool:
        return self.crash_policy == "legacy"

    def _looks_state_changing_query(self, query: str) -> bool:
        return bool(
            re.search(
                r"\b(?:CREATE|MERGE|SET|REMOVE|DELETE|DETACH|DROP|LOAD|FOREACH|"
                r"INSERT|UPDATE|UPSERT|ALTER|COPY|TRUNCATE|CLEAR|REBUILD|SUBMIT|"
                r"GRANT|REVOKE)\b",
                query or "",
                re.IGNORECASE,
            )
        )

    def _json_safe(self, value):
        try:
            json.dumps(value)
            return value
        except TypeError:
            if isinstance(value, dict):
                return {str(k): self._json_safe(v) for k, v in value.items()}
            if isinstance(value, (list, tuple, set)):
                return [self._json_safe(v) for v in value]
            if hasattr(value, "__dict__"):
                return self._json_safe(vars(value))
            return str(value)

    def _target_slug(self) -> str:
        return self.target_name.lower().replace(" ", "_")

    def _artifact_dir(self, *parts: str) -> str:
        return os.path.join(self.output_root, "evidence", *parts)

    def _normalize_cypher(self, query: str) -> str:
        query = (query or "").strip()
        if query and not query.endswith(";"):
            query += ";"
        return query

    def _comment_prefix(self) -> str:
        return "# " if self._target_slug() == "falkordb" else "// "

    def _comment_block(self, text: str) -> str:
        prefix = self._comment_prefix()
        lines = str(text or "").splitlines() or [""]
        return "\n".join(f"{prefix}{line}" for line in lines)

    def _artifact_filename(self, base_dir: str, stem: str, extension: str) -> str:
        os.makedirs(base_dir, exist_ok=True)
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        return os.path.join(base_dir, f"{stem}_{timestamp}_{uuid.uuid4().hex[:8]}.{extension}")

    def _docker_inspect_state(self, container_name: Optional[str] = None) -> str:
        container_name = container_name if container_name is not None else getattr(self, "container_name", "")
        if not container_name:
            return "NO_CONTAINER_CONFIGURED"
        try:
            result = subprocess.run(
                [
                    "docker",
                    "inspect",
                    container_name,
                    "--format",
                    "Status={{.State.Status}} ExitCode={{.State.ExitCode}} "
                    "OOMKilled={{.State.OOMKilled}} Error={{.State.Error}} "
                    "FinishedAt={{.State.FinishedAt}}",
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.stdout.strip()
        except Exception as exc:
            return f"docker inspect failed: {type(exc).__name__}: {exc}"

    def _docker_logs_tail(self, container_name: Optional[str] = None, lines: int = 120) -> str:
        container_name = container_name if container_name is not None else getattr(self, "container_name", "")
        if not container_name:
            return "NO_CONTAINER_CONFIGURED"
        try:
            result = subprocess.run(
                ["docker", "logs", "-t", f"--tail={lines}", container_name],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
            combined = "\n".join(part for part in [result.stdout, result.stderr] if part)
            return combined.strip() or "NO_LOG_OUTPUT"
        except Exception as exc:
            return f"docker logs failed: {type(exc).__name__}: {exc}"

    def _looks_confirmed_crash(self, evidence: Dict[str, str]) -> bool:
        inspect_state = evidence.get("docker_inspect", "").lower()
        logs_tail = evidence.get("docker_logs_tail", "").lower()
        fatal_tokens = (
            "oomkilled=true",
            "status=exited",
            "status=dead",
            "segmentation fault",
            "assertion",
            "panic",
            "fatal",
            "core dumped",
            "aborted",
        )
        return any(token in inspect_state or token in logs_tail for token in fatal_tokens)

    def _collect_crash_evidence(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        evidence = {
            "observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z"),
            "crash_policy": self.crash_policy,
            "docker_inspect": self._docker_inspect_state(),
            "docker_logs_tail": self._docker_logs_tail(),
        }
        if extra:
            evidence.update({k: str(v) for k, v in extra.items()})
        return evidence

    def _format_seed_for_artifact(self) -> str:
        return self._normalize_cypher(self.seed_cypher)

    def _format_history_for_artifact(self) -> List[str]:
        return [self._normalize_cypher(query) for query in self.global_query_history if query and query.strip()]

    def _seed_statements_for_artifact(self) -> List[str]:
        if self.seed_statements:
            return [
                self._normalize_cypher(statement)
                for statement in self.seed_statements
                if str(statement or "").strip()
            ]
        if not self.seed_cypher:
            return []
        # All managed renderers emit one complete statement per non-comment
        # line.  This fallback preserves compatibility with callers that only
        # supplied the legacy combined seed string.
        statements = []
        for line in str(self.seed_cypher).splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith(("//", "#")):
                statements.append(self._normalize_cypher(stripped))
        return statements or [self._normalize_cypher(self.seed_cypher)]

    def _format_state_changing_history(self) -> List[Dict[str, str]]:
        _, records = self._epoch_snapshot()
        return [
            {
                "query": item.get("query", ""),
                "summary": item.get("summary", ""),
                "recorded_at": item.get("recorded_at", ""),
            }
            for item in records
            if item.get("event") == "state_change_committed" and item.get("query")
        ]

    def _write_text_file(self, path: str, content: str):
        with open(path, "w", encoding="utf-8") as f:
            f.write(content or "")
            if content and not content.endswith("\n"):
                f.write("\n")

    def _write_json_file(self, path: str, content):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self._json_safe(content), f, ensure_ascii=False, indent=2, sort_keys=True)
            f.write("\n")

    def _replay_window(self, trigger_query: Optional[str] = None) -> ReplayWindow:
        _, records = self._epoch_snapshot()
        committed = sum(item.get("event") == "state_change_committed" for item in records)
        # The trigger is replayed after this state window. Its own uncertain
        # outcome must not be counted as a *prior* write, even when a hard
        # timeout already wrote its terminal epoch event before publication.
        if trigger_query is not None:
            trigger_text = self._normalize_cypher(trigger_query)
            starts = [index for index, item in enumerate(records) if
                      item.get("event") == "query_started" and item.get("query") == trigger_text]
            if starts:
                records = records[:starts[-1]]
        uncertain = sum(
            item.get("event") == "query_finished"
            and item.get("outcome") not in {"SUCCESS", "REJECTED"}
            and self._looks_state_changing_query(str(item.get("query", "")))
            for item in records
        )
        return ReplayWindow(
            successful_total=self.successful_queries_since_reset,
            successful_retained=len(self.global_query_history),
            successful_evicted=self.global_query_history_evicted,
            state_changes_total=self.state_changes_since_reset,
            state_changes_retained=committed,
            state_changes_evicted=max(0, self.state_changes_since_reset - committed),
            seed_available=self.managed_seed,
            uncertain_prior_writes=uncertain,
        )

    def _artifact_header(self, stem: str, message: str, evidence: Dict[str, str]) -> str:
        lines = [
            self._comment_block(f"GRAF abnormal execution artifact for {self.target_name}"),
            self._comment_block(f"Classification: {stem}"),
            self._comment_block(f"Error: {message}"),
            self._comment_block("Structured context: context.json"),
            self._comment_block("Integrity inventory: manifest.json"),
        ]
        # Full logs live in context.json.  Keeping only short scalar evidence
        # in the executable replay prevents a log line from making it unwieldy.
        for key, value in evidence.items():
            value_text = str(value)
            if key in {"docker_logs_tail"} or len(value_text.encode("utf-8")) > 4096:
                continue
            lines.append(self._comment_block(f"{key}: {value_text}"))
        return "\n".join(lines)

    def _build_cypher_reproduction(
        self,
        stem: str,
        query: str,
        message: str,
        evidence: Dict[str, str],
    ) -> str:
        sections = [self._artifact_header(stem, message, evidence), ""]
        target_slug = self._target_slug()
        if target_slug in {"neo4j", "memgraph"}:
            sections.extend(["// [0] Clean database", "MATCH (n) DETACH DELETE n;", ""])
        elif target_slug in {"kuzudb", "kuzu"}:
            sections.extend([
                "// [0] Run this replay against a fresh Kùzu database path.",
                "//     The seed includes schema DDL and must not be applied over an existing schema.",
                "",
            ])
        elif target_slug in {"nebulagraph", "nebula"}:
            sections.extend([
                "// [0] Run this replay against a fresh GRAF-managed NebulaGraph space.",
                "",
            ])

        seed_query = self._format_seed_for_artifact()
        if seed_query:
            sections.extend(["// [1] Exact seed graph build statements", seed_query, ""])

        state_history = self._format_state_changing_history()
        if state_history:
            sections.append("// [2] Successful state-changing queries since the last graph reset")
            for item in state_history:
                if target_slug in {"nebulagraph", "nebula"}:
                    sections.append(f"USE `{self.space}`;")
                sections.append(item["query"])
            sections.append("")

        sections.append("// [3] Triggering query")
        if target_slug in {"nebulagraph", "nebula"}:
            sections.append(f"USE `{self.space}`;")
        sections.extend([self._normalize_cypher(query), ""])
        return "\n".join(sections)

    def _write_cypher_artifact(
        self,
        base_dir: str,
        stem: str,
        query: str,
        message: str,
        evidence: Dict[str, str],
    ) -> str:
        reproduction = self._build_cypher_reproduction(stem, query, message, evidence)
        return self._publish_abnormal_case(
            base_dir=base_dir,
            stem=stem,
            query=query,
            message=message,
            evidence=evidence,
            extension="cypher",
            reproduction=reproduction,
        )

    def _wrap_falkordb_query(self, query: str) -> str:
        graph_name = getattr(self, "graph_name", "graf_fuzz")
        uncommented = "\n".join(
            line for line in str(query or "").splitlines()
            if line.strip() and not line.strip().startswith("//")
        )
        cypher = self._normalize_cypher(uncommented).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")
        return f'GRAPH.QUERY {graph_name} "{cypher}"'

    def _write_falkordb_artifact(
        self,
        base_dir: str,
        stem: str,
        query: str,
        message: str,
        evidence: Dict[str, str],
    ) -> str:
        graph_name = getattr(self, "graph_name", "graf_fuzz")
        lines = [
            self._artifact_header(stem, message, evidence),
            "",
            self._comment_block("[0] Clean graph; ignore a missing-graph error"),
            f"GRAPH.DELETE {graph_name}",
            "",
        ]
        seed_statements = self._seed_statements_for_artifact()
        if seed_statements:
            lines.append(self._comment_block("[1] Exact seed graph build statements"))
            lines.extend(self._wrap_falkordb_query(statement) for statement in seed_statements)
            lines.append("")
        state_history = self._format_state_changing_history()
        if state_history:
            lines.append(self._comment_block("[2] Successful state-changing queries since the last graph reset"))
            lines.extend(self._wrap_falkordb_query(item["query"]) for item in state_history)
            lines.append("")
        lines.extend([
            self._comment_block("[3] Triggering query"),
            self._wrap_falkordb_query(query),
            "",
        ])
        return self._publish_abnormal_case(
            base_dir=base_dir,
            stem=stem,
            query=query,
            message=message,
            evidence=evidence,
            extension="redis",
            reproduction="\n".join(lines),
        )

    def _publish_abnormal_case(
        self,
        base_dir: str,
        stem: str,
        query: str,
        message: str,
        evidence: Dict[str, str],
        extension: str,
        reproduction: str,
        extra_files: Optional[Dict[str, str]] = None,
    ) -> str:
        case = AbnormalCase(
            target=self.target_name,
            classification=stem,
            message=str(message or ""),
            trigger_query=self._normalize_cypher(query),
            seed_script=self._format_seed_for_artifact(),
            seed_statements=self._seed_statements_for_artifact(),
            state_change_history=self._format_state_changing_history(),
            diagnostic_query_history=self._format_history_for_artifact(),
            replay_window=self._replay_window(query),
            execution_context={
                **self.execution_context,
                "graph_context": self.graph_context_metadata(),
                "target_database": (
                    getattr(self, "space", None) or getattr(self, "database", None)
                    or getattr(self, "graph_name", None) or getattr(self, "db_path", None)
                ),
                "epoch_history_file": "epoch_queries.jsonl",
            },
            evidence=evidence,
            graph_reset_sequence=self.graph_reset_sequence,
            graph_context_started_at=self.graph_context_started_at,
            graph_context_reason=self.graph_context_reason,
            managed_seed=self.managed_seed,
            reproduction_extension=extension,
            reproduction_text=reproduction,
            extra_files={**(extra_files or {}), "epoch_queries.jsonl": self._epoch_snapshot()[0]},
        )
        published = AbnormalCaseBundleWriter(base_dir).publish(case)
        return str(published.reproduction_path)

    def _write_crash_artifact(
        self,
        outcome: ExecutionOutcome,
        query: str,
        message: str,
        evidence: Dict[str, str],
        legacy_unconfirmed: bool = False,
    ) -> str:
        if legacy_unconfirmed:
            base_dir = self._artifact_dir("legacy_crash_like", self._target_slug())
            stem = "legacy_unconfirmed"
        else:
            base_dir = self._artifact_dir("crash_pocs", self._target_slug())
            stem = "confirmed_crash" if outcome == ExecutionOutcome.CONFIRMED_CRASH else "crash_like"

        if self._target_slug() == "falkordb":
            return self._write_falkordb_artifact(base_dir, stem, query, message, evidence)
        return self._write_cypher_artifact(base_dir, stem, query, message, evidence)

    def _write_timeout_artifact(self, query: str, message: str, evidence: Dict[str, str]) -> str:
        base_dir = self._artifact_dir("timeout_cases", self._target_slug())
        stem = "timeout"
        if self._target_slug() == "falkordb":
            return self._write_falkordb_artifact(base_dir, stem, query, message, evidence)
        return self._write_cypher_artifact(base_dir, stem, query, message, evidence)

    def _write_reportable_runtime_bug_artifact(self, query: str, message: str, evidence: Dict[str, str]) -> str:
        base_dir = self._artifact_dir("runtime_bug_reports", self._target_slug())
        stem = "statement_execution_failed" if self._target_slug() == "neo4j" else "reportable_runtime_bug"
        return self._write_cypher_artifact(base_dir, stem, query, message, evidence)

    def _write_resource_exhaustion_bundle(
        self,
        query: str,
        message: str,
        evidence: Dict[str, str],
        graph_state_before=None,
        graph_state_after=None,
        db_config=None,
        outcome: ExecutionOutcome = ExecutionOutcome.RESOURCE_EXHAUSTION,
    ) -> str:
        stem = outcome.value.lower()
        base_dir = self._artifact_dir("resource_exhaustion", self._target_slug())
        reproduction = self._build_cypher_reproduction(stem, query, message, evidence)

        def json_text(value) -> str:
            return json.dumps(
                self._json_safe(value),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            ) + "\n"

        extra_files = {
            "graph_state_before.json": json_text(graph_state_before or {}),
            "graph_state_after.json": json_text(graph_state_after or {}),
            "db_config.json": json_text(db_config or {}),
            "resource_metadata.json": json_text(
                {
                    "outcome": outcome.value,
                    "error": message,
                    "evidence": evidence,
                    "graph_state_before_file": "graph_state_before.json",
                    "graph_state_after_file": "graph_state_after.json",
                    "db_config_file": "db_config.json",
                }
            ),
        }
        return self._publish_abnormal_case(
            base_dir=base_dir,
            stem=stem,
            query=query,
            message=message,
            evidence=evidence,
            extension="cypher",
            reproduction=reproduction,
            extra_files=extra_files,
        )

    def _set_execution_result(
        self,
        outcome: ExecutionOutcome,
        query: str,
        message: str,
        output: str = "",
        elapsed_ms: float = 0.0,
        error_type: str = "",
        health: Optional[Dict[str, Any]] = None,
        artifact_path: str = "",
    ) -> ExecutionResult:
        result = ExecutionResult(
            target=self.target_name,
            outcome=outcome,
            query=query,
            message=message,
            output=output,
            elapsed_ms=elapsed_ms,
            error_type=error_type,
            health=health or {},
            artifact_path=artifact_path,
        )
        self.last_execution = result
        return result

    def _finish_execution(self, query: str, fallback_output: str = "") -> Tuple[bool, str, str]:
        if self.last_execution is None or self.last_execution.query != query:
            self._set_execution_result(
                ExecutionOutcome.RUNTIME_ERROR,
                query,
                "executor finished without structured result",
                output=fallback_output,
            )
        result = self.last_execution
        self._finish_epoch_pending(result.outcome.value, query)
        self._write_log(
            f"[{self.stats['total_executed']}] Query: {query}\n"
            f"--> Status: {result.status_message()}\n"
            f"--> Outcome: {result.outcome.value}\n"
            f"--> Evidence: {result.health}\n"
            f"{'-'*60}"
        )
        return result.is_success, result.status_message(), result.output

    def _save_runtime_error(self, query: str, error_msg: str):
        runtime_dir = self._artifact_dir("runtime_errors", self.target_name.lower())
        os.makedirs(runtime_dir, exist_ok=True)
        filename = self._artifact_filename(runtime_dir, "runtime_error", "cypher")
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(f"// {self.target_name} Runtime Error\n")
                f.write(f"// Error: {error_msg}\n\n")
                f.write(self._normalize_cypher(query))
                f.write("\n")
        except Exception:
            pass

    # def print_fuzzing_report(self):
    #     total = self.stats["total_executed"]
    #     if total == 0:
    #         print(f"[{self.target_name}] 没有执行任何查询。")
    #         return
            
    #     pass_rate = (self.stats["passed"] / total) * 100
    #     avg_time = self.stats["total_time_ms"] / total if total > 0 else 0
        
    #     report_lines = [
    #         "\n" + "="*50,
    #         f"[GRAF Fuzzer - {self.target_name}] 最终执行报告",
    #         "="*50,
    #         f"总计发送查询 : {total}",
    #         f"成功执行 (Pass): {self.stats['passed']}",
    #         f"失败被拒 (Fail): {self.stats['failed']}",
    #         f"整体通过率   : {pass_rate:.2f}%",
    #         f"平均响应耗时 : {avg_time:.2f} ms"
    #     ]
        
    #     if self.error_ledger:
    #         report_lines.append("\n📊 错误分布矩阵 (Error Distribution):")
    #         for err_type, count in sorted(self.error_ledger.items(), key=lambda x: x[1], reverse=True):
    #             report_lines.append(f"   - {err_type.ljust(25)}: {count} 次")
                
    #     final_report = "\n".join(report_lines)
    #     print(final_report)
    #     self._write_log(final_report)



class MemgraphFuzzExecutor(BaseFuzzExecutor):
    def __init__(
        self,
        uri: str,
        user: str = "",
        password: str = "",
        log_file: str = "fuzzer_memgraph.log",
        seed_cypher: str = "",
        container_name: str = "memgraph_fuzz_target",
        ready_timeout_s: int = 60,
        recovery_retries: int = 3,
        delete_batch_size: int = 1000,
        delete_max_batches: int = 1000,
        query_timeout_s: int = 120,
        crash_policy: str = "strict",
    ):
        super().__init__("Memgraph", log_file, seed_cypher, crash_policy=crash_policy)
        self.uri = uri
        self.auth = (user, password)
        self.container_name = container_name
        self.ready_timeout_s = ready_timeout_s
        self.recovery_retries = recovery_retries
        self.delete_batch_size = delete_batch_size
        self.delete_max_batches = delete_max_batches
        self.query_timeout_s = max(0, int(query_timeout_s))
        self.driver = GraphDatabase.driver(self.uri, auth=self.auth)
        self.query_runtime = MemgraphQueryRuntime(self.uri, self.auth)

    def close(self):
        try:
            self.query_runtime.close()
        finally:
            self.driver.close()

    def _wait_until_ready(self):
        deadline = time.time() + self.ready_timeout_s
        last_error = None
        next_report = 0

        while time.time() < deadline:
            try:
                response = self.query_runtime.request(
                    "RETURN 1 AS ok", min(5, max(0.1, deadline - time.time()))
                )
                if response["status"] != "success":
                    raise RuntimeError(response.get("message", "readiness probe failed"))
                return
            except Exception as exc:
                last_error = exc
                now = time.time()
                if now >= next_report:
                    remaining = int(deadline - now)
                    print(f"[Memgraph] Bolt 尚未就绪，剩余等待 {max(0, remaining)}s: {exc}")
                    next_report = now + 10
                time.sleep(2)

        raise RuntimeError(f"Memgraph did not become ready within {self.ready_timeout_s}s: {last_error}")

    def _probe_connection_after_error(self) -> Tuple[bool, str]:
        try:
            response = self.query_runtime.request("RETURN 1 AS ok", 5)
            if response["status"] != "success":
                raise RuntimeError(response.get("message", "health probe failed"))
            return True, "CONNECTION_ALIVE_AFTER_ERROR"
        except Exception as exc:
            return False, f"CONNECTION_LOST_AFTER_ERROR: {type(exc).__name__}: {exc}"

    @staticmethod
    def _is_query_timeout_error(exc) -> bool:
        text = " ".join(
            str(part or "")
            for part in (
                type(exc).__name__,
                getattr(exc, "code", ""),
                getattr(exc, "message", ""),
                str(exc),
            )
        ).lower()
        return any(token in text for token in ("timeout", "timed out", "transaction has been terminated"))

    def _clear_database(self, session):
        total_deleted = 0
        for _ in range(self.delete_max_batches):
            record = session.run(
                "MATCH (n) WITH n LIMIT $batch_size DETACH DELETE n RETURN count(n) AS deleted",
                batch_size=self.delete_batch_size,
            ).single()
            deleted = int(record["deleted"]) if record else 0
            total_deleted += deleted
            if deleted == 0:
                return total_deleted
        raise RuntimeError(
            f"Memgraph clear exceeded {self.delete_max_batches} batches "
            f"(batch_size={self.delete_batch_size}, deleted>={total_deleted})"
        )

    def reset_to_seed(self):
        print("[Memgraph] 周期性清空并重灌种子图...")
        self.query_runtime.restart_boundary()
        self._wait_until_ready()
        with self.driver.session() as session:
            deleted = self._clear_database(session)
            self._run_driver_seed(session)
            self._verify_driver_seed(session, "Memgraph")
        self._clear_recorded_history("periodic_seed_reset")
        print(f"[Memgraph] 周期性初始化完成，删除节点数: {deleted}")

    def _reconnect_and_reseed(self):
        self.query_runtime.restart_boundary()
        try:
            self.driver.close()
        except Exception:
            pass

        last_error = None
        for attempt in range(1, self.recovery_retries + 1):
            try:
                if self.container_name:
                    print(f"[Memgraph] 重启容器 {self.container_name}，恢复尝试 {attempt}/{self.recovery_retries}...")
                    subprocess.run(
                        ["docker", "restart", self.container_name],
                        check=True, capture_output=True, timeout=self.ready_timeout_s,
                    )

                self.driver = GraphDatabase.driver(self.uri, auth=self.auth)
                print("[Memgraph] 等待 Bolt 服务恢复...")
                self._wait_until_ready()

                if self.seed_cypher or self.seed_statements:
                    with self.driver.session() as session:
                        self._clear_database(session)
                        self._run_driver_seed(session)
                        self._verify_driver_seed(session, "Memgraph")
                    self._clear_recorded_history("crash_recovery_seed_reset")
                return
            except Exception as exc:
                last_error = exc
                print(f"[Memgraph] 第 {attempt} 次恢复失败: {exc}")
                try:
                    self.driver.close()
                except Exception:
                    pass
                time.sleep(5)

        raise RuntimeError(f"Memgraph recovery failed after {self.recovery_retries} attempts: {last_error}")

    def execute_single(self, query: str) -> Tuple[bool, str, str]:
        self._begin_query(query)
        self.last_execution = None
        self.stats["total_executed"] += 1
        start_time = time.time()
        execution_output = ""
        
        try:
            response = self.query_runtime.request(query, self.query_timeout_s)
            if response["status"] != "success":
                error_class = {
                    "client": _MemgraphRemoteClientError,
                    "database": _MemgraphRemoteDatabaseError,
                    "connection": _MemgraphRemoteConnectionError,
                }.get(response.get("category"), _MemgraphRemoteError)
                raise error_class(response)
                
            elapsed_ms = (time.time() - start_time) * 1000
            self.stats["total_time_ms"] += elapsed_ms
            self.stats["passed"] += 1
            execution_output = response["output"]
            self._record_query(query)
            self._set_execution_result(
                ExecutionOutcome.SUCCESS,
                query,
                "ok",
                output=execution_output,
                elapsed_ms=elapsed_ms,
            )
            
        except MemgraphWorkerTimeout as e:
            self.stats["failed"] += 1
            self.error_ledger["QUERY_TIMEOUT"] += 1
            execution_output = "QUERY TIMEOUT"
            err_msg = str(e)
            print(f"[Memgraph] {err_msg}; 正在保存证据并恢复专用实例。", flush=True)
            evidence = {
                "timeout_seconds": str(self.query_timeout_s),
                "worker_pid": str(e.pid),
                "worker_terminated": "true",
                "server_execution_state": "unknown_until_container_restart",
            }
            self._finish_epoch_pending(ExecutionOutcome.TIMEOUT.value, query)
            try:
                artifact_path = self._write_timeout_artifact(query, err_msg, evidence)
            except Exception as artifact_exc:
                raise EvidencePersistenceError(
                    f"Memgraph worker terminated after hard timeout, but case publication failed: "
                    f"{artifact_exc}; target state is unsafe"
                ) from artifact_exc
            self._set_execution_result(
                ExecutionOutcome.TIMEOUT, query, err_msg,
                output=execution_output, error_type="MemgraphWorkerTimeout",
                health=evidence, artifact_path=artifact_path,
            )
            try:
                if not self.managed_seed or not self.container_name:
                    raise UnsafeTargetStateError(
                        "hard timeout requires a dedicated restartable Memgraph container "
                        "and --init-mode reset; target state cannot be verified"
                    )
                self._reconnect_and_reseed()
            except Exception as recover_e:
                self.last_execution.message += f" | RECOVERY_FAILED: {recover_e}"
                self._finish_execution(query, execution_output)
                raise UnsafeTargetStateError(
                    f"Memgraph hard timeout evidence saved at {artifact_path}; "
                    f"target state unsafe: {recover_e}"
                ) from recover_e
            self.last_execution.message += " | RECOVERED"

        except (CypherSyntaxError, CypherTypeError, ClientError, _MemgraphRemoteClientError) as e:
            self.stats["failed"] += 1
            err_type = e.code if getattr(e, "code", "") else getattr(e, "remote_type", type(e).__name__)
            err_msg = f"{err_type}: {getattr(e, 'message', str(e))}"
            if self._is_query_timeout_error(e):
                self.error_ledger["QUERY_TIMEOUT"] += 1
                execution_output = "QUERY TIMEOUT"
                evidence = {
                    "connection_state": "SERVER_SIDE_TIMEOUT",
                    "timeout_seconds": str(self.query_timeout_s),
                    "driver_error": err_msg,
                }
                artifact_path = self._write_timeout_artifact(query, err_msg, evidence)
                self._set_execution_result(
                    ExecutionOutcome.TIMEOUT,
                    query,
                    err_msg,
                    output=execution_output,
                    error_type=err_type,
                    health=evidence,
                    artifact_path=artifact_path,
                )
            else:
                self.error_ledger[err_type] += 1
                execution_output = "Semantic/Syntax Error"
                self._set_execution_result(
                    ExecutionOutcome.REJECTED,
                    query,
                    err_msg,
                    output=execution_output,
                    error_type=err_type,
                )

        except (DatabaseError, TransientError, _MemgraphRemoteDatabaseError) as e:
            self.stats["failed"] += 1
            err_type = getattr(e, "code", None) or getattr(e, "remote_type", type(e).__name__)
            err_msg = f"{err_type}: {getattr(e, 'message', str(e))}"
            is_alive, connection_state = self._probe_connection_after_error()
            if self._is_query_timeout_error(e) and is_alive:
                evidence = {
                    "connection_state": connection_state,
                    "timeout_seconds": str(self.query_timeout_s),
                    "driver_error": err_msg,
                }
                artifact_path = self._write_timeout_artifact(query, err_msg, evidence)
                self.error_ledger["QUERY_TIMEOUT"] += 1
                execution_output = "QUERY TIMEOUT"
                self._set_execution_result(
                    ExecutionOutcome.TIMEOUT,
                    query,
                    f"{err_msg} | {connection_state}",
                    output=execution_output,
                    error_type=err_type,
                    health=evidence,
                    artifact_path=artifact_path,
                )
            elif not is_alive:
                evidence = self._collect_crash_evidence({"connection_state": connection_state, "driver_error": err_msg})
                outcome = ExecutionOutcome.CONFIRMED_CRASH if self._looks_confirmed_crash(evidence) else ExecutionOutcome.CRASH_LIKE
                artifact_path = self._write_crash_artifact(outcome, query, err_msg, evidence)
                self.error_ledger[outcome.value] += 1
                self.bug_reports.append({"query": query, "artifact": artifact_path, "outcome": outcome.value})
                execution_output = "DATABASE CRASH DETECTED"
                try:
                    self._reconnect_and_reseed()
                    err_msg += " | RECOVERED"
                except Exception as recover_e:
                    err_msg += f" | RECOVERY_FAILED: {recover_e}"
                    print(f"[Memgraph] 恢复失败: {recover_e}")
                self._set_execution_result(
                    outcome,
                    query,
                    err_msg,
                    output=execution_output,
                    error_type=err_type,
                    health=evidence,
                    artifact_path=artifact_path,
                )
            else:
                if self._use_legacy_crash_policy():
                    legacy_evidence = self._collect_crash_evidence({"connection_state": connection_state, "driver_error": err_msg})
                    legacy_path = self._write_crash_artifact(
                        ExecutionOutcome.CRASH_LIKE,
                        query,
                        err_msg,
                        legacy_evidence,
                        legacy_unconfirmed=True,
                    )
                    err_msg += f" | LEGACY_UNCONFIRMED_ARTIFACT: {legacy_path}"
                    self.error_ledger["LEGACY_DB_ERROR_SERVER_ALIVE"] += 1
                else:
                    self.error_ledger[err_type] += 1
                execution_output = "Database Runtime Error"
                self._save_runtime_error(query, f"RUNTIME_ERROR: {err_msg} | {connection_state}")
                self._set_execution_result(
                    ExecutionOutcome.RUNTIME_ERROR,
                    query,
                    f"{err_msg} | {connection_state}",
                    output=execution_output,
                    error_type=err_type,
                    health={"connection_state": connection_state},
                )

        except (ServiceUnavailable, SessionExpired, OSError, _MemgraphRemoteConnectionError, MemgraphWorkerExited) as e:
            self.stats["failed"] += 1
            err_msg = f"{getattr(e, 'remote_type', type(e).__name__)}: {str(e)}"
            is_alive, connection_state = self._probe_connection_after_error()
            evidence = self._collect_crash_evidence({"connection_state": connection_state, "driver_error": err_msg})
            outcome = ExecutionOutcome.CONFIRMED_CRASH if self._looks_confirmed_crash(evidence) else ExecutionOutcome.CRASH_LIKE
            self.error_ledger[outcome.value] += 1
            execution_output = "DATABASE CRASH DETECTED"
            artifact_path = self._write_crash_artifact(outcome, query, err_msg, evidence)
            self.bug_reports.append({"query": query, "artifact": artifact_path, "outcome": outcome.value})
            
            try:
                self._reconnect_and_reseed()
                err_msg += " | RECOVERED"
            except Exception as recover_e:
                err_msg += f" | RECOVERY_FAILED: {recover_e}"
                print(f"[Memgraph] 恢复失败: {recover_e}")
            self._set_execution_result(
                outcome,
                query,
                err_msg,
                output=execution_output,
                error_type=type(e).__name__,
                health=evidence,
                artifact_path=artifact_path,
            )
        except Exception as e:
            self.stats["failed"] += 1
            execution_output = "Unknown Error"
            err_msg = f"Exception: {str(e)}"
            self._save_runtime_error(query, f"RUNTIME_ERROR: {err_msg}")
            self._set_execution_result(
                ExecutionOutcome.RUNTIME_ERROR,
                query,
                err_msg,
                output=execution_output,
                error_type=type(e).__name__,
            )

        return self._finish_execution(query, execution_output)


class Neo4jFuzzExecutor(BaseFuzzExecutor):
    def __init__(
        self,
        uri: str = "bolt://localhost:7687",
        user: str = "neo4j",
        password: str = "testpassword",
        database: str = "neo4j",
        log_file: str = "fuzzer_neo4j.log",
        seed_cypher: str = "",
        container_name: str = "neo4j_fuzz_target",
        ready_timeout_s: int = 90,
        auto_resolve_uri: bool = False,
        recovery_retries: int = 3,
        delete_batch_size: int = 1000,
        delete_max_batches: int = 1000,
        query_timeout_s: int = 120,
        crash_policy: str = "strict",
    ):
        super().__init__("Neo4j", log_file, seed_cypher, crash_policy=crash_policy)
        self.uri = uri
        self.auth = (user, password)
        self.database = database
        self.container_name = container_name
        self.ready_timeout_s = ready_timeout_s
        self.auto_resolve_uri = auto_resolve_uri
        self.recovery_retries = recovery_retries
        self.delete_batch_size = delete_batch_size
        self.delete_max_batches = delete_max_batches
        self.query_timeout_s = max(0, int(query_timeout_s))
        self.driver = GraphDatabase.driver(self.uri, auth=self.auth)
        self.query_runtime = Neo4jQueryRuntime(self.uri, self.auth, self.database)

    def close(self):
        try:
            self.query_runtime.close()
        finally:
            self.driver.close()

    def _new_driver(self):
        return GraphDatabase.driver(self.uri, auth=self.auth)

    def _refresh_auto_uri(self):
        if not self.auto_resolve_uri:
            return

        result = subprocess.run(
            ["docker", "port", self.container_name, "7687"],
            check=True,
            capture_output=True,
            text=True,
        )
        mappings = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if not mappings:
            raise RuntimeError(f"Neo4j container {self.container_name} has no published Bolt port")

        host, port = mappings[-1].rsplit(":", 1)
        if host in {"0.0.0.0", "::", "[::]"}:
            host = "localhost"
        self.uri = f"bolt://{host}:{port}"
        print(f"[Neo4j] 重新解析 Bolt URI: {self.uri}")

    def _wait_until_ready(self):
        deadline = time.time() + self.ready_timeout_s
        last_error = None
        next_report = 0

        while time.time() < deadline:
            try:
                response = self.query_runtime.request(
                    "RETURN 1 AS ok", min(5, max(0.1, deadline - time.time())),
                    capture_snapshot=False,
                )
                if response["status"] != "success":
                    raise RuntimeError(response.get("message", "readiness probe failed"))
                return
            except Exception as exc:
                last_error = exc
                remaining = int(deadline - time.time())
                now = time.time()
                if now >= next_report:
                    print(f"[Neo4j] Bolt 尚未就绪，剩余等待 {max(0, remaining)}s: {exc}")
                    next_report = now + 10
                time.sleep(2)

        raise RuntimeError(f"Neo4j did not become ready within {self.ready_timeout_s}s: {last_error}")

    def _probe_connection_after_error(self) -> Tuple[bool, str]:
        try:
            response = self.query_runtime.request("RETURN 1 AS ok", 5, capture_snapshot=False)
            if response["status"] != "success":
                raise RuntimeError(response.get("message", "health probe failed"))
            return True, "CONNECTION_ALIVE_AFTER_ERROR"
        except Exception as exc:
            return False, f"CONNECTION_LOST_AFTER_ERROR: {type(exc).__name__}: {exc}"

    def _run_with_timeout(self, session, query: str):
        if self.query_timeout_s and self.query_timeout_s > 0:
            return session.run(Query(query, timeout=self.query_timeout_s))
        return session.run(query)

    def _is_query_timeout_error(self, exc) -> bool:
        code = (getattr(exc, "code", "") or "").lower()
        message = (getattr(exc, "message", str(exc)) or "").lower()
        return "timeout" in code or "timedout" in code or "timed out" in message or "transaction has been terminated" in message

    def _is_resource_exhaustion_error(self, exc) -> bool:
        text = " ".join(
            str(part or "")
            for part in [
                type(exc).__name__,
                getattr(exc, "code", ""),
                getattr(exc, "message", ""),
                str(exc),
            ]
        ).lower()
        resource_tokens = (
            "java heap space",
            "outofmemoryerror",
            "out of memory",
            "gc overhead limit exceeded",
            "memorypooloutofmemory",
            "memory pool",
            "transaction memory",
            "memory limit",
            "heap space",
            "native memory",
            "allocation failed",
        )
        return any(token in text for token in resource_tokens)

    def _is_reportable_statement_execution_failed(self, exc) -> bool:
        code = str(getattr(exc, "code", "") or "")
        message = str(getattr(exc, "message", "") or "")
        text = f"{type(exc).__name__} {code} {message} {exc}"
        return "Neo.DatabaseError.Statement.ExecutionFailed" in text

    def _extract_neo4j_reference(self, text: str) -> str:
        match = re.search(r"\breference\s+([0-9a-fA-F-]{32,36})", text or "")
        return match.group(1) if match else ""

    def _summary_counters_text(self, summary) -> str:
        counters = getattr(summary, "counters", None)
        return str(counters) if counters is not None else ""

    def _summary_indicates_write(self, summary, query: str) -> bool:
        counters = getattr(summary, "counters", None)
        if counters is not None:
            counter_fields = (
                "nodes_created",
                "nodes_deleted",
                "relationships_created",
                "relationships_deleted",
                "properties_set",
                "labels_added",
                "labels_removed",
                "indexes_added",
                "indexes_removed",
                "constraints_added",
                "constraints_removed",
            )
            for field in counter_fields:
                try:
                    if int(getattr(counters, field, 0) or 0) > 0:
                        return True
                except Exception:
                    pass
        return self._looks_state_changing_query(query)

    def _snapshot_graph_state(self) -> Dict[str, Any]:
        return snapshot_graph_state(self.driver, self.database)

    def _neo4j_memory_config(self):
        try:
            with self.driver.session(database=self.database) as session:
                return [
                    {"name": record["name"], "value": record["value"]}
                    for record in session.run(
                        """
                        CALL dbms.listConfig()
                        YIELD name, value
                        WHERE toLower(name) CONTAINS 'memory'
                           OR toLower(name) CONTAINS 'heap'
                           OR toLower(name) CONTAINS 'pagecache'
                        RETURN name, value
                        ORDER BY name
                        """
                    )
                ]
        except Exception as exc:
            return {"config_error": f"{type(exc).__name__}: {exc}"}

    def _handle_resource_exhaustion(self, query: str, exc, graph_state_before, execution_output: str = "RESOURCE EXHAUSTION") -> str:
        err_type = getattr(exc, "code", None) or type(exc).__name__
        err_msg = f"{err_type}: {getattr(exc, 'message', str(exc))}"
        is_alive, connection_state = self._probe_connection_after_error()
        graph_state_after = self._snapshot_graph_state() if is_alive else {"snapshot_error": connection_state}
        db_config = self._neo4j_memory_config() if is_alive else {"config_error": connection_state}
        evidence = self._collect_crash_evidence({
            "connection_state": connection_state,
            "driver_error": err_msg,
            "resource_exhaustion": "true",
            "alive_after_error": str(is_alive),
        })
        outcome = ExecutionOutcome.CONFIRMED_CRASH if self._looks_confirmed_crash(evidence) else ExecutionOutcome.RESOURCE_EXHAUSTION
        artifact_path = self._write_resource_exhaustion_bundle(
            query=query,
            message=err_msg,
            evidence=evidence,
            graph_state_before=graph_state_before,
            graph_state_after=graph_state_after,
            db_config=db_config,
            outcome=outcome,
        )
        self.error_ledger[outcome.value] += 1
        self.bug_reports.append({
            "query": query,
            "artifact": artifact_path,
            "outcome": outcome.value,
            "resource_exhaustion": True,
        })
        if not is_alive:
            print("[Neo4j] 资源耗尽后 Bolt 不可用，正在尝试恢复...")
            try:
                self._reconnect_and_reseed()
                err_msg += " | RECOVERED"
            except Exception as recover_e:
                err_msg += f" | RECOVERY_FAILED: {recover_e}"
                print(f"[Neo4j] 恢复失败: {recover_e}")
        self._set_execution_result(
            outcome,
            query,
            f"{err_msg} | {connection_state}",
            output=execution_output,
            error_type=err_type,
            health=evidence,
            artifact_path=artifact_path,
        )
        return execution_output

    def _clear_database(self, session):
        total_deleted = 0
        for _ in range(self.delete_max_batches):
            record = session.run(
                "MATCH (n) WITH n LIMIT $batch_size DETACH DELETE n RETURN count(n) AS deleted",
                batch_size=self.delete_batch_size,
            ).single()
            deleted = int(record["deleted"]) if record else 0
            total_deleted += deleted
            if deleted == 0:
                return total_deleted
        raise RuntimeError(
            f"Neo4j clear exceeded {self.delete_max_batches} batches "
            f"(batch_size={self.delete_batch_size}, deleted>={total_deleted})"
        )

    def reset_to_seed(self):
        print("[Neo4j] 周期性清空并重灌种子图...")
        self.query_runtime.restart_boundary()
        self._wait_until_ready()
        with self.driver.session(database=self.database) as session:
            deleted = self._clear_database(session)
            self._run_driver_seed(session)
            self._verify_driver_seed(session, "Neo4j")
        self._clear_recorded_history("periodic_seed_reset")
        print(f"[Neo4j] 周期性初始化完成，删除节点数: {deleted}")

    def _reconnect_and_reseed(self):
        self.query_runtime.restart_boundary()
        try:
            self.driver.close()
        except Exception:
            pass

        target_container = getattr(self, "container_name", "neo4j_fuzz_target")
        last_error = None

        for attempt in range(1, self.recovery_retries + 1):
            try:
                if target_container:
                    print(f"[Neo4j] 重启容器 {target_container}，恢复尝试 {attempt}/{self.recovery_retries}...")
                    subprocess.run(
                        ["docker", "restart", target_container],
                        check=True, capture_output=True, timeout=self.ready_timeout_s,
                    )

                self._refresh_auto_uri()
                self.driver = self._new_driver()
                self.query_runtime.close()
                self.query_runtime = Neo4jQueryRuntime(self.uri, self.auth, self.database)
                print("[Neo4j] 等待 Bolt 服务恢复...")
                self._wait_until_ready()
                break
            except Exception as exc:
                last_error = exc
                print(f"[Neo4j] 第 {attempt} 次恢复失败: {exc}")
                try:
                    self.driver.close()
                except Exception:
                    pass
                time.sleep(5)
        else:
            raise RuntimeError(f"Neo4j recovery failed after {self.recovery_retries} attempts: {last_error}")

        if not self.seed_cypher and not self.seed_statements:
            return

        with self.driver.session(database=self.database) as session:
            self._clear_database(session)
            self._run_driver_seed(session)
            self._verify_driver_seed(session, "Neo4j")
        self._clear_recorded_history("crash_recovery_seed_reset")

    def execute_single(self, query: str) -> Tuple[bool, str, str]:
        self._begin_query(query)
        self.last_execution = None
        self.stats["total_executed"] += 1
        start_time = time.time()
        execution_output = ""
        graph_state_before = {}

        try:
            response = self.query_runtime.request(query, self.query_timeout_s)
            graph_state_before = response.get("graph_state_before", {})
            if response["status"] != "success":
                remote_error = {
                    "client": _Neo4jRemoteClientError,
                    "transient": _Neo4jRemoteTransientError,
                    "database": _Neo4jRemoteDatabaseError,
                    "connection": _Neo4jRemoteConnectionError,
                }.get(response.get("category"), _Neo4jRemoteError)
                raise remote_error(response)

            elapsed_ms = (time.time() - start_time) * 1000
            self.stats["total_time_ms"] += elapsed_ms
            self.stats["passed"] += 1
            execution_output = response["output"]
            self._record_query(
                query,
                summary=response.get("summary", ""),
                state_changing=bool(response.get("counter_write")) or self._looks_state_changing_query(query),
            )
            self._set_execution_result(
                ExecutionOutcome.SUCCESS,
                query,
                "ok",
                output=execution_output,
                elapsed_ms=elapsed_ms,
            )

        except Neo4jWorkerTimeout as e:
            self.stats["failed"] += 1
            self.error_ledger["QUERY_TIMEOUT"] += 1
            execution_output = "QUERY TIMEOUT"
            err_msg = str(e)
            evidence = {
                "timeout_seconds": str(self.query_timeout_s),
                "worker_pid": str(e.pid),
                "worker_terminated": "true",
                "server_execution_state": "unknown_until_container_restart",
            }
            self._finish_epoch_pending(ExecutionOutcome.TIMEOUT.value, query)
            try:
                artifact_path = self._write_timeout_artifact(query, err_msg, evidence)
            except Exception as artifact_exc:
                raise EvidencePersistenceError(
                    f"Neo4j hard timeout case publication failed: {artifact_exc}; target state is unsafe"
                ) from artifact_exc
            self._set_execution_result(
                ExecutionOutcome.TIMEOUT, query, err_msg,
                output=execution_output, error_type="Neo4jWorkerTimeout",
                health=evidence, artifact_path=artifact_path,
            )
            try:
                if (not self.managed_seed or not self.container_name or
                        not (self.seed_statements or self.seed_cypher)):
                    raise UnsafeTargetStateError(
                        "hard timeout requires a dedicated restartable Neo4j container "
                        "and a recorded managed seed from --init-mode reset; "
                        "target state cannot be verified"
                    )
                self._reconnect_and_reseed()
            except Exception as recover_e:
                self.last_execution.message += f" | RECOVERY_FAILED: {recover_e}"
                self._finish_execution(query, execution_output)
                raise UnsafeTargetStateError(
                    f"Neo4j hard timeout evidence saved at {artifact_path}; "
                    f"target state unsafe: {recover_e}"
                ) from recover_e
            self.last_execution.message += " | RECOVERED"

        except (CypherSyntaxError, CypherTypeError, ClientError, _Neo4jRemoteClientError) as e:
            self.stats["failed"] += 1
            err_type = getattr(e, "code", "") or getattr(e, "remote_type", type(e).__name__)
            if self._is_resource_exhaustion_error(e):
                execution_output = self._handle_resource_exhaustion(query, e, graph_state_before)
            elif self._is_query_timeout_error(e):
                self.error_ledger["QUERY_TIMEOUT"] += 1
                err_msg = f"{err_type}: {getattr(e, 'message', str(e))}"
                execution_output = "QUERY TIMEOUT"
                evidence = {
                    "connection_state": "SERVER_SIDE_TIMEOUT",
                    "driver_error": err_msg,
                    "timeout_seconds": str(self.query_timeout_s),
                }
                artifact_path = self._write_timeout_artifact(query, err_msg, evidence)
                self._save_runtime_error(query, f"TIMEOUT: {err_msg}")
                self._set_execution_result(
                    ExecutionOutcome.TIMEOUT,
                    query,
                    err_msg,
                    output=execution_output,
                    error_type=err_type,
                    health=evidence,
                    artifact_path=artifact_path,
                )
            else:
                self.error_ledger[err_type] += 1
                execution_output = "Semantic/Syntax Error"
                self._set_execution_result(
                    ExecutionOutcome.REJECTED,
                    query,
                    f"{err_type}: {getattr(e, 'message', str(e))}",
                    output=execution_output,
                    error_type=err_type,
                )

        except (TransientError, _Neo4jRemoteTransientError) as e:
            self.stats["failed"] += 1
            if self._is_resource_exhaustion_error(e):
                execution_output = self._handle_resource_exhaustion(query, e, graph_state_before)
            elif self._is_query_timeout_error(e):
                self.error_ledger["QUERY_TIMEOUT"] += 1
                err_msg = f"TransientError: {getattr(e, 'message', str(e))}"
                execution_output = "QUERY TIMEOUT"
                evidence = {
                    "connection_state": "TRANSIENT_TIMEOUT",
                    "driver_error": err_msg,
                    "timeout_seconds": str(self.query_timeout_s),
                }
                artifact_path = self._write_timeout_artifact(query, err_msg, evidence)
                self._set_execution_result(
                    ExecutionOutcome.TIMEOUT,
                    query,
                    err_msg,
                    output=execution_output,
                    error_type="TransientError",
                    health=evidence,
                    artifact_path=artifact_path,
                )
            else:
                self.error_ledger["Neo4jTransientError"] += 1
                err_msg = f"TransientError: {getattr(e, 'message', str(e))}"
                execution_output = "Transient Runtime Error"
                self._set_execution_result(
                    ExecutionOutcome.RUNTIME_ERROR,
                    query,
                    err_msg,
                    output=execution_output,
                    error_type="TransientError",
                )
            if self.last_execution and self.last_execution.outcome in {ExecutionOutcome.TIMEOUT, ExecutionOutcome.RUNTIME_ERROR}:
                self._save_runtime_error(query, self.last_execution.status_message())

        except (DatabaseError, _Neo4jRemoteDatabaseError) as e:
            self.stats["failed"] += 1
            err_type = getattr(e, "code", None) or getattr(e, "remote_type", type(e).__name__)
            is_alive, connection_state = self._probe_connection_after_error()
            err_msg = f"{err_type}: {getattr(e, 'message', str(e))}"
            if self._is_resource_exhaustion_error(e):
                execution_output = self._handle_resource_exhaustion(query, e, graph_state_before)
            elif self._is_query_timeout_error(e):
                self.error_ledger["QUERY_TIMEOUT"] += 1
                execution_output = "QUERY TIMEOUT"
                evidence = {
                    "connection_state": connection_state,
                    "driver_error": err_msg,
                    "timeout_seconds": str(self.query_timeout_s),
                }
                artifact_path = self._write_timeout_artifact(query, err_msg, evidence)
                self._save_runtime_error(query, f"TIMEOUT: {err_msg} | {connection_state}")
                self._set_execution_result(
                    ExecutionOutcome.TIMEOUT,
                    query,
                    f"{err_msg} | {connection_state}",
                    output=execution_output,
                    error_type=err_type,
                    health=evidence,
                    artifact_path=artifact_path,
                )
            elif not is_alive:
                evidence = self._collect_crash_evidence({"connection_state": connection_state, "driver_error": err_msg})
                outcome = ExecutionOutcome.CONFIRMED_CRASH if self._looks_confirmed_crash(evidence) else ExecutionOutcome.CRASH_LIKE
                artifact_path = self._write_crash_artifact(outcome, query, err_msg, evidence)
                self.error_ledger[outcome.value] += 1
                self.bug_reports.append({"query": query, "artifact": artifact_path, "outcome": outcome.value})
                execution_output = "DATABASE CRASH DETECTED"
                print("[Neo4j] DatabaseError 后 Bolt 不可用，正在尝试恢复...")
                try:
                    self._reconnect_and_reseed()
                    err_msg += " | RECOVERED"
                except Exception as recover_e:
                    err_msg += f" | RECOVERY_FAILED: {recover_e}"
                    print(f"[Neo4j] 恢复失败: {recover_e}")
                self._set_execution_result(
                    outcome,
                    query,
                    err_msg,
                    output=execution_output,
                    error_type=err_type,
                    health=evidence,
                    artifact_path=artifact_path,
                )
            else:
                if self._is_reportable_statement_execution_failed(e):
                    evidence = self._collect_crash_evidence({
                        "connection_state": connection_state,
                        "driver_error": err_msg,
                        "neo4j_error_code": err_type,
                        "neo4j_error_reference": self._extract_neo4j_reference(err_msg),
                        "reportable_reason": "Neo4j returned Neo.DatabaseError.Statement.ExecutionFailed while Bolt remained available",
                    })
                    if not evidence.get("neo4j_error_reference"):
                        evidence["neo4j_error_reference"] = self._extract_neo4j_reference(evidence.get("docker_logs_tail", ""))
                    artifact_path = self._write_reportable_runtime_bug_artifact(query, err_msg, evidence)
                    self.runtime_bug_reports.append({
                        "query": query,
                        "artifact": artifact_path,
                        "outcome": ExecutionOutcome.REPORTABLE_RUNTIME_BUG.value,
                        "error_type": err_type,
                    })
                    self.error_ledger[ExecutionOutcome.REPORTABLE_RUNTIME_BUG.value] += 1
                    self.error_ledger[err_type] += 1
                    execution_output = "Reportable Runtime Bug"
                    self._save_runtime_error(query, f"REPORTABLE_RUNTIME_BUG: {err_msg} | {connection_state} | ARTIFACT: {artifact_path}")
                    self._set_execution_result(
                        ExecutionOutcome.REPORTABLE_RUNTIME_BUG,
                        query,
                        f"{err_msg} | {connection_state}",
                        output=execution_output,
                        error_type=err_type,
                        health=evidence,
                        artifact_path=artifact_path,
                    )
                else:
                    if self._use_legacy_crash_policy():
                        legacy_evidence = self._collect_crash_evidence({"connection_state": connection_state, "driver_error": err_msg})
                        legacy_path = self._write_crash_artifact(
                            ExecutionOutcome.CRASH_LIKE,
                            query,
                            err_msg,
                            legacy_evidence,
                            legacy_unconfirmed=True,
                        )
                        err_msg += f" | LEGACY_UNCONFIRMED_ARTIFACT: {legacy_path}"
                        self.error_ledger["LEGACY_DB_ERROR_SERVER_ALIVE"] += 1
                    self.error_ledger[err_type] += 1
                    execution_output = "Database Runtime Error"
                    self._save_runtime_error(query, f"RUNTIME_ERROR: {err_msg} | {connection_state}")
                    self._set_execution_result(
                        ExecutionOutcome.RUNTIME_ERROR,
                        query,
                        f"{err_msg} | {connection_state}",
                        output=execution_output,
                        error_type=err_type,
                        health={"connection_state": connection_state},
                    )

        except (ServiceUnavailable, SessionExpired, OSError, _Neo4jRemoteConnectionError, Neo4jWorkerExited) as e:
            self.stats["failed"] += 1
            err_msg = f"{type(e).__name__}: {str(e)}"
            evidence = self._collect_crash_evidence({"connection_state": "CONNECTION_EXCEPTION", "driver_error": err_msg})
            outcome = ExecutionOutcome.CONFIRMED_CRASH if self._looks_confirmed_crash(evidence) else ExecutionOutcome.CRASH_LIKE
            self.error_ledger[outcome.value] += 1
            execution_output = "DATABASE CRASH DETECTED"
            artifact_path = self._write_crash_artifact(outcome, query, err_msg, evidence)
            self.bug_reports.append({"query": query, "artifact": artifact_path, "outcome": outcome.value})

            print("[Neo4j] 连接断开或服务异常，正在尝试重启与重灌种子图...")
            try:
                self._reconnect_and_reseed()
                err_msg += " | RECOVERED"
            except Exception as recover_e:
                err_msg += f" | RECOVERY_FAILED: {recover_e}"
                print(f"[Neo4j] 恢复失败: {recover_e}")
            self._set_execution_result(
                outcome,
                query,
                err_msg,
                output=execution_output,
                error_type=type(e).__name__,
                health=evidence,
                artifact_path=artifact_path,
            )

        except Exception as e:
            self.stats["failed"] += 1
            execution_output = "Unknown Error"
            err_msg = f"Exception: {str(e)}"
            self._save_runtime_error(query, f"RUNTIME_ERROR: {err_msg}")
            self._set_execution_result(
                ExecutionOutcome.RUNTIME_ERROR,
                query,
                err_msg,
                output=execution_output,
                error_type=type(e).__name__,
            )

        return self._finish_execution(query, execution_output)



def _falkordb_worker(host: str, port: int, password: str, graph_name: str, query: str, return_dict: dict):
    try:
        from falkordb import FalkorDB

        db = FalkorDB(host=host, port=port, password=password)
        graph = db.select_graph(graph_name)
        res = graph.query(query.strip().rstrip(";"))
        returned_rows = len(res.result_set) if hasattr(res, "result_set") and res.result_set else 0
        stats_str = str(res.statistics) if hasattr(res, "statistics") and res.statistics else "{}"
        return_dict["status"] = "SUCCESS"
        return_dict["output"] = f"Rows: {returned_rows}, Stats: {stats_str}"
        db.connection.close()
    except Exception as exc:
        return_dict["status"] = "ERROR"
        return_dict["error_msg"] = str(exc)
        return_dict["error_type"] = type(exc).__name__


class FalkorDBFuzzExecutor(BaseFuzzExecutor):
    def __init__(
        self,
        host="localhost",
        port=6379,
        password="",
        graph_name="graf_fuzz",
        log_file="fuzzer_falkordb.log",
        seed_cypher="",
        query_timeout_s: int = 120,
        container_name: str = "falkordb_fuzz_target",
        crash_policy: str = "strict",
    ):
        super().__init__("FalkorDB", log_file, seed_cypher, crash_policy=crash_policy)
        self.host = host
        self.port = port
        self.password = password
        self.graph_name = graph_name
        self.query_timeout_s = query_timeout_s
        
        self.db = FalkorDB(host=self.host, port=self.port, password=self.password)
        self.graph = self.db.select_graph(self.graph_name)
        
        self.container_name = container_name
        self.initializer = None

    def set_seed_spec(self, seed_spec, seed_cypher: str, seed_statements=None):
        super().set_seed_spec(seed_spec, seed_cypher, seed_statements)
        initializer = getattr(self, "initializer", None)
        if initializer is not None and seed_spec is not None:
            initializer.set_seed_spec(seed_spec)

    def close(self):
        try:
            self.db.connection.close()
        finally:
            initializer = getattr(self, "initializer", None)
            if initializer is not None:
                try:
                    initializer.close()
                except Exception:
                    pass

    def _probe_server_health(self) -> Tuple[bool, str]:
        try:
            db = FalkorDB(host=self.host, port=self.port, password=self.password)
            db.connection.ping()
            db.connection.close()
            return True, "SERVER_ALIVE"
        except Exception as exc:
            return False, f"SERVER_UNAVAILABLE: {type(exc).__name__}: {exc}"

    def _container_state_summary(self) -> str:
        target_container = getattr(self, 'container_name', 'falkordb_fuzz_target')
        try:
            result = subprocess.run(
                [
                    "docker",
                    "inspect",
                    target_container,
                    "--format",
                    "Status={{.State.Status}} ExitCode={{.State.ExitCode}} OOMKilled={{.State.OOMKilled}} Error={{.State.Error}} FinishedAt={{.State.FinishedAt}}",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            return result.stdout.strip()
        except Exception as exc:
            return f"docker inspect failed: {exc}"

    def _is_connection_error_type(self, err_type: str) -> bool:
        return err_type in {
            "ConnectionError",
            "TimeoutError",
            "BusyLoadingError",
            "AuthenticationError",
        }

    def _recover_container_and_seed(self):
        target_container = getattr(self, 'container_name', 'falkordb_fuzz_target')
        print(f"\n[FalkorDB] 正在重启容器: {target_container} ...")

        try:
            subprocess.run(["docker", "restart", target_container], check=True, capture_output=True)
        except subprocess.CalledProcessError as sub_e:
            print(f"容器重启失败: {sub_e.stderr.decode().strip()}。熔断退出！")
            sys.exit(1)

        print("[FalkorDB] 容器已拉起，等待数据库服务就绪...")
        db_ready = False
        for attempt in range(20):
            time.sleep(2)
            try:
                self.db = FalkorDB(host=self.host, port=self.port, password=self.password)
                self.db.connection.ping()
                self.graph = self.db.select_graph(self.graph_name)
                db_ready = True
                break
            except Exception:
                continue

        if not db_ready:
            print("数据库无法恢复连通性，熔断退出！")
            sys.exit(1)

        print("[FalkorDB] 数据库已恢复，正在重新注入种子图谱...")
        try:
            if self.managed_seed and hasattr(self, 'initializer') and self.initializer:
                self.initializer.reset_and_initialize()
                self._clear_recorded_history("container_recovery_seed_reset")
            else:
                print("[FalkorDB] 外部 reuse 图不由 GRAF 重建，已仅恢复连接。")
        except Exception as init_e:
            print(f"种子图重置失败: {init_e}。熔断退出！")
            sys.exit(1)

        print("[FalkorDB] 环境重置完毕，Fuzzer 继续运行。\n")

    def reset_to_seed(self):
        print("[FalkorDB] 周期性清空并重灌种子图...")
        if self.managed_seed and hasattr(self, 'initializer') and self.initializer:
            self.initializer.reset_and_initialize()
            self.db = FalkorDB(host=self.host, port=self.port, password=self.password)
            self.graph = self.db.select_graph(self.graph_name)
            self._clear_recorded_history("periodic_seed_reset")
            print("[FalkorDB] 周期性初始化完成。")
            return
        raise RuntimeError("FalkorDB periodic reset requires a GRAF-managed seed graph")

    def execute_single(self, query: str) -> Tuple[bool, str, str]:
        self._begin_query(query)
        self.last_execution = None
        self.stats["total_executed"] += 1
        start_time = time.time()
        execution_output = ""
        clean_query = query.strip().rstrip(';')
        manager = None
        
        try:
            manager = multiprocessing.Manager()
            return_dict = manager.dict()
            worker = multiprocessing.Process(
                target=_falkordb_worker,
                args=(self.host, self.port, self.password, self.graph_name, clean_query, return_dict),
            )
            worker.start()
            # ``multiprocessing.Process.join(0)`` is a non-blocking poll, not
            # "wait forever".  Treat non-positive values as an explicit
            # unlimited timeout so ``--falkordb-query-timeout 0`` cannot kill
            # every query immediately.
            worker.join(timeout=None if self.query_timeout_s <= 0 else self.query_timeout_s)

            if worker.is_alive():
                worker.terminate()
                worker.join(timeout=5)
                if worker.is_alive():
                    worker.kill()
                    worker.join()

                self.stats["failed"] += 1
                server_alive, health_msg = self._probe_server_health()
                evidence = {"server_health": health_msg, "timeout_seconds": str(self.query_timeout_s)}
                if server_alive:
                    self.error_ledger["QUERY_TIMEOUT"] += 1
                    err_msg = f"query exceeded {self.query_timeout_s}s | {health_msg}"
                    execution_output = "QUERY TIMEOUT"
                    artifact_path = self._write_timeout_artifact(query, err_msg, evidence)
                    self._set_execution_result(
                        ExecutionOutcome.TIMEOUT,
                        query,
                        err_msg,
                        output=execution_output,
                        error_type="QueryTimeout",
                        health=evidence,
                        artifact_path=artifact_path,
                    )
                else:
                    evidence = self._collect_crash_evidence(evidence)
                    outcome = ExecutionOutcome.CONFIRMED_CRASH if self._looks_confirmed_crash(evidence) else ExecutionOutcome.CRASH_LIKE
                    self.error_ledger[outcome.value] += 1
                    err_msg = f"query exceeded {self.query_timeout_s}s | {health_msg}"
                    execution_output = "DATABASE CRASH DETECTED"
                    artifact_path = self._write_crash_artifact(outcome, query, err_msg, evidence)
                    self.bug_reports.append({"query": query, "artifact": artifact_path, "outcome": outcome.value})
                    self._set_execution_result(
                        outcome,
                        query,
                        err_msg,
                        output=execution_output,
                        error_type="QueryTimeoutServerUnavailable",
                        health=evidence,
                        artifact_path=artifact_path,
                    )
                self._recover_container_and_seed()
                return self._finish_execution(query, execution_output)

            elapsed_ms = (time.time() - start_time) * 1000
            status = return_dict.get("status", "UNKNOWN")
            if status != "SUCCESS":
                err_msg = return_dict.get("error_msg", "Unknown FalkorDB error")
                err_type = return_dict.get("error_type", "Exception")
                server_alive, health_msg = self._probe_server_health()
                if not server_alive:
                    self.stats["failed"] += 1
                    evidence = self._collect_crash_evidence({"server_health": health_msg, "worker_error": f"{err_type}: {err_msg}"})
                    outcome = ExecutionOutcome.CONFIRMED_CRASH if self._looks_confirmed_crash(evidence) else ExecutionOutcome.CRASH_LIKE
                    self.error_ledger[outcome.value] += 1
                    full_msg = f"{err_type}: {err_msg} | {health_msg}"
                    execution_output = "DATABASE CRASH DETECTED"
                    artifact_path = self._write_crash_artifact(outcome, query, full_msg, evidence)
                    self.bug_reports.append({"query": query, "artifact": artifact_path, "outcome": outcome.value})
                    self._recover_container_and_seed()
                    self._set_execution_result(
                        outcome,
                        query,
                        full_msg,
                        output=execution_output,
                        error_type=err_type,
                        health=evidence,
                        artifact_path=artifact_path,
                    )
                    return self._finish_execution(query, execution_output)
                if self._is_connection_error_type(err_type):
                    self.stats["failed"] += 1
                    self.error_ledger["FALKORDB_CONNECTION_ERROR_SERVER_ALIVE"] += 1
                    full_msg = f"{err_type}: {err_msg} | {health_msg}"
                    execution_output = "Connection Error, Server Alive"
                    self._save_runtime_error(query, f"RUNTIME_ERROR: {full_msg}")
                    self._set_execution_result(
                        ExecutionOutcome.RUNTIME_ERROR,
                        query,
                        full_msg,
                        output=execution_output,
                        error_type=err_type,
                        health={"server_health": health_msg},
                    )
                    return self._finish_execution(query, execution_output)

                self.stats["failed"] += 1
                self.error_ledger[err_type] += 1
                full_msg = f"{err_type}: {err_msg} | {health_msg}"
                execution_output = "FalkorDB Runtime Error"
                self._save_runtime_error(query, f"RUNTIME_ERROR: {full_msg}")
                self._set_execution_result(
                    ExecutionOutcome.RUNTIME_ERROR,
                    query,
                    full_msg,
                    output=execution_output,
                    error_type=err_type,
                    health={"server_health": health_msg},
                )
                return self._finish_execution(query, execution_output)

            self.stats["passed"] += 1
            self.stats["total_time_ms"] += elapsed_ms
            execution_output = return_dict.get("output", "")
            self._record_query(query)
            self._set_execution_result(
                ExecutionOutcome.SUCCESS,
                query,
                "ok",
                output=execution_output,
                elapsed_ms=elapsed_ms,
            )
            
        except (RedisConnectionError, RedisTimeoutError) as e:
            self.stats["failed"] += 1
            server_alive, health_msg = self._probe_server_health()
            err_msg = f"{type(e).__name__}: {str(e)} | {health_msg}"
            if server_alive:
                outcome = ExecutionOutcome.TIMEOUT if isinstance(e, RedisTimeoutError) else ExecutionOutcome.RUNTIME_ERROR
                ledger_key = "QUERY_TIMEOUT" if outcome == ExecutionOutcome.TIMEOUT else "FALKORDB_CONNECTION_ERROR_SERVER_ALIVE"
                self.error_ledger[ledger_key] += 1
                execution_output = "QUERY TIMEOUT" if outcome == ExecutionOutcome.TIMEOUT else "Connection Error, Server Alive"
                evidence = {"server_health": health_msg, "driver_error": err_msg}
                artifact_path = self._write_timeout_artifact(query, err_msg, evidence) if outcome == ExecutionOutcome.TIMEOUT else ""
                self._save_runtime_error(query, f"{outcome.value}: {err_msg}")
                self._set_execution_result(
                    outcome,
                    query,
                    err_msg,
                    output=execution_output,
                    error_type=type(e).__name__,
                    health=evidence,
                    artifact_path=artifact_path,
                )
            else:
                evidence = self._collect_crash_evidence({"server_health": health_msg, "driver_error": err_msg})
                outcome = ExecutionOutcome.CONFIRMED_CRASH if self._looks_confirmed_crash(evidence) else ExecutionOutcome.CRASH_LIKE
                self.error_ledger[outcome.value] += 1
                execution_output = "DATABASE CRASH DETECTED"
                artifact_path = self._write_crash_artifact(outcome, query, err_msg, evidence)
                self.bug_reports.append({"query": query, "artifact": artifact_path, "outcome": outcome.value})
                self._recover_container_and_seed()
                self._set_execution_result(
                    outcome,
                    query,
                    err_msg,
                    output=execution_output,
                    error_type=type(e).__name__,
                    health=evidence,
                    artifact_path=artifact_path,
                )
            
        except Exception as e:
            self.stats["failed"] += 1
            execution_output = "Error"
            err_msg = f"Exception: {str(e)}"
            self._save_runtime_error(query, f"RUNTIME_ERROR: {err_msg}")
            self._set_execution_result(
                ExecutionOutcome.RUNTIME_ERROR,
                query,
                err_msg,
                output=execution_output,
                error_type=type(e).__name__,
            )

        finally:
            if manager is not None:
                try:
                    manager.shutdown()
                except Exception:
                    pass

        return self._finish_execution(query, execution_output)



class KuzuFuzzExecutor(BaseFuzzExecutor):
    def __init__(
        self,
        db_path="./kuzu_fuzz_test",
        log_file="fuzzer_kuzu.log",
        seed_cypher="",
        query_timeout_s: int = 120,
        crash_policy: str = "strict",
        runtime: Optional[KuzuWorkerSupervisor] = None,
        compile_cache_capacity: int = 10_000,
    ):
        super().__init__("KuzuDB", log_file, seed_cypher, crash_policy=crash_policy)
        self.db_path = db_path
        self.query_timeout_s = max(0, int(query_timeout_s))
        self.control_timeout_s = self.query_timeout_s if self.query_timeout_s > 0 else 120
        self.runtime = runtime or KuzuWorkerSupervisor(db_path)
        self._compile_window = self._new_compile_window()
        self.compile_cache_capacity = max(0, int(compile_cache_capacity))
        self._compile_cache: OrderedDict[str, Tuple[bool, str]] = OrderedDict()
        self._compile_cache_hits = 0
        self._compile_cache_misses = 0
        self._compile_schema_fingerprint = ""

    @staticmethod
    def _new_compile_window() -> Dict[str, Any]:
        return {
            "requests": 0,
            "accepted": 0,
            "rejected": 0,
            "timeouts": 0,
            "worker_failures": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "roundtrip_ms": 0.0,
            "last_error": "",
        }

    def _take_compile_window(self) -> Dict[str, Any]:
        snapshot = dict(self._compile_window)
        snapshot["roundtrip_ms"] = round(float(snapshot["roundtrip_ms"]), 3)
        self._compile_window = self._new_compile_window()
        return snapshot

    def close(self):
        self.runtime.close()

    def runtime_telemetry(self) -> Dict[str, Any]:
        return {
            **self.runtime.snapshot(),
            "compile_cache": {
                "capacity": self.compile_cache_capacity,
                "entries": len(self._compile_cache),
                "hits": self._compile_cache_hits,
                "misses": self._compile_cache_misses,
                "schema_fingerprint": self._compile_schema_fingerprint,
            },
            "pending_compile_window": {
                **self._compile_window,
                "roundtrip_ms": round(float(self._compile_window["roundtrip_ms"]), 3),
            },
        }

    def compile_query(self, query: str, timeout_seconds: int = 15) -> Tuple[bool, str]:
        """Compile through the same ordered worker used for execution.

        This preserves the hard timeout boundary without opening the embedded
        database once per parent/candidate.  Metrics are accumulated until the
        next target execution so journal records can attribute gate overhead.
        """

        started = time.monotonic()
        response_recorded = False
        self._compile_window["requests"] += 1
        prepared_query = prepare_target_query("kuzu", query)
        cache_key = hashlib.sha256(prepared_query.encode("utf-8")).hexdigest()
        try:
            cached = self._compile_cache.get(cache_key)
            if cached is not None:
                self._compile_cache.move_to_end(cache_key)
                self._compile_cache_hits += 1
                self._compile_window["cache_hits"] += 1
                accepted, message = cached
                if accepted:
                    self._compile_window["accepted"] += 1
                else:
                    self._compile_window["rejected"] += 1
                    self._compile_window["last_error"] = message
                response_recorded = True
                return accepted, message

            self._compile_cache_misses += 1
            self._compile_window["cache_misses"] += 1
            response = self.runtime.request(
                "compile",
                query=prepared_query,
                timeout_seconds=max(0, int(timeout_seconds)),
            )
            self._compile_window["roundtrip_ms"] += response.roundtrip_ms
            response_recorded = True
            if response.success:
                self._compile_window["accepted"] += 1
                result = (True, "EXPLAIN accepted")
                self._remember_compile_result(cache_key, result)
                return result
            self._compile_window["rejected"] += 1
            self._compile_window["last_error"] = (
                f"{response.error_type}: {response.error_message}"
            )
            result = (False, self._compile_window["last_error"])
            return result
        except KuzuWorkerTimeout as exc:
            self._compile_window["timeouts"] += 1
            self._compile_window["last_error"] = str(exc)
            return False, (
                f"target compile check exceeded {exc.timeout_seconds:g}s; "
                f"worker generation {exc.worker_generation} was terminated"
            )
        except (KuzuWorkerCrashed, KuzuWorkerStartError, KuzuRuntimeError) as exc:
            self._compile_window["worker_failures"] += 1
            self._compile_window["last_error"] = f"{type(exc).__name__}: {exc}"
            return False, f"Kuzu compile worker failure: {type(exc).__name__}: {exc}"
        finally:
            elapsed_ms = (time.monotonic() - started) * 1000.0
            # Include supervisor startup/failure time that has no response.
            if not response_recorded:
                self._compile_window["roundtrip_ms"] += elapsed_ms

    def _remember_compile_result(self, key: str, result: Tuple[bool, str]) -> None:
        if self.compile_cache_capacity <= 0:
            return
        self._compile_cache[key] = (bool(result[0]), str(result[1]))
        self._compile_cache.move_to_end(key)
        while len(self._compile_cache) > self.compile_cache_capacity:
            self._compile_cache.popitem(last=False)

    def _invalidate_compile_cache(self) -> None:
        self._compile_cache.clear()

    def on_context_refreshed(self, schema_snapshot: Dict[str, Any]) -> None:
        """Invalidate cached EXPLAIN outcomes when the compilable schema changes."""

        compilable_schema = {
            "labels": schema_snapshot.get("labels", []),
            "edges": schema_snapshot.get("edges", []),
            "properties": schema_snapshot.get("properties", {}),
        }
        encoded = json.dumps(
            compilable_schema,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        fingerprint = hashlib.sha256(encoded).hexdigest()
        if self._compile_schema_fingerprint and fingerprint != self._compile_schema_fingerprint:
            self._invalidate_compile_cache()
        self._compile_schema_fingerprint = fingerprint

    def query_rows(self, query: str, timeout_seconds: Optional[int] = None) -> List[List[Any]]:
        timeout = self.control_timeout_s if timeout_seconds is None else max(0, int(timeout_seconds))
        response = self.runtime.request(
            "query_rows",
            query=prepare_target_query("kuzu", query),
            timeout_seconds=timeout,
        )
        if not response.success:
            raise RuntimeError(f"{response.error_type}: {response.error_message}")
        return [list(row) for row in response.rows]

    def _generate_poc_file(self, crashing_query: str, error_msg: str):
        evidence = {"worker_exit": error_msg}
        return self._write_crash_artifact(
            ExecutionOutcome.CRASH_LIKE,
            crashing_query,
            error_msg,
            evidence,
        )

    def reset_to_seed(self):
        from GraphInitializer import KuzuSeedGenerator

        if not self.managed_seed or self.seed_spec is None:
            raise RuntimeError("Kuzu reset is disabled for init-mode=reuse")
        # Kuzu is embedded. The sole owner must release all file handles before
        # the database directory is atomically replaced by the initializer.
        self.runtime.restart_boundary("seed_reset")
        self._invalidate_compile_cache()
        self._compile_schema_fingerprint = ""
        generator = KuzuSeedGenerator(self.db_path, seed_spec=self.seed_spec)
        generator.reset_and_initialize(reset=True)
        self.set_seed_spec(generator.seed_spec, generator.seed_cypher, generator.seed_statements)
        self._clear_recorded_history("seed_reset")

    def execute_single(self, query: str) -> Tuple[bool, str, str]:
        self._begin_query(query, wire_query=prepare_target_query("kuzu", query))
        self.last_execution = None
        self.stats["total_executed"] += 1
        start_time = time.time()
        compile_window = self._take_compile_window()
        execution_output = ""
        try:
            response: KuzuRuntimeResponse = self.runtime.request(
                "execute",
                query=prepare_target_query("kuzu", query),
                timeout_seconds=self.query_timeout_s,
            )
            elapsed_ms = (time.time() - start_time) * 1000
            runtime_health = {
                "runtime": response.telemetry(),
                "compile_gate_since_previous_execution": compile_window,
            }
            if response.success:
                self.stats["passed"] += 1
                self.stats["total_time_ms"] += elapsed_ms
                execution_output = response.output
                self._record_query(query)
                if re.search(
                    r"\b(?:CREATE\s+(?:NODE|REL)\s+TABLE|DROP\s+TABLE|ALTER\s+TABLE)\b",
                    query,
                    re.IGNORECASE,
                ):
                    self._invalidate_compile_cache()
                self._set_execution_result(
                    ExecutionOutcome.SUCCESS,
                    query,
                    "ok",
                    output=execution_output,
                    elapsed_ms=elapsed_ms,
                    health=runtime_health,
                )
            else:
                self.stats["failed"] += 1
                error_type = response.error_type or "RuntimeError"
                message = response.error_message or "Kuzu worker returned no status"
                self.error_ledger[error_type] += 1
                execution_output = "Semantic/Syntax Error"
                self._save_runtime_error(query, f"RUNTIME_ERROR: {message}")
                self._set_execution_result(
                    ExecutionOutcome.RUNTIME_ERROR,
                    query,
                    message,
                    output=execution_output,
                    elapsed_ms=elapsed_ms,
                    error_type=error_type,
                    health=runtime_health,
                )
        except KuzuWorkerTimeout as exc:
            self.stats["failed"] += 1
            self.error_ledger["QUERY_TIMEOUT"] += 1
            elapsed_ms = (time.time() - start_time) * 1000
            message = f"query exceeded {exc.timeout_seconds:g}s"
            evidence = {
                "timeout_seconds": str(exc.timeout_seconds),
                "worker_terminated": "true",
                "worker_pid": str(exc.worker_pid or ""),
                "worker_generation": str(exc.worker_generation),
                "worker_exitcode": str(exc.worker_exitcode),
                "compile_gate_since_previous_execution": compile_window,
                "recovery_planned": (
                    "managed_seed_reset_after_evidence_commit"
                    if self.managed_seed
                    else "none_external_reuse_graph"
                ),
            }
            artifact_path = self._write_timeout_artifact(query, message, evidence)
            execution_output = "QUERY TIMEOUT"
            if self.managed_seed:
                try:
                    # Evidence is durable before the possibly destructive reset.
                    self.reset_to_seed()
                    evidence["recovery"] = "seed_reset_after_evidence_commit"
                except Exception as recovery_exc:
                    evidence["recovery_error"] = (
                        f"{type(recovery_exc).__name__}: {recovery_exc}"
                    )
            else:
                evidence["recovery"] = "skipped_external_reuse_graph"
            evidence["runtime_after_recovery"] = self.runtime.snapshot()
            self._set_execution_result(
                ExecutionOutcome.TIMEOUT,
                query,
                message,
                output=execution_output,
                elapsed_ms=elapsed_ms,
                error_type="QueryTimeout",
                health=evidence,
                artifact_path=artifact_path,
            )
        except KuzuWorkerCrashed as exc:
            self.stats["failed"] += 1
            outcome = (
                ExecutionOutcome.CONFIRMED_CRASH
                if exc.worker_exitcode is not None and exc.worker_exitcode < 0
                else ExecutionOutcome.CRASH_LIKE
            )
            self.error_ledger[outcome.value] += 1
            message = str(exc)
            execution_output = "DATABASE CRASH DETECTED"
            evidence = {
                "worker_exitcode": str(exc.worker_exitcode),
                "worker_pid": str(exc.worker_pid or ""),
                "worker_generation": str(exc.worker_generation),
                "isolated_worker": "true",
                "compile_gate_since_previous_execution": compile_window,
                "recovery_planned": (
                    "managed_seed_reset_after_evidence_commit"
                    if self.managed_seed
                    else "none_external_reuse_graph"
                ),
            }
            artifact_path = self._write_crash_artifact(outcome, query, message, evidence)
            if self.managed_seed:
                try:
                    self.reset_to_seed()
                    evidence["recovery"] = "seed_reset_after_evidence_commit"
                except Exception as recovery_exc:
                    evidence["recovery_error"] = (
                        f"{type(recovery_exc).__name__}: {recovery_exc}"
                    )
            else:
                evidence["recovery"] = "skipped_external_reuse_graph"
            evidence["runtime_after_recovery"] = self.runtime.snapshot()
            self._set_execution_result(
                outcome,
                query,
                message,
                output=execution_output,
                elapsed_ms=(time.time() - start_time) * 1000,
                error_type="WorkerAbnormalExit",
                health=evidence,
                artifact_path=artifact_path,
            )
        except (KuzuWorkerStartError, KuzuRuntimeError) as exc:
            self.stats["failed"] += 1
            self.error_ledger[type(exc).__name__] += 1
            execution_output = "Executor infrastructure error"
            self._set_execution_result(
                ExecutionOutcome.RUNTIME_ERROR,
                query,
                f"{type(exc).__name__}: {exc}",
                output=execution_output,
                elapsed_ms=(time.time() - start_time) * 1000,
                error_type=type(exc).__name__,
                health={
                    "compile_gate_since_previous_execution": compile_window,
                    "runtime": self.runtime.snapshot(),
                },
            )
        except Exception as exc:
            self.stats["failed"] += 1
            self.error_ledger["ExecutorInfrastructureError"] += 1
            execution_output = "Executor infrastructure error"
            self._set_execution_result(
                ExecutionOutcome.RUNTIME_ERROR,
                query,
                f"{type(exc).__name__}: {exc}",
                output=execution_output,
                elapsed_ms=(time.time() - start_time) * 1000,
                error_type=type(exc).__name__,
                health={
                    "compile_gate_since_previous_execution": compile_window,
                    "runtime": self.runtime.snapshot(),
                },
            )

        return self._finish_execution(query, execution_output)


class NebulaFuzzExecutor(BaseFuzzExecutor):
    def __init__(
        self,
        host="127.0.0.1",
        port=9669,
        user="root",
        password="nebula",
        space="graf_fuzz",
        log_file="fuzzer_nebula.log",
        seed_cypher="",
        container_name: str = "nebula-docker-compose-graphd-1",
        recovery_retries: int = 5,
        recovery_delay_s: float = 2.0,
        query_timeout_s: int = 120,
        crash_policy: str = "strict",
    ):
        super().__init__("NebulaGraph", log_file, seed_cypher, crash_policy=crash_policy)
        if Config is None or ConnectionPool is None:
            raise RuntimeError(
                "NebulaGraph support requires nebula3-python; install requirements.txt"
            ) from _NEBULA_IMPORT_ERROR
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", space or ""):
            raise ValueError(f"Unsafe NebulaGraph space identifier: {space!r}")
        self.host = host
        self.port = int(port)
        self.user = user
        self.password = password
        self.space = space
        self.container_name = container_name
        self.recovery_retries = max(1, int(recovery_retries))
        self.recovery_delay_s = max(0.0, float(recovery_delay_s))
        self.query_timeout_s = max(0, int(query_timeout_s))
        self.config = Config()
        self.config.max_connection_pool_size = 5
        self.config.timeout = self.query_timeout_s * 1000
        self.pool = None
        self.session = None
        self._reconnect(clear_history=False)

    @staticmethod
    def _response_error(response) -> str:
        code = response.error_code() if hasattr(response, "error_code") else "UNKNOWN"
        message = response.error_msg() if hasattr(response, "error_msg") else str(response)
        return f"[{code}] {message}"

    def _close_connection(self):
        session, pool = self.session, self.pool
        self.session = None
        self.pool = None
        if session is not None:
            try:
                session.release()
            except Exception:
                pass
        if pool is not None:
            try:
                pool.close()
            except Exception:
                pass

    def close(self):
        self._close_connection()

    def _reconnect(self, clear_history: bool = True):
        self._close_connection()
        last_error = None
        for attempt in range(1, self.recovery_retries + 1):
            candidate_pool = None
            candidate_session = None
            try:
                candidate_pool = ConnectionPool()
                initialized = candidate_pool.init([(self.host, self.port)], self.config)
                if not initialized:
                    raise RuntimeError("connection pool initialization returned false")
                candidate_session = candidate_pool.get_session(self.user, self.password)
                response = candidate_session.execute(f"USE `{self.space}`;")
                if hasattr(response, "is_succeeded") and not response.is_succeeded():
                    raise RuntimeError(f"USE space failed: {self._response_error(response)}")
                self.pool = candidate_pool
                self.session = candidate_session
                if clear_history:
                    self._clear_recorded_history("seed_reset")
                return
            except Exception as exc:
                last_error = exc
                if candidate_session is not None:
                    try:
                        candidate_session.release()
                    except Exception:
                        pass
                if candidate_pool is not None:
                    try:
                        candidate_pool.close()
                    except Exception:
                        pass
                if attempt < self.recovery_retries and self.recovery_delay_s:
                    time.sleep(self.recovery_delay_s)
        raise RuntimeError(
            f"NebulaGraph reconnect failed after {self.recovery_retries} attempts: "
            f"{type(last_error).__name__}: {last_error}"
        ) from last_error

    def reset_to_seed(self):
        from GraphInitializer import NebulaSeedGenerator

        if not self.managed_seed or self.seed_spec is None:
            raise RuntimeError("NebulaGraph reset is disabled for init-mode=reuse")
        generator = None
        reset_error = None
        try:
            generator = NebulaSeedGenerator(
                host=self.host,
                port=self.port,
                user=self.user,
                password=self.password,
                space=self.space,
                seed_spec=self.seed_spec,
            )
            generator.reset_and_initialize(reset=True)
            self.set_seed_spec(generator.seed_spec, generator.seed_cypher, generator.seed_statements)
        except Exception as exc:
            reset_error = exc
        finally:
            if generator is not None:
                try:
                    generator.close()
                except Exception:
                    pass

        try:
            self._reconnect(clear_history=reset_error is None)
        except Exception as reconnect_error:
            if reset_error is not None:
                raise RuntimeError(
                    f"NebulaGraph reset failed ({type(reset_error).__name__}: {reset_error}); "
                    f"reconnect also failed ({type(reconnect_error).__name__}: {reconnect_error})"
                ) from reset_error
            raise
        if reset_error is not None:
            raise reset_error

    def _generate_poc_file(self, crashing_query: str, error_msg: str, evidence: Optional[Dict[str, str]] = None):
        crash_evidence = evidence or {}
        outcome = (
            ExecutionOutcome.CONFIRMED_CRASH
            if self._looks_confirmed_crash(crash_evidence)
            else ExecutionOutcome.CRASH_LIKE
        )
        return self._write_crash_artifact(
            outcome,
            crashing_query,
            error_msg,
            crash_evidence,
        )

    def _jit_dialect_transpile(self, query: str) -> str:
        return prepare_target_query("nebula", query)

    @staticmethod
    def _is_query_timeout_error(exc) -> bool:
        text = f"{type(exc).__name__} {exc}".lower()
        return any(token in text for token in ("timeout", "timed out", "e_timed_out"))

    def execute_single(self, query: str) -> Tuple[bool, str, str]:
        transpiled_query = self._jit_dialect_transpile(query)
        wire_query = f"USE `{self.space}`; {transpiled_query.strip().rstrip(';')};"
        self._begin_query(transpiled_query, wire_query=wire_query)
        self.last_execution = None
        self.stats["total_executed"] += 1
        start_time = time.time()
        execution_output = ""
        
        try:
            selected = self.session.execute(f"USE `{self.space}`;")
            if not selected.is_succeeded():
                raise RuntimeError(f"NebulaGraph USE `{self.space}` failed: {self._response_error(selected)}")
            resp = self.session.execute(transpiled_query.strip().rstrip(";") + ";")
            elapsed_ms = (time.time() - start_time) * 1000
            
            if resp.is_succeeded():
                self.stats["passed"] += 1
                self.stats["total_time_ms"] += elapsed_ms
                execution_output = f"Returned {resp.row_size()} rows"
                self._record_query(transpiled_query)
                self._set_execution_result(
                    ExecutionOutcome.SUCCESS,
                    transpiled_query,
                    "ok",
                    output=execution_output,
                    elapsed_ms=elapsed_ms,
                )
            else:
                self.stats["failed"] += 1
                error_message = self._response_error(resp)
                if self._is_query_timeout_error(error_message):
                    self.error_ledger[ExecutionOutcome.TIMEOUT.value] += 1
                    execution_output = "QUERY TIMEOUT"
                    evidence = {
                        "response_error": error_message,
                        "timeout_seconds": str(self.query_timeout_s),
                        "connection_state": "SERVER_RESPONDED",
                    }
                    artifact_path = self._write_timeout_artifact(
                        transpiled_query,
                        error_message,
                        evidence,
                    )
                    self._set_execution_result(
                        ExecutionOutcome.TIMEOUT,
                        transpiled_query,
                        error_message,
                        output=execution_output,
                        elapsed_ms=elapsed_ms,
                        error_type="NebulaTimeout",
                        health=evidence,
                        artifact_path=artifact_path,
                    )
                else:
                    self.error_ledger["NebulaError"] += 1
                    execution_output = "Semantic/Syntax Error"
                    self._save_runtime_error(transpiled_query, f"REJECTED: {error_message}")
                    self._set_execution_result(
                        ExecutionOutcome.REJECTED,
                        transpiled_query,
                        error_message,
                        output=execution_output,
                        elapsed_ms=elapsed_ms,
                        error_type="NebulaError",
                    )
                
        except NebulaConnectionErrors as e:
            self.stats["failed"] += 1
            evidence = self._collect_crash_evidence({
                "driver_error": f"{type(e).__name__}: {e}",
                "timeout_seconds": str(getattr(self, "query_timeout_s", 0)),
            })
            confirmed_crash = self._looks_confirmed_crash(evidence)
            if self._is_query_timeout_error(e) and not confirmed_crash:
                outcome = ExecutionOutcome.TIMEOUT
                artifact_path = self._write_timeout_artifact(transpiled_query, str(e), evidence)
                execution_output = "QUERY TIMEOUT"
            else:
                outcome = ExecutionOutcome.CONFIRMED_CRASH if confirmed_crash else ExecutionOutcome.CRASH_LIKE
                artifact_path = self._generate_poc_file(transpiled_query, str(e), evidence)
                execution_output = "DATABASE CRASH DETECTED"
                self.bug_reports.append({"query": transpiled_query, "artifact": artifact_path, "outcome": outcome.value})
            self.error_ledger[outcome.value] += 1
            self._set_execution_result(
                outcome,
                transpiled_query,
                f"{type(e).__name__}: {e}",
                output=execution_output,
                elapsed_ms=(time.time() - start_time) * 1000,
                error_type=type(e).__name__,
                health=evidence,
                artifact_path=artifact_path,
            )
            try:
                # A transport reconnect does not prove that the graph was
                # reset.  Preserve replay history so subsequent evidence still
                # describes the state that remains on the server.
                self._reconnect(clear_history=False)
                self.last_execution.health["recovery"] = "reconnected"
            except Exception as recovery_error:
                self.last_execution.health["recovery_error"] = (
                    f"{type(recovery_error).__name__}: {recovery_error}"
                )
        except Exception as e:
            self.stats["failed"] += 1
            message = f"{type(e).__name__}: {e}"
            if self._is_query_timeout_error(e):
                evidence = self._collect_crash_evidence({
                    "driver_error": message,
                    "timeout_seconds": str(getattr(self, "query_timeout_s", 0)),
                })
                if self._looks_confirmed_crash(evidence):
                    outcome = ExecutionOutcome.CONFIRMED_CRASH
                    artifact_path = self._generate_poc_file(transpiled_query, message, evidence)
                    execution_output = "DATABASE CRASH DETECTED"
                    self.bug_reports.append({"query": transpiled_query, "artifact": artifact_path, "outcome": outcome.value})
                else:
                    outcome = ExecutionOutcome.TIMEOUT
                    artifact_path = self._write_timeout_artifact(transpiled_query, message, evidence)
                    execution_output = "QUERY TIMEOUT"
                self.error_ledger[outcome.value] += 1
                self._set_execution_result(
                    outcome,
                    transpiled_query,
                    message,
                    output=execution_output,
                    elapsed_ms=(time.time() - start_time) * 1000,
                    error_type=type(e).__name__,
                    health=evidence,
                    artifact_path=artifact_path,
                )
                try:
                    self._reconnect(clear_history=False)
                    self.last_execution.health["recovery"] = "reconnected"
                except Exception as recovery_error:
                    self.last_execution.health["recovery_error"] = (
                        f"{type(recovery_error).__name__}: {recovery_error}"
                    )
            else:
                self.error_ledger[type(e).__name__] += 1
                execution_output = "Unknown Error"
                self._save_runtime_error(transpiled_query, f"RUNTIME_ERROR: {message}")
                self._set_execution_result(
                    ExecutionOutcome.RUNTIME_ERROR,
                    transpiled_query,
                    message,
                    output=execution_output,
                    elapsed_ms=(time.time() - start_time) * 1000,
                    error_type=type(e).__name__,
                )

        return self._finish_execution(transpiled_query, execution_output)
