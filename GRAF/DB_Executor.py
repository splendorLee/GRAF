import time
import datetime
import os
import multiprocessing
import uuid
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Tuple, List, Dict, Optional, Any
import sys
import subprocess

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
    import kuzu
except ImportError:
    pass

try:
    from nebula3.gclient.net import ConnectionPool
    from nebula3.Config import Config
    from nebula3.Exception import IOErrorException, InValidHostname, OutOfConnection
except ImportError:
    pass


class ExecutionOutcome(Enum):
    SUCCESS = "SUCCESS"
    REJECTED = "REJECTED"
    RUNTIME_ERROR = "RUNTIME_ERROR"
    REPORTABLE_RUNTIME_BUG = "REPORTABLE_RUNTIME_BUG"
    TIMEOUT = "TIMEOUT"
    RESOURCE_EXHAUSTION = "RESOURCE_EXHAUSTION"
    CRASH_LIKE = "CRASH_LIKE"
    CONFIRMED_CRASH = "CONFIRMED_CRASH"


@dataclass
class ExecutionResult:
    target: str
    outcome: ExecutionOutcome
    query: str
    message: str
    output: str = ""
    elapsed_ms: float = 0.0
    error_type: str = ""
    health: Dict[str, str] = field(default_factory=dict)
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
    def __init__(self, target_name: str, log_file: str, seed_cypher: str, history_limit: int = 200, crash_policy: str = "strict"):
        self.target_name = target_name
        self.seed_cypher = seed_cypher
        self.history_limit = history_limit
        self.crash_policy = crash_policy
        
        current_dir = os.path.dirname(os.path.abspath(__file__))
        self.log_file = os.path.join(current_dir, log_file)
        
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
        self.execution_context: Dict[str, Any] = {}
        self.last_execution: Optional[ExecutionResult] = None

    def _write_log(self, content: str):
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(content + "\n")

    def set_execution_context(self, **context):
        self.execution_context = self._json_safe(context)

    def _record_query(self, query: str, summary: str = "", state_changing: Optional[bool] = None):
        self.global_query_history.append(query)
        if len(self.global_query_history) > self.history_limit:
            del self.global_query_history[: len(self.global_query_history) - self.history_limit]
        if state_changing is None:
            state_changing = self._looks_state_changing_query(query)
        if state_changing:
            self.state_changing_success_history.append({
                "query": self._normalize_cypher(query),
                "summary": str(summary or ""),
                "recorded_at": datetime.datetime.utcnow().isoformat(timespec="microseconds") + "Z",
            })
            if len(self.state_changing_success_history) > self.history_limit:
                del self.state_changing_success_history[: len(self.state_changing_success_history) - self.history_limit]

    def _clear_recorded_history(self):
        self.global_query_history.clear()
        self.state_changing_success_history.clear()

    def _use_legacy_crash_policy(self) -> bool:
        return self.crash_policy == "legacy"

    def _looks_state_changing_query(self, query: str) -> bool:
        return bool(re.search(r"\b(CREATE|MERGE|SET|REMOVE|DELETE|DETACH|DROP|LOAD|FOREACH)\b", query or "", re.IGNORECASE))

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
        timestamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%S%fZ")
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
            "observed_at": datetime.datetime.utcnow().isoformat(timespec="microseconds") + "Z",
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

    def _format_state_changing_history(self) -> List[Dict[str, str]]:
        return [
            {
                "query": item.get("query", ""),
                "summary": item.get("summary", ""),
                "recorded_at": item.get("recorded_at", ""),
            }
            for item in self.state_changing_success_history
            if item.get("query")
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

    def _write_cypher_artifact(
        self,
        base_dir: str,
        stem: str,
        query: str,
        message: str,
        evidence: Dict[str, str],
    ) -> str:
        filename = self._artifact_filename(base_dir, stem, "cypher")
        with open(filename, "w", encoding="utf-8") as f:
            f.write(self._comment_block(f"{self.target_name} crash artifact") + "\n")
            f.write(self._comment_block(f"Classification: {stem}") + "\n")
            f.write(self._comment_block(f"Error: {message}") + "\n")
            for key, value in evidence.items():
                f.write(self._comment_block(f"{key}: {value}") + "\n")
            f.write("\n")
            f.write("// [0] Clean Database\n")
            f.write("MATCH (n) DETACH DELETE n;\n\n")
            if self.seed_cypher:
                f.write("// [1] Seed Graph Generation\n")
                f.write(self._format_seed_for_artifact())
                f.write("\n\n")
            history = self._format_history_for_artifact()
            if history:
                f.write("// [2] Successful Upstream Execution History\n")
                for hist_query in history:
                    f.write(f"{hist_query}\n")
                f.write("\n")
            f.write("// [3] Triggering Query\n")
            f.write(self._normalize_cypher(query))
            f.write("\n")
        return filename

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
        filename = self._artifact_filename(base_dir, stem, "redis")
        with open(filename, "w", encoding="utf-8") as f:
            f.write(self._comment_block(f"{self.target_name} crash artifact") + "\n")
            f.write(self._comment_block(f"Classification: {stem}") + "\n")
            f.write(self._comment_block(f"Error: {message}") + "\n")
            for key, value in evidence.items():
                f.write(self._comment_block(f"{key}: {value}") + "\n")
            f.write("\n")
            if self.seed_cypher:
                f.write(self._comment_block("[1] Seed Graph Generation") + "\n")
                f.write(self._wrap_falkordb_query(self.seed_cypher) + "\n\n")
            history = self._format_history_for_artifact()
            if history:
                f.write(self._comment_block("[2] Successful Upstream Execution History") + "\n")
                for hist_query in history:
                    f.write(self._wrap_falkordb_query(hist_query) + "\n")
                f.write("\n")
            f.write(self._comment_block("[3] Triggering Query") + "\n")
            f.write(self._wrap_falkordb_query(query) + "\n")
        return filename

    def _write_crash_artifact(
        self,
        outcome: ExecutionOutcome,
        query: str,
        message: str,
        evidence: Dict[str, str],
        legacy_unconfirmed: bool = False,
    ) -> str:
        if legacy_unconfirmed:
            base_dir = os.path.join("legacy_crash_like", self._target_slug())
            stem = "legacy_unconfirmed"
        else:
            base_dir = os.path.join("crash_pocs", self._target_slug())
            stem = "confirmed_crash" if outcome == ExecutionOutcome.CONFIRMED_CRASH else "crash_like"

        if self._target_slug() == "falkordb":
            return self._write_falkordb_artifact(base_dir, stem, query, message, evidence)
        return self._write_cypher_artifact(base_dir, stem, query, message, evidence)

    def _write_timeout_artifact(self, query: str, message: str, evidence: Dict[str, str]) -> str:
        base_dir = os.path.join("timeout_cases", self._target_slug())
        stem = "timeout"
        if self._target_slug() == "falkordb":
            return self._write_falkordb_artifact(base_dir, stem, query, message, evidence)
        return self._write_cypher_artifact(base_dir, stem, query, message, evidence)

    def _write_reportable_runtime_bug_artifact(self, query: str, message: str, evidence: Dict[str, str]) -> str:
        base_dir = os.path.join("runtime_bug_reports", self._target_slug())
        stem = "statement_execution_failed" if self._target_slug() == "neo4j" else "reportable_runtime_bug"
        filename = self._artifact_filename(base_dir, stem, "cypher")
        with open(filename, "w", encoding="utf-8") as f:
            f.write(self._comment_block(f"{self.target_name} reportable runtime bug artifact") + "\n")
            f.write(self._comment_block(f"Classification: {stem}") + "\n")
            f.write(self._comment_block(f"Outcome: {ExecutionOutcome.REPORTABLE_RUNTIME_BUG.value}") + "\n")
            f.write(self._comment_block(f"Error: {message}") + "\n")
            for key, value in evidence.items():
                f.write(self._comment_block(f"{key}: {value}") + "\n")
            f.write("\n")
            f.write("// [0] Clean Database\n")
            f.write("MATCH (n) DETACH DELETE n;\n\n")
            if self.seed_cypher:
                f.write("// [1] Seed Graph Generation\n")
                f.write(self._format_seed_for_artifact())
                f.write("\n\n")
            history = self._format_history_for_artifact()
            if history:
                f.write("// [2] Successful Upstream Execution History\n")
                for hist_query in history:
                    f.write(f"{hist_query}\n")
                f.write("\n")
            f.write("// [3] Triggering Query\n")
            f.write(self._normalize_cypher(query))
            f.write("\n")
        return filename

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
        timestamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%S%fZ")
        case_id = f"case_{timestamp}_{uuid.uuid4().hex[:8]}"
        case_dir = os.path.join("resource_exhaustion", self._target_slug(), case_id)
        os.makedirs(case_dir, exist_ok=True)

        trigger_query = self._normalize_cypher(query)
        seed_query = self._format_seed_for_artifact()
        state_history = self._format_state_changing_history()
        replay_history = "\n".join(item["query"] for item in state_history)
        reproduce_sections = [
            "// [0] Clean database",
            "MATCH (n) DETACH DELETE n;",
            "",
            "// [1] Seed graph",
            seed_query,
            "",
            "// [2] Replay successful state-changing queries since last reset/reseed",
            replay_history,
            "",
            "// [3] Trigger resource exhaustion",
            trigger_query,
            "",
        ]

        self._write_text_file(os.path.join(case_dir, "seed.cypher"), seed_query)
        self._write_text_file(os.path.join(case_dir, "trigger.cypher"), trigger_query)
        self._write_text_file(os.path.join(case_dir, "replay_success_history.cypher"), replay_history)
        self._write_text_file(os.path.join(case_dir, "reproduce.cypher"), "\n".join(reproduce_sections))
        self._write_text_file(os.path.join(case_dir, f"{self._target_slug()}_docker_inspect.txt"), evidence.get("docker_inspect", ""))
        self._write_text_file(os.path.join(case_dir, f"{self._target_slug()}_logs_tail.txt"), evidence.get("docker_logs_tail", ""))
        self._write_json_file(os.path.join(case_dir, "graph_state_before.json"), graph_state_before or {})
        self._write_json_file(os.path.join(case_dir, "graph_state_after.json"), graph_state_after or {})
        self._write_json_file(os.path.join(case_dir, "fuzzer_context.json"), self.execution_context)
        self._write_json_file(os.path.join(case_dir, "db_config.json"), db_config or {})

        metadata = {
            "case_id": case_id,
            "target": self.target_name,
            "classification": outcome.value,
            "error": message,
            "artifact_dir": case_dir,
            "trigger_query": trigger_query,
            "state_changing_history_count": len(state_history),
            "state_changing_history": state_history,
            "evidence": evidence,
            "fuzzer_context": self.execution_context,
            "graph_state_before": graph_state_before or {},
            "graph_state_after": graph_state_after or {},
            "db_config": db_config or {},
        }
        self._write_json_file(os.path.join(case_dir, "metadata.json"), metadata)
        return case_dir

    def _set_execution_result(
        self,
        outcome: ExecutionOutcome,
        query: str,
        message: str,
        output: str = "",
        elapsed_ms: float = 0.0,
        error_type: str = "",
        health: Optional[Dict[str, str]] = None,
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
        self._write_log(
            f"[{self.stats['total_executed']}] Query: {query}\n"
            f"--> Status: {result.status_message()}\n"
            f"--> Outcome: {result.outcome.value}\n"
            f"--> Evidence: {result.health}\n"
            f"{'-'*60}"
        )
        return result.is_success, result.status_message(), result.output

    def _save_runtime_error(self, query: str, error_msg: str):
        runtime_dir = os.path.join("runtime_errors", self.target_name.lower())
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
        self.driver = GraphDatabase.driver(self.uri, auth=self.auth)

    def close(self):
        self.driver.close()

    def _wait_until_ready(self):
        deadline = time.time() + self.ready_timeout_s
        last_error = None
        next_report = 0

        while time.time() < deadline:
            try:
                self.driver.verify_connectivity()
                with self.driver.session() as session:
                    session.run("RETURN 1 AS ok").consume()
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
            self.driver.verify_connectivity()
            with self.driver.session() as session:
                session.run("RETURN 1 AS ok").consume()
            return True, "CONNECTION_ALIVE_AFTER_ERROR"
        except Exception as exc:
            return False, f"CONNECTION_LOST_AFTER_ERROR: {type(exc).__name__}: {exc}"

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
        self._wait_until_ready()
        with self.driver.session() as session:
            deleted = self._clear_database(session)
            if self.seed_cypher:
                session.run(self.seed_cypher).consume()
        self._clear_recorded_history()
        print(f"[Memgraph] 周期性初始化完成，删除节点数: {deleted}")

    def _reconnect_and_reseed(self):
        try:
            self.driver.close()
        except Exception:
            pass

        last_error = None
        for attempt in range(1, self.recovery_retries + 1):
            try:
                if self.container_name:
                    print(f"[Memgraph] 重启容器 {self.container_name}，恢复尝试 {attempt}/{self.recovery_retries}...")
                    subprocess.run(["docker", "restart", self.container_name], check=True, capture_output=True)

                self.driver = GraphDatabase.driver(self.uri, auth=self.auth)
                print("[Memgraph] 等待 Bolt 服务恢复...")
                self._wait_until_ready()

                self._clear_recorded_history()
                if self.seed_cypher:
                    with self.driver.session() as session:
                        self._clear_database(session)
                        session.run(self.seed_cypher).consume()
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
        self.last_execution = None
        self.stats["total_executed"] += 1
        start_time = time.time()
        execution_output = ""
        
        try:
            with self.driver.session() as session:
                result = session.run(query)
                records = [str(record.data()) for i, record in enumerate(result) if i < 5]
                summary = result.consume() 
                
            elapsed_ms = (time.time() - start_time) * 1000
            self.stats["total_time_ms"] += elapsed_ms
            self.stats["passed"] += 1
            execution_output = "\n".join(records) if records else "Empty result"
            self._record_query(query)
            self._set_execution_result(
                ExecutionOutcome.SUCCESS,
                query,
                "ok",
                output=execution_output,
                elapsed_ms=elapsed_ms,
            )
            
        except (CypherSyntaxError, CypherTypeError, ClientError) as e:
            self.stats["failed"] += 1
            err_type = e.code if isinstance(e, ClientError) and e.code else type(e).__name__
            self.error_ledger[err_type] += 1
            execution_output = "Semantic/Syntax Error"
            self._set_execution_result(
                ExecutionOutcome.REJECTED,
                query,
                f"{err_type}: {getattr(e, 'message', str(e))}",
                output=execution_output,
                error_type=err_type,
            )

        except DatabaseError as e:
            self.stats["failed"] += 1
            err_type = getattr(e, "code", None) or type(e).__name__
            err_msg = f"{err_type}: {getattr(e, 'message', str(e))}"
            is_alive, connection_state = self._probe_connection_after_error()
            if not is_alive:
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

        except (ServiceUnavailable, OSError) as e:
            self.stats["failed"] += 1
            err_msg = f"{type(e).__name__}: {str(e)}"
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
        query_timeout_s: int = 60,
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
        self.query_timeout_s = query_timeout_s
        self.driver = GraphDatabase.driver(self.uri, auth=self.auth)

    def close(self):
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
                self.driver.verify_connectivity()
                with self.driver.session(database=self.database) as session:
                    session.run("RETURN 1 AS ok").consume()
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
            self.driver.verify_connectivity()
            with self.driver.session(database=self.database) as session:
                session.run("RETURN 1 AS ok").consume()
            return True, "CONNECTION_ALIVE_AFTER_ERROR"
        except Exception as exc:
            return False, f"CONNECTION_LOST_AFTER_ERROR: {exc}"

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
        state: Dict[str, Any] = {"captured_at": datetime.datetime.utcnow().isoformat(timespec="microseconds") + "Z"}
        try:
            with self.driver.session(database=self.database) as session:
                state["total_nodes"] = session.run("MATCH (n) RETURN count(n) AS count").single()["count"]
                state["total_relationships"] = session.run("MATCH ()-[r]->() RETURN count(r) AS count").single()["count"]
                state["labels"] = [
                    {"label": record["label"], "count": record["count"]}
                    for record in session.run(
                        """
                        MATCH (n)
                        UNWIND labels(n) AS label
                        RETURN label, count(*) AS count
                        ORDER BY count DESC
                        LIMIT 100
                        """
                    )
                ]
                state["relationship_types"] = [
                    {"type": record["type"], "count": record["count"]}
                    for record in session.run(
                        """
                        MATCH ()-[r]->()
                        RETURN type(r) AS type, count(*) AS count
                        ORDER BY count DESC
                        LIMIT 100
                        """
                    )
                ]
                state["topology"] = [
                    {
                        "src_labels": record["src_labels"],
                        "type": record["type"],
                        "dst_labels": record["dst_labels"],
                        "count": record["count"],
                    }
                    for record in session.run(
                        """
                        MATCH (a)-[r]->(b)
                        RETURN labels(a) AS src_labels, type(r) AS type, labels(b) AS dst_labels, count(*) AS count
                        ORDER BY count DESC
                        LIMIT 100
                        """
                    )
                ]
        except Exception as exc:
            state["snapshot_error"] = f"{type(exc).__name__}: {exc}"
        return state

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
        self._wait_until_ready()
        with self.driver.session(database=self.database) as session:
            deleted = self._clear_database(session)
            if self.seed_cypher:
                session.run(self.seed_cypher).consume()
        self._clear_recorded_history()
        print(f"[Neo4j] 周期性初始化完成，删除节点数: {deleted}")

    def _reconnect_and_reseed(self):
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
                    subprocess.run(["docker", "restart", target_container], check=True, capture_output=True)

                self._refresh_auto_uri()
                self.driver = self._new_driver()
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

        self._clear_recorded_history()

        if not self.seed_cypher:
            return

        with self.driver.session(database=self.database) as session:
            self._clear_database(session)
            session.run(self.seed_cypher).consume()

    def execute_single(self, query: str) -> Tuple[bool, str, str]:
        self.last_execution = None
        self.stats["total_executed"] += 1
        start_time = time.time()
        execution_output = ""
        graph_state_before = self._snapshot_graph_state()

        try:
            with self.driver.session(database=self.database) as session:
                result = self._run_with_timeout(session, query)
                records = [str(record.data()) for i, record in enumerate(result) if i < 5]
                summary = result.consume()

            elapsed_ms = (time.time() - start_time) * 1000
            self.stats["total_time_ms"] += elapsed_ms
            self.stats["passed"] += 1
            counters = summary.counters if summary else None
            execution_output = "\n".join(records) if records else f"Summary: {counters}"
            self._record_query(
                query,
                summary=self._summary_counters_text(summary),
                state_changing=self._summary_indicates_write(summary, query),
            )
            self._set_execution_result(
                ExecutionOutcome.SUCCESS,
                query,
                "ok",
                output=execution_output,
                elapsed_ms=elapsed_ms,
            )

        except (CypherSyntaxError, CypherTypeError, ClientError) as e:
            self.stats["failed"] += 1
            err_type = e.code if isinstance(e, ClientError) and e.code else type(e).__name__
            if self._is_resource_exhaustion_error(e):
                execution_output = self._handle_resource_exhaustion(query, e, graph_state_before)
            elif self._is_query_timeout_error(e):
                self.error_ledger["QUERY_TIMEOUT"] += 1
                err_msg = f"{err_type}: {getattr(e, 'message', str(e))}"
                execution_output = "QUERY TIMEOUT"
                evidence = {"connection_state": "SERVER_SIDE_TIMEOUT", "driver_error": err_msg}
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

        except TransientError as e:
            self.stats["failed"] += 1
            if self._is_resource_exhaustion_error(e):
                execution_output = self._handle_resource_exhaustion(query, e, graph_state_before)
            elif self._is_query_timeout_error(e):
                self.error_ledger["QUERY_TIMEOUT"] += 1
                err_msg = f"TransientError: {getattr(e, 'message', str(e))}"
                execution_output = "QUERY TIMEOUT"
                evidence = {"connection_state": "TRANSIENT_TIMEOUT", "driver_error": err_msg}
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

        except DatabaseError as e:
            self.stats["failed"] += 1
            err_type = getattr(e, "code", None) or type(e).__name__
            is_alive, connection_state = self._probe_connection_after_error()
            err_msg = f"{err_type}: {getattr(e, 'message', str(e))}"
            if self._is_resource_exhaustion_error(e):
                execution_output = self._handle_resource_exhaustion(query, e, graph_state_before)
            elif self._is_query_timeout_error(e):
                self.error_ledger["QUERY_TIMEOUT"] += 1
                execution_output = "QUERY TIMEOUT"
                evidence = {"connection_state": connection_state, "driver_error": err_msg}
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

        except (ServiceUnavailable, SessionExpired, OSError) as e:
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
    def __init__(self, host="localhost", port=6379, password="", graph_name="graf_fuzz", log_file="fuzzer_falkordb.log", seed_cypher="", query_timeout_s: int = 60):
        super().__init__("FalkorDB", log_file, seed_cypher)
        self.host = host
        self.port = port
        self.password = password
        self.graph_name = graph_name
        self.query_timeout_s = query_timeout_s
        
        self.db = FalkorDB(host=self.host, port=self.port, password=self.password)
        self.graph = self.db.select_graph(self.graph_name)
        
        self.container_name = "falkordb_fuzz_target" 
        self.initializer = None

    def close(self):
        self.db.connection.close()

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
            if hasattr(self, 'initializer') and self.initializer:
                self.initializer.reset_and_initialize()
            else:
                print("未绑定 initializer，图数据库当前为空！")
        except Exception as init_e:
            print(f"种子图重置失败: {init_e}。熔断退出！")
            sys.exit(1)

        self._clear_recorded_history()
        print("[FalkorDB] 环境重置完毕，Fuzzer 继续运行。\n")

    def reset_to_seed(self):
        print("[FalkorDB] 周期性清空并重灌种子图...")
        if hasattr(self, 'initializer') and self.initializer:
            self.initializer.reset_and_initialize()
            self.db = FalkorDB(host=self.host, port=self.port, password=self.password)
            self.graph = self.db.select_graph(self.graph_name)
            self._clear_recorded_history()
            print("[FalkorDB] 周期性初始化完成。")
            return
        raise RuntimeError("FalkorDB periodic reset requires executor.initializer")

    def execute_single(self, query: str) -> Tuple[bool, str, str]:
        self.last_execution = None
        self.stats["total_executed"] += 1
        start_time = time.time()
        execution_output = ""
        clean_query = query.strip().rstrip(';')
        
        try:
            manager = multiprocessing.Manager()
            return_dict = manager.dict()
            worker = multiprocessing.Process(
                target=_falkordb_worker,
                args=(self.host, self.port, self.password, self.graph_name, clean_query, return_dict),
            )
            worker.start()
            worker.join(timeout=self.query_timeout_s)

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

        return self._finish_execution(query, execution_output)



def _kuzu_worker(db_path: str, query: str, return_dict: dict):
    import kuzu
    try:
        db = kuzu.Database(db_path)
        conn = kuzu.Connection(db)
        res = conn.execute(query)
        if res.has_next():
            return_dict["output"] = str(res.get_next())
        else:
            return_dict["output"] = "Empty result"
        return_dict["status"] = "SUCCESS"
    except Exception as e:
        return_dict["status"] = "ERROR"
        return_dict["error_msg"] = str(e)

class KuzuFuzzExecutor(BaseFuzzExecutor):
    def __init__(self, db_path="./kuzu_fuzz_test", log_file="fuzzer_kuzu.log", seed_cypher=""):
        super().__init__("KuzuDB", log_file, seed_cypher)
        self.db_path = db_path

    def close(self): pass

    def _generate_poc_file(self, crashing_query: str, error_msg: str):
        poc_dir = os.path.join("crash_pocs", "kuzu")
        os.makedirs(poc_dir, exist_ok=True)
        timestamp = int(time.time())
        poc_filename = os.path.join(poc_dir, f"poc_crash_{timestamp}.cypher")
        
        def clean_cypher(cypher: str) -> str:
            cypher = cypher.strip()
            if not cypher: return ""
            cypher = cypher.replace('`', '')
            if not cypher.endswith(';'): cypher += ';'
            return cypher

        with open(poc_filename, "w", encoding="utf-8") as f:
            f.write(f"//KùzuDB Crash PoC\n// Error: {error_msg}\n\n")
            
            if self.seed_cypher: 
                f.write("// [1] 初始化建图语句 (Seed Graph Generation)\n")
                for line in self.seed_cypher.split('\n'):
                    if line.strip().startswith('//'): f.write(f"{line.strip()}\n")
                    elif line.strip(): f.write(f"{clean_cypher(line)}\n")
                f.write("\n")
                
            if self.global_query_history:
                f.write("// [2] 上游状态改变轨迹 (Upstream Execution History)\n")
                for q in self.global_query_history: 
                    f.write(f"{clean_cypher(q)}\n")
                f.write("\n")
                
            f.write("// [3] 致命一击 (The Killing Query)\n")
            f.write(f"{clean_cypher(crashing_query)}\n")
            
        print(f"\n[PoC 已导出] KùzuDB: {poc_filename}")

    def execute_single(self, query: str) -> Tuple[bool, str, str]:
        self.stats["total_executed"] += 1
        start_time = time.time()
        
        manager = multiprocessing.Manager()
        return_dict = manager.dict()
        
        p = multiprocessing.Process(target=_kuzu_worker, args=(self.db_path, query, return_dict))
        p.start()
        p.join(timeout=10) 

        is_success, status_msg, execution_output = False, "", ""
        
        if p.is_alive():
            p.terminate()
            p.join()
            self.stats["failed"] += 1
            status_msg = "TIMEOUT: Query execution killed"
            execution_output = "Process terminated"
            
        elif p.exitcode != 0:
            self.stats["failed"] += 1
            self.error_ledger["CRITICAL_DB_CRASH"] += 1
            status_msg = f"CRASH_LIKE: Process exited with code {p.exitcode}"
            execution_output = "DATABASE CRASH DETECTED"
            self._generate_poc_file(query, status_msg)
            
            print(f"KùzuDB 进程暴毙，正在重新构建嵌入式图空间...")
            from GraphInitializer import KuzuSeedGenerator
            try:
                gen = KuzuSeedGenerator(self.db_path)
                gen.reset_and_initialize()
                self._clear_recorded_history()
            except Exception as e:
                print(f"重建失败: {e}")
                
        else:
            status = return_dict.get("status", "UNKNOWN")
            elapsed_ms = (time.time() - start_time) * 1000
            
            if status == "SUCCESS":
                self.stats["passed"] += 1
                self.stats["total_time_ms"] += elapsed_ms
                is_success = True
                status_msg = f"Success ({elapsed_ms:.2f}ms)"
                execution_output = return_dict.get("output", "")
                self._record_query(query)
            else:
                self.stats["failed"] += 1
                err_msg = return_dict.get("error_msg", "Unknown Exception")
                self.error_ledger["RuntimeError"] += 1
                status_msg = f"RUNTIME_ERROR: {err_msg}"
                execution_output = "Semantic/Syntax Error"
                self._record_query(query)

        self._write_log(f"[{self.stats['total_executed']}] Query: {query}\n--> Status: {status_msg}\n{'-'*60}")
        return is_success, status_msg, execution_output


class NebulaFuzzExecutor(BaseFuzzExecutor):
    def __init__(self, host="127.0.0.1", port=9669, user="root", password="nebula", space="graf_fuzz", log_file="fuzzer_nebula.log", seed_cypher=""):
        super().__init__("NebulaGraph", log_file, seed_cypher)
        self.host, self.port, self.user, self.password, self.space = host, port, user, password, space
        
        self.config = Config()
        self.config.max_connection_pool_size = 5
        self.pool = ConnectionPool()
        self.pool.init([(self.host, self.port)], self.config)
        self.session = self.pool.get_session(self.user, self.password)
        self.session.execute(f"USE {self.space};")

    def close(self):
        self.session.release()
        self.pool.close()

    def _generate_poc_file(self, crashing_query: str, error_msg: str):
        poc_dir = os.path.join("crash_pocs", "nebula")
        os.makedirs(poc_dir, exist_ok=True)
        timestamp = int(time.time())
        poc_filename = os.path.join(poc_dir, f"poc_crash_{timestamp}.cypher")
        
        def clean_cypher(cypher: str) -> str:
            cypher = cypher.strip()
            if not cypher: return ""
            cypher = cypher.replace('`', '')
            if not cypher.endswith(';'): cypher += ';'
            return cypher

        with open(poc_filename, "w", encoding="utf-8") as f:
            f.write(f"//NebulaGraph Crash PoC\n// Error: {error_msg}\n\n")
            
            if self.seed_cypher: 
                f.write("// [1] 初始化建图语句 (Seed Graph Generation)\n")
                for line in self.seed_cypher.split('\n'):
                    if line.strip().startswith('//'): f.write(f"{line.strip()}\n")
                    elif line.strip(): f.write(f"{clean_cypher(line)}\n")
                f.write("\n")
                
            f.write(f"USE {self.space};\n\n")
            
            if self.global_query_history:
                f.write("// [2] 上游状态改变轨迹 (Upstream Execution History)\n")
                for q in self.global_query_history: 
                    f.write(f"{clean_cypher(q)}\n")
                f.write("\n")
                
            f.write("// [3] 致命一击 (The Killing Query)\n")
            f.write(f"{clean_cypher(crashing_query)}\n")
            
        print(f"\n[PoC 已导出] NebulaGraph: {poc_filename}")

    def _jit_dialect_transpile(self, query: str) -> str:
        result = []
        in_string = False
        string_char = ''
        i = 0
        while i < len(query):
            c = query[i]
            if c in ('"', "'"):
                if not in_string:
                    in_string = True
                    string_char = c
                elif string_char == c:
                    escaped = False
                    j = i - 1
                    while j >= 0 and query[j] == '\\':
                        escaped = not escaped
                        j -= 1
                    if not escaped:
                        in_string = False
            
            if not in_string and c == '=':
                prev_c = query[i-1] if i > 0 else ''
                next_c = query[i+1] if i < len(query)-1 else ''
                if prev_c not in ('<', '>', '!', '=') and next_c != '=':
                    result.append('==')
                    i += 1
                    continue
            
            result.append(c)
            i += 1
            
        adapted_query = "".join(result)

        import re
        match = re.search(r'(ORDER\s+BY\s+)(.*)', adapted_query, re.IGNORECASE)
        if match:
            prefix = adapted_query[:match.start(2)]
            suffix = match.group(2)
            suffix = re.sub(r'\b([a-zA-Z0-9_]+)\.[a-zA-Z0-9_]+\b', r'\1', suffix)
            adapted_query = prefix + suffix

        return adapted_query

    def execute_single(self, query: str) -> Tuple[bool, str, str]:
        transpiled_query = self._jit_dialect_transpile(query)
        
        self.stats["total_executed"] += 1
        start_time = time.time()
        is_success, status_msg, execution_output = False, "", ""
        
        try:
            resp = self.session.execute(transpiled_query)
            elapsed_ms = (time.time() - start_time) * 1000
            
            if resp.is_succeeded():
                self.stats["passed"] += 1
                self.stats["total_time_ms"] += elapsed_ms
                is_success = True
                status_msg = f"Success ({elapsed_ms:.2f}ms)"
                execution_output = f"Returned {resp.row_size()} rows"
                self._record_query(transpiled_query)
            else:
                self.stats["failed"] += 1
                self.error_ledger["NebulaError"] += 1
                status_msg = f"Error [{resp.error_code()}]: {resp.error_msg()}"
                execution_output = "Semantic/Syntax Error"
                self._record_query(transpiled_query)
                
        except (IOErrorException, InValidHostname, OutOfConnection) as e:
            self.stats["failed"] += 1
            self.error_ledger["CRITICAL_DB_CRASH"] += 1
            self.bug_reports.append(transpiled_query)
            status_msg = f"CRASH_LIKE: {str(e)}"
            execution_output = "DATABASE CRASH DETECTED"
            self._generate_poc_file(transpiled_query, str(e))
            
            print(f"Nebula 连接丢失，重试中 (10s)...")
            time.sleep(10)
            try:
                self.pool.init([(self.host, self.port)], self.config)
                self.session = self.pool.get_session(self.user, self.password)
                self.session.execute(f"USE {self.space};")
                self._clear_recorded_history()
            except Exception: pass
        except Exception as e:
            self.stats["failed"] += 1
            status_msg = f"RUNTIME_ERROR: Exception: {str(e)}"
            execution_output = "Unknown Error"

        self._write_log(f"[{self.stats['total_executed']}] Query: {transpiled_query}\n--> Status: {status_msg}\n{'-'*60}")
        return is_success, status_msg, execution_output
