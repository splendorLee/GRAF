from __future__ import annotations

import atexit
import logging
import multiprocessing
import queue
import re
import threading
import time
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Optional

from .target_queries import prepare_target_query


@dataclass(frozen=True)
class TargetCheckConfig:
    enabled: bool = True
    required: bool = True
    timeout_seconds: int = 15


class TargetCheckStatus(str, Enum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    TIMEOUT = "timeout"
    INFRASTRUCTURE = "infrastructure"
    CRASH_SUSPECTED = "crash_suspected"


@dataclass(frozen=True)
class TargetCheckResult:
    status: TargetCheckStatus
    message: str

    @property
    def accepted(self) -> bool:
        return self.status is TargetCheckStatus.ACCEPTED


def _classify_exception(exc: BaseException) -> TargetCheckStatus:
    """Only clear target compiler diagnostics are definitive rejections."""
    code = str(getattr(exc, "code", "") or "")
    if code.startswith("Neo.ClientError.Statement."):
        return TargetCheckStatus.REJECTED
    if type(exc).__name__ == "ResponseError":
        return _classify_message(str(exc))
    if type(exc).__name__ in {"BinderException", "ParserException",
                              "CatalogException", "SyntaxError", "SemanticError"}:
        return TargetCheckStatus.REJECTED
    return _classify_message(str(exc))


def _classify_message(message: str) -> TargetCheckStatus:
    lowered = message.lower()
    if "space was not chosen" in lowered or any(part in lowered for part in (
            "connection", "refused", "unavailable", "worker", "database is closed")):
        return TargetCheckStatus.INFRASTRUCTURE
    if any(part in lowered for part in ("syntaxerror", "semanticerror", "syntax error",
                                         "semantic error", "parser error", "binder error",
                                         "catalog exception", "binder exception", "parser exception",
                                         "invalid input", "unknown function", "unknown procedure",
                                         "undefined variable", "not supported")):
        return TargetCheckStatus.REJECTED
    return TargetCheckStatus.INFRASTRUCTURE


def _clean(query: str) -> str:
    return (query or "").strip().rstrip(";")


def _compile_once(payload: dict[str, Any], query: str) -> tuple[bool, str]:
    """Execute one side-effect-free target compilation in an isolated process."""

    kind = payload["kind"]
    statement = _clean(prepare_target_query(payload.get("target", kind), query))
    if re.match(r"^(?:EXPLAIN|PROFILE)\b", statement, re.IGNORECASE):
        return False, "SyntaxError: input already starts with EXPLAIN or PROFILE; expected an executable query"
    if kind == "bolt":
        from neo4j import GraphDatabase, Query

        driver = GraphDatabase.driver(payload["uri"], auth=tuple(payload["auth"]))
        try:
            session_kwargs = {}
            if payload.get("database"):
                session_kwargs["database"] = payload["database"]
            with driver.session(**session_kwargs) as session:
                explain = "EXPLAIN " + statement
                server_timeout = int(payload.get("server_timeout", 0) or 0)
                if payload.get("target") == "neo4j" and server_timeout > 0:
                    session.run(Query(explain, timeout=server_timeout)).consume()
                else:
                    session.run(explain).consume()
            return True, "EXPLAIN accepted"
        finally:
            driver.close()

    if kind == "falkordb":
        from falkordb import FalkorDB

        database = FalkorDB(
            host=payload["host"],
            port=int(payload["port"]),
            password=payload.get("password", ""),
        )
        try:
            graph = database.select_graph(payload["graph_name"])
            explain_method = getattr(graph, "explain", None)
            if callable(explain_method):
                explain_method(statement)
            else:
                database.connection.execute_command("GRAPH.EXPLAIN", payload["graph_name"], statement)
            return True, "GRAPH.EXPLAIN accepted"
        finally:
            database.connection.close()

    if kind == "kuzu":
        import kuzu

        database = kuzu.Database(payload["db_path"])
        connection = kuzu.Connection(database)
        try:
            result = connection.execute("EXPLAIN " + statement)
            if hasattr(result, "has_next"):
                while result.has_next():
                    result.get_next()
            return True, "EXPLAIN accepted"
        finally:
            del connection
            del database

    if kind == "nebula":
        from nebula3.Config import Config
        from nebula3.gclient.net import ConnectionPool

        config = Config()
        config.max_connection_pool_size = 1
        pool = ConnectionPool()
        if not pool.init([(payload["host"], int(payload["port"]))], config):
            raise RuntimeError("NebulaGraph connection pool initialization failed")
        session = pool.get_session(payload["user"], payload["password"])
        try:
            use_result = session.execute(f"USE `{payload['space']}`;")
            if hasattr(use_result, "is_succeeded") and not use_result.is_succeeded():
                raise RuntimeError(str(use_result.error_msg()))
            response = session.execute(f"EXPLAIN {statement.strip().rstrip(';')};")
            if hasattr(response, "is_succeeded") and not response.is_succeeded():
                message = response.error_msg() if hasattr(response, "error_msg") else str(response)
                return False, str(message)
            return True, "EXPLAIN accepted"
        finally:
            session.release()
            pool.close()

    raise RuntimeError(f"unsupported target checker payload kind: {kind}")


def _compile_worker(
    payload: dict[str, Any],
    requests: multiprocessing.Queue,
    responses: multiprocessing.Queue,
) -> None:
    # Neo4j logs server notifications (including deprecations) through this
    # logger. They do not determine compile acceptance and can flood output.
    logging.getLogger("neo4j.notifications").setLevel(logging.ERROR)
    while True:
        item = requests.get()
        if item is None:
            return
        request_id, query = item
        try:
            accepted, message = _compile_once(payload, query)
            status = (TargetCheckStatus.ACCEPTED if accepted else _classify_message(message))
            responses.put((request_id, status.value, str(message)))
        except BaseException as exc:  # process boundary: serialize only text
            responses.put((request_id, _classify_exception(exc).value,
                           f"{type(exc).__name__}: {exc}"))


class IsolatedTargetCompileChecker:
    """Persistent compile worker with a killable hard-timeout boundary.

    A target parser or driver can hang while compiling adversarial input. The
    checker therefore never runs in the fuzzer process. One worker is reused
    for throughput and is terminated/recreated after a timeout or abnormal
    exit, so a wedged validation cannot stall the campaign indefinitely.
    """

    def __init__(self, payload: dict[str, Any], config: TargetCheckConfig) -> None:
        self.payload = dict(payload)
        self.config = config
        self._context = multiprocessing.get_context("spawn")
        self._requests = None
        self._responses = None
        self._process = None
        self._lock = threading.Lock()
        self._closed = False
        atexit.register(self.close)

    def __call__(self, query: str) -> tuple[bool, str]:
        result = self.check(query)
        if result.status in {TargetCheckStatus.TIMEOUT, TargetCheckStatus.INFRASTRUCTURE,
                             TargetCheckStatus.CRASH_SUSPECTED} and not self.config.required:
            return True, f"best-effort compile check skipped: {result.message}"
        return result.accepted, result.message

    def check(self, query: str) -> TargetCheckResult:
        with self._lock:
            if self._closed:
                return TargetCheckResult(TargetCheckStatus.INFRASTRUCTURE, "target compile checker is closed")
            self._ensure_worker()
            request_id = uuid.uuid4().hex
            try:
                self._requests.put((request_id, query))
                deadline = (time.monotonic() + self.config.timeout_seconds
                            if self.config.timeout_seconds > 0 else None)
                while True:
                    if self._process is not None and not self._process.is_alive():
                        self._stop_worker(force=True)
                        return TargetCheckResult(TargetCheckStatus.CRASH_SUSPECTED,
                                                 "isolated compile worker exited unexpectedly")
                    remaining = (deadline - time.monotonic()) if deadline is not None else 0.25
                    if deadline is not None and remaining <= 0:
                        self._stop_worker(force=True)
                        return TargetCheckResult(TargetCheckStatus.TIMEOUT,
                                                 f"target compile check exceeded {self.config.timeout_seconds}s")
                    try:
                        response_id, status, message = self._responses.get(timeout=min(0.25, remaining))
                    except queue.Empty:
                        continue
                    if response_id == request_id:
                        return TargetCheckResult(TargetCheckStatus(status), str(message))
            except (EOFError, BrokenPipeError, OSError) as exc:
                self._stop_worker(force=True)
                return TargetCheckResult(TargetCheckStatus.INFRASTRUCTURE,
                                         f"target compile worker failed: {type(exc).__name__}: {exc}")

    def _infrastructure_result(self, message: str) -> tuple[bool, str]:
        if self.config.required:
            return False, message
        return True, f"best-effort compile check skipped: {message}"

    def _ensure_worker(self) -> None:
        if self._process is not None and self._process.is_alive():
            return
        self._stop_worker(force=True)
        self._requests = self._context.Queue(maxsize=1)
        self._responses = self._context.Queue(maxsize=1)
        self._process = self._context.Process(
            target=_compile_worker,
            args=(self.payload, self._requests, self._responses),
            name=f"graf-compile-{self.payload.get('target', self.payload.get('kind', 'target'))}",
            daemon=True,
        )
        self._process.start()

    def _stop_worker(self, *, force: bool) -> None:
        process = self._process
        requests = self._requests
        responses = self._responses
        self._process = None
        self._requests = None
        self._responses = None
        if process is not None:
            if process.is_alive() and not force and requests is not None:
                try:
                    requests.put_nowait(None)
                except (queue.Full, OSError):
                    pass
                process.join(timeout=1.0)
            if process.is_alive():
                process.terminate()
                process.join(timeout=2.0)
            if process.is_alive() and hasattr(process, "kill"):
                process.kill()
                process.join(timeout=2.0)
            process.close()
        for channel in (requests, responses):
            if channel is not None:
                try:
                    channel.close()
                    channel.join_thread()
                except (OSError, ValueError):
                    pass

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._stop_worker(force=False)


class ExecutorTargetCompileChecker:
    """Delegate compilation to an executor-owned isolated runtime.

    Embedded engines such as Kuzu must have one process own the database file.
    The executor provides the process boundary, timeout and lifecycle; starting
    another compile process would defeat that ownership model.
    """

    def __init__(self, executor: Any, config: TargetCheckConfig) -> None:
        self.executor = executor
        self.config = config
        self._closed = False

    def __call__(self, query: str) -> tuple[bool, str]:
        result = self.check(query)
        if result.status in {TargetCheckStatus.TIMEOUT, TargetCheckStatus.INFRASTRUCTURE} and not self.config.required:
            return True, f"best-effort compile check skipped: {result.message}"
        return result.accepted, result.message

    def check(self, query: str) -> TargetCheckResult:
        if re.match(r"^\s*(?:EXPLAIN|PROFILE)\b", query, re.IGNORECASE):
            return TargetCheckResult(TargetCheckStatus.REJECTED,
                                     "input already starts with EXPLAIN or PROFILE")
        if self._closed:
            return TargetCheckResult(TargetCheckStatus.INFRASTRUCTURE, "target compile checker is closed")
        try:
            accepted, message = self.executor.compile_query(
                query,
                timeout_seconds=self.config.timeout_seconds,
            )
            status = TargetCheckStatus.ACCEPTED if accepted else _classify_message(str(message))
            if "timeout" in str(message).lower() or "timed out" in str(message).lower():
                status = TargetCheckStatus.TIMEOUT
            return TargetCheckResult(status, str(message))
        except Exception as exc:
            return TargetCheckResult(TargetCheckStatus.INFRASTRUCTURE,
                                     f"executor compile check failed: {type(exc).__name__}: {exc}")

    def _infrastructure_result(self, message: str) -> tuple[bool, str]:
        if self.config.required:
            return False, message
        return True, f"best-effort compile check skipped: {message}"

    def close(self) -> None:
        # The executor owns and closes the shared runtime after all orchestrator
        # consumers have stopped using it.
        self._closed = True


def _payload_for(executor: Any, target_name: str, cfg: TargetCheckConfig) -> Optional[dict[str, Any]]:
    if target_name in {"neo4j", "memgraph"} and hasattr(executor, "driver"):
        return {
            "kind": "bolt",
            "target": target_name,
            "uri": executor.uri,
            "auth": tuple(getattr(executor, "auth", ("", ""))),
            "database": getattr(executor, "database", None),
            "server_timeout": cfg.timeout_seconds,
        }
    if target_name == "falkordb" and hasattr(executor, "graph"):
        return {
            "kind": "falkordb",
            "target": target_name,
            "host": executor.host,
            "port": executor.port,
            "password": executor.password,
            "graph_name": executor.graph_name,
        }
    if target_name == "kuzu" and getattr(executor, "db_path", None):
        return {"kind": "kuzu", "target": target_name, "db_path": executor.db_path}
    if target_name == "nebula" and hasattr(executor, "session"):
        return {
            "kind": "nebula",
            "target": target_name,
            "host": executor.host,
            "port": executor.port,
            "user": executor.user,
            "password": executor.password,
            "space": executor.space,
        }
    return None


def build_target_compile_checker(
    executor: Any,
    target: str,
    config: Optional[TargetCheckConfig] = None,
) -> Optional[Callable[[str], tuple[bool, str]]]:
    cfg = config or TargetCheckConfig()
    if not cfg.enabled:
        return None
    target_name = (target or "").lower()
    if target_name == "kuzu" and callable(getattr(executor, "compile_query", None)):
        return ExecutorTargetCompileChecker(executor, cfg)
    payload = _payload_for(executor, target_name, cfg)
    if payload is not None:
        return IsolatedTargetCompileChecker(payload, cfg)
    if cfg.required:
        def unavailable(_query: str) -> tuple[bool, str]:
            return False, f"no compile checker is available for target `{target_name}`"

        return unavailable
    return None
