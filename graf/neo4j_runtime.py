"""Killable, persistent Neo4j Bolt query boundary.

The deadline covers the evidence snapshot, connection acquisition, query
submission, the full result stream and commit acknowledgement.  The parent
alone owns the audit ledger, classification and container recovery.
"""

from __future__ import annotations

import datetime
import multiprocessing
import os
import threading
import time
import uuid
from typing import Any, Callable


class Neo4jWorkerTimeout(RuntimeError):
    def __init__(self, seconds: float, pid: int | None):
        self.seconds = seconds
        self.pid = pid
        super().__init__(f"Neo4j query exceeded {seconds:g}s; worker pid={pid} terminated")


class Neo4jWorkerExited(RuntimeError):
    pass


def snapshot_graph_state(driver: Any, database: str) -> dict[str, Any]:
    """Preserve the existing pre-execution evidence, inside the killable worker."""
    state: dict[str, Any] = {
        "captured_at": datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="microseconds").replace("+00:00", "Z")
    }
    try:
        with driver.session(database=database) as session:
            state["total_nodes"] = session.run("MATCH (n) RETURN count(n) AS count").single()["count"]
            state["total_relationships"] = session.run("MATCH ()-[r]->() RETURN count(r) AS count").single()["count"]
            state["labels"] = [
                {"label": row["label"], "count": row["count"]}
                for row in session.run(
                    "MATCH (n) UNWIND labels(n) AS label "
                    "RETURN label, count(*) AS count ORDER BY count DESC LIMIT 100"
                )
            ]
            state["relationship_types"] = [
                {"type": row["type"], "count": row["count"]}
                for row in session.run(
                    "MATCH ()-[r]->() RETURN type(r) AS type, count(*) AS count "
                    "ORDER BY count DESC LIMIT 100"
                )
            ]
            state["topology"] = [
                {
                    "src_labels": row["src_labels"], "type": row["type"],
                    "dst_labels": row["dst_labels"], "count": row["count"],
                }
                for row in session.run(
                    "MATCH (a)-[r]->(b) RETURN labels(a) AS src_labels, "
                    "type(r) AS type, labels(b) AS dst_labels, count(*) AS count "
                    "ORDER BY count DESC LIMIT 100"
                )
            ]
    except Exception as exc:
        state["snapshot_error"] = f"{type(exc).__name__}: {exc}"
    return state


def _neo4j_worker(uri: str, auth: tuple[str, str], channel: Any, database: str) -> None:
    from neo4j import GraphDatabase, Query
    from neo4j.exceptions import ClientError, DatabaseError, ServiceUnavailable, SessionExpired, TransientError

    driver = None
    try:
        driver = GraphDatabase.driver(uri, auth=auth)
        channel.send({"kind": "ready", "pid": os.getpid()})
        while True:
            try:
                request = channel.recv()
            except EOFError:
                break
            if request.get("kind") == "stop":
                break
            if request.get("kind") != "query":
                continue
            request_id = request["id"]
            started = time.monotonic()
            graph_state_before = (
                snapshot_graph_state(driver, database)
                if request.get("capture_snapshot", True) else {}
            )
            try:
                with driver.session(database=database) as session:
                    seconds = request["server_timeout"]
                    statement = Query(request["query"], timeout=seconds) if seconds > 0 else request["query"]
                    result = session.run(statement)
                    records = [str(row.data()) for i, row in enumerate(result) if i < 5]
                    summary = result.consume()
                counters = getattr(summary, "counters", None)
                fields = (
                    "nodes_created", "nodes_deleted", "relationships_created", "relationships_deleted",
                    "properties_set", "labels_added", "labels_removed", "indexes_added",
                    "indexes_removed", "constraints_added", "constraints_removed",
                )
                counter_write = False
                for field in fields:
                    try:
                        if int(getattr(counters, field, 0) or 0) > 0:
                            counter_write = True
                            break
                    except (TypeError, ValueError):
                        pass
                reply = {
                    "id": request_id, "status": "success", "graph_state_before": graph_state_before,
                    "output": "\n".join(records) if records else f"Summary: {counters}",
                    "summary": str(counters) if counters is not None else "",
                    "counter_write": counter_write,
                    "elapsed_ms": (time.monotonic() - started) * 1000,
                }
            except BaseException as exc:
                if isinstance(exc, ClientError):
                    category = "client"
                elif isinstance(exc, TransientError):
                    category = "transient"
                elif isinstance(exc, DatabaseError):
                    category = "database"
                elif isinstance(exc, (ServiceUnavailable, SessionExpired, OSError)):
                    category = "connection"
                else:
                    category = "internal"
                reply = {
                    "id": request_id, "status": "error", "category": category,
                    "error_type": type(exc).__name__,
                    "code": str(getattr(exc, "code", "") or ""),
                    "message": str(getattr(exc, "message", str(exc))),
                    "graph_state_before": graph_state_before,
                }
            channel.send(reply)
    except BaseException as exc:
        try:
            channel.send({"kind": "start_error", "message": f"{type(exc).__name__}: {exc}"})
        except (OSError, EOFError):
            pass
    finally:
        if driver is not None:
            driver.close()
        channel.close()


class Neo4jQueryRuntime:
    """A single reusable child, forcibly stopped at the complete query deadline."""

    def __init__(
        self, uri: str, auth: tuple[str, str], database: str, *,
        worker_target: Callable[..., None] = _neo4j_worker,
        startup_timeout_s: float = 15.0,
    ) -> None:
        self.uri, self.auth, self.database = uri, auth, database
        self._target = worker_target
        self.startup_timeout_s = startup_timeout_s
        self._context = multiprocessing.get_context("spawn")
        self._lock = threading.Lock()
        self._channel = None
        self._process = None
        self._closed = False

    def _stop_locked(self) -> None:
        process, channel = self._process, self._channel
        self._process = self._channel = None
        if process is not None:
            if process.is_alive():
                process.terminate()
                process.join(timeout=1)
            if process.is_alive():
                process.kill()
                process.join(timeout=1)
            if process.is_alive():
                raise Neo4jWorkerExited(f"could not stop Neo4j worker pid={process.pid}")
            process.close()
        if channel is not None:
            channel.close()

    def _receive_locked(self, deadline: float | None) -> dict[str, Any]:
        while True:
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                raise TimeoutError("Neo4j worker response deadline exceeded")
            if self._channel.poll(0.1 if remaining is None else min(0.1, remaining)):
                try:
                    return self._channel.recv()
                except EOFError as exc:
                    raise Neo4jWorkerExited("Neo4j worker closed its pipe") from exc
            if not self._process.is_alive():
                raise Neo4jWorkerExited(f"Neo4j worker exited (exitcode={self._process.exitcode})")

    def _start_locked(self, deadline: float | None) -> None:
        if self._process is not None and self._process.is_alive():
            return
        self._stop_locked()
        parent, child = self._context.Pipe(duplex=True)
        process = self._context.Process(
            target=self._target, args=(self.uri, self.auth, child, self.database),
            name="graf-neo4j-query", daemon=True,
        )
        self._channel, self._process = parent, process
        try:
            process.start()
        except BaseException:
            child.close()
            self._stop_locked()
            raise
        child.close()
        startup_deadline = time.monotonic() + self.startup_timeout_s
        if deadline is not None:
            startup_deadline = min(deadline, startup_deadline)
        try:
            ready = self._receive_locked(startup_deadline)
        except TimeoutError as exc:
            if deadline is not None and time.monotonic() >= deadline:
                raise
            raise Neo4jWorkerExited(
                f"Neo4j worker startup exceeded {self.startup_timeout_s:g}s"
            ) from exc
        if ready.get("kind") != "ready":
            raise Neo4jWorkerExited(f"Neo4j worker startup failed: {ready}")

    def request(
        self, query: str, timeout_seconds: float, *, capture_snapshot: bool = True,
    ) -> dict[str, Any]:
        with self._lock:
            if self._closed:
                raise Neo4jWorkerExited("Neo4j worker is closed")
            deadline = time.monotonic() + timeout_seconds if timeout_seconds > 0 else None
            try:
                self._start_locked(deadline)
                request_id = uuid.uuid4().hex
                self._channel.send({
                    "kind": "query", "id": request_id, "query": query,
                    "server_timeout": timeout_seconds,
                    "capture_snapshot": capture_snapshot,
                })
                response = self._receive_locked(deadline)
                if response.get("id") != request_id:
                    raise Neo4jWorkerExited("Neo4j worker returned a mismatched response")
                return response
            except TimeoutError as exc:
                pid = self._process.pid if self._process is not None else None
                self._stop_locked()
                raise Neo4jWorkerTimeout(timeout_seconds, pid) from exc
            except (Neo4jWorkerExited, BrokenPipeError, OSError):
                self._stop_locked()
                raise

    def restart_boundary(self) -> None:
        with self._lock:
            self._stop_locked()

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._stop_locked()
