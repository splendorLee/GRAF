"""Killable, reusable Bolt query owner for Memgraph fuzz executions.

The Neo4j driver's Query(timeout=...) requests a server-side transaction
timeout; it does not put a deadline on a blocked socket or result stream.
Only the supervisor owns the clock, and only the child owns the fuzz session.
"""

from __future__ import annotations

import multiprocessing
import os
import threading
import time
import uuid
from typing import Any, Callable


class MemgraphWorkerError(RuntimeError):
    pass


class MemgraphWorkerTimeout(MemgraphWorkerError):
    def __init__(self, seconds: float, pid: int | None):
        super().__init__(f"Memgraph query exceeded {seconds:g}s; worker pid={pid} terminated")
        self.seconds = seconds
        self.pid = pid


class MemgraphWorkerExited(MemgraphWorkerError):
    pass


def _memgraph_worker(uri: str, auth: tuple[str, str], channel: Any) -> None:
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
            try:
                with driver.session() as session:
                    timeout = request["server_timeout"]
                    statement = Query(request["query"], timeout=timeout) if timeout > 0 else request["query"]
                    result = session.run(statement)
                    rows = [str(record.data()) for index, record in enumerate(result) if index < 5]
                    result.consume()  # commit/finish the whole stream before reporting success
                reply = {
                    "id": request_id,
                    "status": "success",
                    "output": "\n".join(rows) if rows else "Empty result",
                    "elapsed_ms": (time.monotonic() - started) * 1000,
                }
            except BaseException as exc:
                if isinstance(exc, ClientError):
                    category = "client"
                elif isinstance(exc, (DatabaseError, TransientError)):
                    category = "database"
                elif isinstance(exc, (ServiceUnavailable, SessionExpired, OSError)):
                    category = "connection"
                else:
                    category = "internal"
                reply = {
                    "id": request_id,
                    "status": "error",
                    "category": category,
                    "error_type": type(exc).__name__,
                    "code": str(getattr(exc, "code", "") or ""),
                    "message": str(getattr(exc, "message", str(exc))),
                    "elapsed_ms": (time.monotonic() - started) * 1000,
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


class MemgraphQueryRuntime:
    """One spawn-based worker, reused until reset, crash or hard timeout."""

    def __init__(
        self,
        uri: str,
        auth: tuple[str, str],
        *,
        worker_target: Callable[..., None] = _memgraph_worker,
        startup_timeout_s: float = 15.0,
    ) -> None:
        self.uri = uri
        self.auth = auth
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
                raise MemgraphWorkerError(f"could not stop Memgraph query worker pid={process.pid}")
            process.close()
        if channel is not None:
            channel.close()

    def _receive_locked(self, deadline: float | None) -> dict[str, Any]:
        while True:
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                raise TimeoutError("worker response deadline exceeded")
            if self._channel.poll(0.1 if remaining is None else min(0.1, remaining)):
                try:
                    return self._channel.recv()
                except EOFError as exc:
                    raise MemgraphWorkerExited("Memgraph query worker closed its pipe") from exc
            if not self._process.is_alive():
                raise MemgraphWorkerExited(f"Memgraph query worker exited (exitcode={self._process.exitcode})")

    def _start_locked(self, deadline: float | None) -> None:
        if self._process is not None and self._process.is_alive():
            return
        self._stop_locked()
        parent, child = self._context.Pipe(duplex=True)
        process = self._context.Process(
            target=self._target,
            args=(self.uri, self.auth, child),
            name="graf-memgraph-query",
            daemon=True,
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
            raise MemgraphWorkerExited(
                f"Memgraph query worker startup exceeded {self.startup_timeout_s:g}s"
            ) from exc
        if ready.get("kind") != "ready":
            raise MemgraphWorkerExited(f"Memgraph query worker startup failed: {ready}")

    def request(self, query: str, timeout_seconds: float) -> dict[str, Any]:
        with self._lock:
            if self._closed:
                raise MemgraphWorkerError("Memgraph query runtime is closed")
            deadline = time.monotonic() + timeout_seconds if timeout_seconds > 0 else None
            try:
                self._start_locked(deadline)
                request_id = uuid.uuid4().hex
                self._channel.send({
                    "kind": "query", "id": request_id, "query": query,
                    "server_timeout": timeout_seconds,
                })
                response = self._receive_locked(deadline)
                if response.get("id") != request_id:
                    raise MemgraphWorkerExited("Memgraph query worker returned a mismatched response")
                return response
            except TimeoutError as exc:
                pid = self._process.pid if self._process is not None else None
                self._stop_locked()
                raise MemgraphWorkerTimeout(timeout_seconds, pid) from exc
            except (MemgraphWorkerExited, BrokenPipeError, OSError):
                self._stop_locked()
                raise

    def restart_boundary(self) -> None:
        with self._lock:
            self._stop_locked()

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._stop_locked()
