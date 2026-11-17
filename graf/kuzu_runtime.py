from __future__ import annotations

import datetime
import multiprocessing
import os
import threading
import time
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from multiprocessing.connection import Connection
from typing import Any, Mapping, Optional


PROTOCOL_VERSION = "graf.kuzu-runtime/v1"


class KuzuRuntimeError(RuntimeError):
    """Base class for failures at the isolated Kuzu worker boundary."""


class KuzuWorkerStartError(KuzuRuntimeError):
    pass


class KuzuWorkerTimeout(KuzuRuntimeError):
    def __init__(
        self,
        operation: str,
        timeout_seconds: float,
        *,
        worker_pid: Optional[int],
        worker_generation: int,
        worker_exitcode: Optional[int],
    ) -> None:
        super().__init__(f"Kuzu {operation} exceeded {timeout_seconds:g}s")
        self.operation = operation
        self.timeout_seconds = timeout_seconds
        self.worker_pid = worker_pid
        self.worker_generation = worker_generation
        self.worker_exitcode = worker_exitcode


class KuzuWorkerCrashed(KuzuRuntimeError):
    def __init__(
        self,
        operation: str,
        *,
        worker_pid: Optional[int],
        worker_generation: int,
        worker_exitcode: Optional[int],
        detail: str = "",
    ) -> None:
        message = f"Kuzu worker exited while processing {operation}"
        if worker_exitcode is not None:
            message += f" (exitcode={worker_exitcode})"
        if detail:
            message += f": {detail}"
        super().__init__(message)
        self.operation = operation
        self.worker_pid = worker_pid
        self.worker_generation = worker_generation
        self.worker_exitcode = worker_exitcode
        self.detail = detail


@dataclass(frozen=True)
class KuzuRuntimeResponse:
    request_id: str
    operation: str
    status: str
    output: str = ""
    rows: tuple[tuple[Any, ...], ...] = ()
    error_type: str = ""
    error_message: str = ""
    worker_pid: Optional[int] = None
    worker_generation: int = 0
    worker_reused: bool = False
    roundtrip_ms: float = 0.0
    timings_ms: Mapping[str, float] = field(default_factory=dict)

    @property
    def success(self) -> bool:
        return self.status == "SUCCESS"

    def telemetry(self) -> dict[str, Any]:
        return {
            "protocol": PROTOCOL_VERSION,
            "operation": self.operation,
            "status": self.status,
            "worker_pid": self.worker_pid,
            "worker_generation": self.worker_generation,
            "worker_reused": self.worker_reused,
            "roundtrip_ms": round(self.roundtrip_ms, 3),
            "timings_ms": {
                key: round(float(value), 3)
                for key, value in self.timings_ms.items()
            },
        }


def _utc_now() -> str:
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _wire_safe(value: Any, depth: int = 0) -> Any:
    """Convert Kuzu values to bounded, pickle-safe control-plane data."""

    if depth > 8:
        return repr(value)
    if value is None or isinstance(value, (str, int, float, bool, bytes)):
        return value
    if isinstance(value, (datetime.date, datetime.datetime, datetime.time)):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {
            str(key): _wire_safe(item, depth + 1)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return tuple(_wire_safe(item, depth + 1) for item in value)
    return str(value)


def _clean_statement(query: str) -> str:
    return str(query or "").strip().rstrip(";")


def _close_kuzu_handle(handle: Any) -> None:
    if handle is None:
        return
    close = getattr(handle, "close", None)
    if callable(close):
        try:
            close()
        except Exception:
            pass


def _runtime_worker(
    db_path: str,
    channel: Connection,
    generation: int,
    max_control_rows: int,
) -> None:
    """Own one Kuzu Database/Connection for the lifetime of a graph epoch.

    The process is intentionally single-threaded. EXPLAIN, context reads and
    target execution therefore observe one ordered database state and never
    contend for an embedded-database file lock. The parent retains the ability
    to terminate this process at the hard timeout boundary.
    """

    database = None
    connection = None
    startup_started = time.monotonic()
    try:
        import kuzu

        database = kuzu.Database(db_path)
        connection = kuzu.Connection(database)
        channel.send(
            {
                "protocol": PROTOCOL_VERSION,
                "kind": "READY",
                "worker_pid": os.getpid(),
                "worker_generation": generation,
                "started_at": _utc_now(),
                "db_open_ms": (time.monotonic() - startup_started) * 1000.0,
            }
        )
    except BaseException as exc:
        try:
            channel.send(
                {
                    "protocol": PROTOCOL_VERSION,
                    "kind": "START_ERROR",
                    "worker_pid": os.getpid(),
                    "worker_generation": generation,
                    "error_type": type(exc).__name__,
                    "error_message": str(exc),
                }
            )
        except BaseException:
            pass
        _close_kuzu_handle(connection)
        _close_kuzu_handle(database)
        channel.close()
        return

    try:
        while True:
            try:
                request = channel.recv()
            except EOFError:
                return

            if not isinstance(request, dict):
                continue
            request_id = str(request.get("request_id", ""))
            operation = str(request.get("operation", ""))
            if operation == "shutdown":
                channel.send(
                    {
                        "protocol": PROTOCOL_VERSION,
                        "kind": "RESPONSE",
                        "request_id": request_id,
                        "operation": operation,
                        "status": "SUCCESS",
                        "worker_pid": os.getpid(),
                        "worker_generation": generation,
                        "timings_ms": {"execute": 0.0, "serialize": 0.0, "total": 0.0},
                    }
                )
                return

            request_started = time.monotonic()
            execute_started = request_started
            try:
                query = _clean_statement(request.get("query", ""))
                output = ""
                rows: tuple[tuple[Any, ...], ...] = ()

                if operation == "ping":
                    result = connection.execute("RETURN 1")
                    if result.has_next():
                        result.get_next()
                elif operation == "compile":
                    result = connection.execute("EXPLAIN " + query)
                    while result.has_next():
                        result.get_next()
                elif operation == "execute":
                    result = connection.execute(query)
                    if result.has_next():
                        output = str(_wire_safe(result.get_next()))
                    else:
                        output = "Empty result"
                elif operation == "query_rows":
                    result = connection.execute(query)
                    materialized: list[tuple[Any, ...]] = []
                    while result.has_next():
                        if len(materialized) >= max_control_rows:
                            raise RuntimeError(
                                f"control query exceeded {max_control_rows} materialized rows"
                            )
                        row = result.get_next()
                        materialized.append(tuple(_wire_safe(item) for item in row))
                    rows = tuple(materialized)
                else:
                    raise ValueError(f"unsupported Kuzu worker operation: {operation}")

                execute_finished = time.monotonic()
                response = {
                    "protocol": PROTOCOL_VERSION,
                    "kind": "RESPONSE",
                    "request_id": request_id,
                    "operation": operation,
                    "status": "SUCCESS",
                    "output": output,
                    "rows": rows,
                    "worker_pid": os.getpid(),
                    "worker_generation": generation,
                    "timings_ms": {
                        "execute": (execute_finished - execute_started) * 1000.0,
                        "serialize": (time.monotonic() - execute_finished) * 1000.0,
                        "total": (time.monotonic() - request_started) * 1000.0,
                    },
                }
            except BaseException as exc:
                response = {
                    "protocol": PROTOCOL_VERSION,
                    "kind": "RESPONSE",
                    "request_id": request_id,
                    "operation": operation,
                    "status": "ERROR",
                    "error_type": type(exc).__name__,
                    "error_message": str(exc),
                    "worker_pid": os.getpid(),
                    "worker_generation": generation,
                    "timings_ms": {
                        "execute": (time.monotonic() - execute_started) * 1000.0,
                        "serialize": 0.0,
                        "total": (time.monotonic() - request_started) * 1000.0,
                    },
                }

            try:
                channel.send(response)
            except (BrokenPipeError, EOFError, OSError):
                return
    finally:
        _close_kuzu_handle(connection)
        _close_kuzu_handle(database)
        try:
            channel.close()
        except OSError:
            pass


class KuzuWorkerSupervisor:
    """Crash-contained, reusable Kuzu runtime with a hard timeout boundary."""

    def __init__(
        self,
        db_path: str,
        *,
        startup_timeout_seconds: float = 30.0,
        shutdown_timeout_seconds: float = 5.0,
        poll_interval_seconds: float = 0.05,
        max_control_rows: int = 10_000,
        start_method: str = "spawn",
    ) -> None:
        self.db_path = str(db_path)
        self.startup_timeout_seconds = max(0.1, float(startup_timeout_seconds))
        self.shutdown_timeout_seconds = max(0.1, float(shutdown_timeout_seconds))
        self.poll_interval_seconds = max(0.001, float(poll_interval_seconds))
        self.max_control_rows = max(1, int(max_control_rows))
        self._context = multiprocessing.get_context(start_method)
        self._lock = threading.RLock()
        self._process: Optional[multiprocessing.Process] = None
        self._channel: Optional[Connection] = None
        self._generation = 0
        self._closed = False
        self._starts = 0
        self._graceful_stops = 0
        self._forced_stops = 0
        self._crashes = 0
        self._request_counts: Counter[str] = Counter()
        self._success_counts: Counter[str] = Counter()
        self._error_counts: Counter[str] = Counter()
        self._timeout_counts: Counter[str] = Counter()
        self._total_roundtrip_ms: defaultdict[str, float] = defaultdict(float)
        self._last_startup: dict[str, Any] = {}
        self._last_response: dict[str, Any] = {}

    @property
    def generation(self) -> int:
        return self._generation

    @property
    def active_pid(self) -> Optional[int]:
        process = self._process
        return process.pid if process is not None and process.is_alive() else None

    def _receive_until_locked(self, deadline: Optional[float], operation: str) -> dict[str, Any]:
        channel = self._channel
        process = self._process
        if channel is None or process is None:
            raise KuzuWorkerCrashed(
                operation,
                worker_pid=None,
                worker_generation=self._generation,
                worker_exitcode=None,
                detail="worker channel is unavailable",
            )

        while True:
            if deadline is None:
                wait_seconds = self.poll_interval_seconds
            else:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                wait_seconds = min(self.poll_interval_seconds, remaining)
            try:
                if channel.poll(wait_seconds):
                    return channel.recv()
            except (EOFError, BrokenPipeError, OSError) as exc:
                process.join(timeout=0.2)
                raise KuzuWorkerCrashed(
                    operation,
                    worker_pid=process.pid,
                    worker_generation=self._generation,
                    worker_exitcode=process.exitcode,
                    detail=f"{type(exc).__name__}: {exc}",
                ) from exc
            if not process.is_alive():
                process.join(timeout=0.2)
                raise KuzuWorkerCrashed(
                    operation,
                    worker_pid=process.pid,
                    worker_generation=self._generation,
                    worker_exitcode=process.exitcode,
                )

    def _ensure_worker_locked(self) -> bool:
        if self._closed:
            raise KuzuRuntimeError("Kuzu worker supervisor is closed")
        if self._process is not None and self._process.is_alive() and self._channel is not None:
            return True

        self._discard_worker_locked(force=True, count_forced=False)
        self._generation += 1
        parent_channel, child_channel = self._context.Pipe(duplex=True)
        process = self._context.Process(
            target=_runtime_worker,
            args=(self.db_path, child_channel, self._generation, self.max_control_rows),
            name=f"graf-kuzu-runtime-{self._generation}",
            daemon=True,
        )
        self._channel = parent_channel
        self._process = process
        process.start()
        child_channel.close()
        self._starts += 1
        try:
            startup = self._receive_until_locked(
                time.monotonic() + self.startup_timeout_seconds,
                "startup",
            )
        except TimeoutError as exc:
            pid = process.pid
            self._discard_worker_locked(force=True, count_forced=True)
            raise KuzuWorkerStartError(
                f"Kuzu worker startup exceeded {self.startup_timeout_seconds:g}s (pid={pid})"
            ) from exc
        except KuzuWorkerCrashed as exc:
            self._crashes += 1
            self._discard_worker_locked(force=True, count_forced=False)
            raise KuzuWorkerStartError(str(exc)) from exc

        if startup.get("protocol") != PROTOCOL_VERSION or startup.get("kind") != "READY":
            self._discard_worker_locked(force=True, count_forced=True)
            raise KuzuWorkerStartError(
                f"Kuzu worker failed to initialize: "
                f"{startup.get('error_type', 'ProtocolError')}: "
                f"{startup.get('error_message', 'invalid startup response')}"
            )
        self._last_startup = dict(startup)
        return False

    def request(
        self,
        operation: str,
        *,
        query: str = "",
        timeout_seconds: float = 0,
    ) -> KuzuRuntimeResponse:
        timeout_seconds = max(0.0, float(timeout_seconds))
        with self._lock:
            reused = self._ensure_worker_locked()
            process = self._process
            channel = self._channel
            if process is None or channel is None:
                raise KuzuRuntimeError("Kuzu worker did not initialize")

            request_id = uuid.uuid4().hex
            payload = {
                "protocol": PROTOCOL_VERSION,
                "request_id": request_id,
                "operation": operation,
                "query": str(query or ""),
                "sent_at": _utc_now(),
            }
            started = time.monotonic()
            self._request_counts[operation] += 1
            try:
                channel.send(payload)
                deadline = started + timeout_seconds if timeout_seconds > 0 else None
                while True:
                    response = self._receive_until_locked(deadline, operation)
                    if response.get("request_id") == request_id:
                        break
            except TimeoutError as exc:
                pid = process.pid
                generation = self._generation
                self._timeout_counts[operation] += 1
                exitcode = self._discard_worker_locked(force=True, count_forced=True)
                raise KuzuWorkerTimeout(
                    operation,
                    timeout_seconds,
                    worker_pid=pid,
                    worker_generation=generation,
                    worker_exitcode=exitcode,
                ) from exc
            except KuzuWorkerCrashed:
                self._crashes += 1
                self._discard_worker_locked(force=True, count_forced=False)
                raise
            except (BrokenPipeError, EOFError, OSError) as exc:
                pid = process.pid
                generation = self._generation
                process.join(timeout=0.2)
                exitcode = process.exitcode
                self._crashes += 1
                self._discard_worker_locked(force=True, count_forced=False)
                raise KuzuWorkerCrashed(
                    operation,
                    worker_pid=pid,
                    worker_generation=generation,
                    worker_exitcode=exitcode,
                    detail=f"{type(exc).__name__}: {exc}",
                ) from exc

            roundtrip_ms = (time.monotonic() - started) * 1000.0
            status = str(response.get("status", "ERROR"))
            if status == "SUCCESS":
                self._success_counts[operation] += 1
            else:
                self._error_counts[operation] += 1
            self._total_roundtrip_ms[operation] += roundtrip_ms
            self._last_response = {
                "operation": operation,
                "status": status,
                "worker_pid": response.get("worker_pid"),
                "worker_generation": response.get("worker_generation", self._generation),
                "worker_reused": reused,
                "roundtrip_ms": round(roundtrip_ms, 3),
                "timings_ms": dict(response.get("timings_ms") or {}),
            }
            raw_rows = response.get("rows") or ()
            return KuzuRuntimeResponse(
                request_id=request_id,
                operation=operation,
                status=status,
                output=str(response.get("output", "")),
                rows=tuple(tuple(row) for row in raw_rows),
                error_type=str(response.get("error_type", "")),
                error_message=str(response.get("error_message", "")),
                worker_pid=response.get("worker_pid"),
                worker_generation=int(response.get("worker_generation", self._generation)),
                worker_reused=reused,
                roundtrip_ms=roundtrip_ms,
                timings_ms=dict(response.get("timings_ms") or {}),
            )

    def _discard_worker_locked(self, *, force: bool, count_forced: bool) -> Optional[int]:
        process = self._process
        channel = self._channel
        self._process = None
        self._channel = None
        exitcode = None
        if process is not None:
            if process.is_alive() and force:
                process.terminate()
                process.join(timeout=self.shutdown_timeout_seconds)
                if process.is_alive() and hasattr(process, "kill"):
                    process.kill()
                    process.join(timeout=self.shutdown_timeout_seconds)
                if count_forced:
                    self._forced_stops += 1
            elif not process.is_alive():
                process.join(timeout=0.2)
            exitcode = process.exitcode
            try:
                process.close()
            except (OSError, ValueError):
                pass
        if channel is not None:
            try:
                channel.close()
            except OSError:
                pass
        return exitcode

    def restart_boundary(self, reason: str = "graph_epoch_changed") -> None:
        """Stop the worker before an external graph reset; restart lazily."""

        del reason  # The caller records the graph reset reason in its journal.
        with self._lock:
            self._graceful_stop_locked()

    def _graceful_stop_locked(self) -> None:
        process = self._process
        channel = self._channel
        if process is None:
            return
        if process.is_alive() and channel is not None:
            request_id = uuid.uuid4().hex
            try:
                channel.send(
                    {
                        "protocol": PROTOCOL_VERSION,
                        "request_id": request_id,
                        "operation": "shutdown",
                        "query": "",
                        "sent_at": _utc_now(),
                    }
                )
                deadline = time.monotonic() + self.shutdown_timeout_seconds
                while process.is_alive() and time.monotonic() < deadline:
                    wait_seconds = max(
                        0.0,
                        min(self.poll_interval_seconds, deadline - time.monotonic()),
                    )
                    if channel.poll(wait_seconds):
                        response = channel.recv()
                        if response.get("request_id") == request_id:
                            break
                process.join(timeout=max(0.0, deadline - time.monotonic()))
            except (EOFError, BrokenPipeError, OSError, ValueError):
                pass
        if process.is_alive():
            self._discard_worker_locked(force=True, count_forced=True)
        else:
            self._graceful_stops += 1
            self._discard_worker_locked(force=False, count_forced=False)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._graceful_stop_locked()
            self._closed = True

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            process = self._process
            active = bool(process is not None and process.is_alive())
            operations = sorted(
                set(self._request_counts)
                | set(self._success_counts)
                | set(self._error_counts)
                | set(self._timeout_counts)
            )
            per_operation = {}
            for operation in operations:
                requests = int(self._request_counts[operation])
                per_operation[operation] = {
                    "requests": requests,
                    "successes": int(self._success_counts[operation]),
                    "errors": int(self._error_counts[operation]),
                    "timeouts": int(self._timeout_counts[operation]),
                    "mean_roundtrip_ms": (
                        round(float(self._total_roundtrip_ms[operation]) / requests, 3)
                        if requests
                        else 0.0
                    ),
                }
            return {
                "schema": "graf-kuzu-runtime-telemetry/v1",
                "protocol": PROTOCOL_VERSION,
                "db_path": self.db_path,
                "worker_active": active,
                "worker_pid": process.pid if active and process is not None else None,
                "worker_generation": self._generation,
                "worker_starts": self._starts,
                "graceful_stops": self._graceful_stops,
                "forced_stops": self._forced_stops,
                "worker_crashes": self._crashes,
                "operations": per_operation,
                "last_startup": dict(self._last_startup),
                "last_response": dict(self._last_response),
            }

