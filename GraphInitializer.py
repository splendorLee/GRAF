"""Cross-engine initialization from a single typed seed-graph specification."""

from __future__ import annotations

import os
import re
import shutil
import time
from pathlib import Path
from typing import Any, Iterable

from graf.seed_profiles import (
    GraphSeedSpec,
    render_kuzu,
    render_nebula,
    render_shared_cypher,
    seed_profile,
    statements_as_script,
)

try:
    from neo4j import GraphDatabase
except ImportError:  # pragma: no cover - target-specific optional dependency
    GraphDatabase = None

try:
    from falkordb import FalkorDB
except ImportError:  # pragma: no cover - target-specific optional dependency
    FalkorDB = None

try:
    import kuzu
except ImportError:  # pragma: no cover - target-specific optional dependency
    kuzu = None

try:
    from nebula3.gclient.net import ConnectionPool
    from nebula3.Config import Config
except ImportError:  # pragma: no cover - target-specific optional dependency
    ConnectionPool = None
    Config = None


def _default_spec(seed_spec: GraphSeedSpec | None) -> GraphSeedSpec:
    return seed_spec or seed_profile("baseline")


def _require_dependency(value: Any, package: str) -> None:
    if value is None:
        raise RuntimeError(f"Missing target dependency: install {package}")


def _assert_exact(actual: int, expected: int, engine: str, subject: str) -> None:
    if actual != expected:
        raise RuntimeError(
            f"{engine} seed graph verification failed for {subject}: "
            f"expected {expected}, observed {actual}"
        )


def _record_int(record: Any, key: str) -> int:
    if record is None:
        return 0
    try:
        return int(record[key])
    except (KeyError, TypeError):
        try:
            return int(record[0])
        except (IndexError, KeyError, TypeError):
            return 0


def execute_driver_seed(session: Any, statements: Iterable[str]) -> None:
    for statement in statements:
        session.run(statement).consume()


def verify_driver_seed(session: Any, spec: GraphSeedSpec, engine: str) -> None:
    nodes = _record_int(session.run("MATCH (n) RETURN count(n) AS count").single(), "count")
    edges = _record_int(session.run("MATCH ()-[r]->() RETURN count(r) AS count").single(), "count")
    _assert_exact(nodes, len(spec.nodes), engine, "total nodes")
    _assert_exact(edges, len(spec.edges), engine, "total relationships")
    for label, expected in spec.node_counts().items():
        actual = _record_int(
            session.run(f"MATCH (n:`{label}`) RETURN count(n) AS count").single(), "count"
        )
        _assert_exact(actual, expected, engine, f"label {label}")
    for rel_type, expected in spec.relationship_counts().items():
        actual = _record_int(
            session.run(f"MATCH ()-[r:`{rel_type}`]->() RETURN count(r) AS count").single(),
            "count",
        )
        _assert_exact(actual, expected, engine, f"relationship {rel_type}")


class _SharedCypherSeed:
    seed_spec: GraphSeedSpec
    seed_statements: tuple[str, ...]
    seed_cypher: str

    def set_seed_spec(self, seed_spec: GraphSeedSpec) -> None:
        self.seed_spec = _default_spec(seed_spec)
        self.seed_statements = render_shared_cypher(self.seed_spec)
        self.seed_cypher = statements_as_script(self.seed_statements)

    @property
    def seed_manifest(self) -> dict[str, object]:
        return self.seed_spec.manifest()


class MemgraphSeedGenerator(_SharedCypherSeed):
    def __init__(
        self,
        uri: str,
        user: str = "",
        password: str = "",
        ready_timeout_s: int = 60,
        delete_batch_size: int = 1000,
        delete_max_batches: int = 1000,
        seed_spec: GraphSeedSpec | None = None,
    ):
        _require_dependency(GraphDatabase, "neo4j")
        self.uri = uri
        self.auth = (user, password)
        self.ready_timeout_s = ready_timeout_s
        self.delete_batch_size = delete_batch_size
        self.delete_max_batches = delete_max_batches
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self.set_seed_spec(_default_spec(seed_spec))

    def close(self):
        self.driver.close()

    def _wait_until_ready(self):
        deadline = time.time() + self.ready_timeout_s
        last_error = None
        while time.time() < deadline:
            try:
                self.driver.verify_connectivity()
                with self.driver.session() as session:
                    session.run("RETURN 1 AS ok").consume()
                return
            except Exception as exc:
                last_error = exc
                time.sleep(2)
        raise RuntimeError(
            f"Memgraph did not become ready within {self.ready_timeout_s}s: {last_error}. "
            "请确认测试容器和 Bolt 端口映射可用。"
        )

    def _clear_database(self, session):
        total_deleted = 0
        for _ in range(self.delete_max_batches):
            record = session.run(
                "MATCH (n) WITH n LIMIT $batch_size DETACH DELETE n RETURN count(n) AS deleted",
                batch_size=self.delete_batch_size,
            ).single()
            deleted = _record_int(record, "deleted")
            total_deleted += deleted
            if deleted == 0:
                return total_deleted
        raise RuntimeError(
            f"Memgraph clear exceeded {self.delete_max_batches} batches "
            f"(batch_size={self.delete_batch_size}, deleted>={total_deleted})"
        )

    def reset_and_initialize(self, reset: bool = True):
        print(f"[Memgraph] 初始化种子图 profile={self.seed_spec.name}...")
        self._wait_until_ready()
        if not reset:
            print("[Memgraph] init-mode=reuse，跳过清空和种子注入。")
            return
        with self.driver.session() as session:
            deleted = self._clear_database(session)
            execute_driver_seed(session, self.seed_statements)
            verify_driver_seed(session, self.seed_spec, "Memgraph")
        print(
            f"[Memgraph] 注入并校验完成，删除={deleted}，"
            f"节点={len(self.seed_spec.nodes)}，边={len(self.seed_spec.edges)}。"
        )


class Neo4jSeedGenerator(_SharedCypherSeed):
    def __init__(
        self,
        uri: str = "bolt://localhost:7687",
        user: str = "neo4j",
        password: str = "testpassword",
        database: str = "neo4j",
        ready_timeout_s: int = 90,
        delete_batch_size: int = 1000,
        delete_max_batches: int = 1000,
        seed_spec: GraphSeedSpec | None = None,
    ):
        _require_dependency(GraphDatabase, "neo4j")
        self.uri = uri
        self.auth = (user, password)
        self.database = database
        self.ready_timeout_s = ready_timeout_s
        self.delete_batch_size = delete_batch_size
        self.delete_max_batches = delete_max_batches
        self.driver = GraphDatabase.driver(uri, auth=self.auth)
        self.set_seed_spec(_default_spec(seed_spec))

    def close(self):
        self.driver.close()

    def _wait_until_ready(self):
        deadline = time.time() + self.ready_timeout_s
        last_error = None
        while time.time() < deadline:
            try:
                self.driver.verify_connectivity()
                with self.driver.session(database=self.database) as session:
                    session.run("RETURN 1 AS ok").consume()
                return
            except Exception as exc:
                last_error = exc
                time.sleep(2)
        raise RuntimeError(f"Neo4j did not become ready within {self.ready_timeout_s}s: {last_error}")

    def _clear_database(self, session):
        total_deleted = 0
        for _ in range(self.delete_max_batches):
            record = session.run(
                "MATCH (n) WITH n LIMIT $batch_size DETACH DELETE n RETURN count(n) AS deleted",
                batch_size=self.delete_batch_size,
            ).single()
            deleted = _record_int(record, "deleted")
            total_deleted += deleted
            if deleted == 0:
                return total_deleted
        raise RuntimeError(
            f"Neo4j clear exceeded {self.delete_max_batches} batches "
            f"(batch_size={self.delete_batch_size}, deleted>={total_deleted})"
        )

    def reset_and_initialize(self, reset: bool = True):
        print(
            f"[Neo4j] 初始化种子图 database={self.database} "
            f"profile={self.seed_spec.name}..."
        )
        self._wait_until_ready()
        if not reset:
            print("[Neo4j] init-mode=reuse，跳过清空和种子注入。")
            return
        with self.driver.session(database=self.database) as session:
            deleted = self._clear_database(session)
            execute_driver_seed(session, self.seed_statements)
            verify_driver_seed(session, self.seed_spec, "Neo4j")
        print(
            f"[Neo4j] 注入并校验完成，删除={deleted}，"
            f"节点={len(self.seed_spec.nodes)}，边={len(self.seed_spec.edges)}。"
        )


class FalkorDBSeedGenerator(_SharedCypherSeed):
    def __init__(
        self,
        host="localhost",
        port=6379,
        password="",
        graph_name="graf_fuzz",
        seed_spec: GraphSeedSpec | None = None,
    ):
        _require_dependency(FalkorDB, "falkordb")
        self.host = host
        self.port = int(port)
        self.password = password
        self.graph_name = graph_name
        self.db = None
        self.graph = None
        self._connect()
        self.set_seed_spec(_default_spec(seed_spec))

    def _connect(self):
        previous = self.db
        self.db = FalkorDB(host=self.host, port=self.port, password=self.password)
        self.graph = self.db.select_graph(self.graph_name)
        if previous is not None:
            try:
                previous.connection.close()
            except Exception:
                pass

    def _ensure_connection(self):
        try:
            self.db.connection.ping()
        except Exception:
            self._connect()
            self.db.connection.ping()

    def close(self):
        if self.db is not None:
            self.db.connection.close()

    @staticmethod
    def _query_count(graph: Any, query: str) -> int:
        response = graph.query(query)
        rows = getattr(response, "result_set", None) or []
        return int(rows[0][0]) if rows and rows[0] else 0

    def _verify_seed(self) -> None:
        _assert_exact(
            self._query_count(self.graph, "MATCH (n) RETURN count(n)"),
            len(self.seed_spec.nodes),
            "FalkorDB",
            "total nodes",
        )
        _assert_exact(
            self._query_count(self.graph, "MATCH ()-[r]->() RETURN count(r)"),
            len(self.seed_spec.edges),
            "FalkorDB",
            "total relationships",
        )
        for label, expected in self.seed_spec.node_counts().items():
            actual = self._query_count(self.graph, f"MATCH (n:`{label}`) RETURN count(n)")
            _assert_exact(actual, expected, "FalkorDB", f"label {label}")
        for rel_type, expected in self.seed_spec.relationship_counts().items():
            actual = self._query_count(
                self.graph, f"MATCH ()-[r:`{rel_type}`]->() RETURN count(r)"
            )
            _assert_exact(actual, expected, "FalkorDB", f"relationship {rel_type}")

    def reset_and_initialize(self, reset: bool = True):
        print(
            f"[FalkorDB] 初始化种子图 graph={self.graph_name} "
            f"profile={self.seed_spec.name}..."
        )
        self._ensure_connection()
        if not reset:
            print("[FalkorDB] init-mode=reuse，跳过清空和种子注入。")
            return
        try:
            self.graph.delete()
        except Exception as exc:
            message = str(exc).lower()
            if not any(token in message for token in ("does not exist", "not found", "unknown graph")):
                raise RuntimeError(f"FalkorDB graph reset failed: {exc}") from exc
        self.graph = self.db.select_graph(self.graph_name)

        completed = 0
        try:
            for statement in self.seed_statements:
                self.graph.query(statement)
                completed += 1
        except Exception as exc:
            raise RuntimeError(
                f"FalkorDB seed injection failed after {completed}/{len(self.seed_statements)} "
                f"statements: {type(exc).__name__}: {exc}"
            ) from exc
        self._verify_seed()
        print(
            f"[FalkorDB] 注入并校验完成，语句={completed}，"
            f"节点={len(self.seed_spec.nodes)}，边={len(self.seed_spec.edges)}。"
        )


class KuzuSeedGenerator:
    def __init__(self, db_path="./kuzu_fuzz_test", seed_spec: GraphSeedSpec | None = None):
        self.db_path = db_path
        self.set_seed_spec(_default_spec(seed_spec))

    def set_seed_spec(self, seed_spec: GraphSeedSpec) -> None:
        self.seed_spec = _default_spec(seed_spec)
        self.schema_statements, self.data_statements = render_kuzu(self.seed_spec)
        self.seed_statements = self.schema_statements + self.data_statements
        self.seed_cypher = statements_as_script(self.seed_statements)

    @property
    def seed_manifest(self) -> dict[str, object]:
        return self.seed_spec.manifest()

    def close(self):
        pass

    @staticmethod
    def _result_count(result: Any) -> int:
        return int(result.get_next()[0]) if result.has_next() else 0

    def _verify_seed(self, conn: Any) -> None:
        _assert_exact(
            self._result_count(conn.execute("MATCH (n) RETURN count(n)")),
            len(self.seed_spec.nodes),
            "Kuzu",
            "total nodes",
        )
        _assert_exact(
            self._result_count(conn.execute("MATCH ()-[r]->() RETURN count(r)")),
            len(self.seed_spec.edges),
            "Kuzu",
            "total relationships",
        )
        for label, expected in self.seed_spec.node_counts().items():
            actual = self._result_count(conn.execute(f"MATCH (n:`{label}`) RETURN count(n)"))
            _assert_exact(actual, expected, "Kuzu", f"label {label}")
        for rel_type, expected in self.seed_spec.relationship_counts().items():
            actual = self._result_count(
                conn.execute(f"MATCH ()-[r:`{rel_type}`]->() RETURN count(r)")
            )
            _assert_exact(actual, expected, "Kuzu", f"relationship {rel_type}")

    def reset_and_initialize(self, reset: bool = True):
        _require_dependency(kuzu, "kuzu")
        print(
            f"[Kuzu] 初始化种子图 path={self.db_path} "
            f"profile={self.seed_spec.name}..."
        )
        if not reset:
            if not os.path.exists(self.db_path):
                raise RuntimeError(
                    f"Kuzu init-mode=reuse requested but database does not exist: {self.db_path}"
                )
            db = kuzu.Database(self.db_path)
            conn = kuzu.Connection(db)
            conn.execute("RETURN 1")
            del conn
            del db
            print("[Kuzu] init-mode=reuse，现有数据库连通性检查通过。")
            return

        resolved_path = Path(self.db_path).expanduser().resolve()
        forbidden = {Path("/").resolve(), Path.home().resolve(), Path.cwd().resolve()}
        if resolved_path in forbidden:
            raise RuntimeError(f"Refusing unsafe Kuzu database reset path: {resolved_path}")
        if resolved_path.exists():
            shutil.rmtree(resolved_path) if resolved_path.is_dir() else resolved_path.unlink()
        wal_path = Path(f"{resolved_path}.wal")
        if wal_path.exists():
            shutil.rmtree(wal_path) if wal_path.is_dir() else wal_path.unlink()

        self.db_path = str(resolved_path)
        db = kuzu.Database(self.db_path)
        conn = kuzu.Connection(db)
        try:
            for statement in self.schema_statements:
                conn.execute(statement)
            for statement in self.data_statements:
                conn.execute(statement)
            self._verify_seed(conn)
        finally:
            del conn
            del db
        print(
            f"[Kuzu] 注入并校验完成，节点={len(self.seed_spec.nodes)}，"
            f"边={len(self.seed_spec.edges)}。"
        )


class NebulaSeedGenerator:
    def __init__(
        self,
        host="127.0.0.1",
        port=9669,
        user="root",
        password="nebula",
        space="graf_fuzz",
        ready_timeout_s=60,
        propagation_wait_s=15,
        seed_spec: GraphSeedSpec | None = None,
    ):
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", space or ""):
            raise ValueError(f"Unsafe NebulaGraph space identifier: {space!r}")
        _require_dependency(Config, "nebula3-python")
        self.space = space
        self.ready_timeout_s = max(1, int(ready_timeout_s))
        self.propagation_wait_s = max(0, int(propagation_wait_s))
        self.set_seed_spec(_default_spec(seed_spec))
        self.config = Config()
        self.config.max_connection_pool_size = 2
        self.pool = ConnectionPool()
        if not self.pool.init([(host, port)], self.config):
            raise RuntimeError("NebulaGraph connection pool initialization failed")
        self.session = self.pool.get_session(user, password)

    def set_seed_spec(self, seed_spec: GraphSeedSpec) -> None:
        self.seed_spec = _default_spec(seed_spec)
        self.schema_statements, self.data_statements = render_nebula(self.seed_spec, self.space)
        self.seed_statements = self.schema_statements + self.data_statements
        self.seed_cypher = statements_as_script(self.seed_statements)

    @property
    def seed_manifest(self) -> dict[str, object]:
        return self.seed_spec.manifest()

    def close(self):
        self.session.release()
        self.pool.close()

    @staticmethod
    def _error(response):
        if hasattr(response, "error_msg"):
            return str(response.error_msg())
        return str(response)

    def _execute_checked(self, statement, phase):
        sql = statement.rstrip(";") + ";"
        if phase not in {"DROP SPACE", "CREATE SPACE"} and not sql.lstrip().upper().startswith("USE "):
            # The session retains the selected space. Keep USE as its own
            # request so a multi-statement response cannot hide a failed USE.
            selected = self.session.execute(f"USE `{self.space}`;")
            if hasattr(selected, "is_succeeded") and not selected.is_succeeded():
                raise RuntimeError(f"NebulaGraph {phase} USE failed: {self._error(selected)}")
        response = self.session.execute(sql)
        if hasattr(response, "is_succeeded") and not response.is_succeeded():
            raise RuntimeError(f"NebulaGraph {phase} failed: {self._error(response)} | {statement}")
        return response

    def _wait_for_space(self):
        deadline = time.time() + self.ready_timeout_s
        last_error = "space not visible"
        while time.time() < deadline:
            response = self.session.execute(f"USE `{self.space}`;")
            if not hasattr(response, "is_succeeded") or response.is_succeeded():
                return
            last_error = self._error(response)
            time.sleep(2)
        raise RuntimeError(
            f"NebulaGraph space `{self.space}` was not ready within "
            f"{self.ready_timeout_s}s: {last_error}"
        )

    @staticmethod
    def _response_count(response: Any) -> int:
        if hasattr(response, "is_succeeded") and not response.is_succeeded():
            raise RuntimeError("count query failed")
        rows = response.rows() if hasattr(response, "rows") else []
        if not rows:
            return 0
        value = rows[0].values[0]
        if hasattr(value, "as_int"):
            return int(value.as_int())
        if hasattr(value, "get_iVal"):
            return int(value.get_iVal())
        return int(value.value if hasattr(value, "value") else value)

    def _count(self, query: str) -> int:
        response = self._execute_checked(query, "seed verification")
        return self._response_count(response)

    def _verify_seed(self) -> None:
        _assert_exact(
            self._count("MATCH (n) RETURN count(n)"),
            len(self.seed_spec.nodes),
            "NebulaGraph",
            "total nodes",
        )
        _assert_exact(
            self._count("MATCH ()-[r]->() RETURN count(r)"),
            len(self.seed_spec.edges),
            "NebulaGraph",
            "total relationships",
        )
        for label, expected in self.seed_spec.node_counts().items():
            actual = self._count(f"MATCH (n:`{label}`) RETURN count(n)")
            _assert_exact(actual, expected, "NebulaGraph", f"tag {label}")
        for rel_type, expected in self.seed_spec.relationship_counts().items():
            actual = self._count(f"MATCH ()-[r:`{rel_type}`]->() RETURN count(r)")
            _assert_exact(actual, expected, "NebulaGraph", f"edge {rel_type}")

    def reset_and_initialize(self, reset: bool = True):
        print(f"[NebulaGraph] 初始化种子图 profile={self.seed_spec.name}...")
        if not reset:
            self._wait_for_space()
            print("[NebulaGraph] init-mode=reuse，跳过 SPACE 重建和种子注入。")
            return

        self._execute_checked(self.schema_statements[0], "DROP SPACE")
        self._execute_checked(self.schema_statements[1], "CREATE SPACE")
        self._wait_for_space()
        for statement in self.schema_statements[3:]:
            self._execute_checked(statement, "schema creation")
        if self.propagation_wait_s:
            time.sleep(self.propagation_wait_s)
        for statement in self.data_statements[1:]:
            self._execute_checked(statement, "seed data injection")
        self._verify_seed()
        print(
            f"[NebulaGraph] 注入并校验完成，节点={len(self.seed_spec.nodes)}，"
            f"边={len(self.seed_spec.edges)}。"
        )


if __name__ == "__main__":
    generator = KuzuSeedGenerator(db_path="./kuzu_fuzz_test")
    try:
        generator.reset_and_initialize()
        print("KUZU 初始化完成")
    finally:
        generator.close()

