import os
import shutil
import time

from SeedGraph import (
    SHARED_SEED_CYPHER, 
    KUZU_SCHEMA, KUZU_DATA, 
    NEBULA_SCHEMA, NEBULA_DATA
)

try:
    from neo4j import GraphDatabase
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
except ImportError:
    pass


# ========================================================================================
# 1. Memgraph 种子图构造器
# ========================================================================================
class MemgraphSeedGenerator:
    def __init__(
        self,
        uri: str,
        user: str = "",
        password: str = "",
        ready_timeout_s: int = 60,
        delete_batch_size: int = 1000,
        delete_max_batches: int = 1000,
    ):
        self.uri = uri
        self.auth = (user, password)
        self.ready_timeout_s = ready_timeout_s
        self.delete_batch_size = delete_batch_size
        self.delete_max_batches = delete_max_batches
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self.seed_cypher = SHARED_SEED_CYPHER

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
            "请先确认 memgraph_fuzz_target 容器正在运行，并且宿主机 7687 已映射到容器 7687。"
        )

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

    def _assert_seed_graph(self, session):
        record = session.run("MATCH (n) RETURN count(n) AS nodes").single()
        node_count = int(record["nodes"]) if record else 0
        if node_count <= 0:
            raise RuntimeError("Memgraph seed graph verification failed: node count is 0")

    def reset_and_initialize(self, reset: bool = True):
        print("[Memgraph] 开始构建初始种子图...")
        print("[Memgraph] 等待 Bolt 服务就绪...")
        self._wait_until_ready()
        if not reset:
            print("[Memgraph] init-mode=reuse，跳过清空和种子注入。")
            return
        with self.driver.session() as session:
            print("正在分批清空现有数据库 (DETACH DELETE)...")
            deleted = self._clear_database(session)
            print(f"清空完成，删除节点数: {deleted}")
            print("正在注入强类型的初始化拓扑...")
            session.run(self.seed_cypher).consume()
            self._assert_seed_graph(session)
            print("种子图注入完毕！")


class Neo4jSeedGenerator:
    def __init__(
        self,
        uri: str = "bolt://localhost:7687",
        user: str = "neo4j",
        password: str = "testpassword",
        database: str = "neo4j",
        ready_timeout_s: int = 90,
        delete_batch_size: int = 1000,
        delete_max_batches: int = 1000,
    ):
        self.uri = uri
        self.auth = (user, password)
        self.database = database
        self.ready_timeout_s = ready_timeout_s
        self.delete_batch_size = delete_batch_size
        self.delete_max_batches = delete_max_batches
        self.driver = GraphDatabase.driver(uri, auth=self.auth)
        self.seed_cypher = SHARED_SEED_CYPHER

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
            deleted = int(record["deleted"]) if record else 0
            total_deleted += deleted
            if deleted == 0:
                return total_deleted
        raise RuntimeError(
            f"Neo4j clear exceeded {self.delete_max_batches} batches "
            f"(batch_size={self.delete_batch_size}, deleted>={total_deleted})"
        )

    def _assert_seed_graph(self, session):
        record = session.run("MATCH (n) RETURN count(n) AS nodes").single()
        node_count = int(record["nodes"]) if record else 0
        if node_count <= 0:
            raise RuntimeError("Neo4j seed graph verification failed: node count is 0")

    def reset_and_initialize(self, reset: bool = True):
        print(f"[Neo4j] 开始构建初始种子图 (Database: {self.database})...")
        print("[Neo4j] 等待 Bolt 服务就绪...")
        self._wait_until_ready()
        if not reset:
            print("[Neo4j] init-mode=reuse，跳过清空和种子注入。")
            return
        with self.driver.session(database=self.database) as session:
            print("正在分批清空现有数据库 (DETACH DELETE)...")
            deleted = self._clear_database(session)
            print(f"清空完成，删除节点数: {deleted}")
            print("正在注入强类型的初始化拓扑...")
            session.run(self.seed_cypher).consume()
            self._assert_seed_graph(session)
            print("种子图注入完毕！")

# ========================================================================================
# 2. FalkorDB 种子图构造器
# ========================================================================================
class FalkorDBSeedGenerator:
    def __init__(self, host="localhost", port=6379, password="", graph_name="graf_fuzz"):
        self.db = FalkorDB(host=host, port=port, password=password)
        self.graph_name = graph_name
        self.graph = self.db.select_graph(graph_name)
        self.seed_cypher = SHARED_SEED_CYPHER

    def close(self):
        self.db.connection.close()

    def reset_and_initialize(self):
        print(f"[FalkorDB] 开始构建初始种子图 (Graph: {self.graph_name})...")
        try:
            self.graph.delete()
            print("正在清空现有数据库 (Graph.delete)...")
        except Exception:
            pass  

        print("正在注入初始化拓扑...")
        
        if isinstance(self.seed_cypher, str):
            statements = self.seed_cypher.split('\n')
        else:
            statements = self.seed_cypher

        success_count = 0
        for stmt in statements:
            stmt = stmt.strip()
            if not stmt or stmt.startswith('//'):
                continue
                
            try:
                self.graph.query(stmt)
                success_count += 1
            except Exception as e:
                print(f"数据注入警告: {str(e)} -> {stmt}")

        print(f"种子图注入完毕！成功执行了 {success_count} 条语句。")


class KuzuSeedGenerator:
    def __init__(self, db_path="./kuzu_fuzz_test"):
        self.db_path = db_path
        self.seed_cypher = "\n".join(KUZU_SCHEMA + KUZU_DATA)

    def close(self):
        pass # Kuzu 无需显式关闭网络连接

    def reset_and_initialize(self):
        print(f"[KùzuDB] 开始构建初始种子图 (嵌入式路径: {self.db_path})...")
        
        print("正在销毁旧数据库文件...")
        if os.path.exists(self.db_path):
            if os.path.isdir(self.db_path):
                shutil.rmtree(self.db_path)
            else:
                os.remove(self.db_path)
                
        # 清除附带的预写式日志 (WAL)
        wal_path = f"{self.db_path}.wal"
        if os.path.exists(wal_path):
            os.remove(wal_path)

        # 启动嵌入式实例 (Kuzu 会自动在这里创建一个同名单文件)
        db = kuzu.Database(self.db_path)
        conn = kuzu.Connection(db)

        print("正在创建强类型 Schema (DDL)...")
        for stmt in KUZU_SCHEMA:
            conn.execute(stmt)

        print("正在注入初始化数据 (DML)...")
        for stmt in KUZU_DATA:
            conn.execute(stmt)
            
        print("种子图注入完毕！")
        del conn
        del db

class NebulaSeedGenerator:
    def __init__(self, host="127.0.0.1", port=9669, user="root", password="nebula"):
        self.config = Config()
        self.config.max_connection_pool_size = 2
        self.pool = ConnectionPool()
        if not self.pool.init([(host, port)], self.config):
            raise Exception("❌ NebulaGraph 连接池初始化失败")
        self.session = self.pool.get_session(user, password)
        self.seed_cypher = "\n".join(NEBULA_SCHEMA + NEBULA_DATA)

    def close(self):
        self.session.release()
        self.pool.close()

    def reset_and_initialize(self):
        import time
        print("[NebulaGraph] 开始构建初始种子图...")
        
        print("正在创建 SPACE...")
        self.session.execute(NEBULA_SCHEMA[0]) # 执行 CREATE SPACE
            
        print("等待 NebulaGraph 分布式心跳同步 (15秒)...")
        time.sleep(15)
        
        print("尝试挂载 SPACE...")
        space_ready = False
        for _ in range(5):
            if self.session.execute(NEBULA_SCHEMA[1]).is_succeeded(): # 执行 USE graf_fuzz
                space_ready = True
                break
            time.sleep(3)
            
        if not space_ready:
            raise Exception("SPACE 同步失败，集群心跳异常。")

        print("正在创建分布式 Schema (TAG / EDGE)...")
        for stmt in NEBULA_SCHEMA[2:]:
            self.session.execute(stmt)
            
        print("等待 Schema 同步至所有 Graphd 节点 (15秒)...")
        time.sleep(15)

        print("正在注入初始化数据 (INSERT)...")
        for stmt in NEBULA_DATA:
            resp = self.session.execute(stmt)
            if not resp.is_succeeded():
                print(f" 数据插入警告: {resp.error_msg()}")

        print("种子图注入完毕！")


if __name__ == "__main__":
    print("==================================================")
    print("跨引擎图数据库种子图构造器本地测试")
    print("==================================================")
    
    target = "kuzu" 
    
    try:
        if target == "memgraph":
            generator = MemgraphSeedGenerator("bolt://localhost:7687", "", "")
        elif target == "falkordb":
            generator = FalkorDBSeedGenerator(host="localhost", port=6379, password="", graph_name="graf_fuzz")
        elif target == "kuzu":
            generator = KuzuSeedGenerator(db_path="./kuzu_fuzz_test")
        elif target == "nebula":
            generator = NebulaSeedGenerator(host="127.0.0.1", port=9669)
            
        generator.reset_and_initialize()
        generator.close()
        print(f"\n{target.upper()} 初始化完成")
        
    except Exception as e:
        print(f"初始化失败: {e}")
