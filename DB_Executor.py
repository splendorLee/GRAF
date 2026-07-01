import time
import datetime
import os
import multiprocessing
from collections import defaultdict
from typing import Tuple, List
import sys
import subprocess
import redis

try:
    from neo4j import GraphDatabase
    from neo4j.exceptions import CypherSyntaxError, CypherTypeError, ClientError, DatabaseError, ServiceUnavailable
except ImportError:
    pass

try:
    from falkordb import FalkorDB
    from redis.exceptions import ConnectionError, TimeoutError, ResponseError
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


class BaseFuzzExecutor:
    def __init__(self, target_name: str, log_file: str, seed_cypher: str):
        self.target_name = target_name
        self.seed_cypher = seed_cypher
        
        current_dir = os.path.dirname(os.path.abspath(__file__))
        self.log_file = os.path.join(current_dir, log_file)
        
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(f"\n{'='*80}\n")
            f.write(f"[GRAF Fuzzer - {self.target_name}] Session Started at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"{'='*80}\n")
        
        self.stats = {"total_executed": 0, "passed": 0, "failed": 0, "total_time_ms": 0.0}
        self.error_ledger = defaultdict(int)
        self.bug_reports = []  
        self.global_query_history = [] 

    def _write_log(self, content: str):
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(content + "\n")
            f.flush() 
            os.fsync(f.fileno())

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
    def __init__(self, uri: str, user: str = "", password: str = "", log_file: str = "fuzzer_memgraph.log", seed_cypher: str = ""):
        super().__init__("Memgraph", log_file, seed_cypher)
        self.uri = uri
        self.auth = (user, password)
        self.driver = GraphDatabase.driver(self.uri, auth=self.auth)

    def close(self):
        self.driver.close()

    def _generate_poc_file(self, crashing_query: str, error_msg: str):
        poc_dir = os.path.join("crash_pocs", "memgraph")
        os.makedirs(poc_dir, exist_ok=True)
        timestamp = int(time.time())
        poc_filename = os.path.join(poc_dir, f"poc_crash_{timestamp}.cypher")
        
        # 内部清洗函数：去除反引号，补齐分号
        def clean_cypher(cypher: str) -> str:
            cypher = cypher.strip()
            if not cypher: return ""
            cypher = cypher.replace('`', '')
            if not cypher.endswith(';'): cypher += ';'
            return cypher

        with open(poc_filename, "w", encoding="utf-8") as f:
            f.write(f"//Memgraph Crash PoC\n// Error: {error_msg}\n\n")
            
            f.write("// [0] 清空数据库环境 (Clean Database)\n")
            f.write("MATCH (n) DETACH DELETE n;\n\n")
            
            if self.seed_cypher:
                f.write("// [1] 初始化建图语句 (Seed Graph Generation)\n")
                for line in self.seed_cypher.split('\n'):
                    line = line.strip()
                    if not line: continue
                    if line.startswith('//'):
                        f.write(f"{line}\n")
                    else:
                        f.write(f"{clean_cypher(line)}\n")
                f.write("\n")
                
            if self.global_query_history:
                f.write("// [2] 上游状态改变轨迹 (Upstream Execution History)\n")
                for q in self.global_query_history: 
                    f.write(f"{clean_cypher(q)}\n")
                f.write("\n")
                
            f.write("// [3] 致命一击 (The Killing Query)\n")
            f.write(f"{clean_cypher(crashing_query)}\n")
            
        print(f"\n[PoC 已导出] Memgraph: {poc_filename}")

    def execute_single(self, query: str) -> Tuple[bool, str, str]:
        self.stats["total_executed"] += 1
        start_time = time.time()
        is_success, status_msg, execution_output = False, "", ""
        
        try:
            with self.driver.session() as session:
                result = session.run(query)
                records = [str(record.data()) for i, record in enumerate(result) if i < 5]
                summary = result.consume() 
                
            elapsed_ms = (time.time() - start_time) * 1000
            self.stats["total_time_ms"] += elapsed_ms
            self.stats["passed"] += 1
            is_success = True
            status_msg = f"Success ({elapsed_ms:.2f}ms)"
            execution_output = "\n".join(records) if records else "Empty result"
            self.global_query_history.append(query)
            
        except (CypherSyntaxError, CypherTypeError, ClientError) as e:
            self.stats["failed"] += 1
            err_type = e.code if isinstance(e, ClientError) and e.code else type(e).__name__
            self.error_ledger[err_type] += 1
            status_msg = f"{err_type}: {e.message}"
            execution_output = "Semantic/Syntax Error"
            self.global_query_history.append(query)
            
        except (DatabaseError, ServiceUnavailable, OSError) as e:
            self.stats["failed"] += 1
            self.error_ledger["CRITICAL_DB_CRASH"] += 1
            self.bug_reports.append(query)
            status_msg = f"CRASH: {str(e)}"
            execution_output = "DATABASE CRASH DETECTED"
            self._generate_poc_file(query, str(e))
            
            print(f"容器重启中 (10s)...")
            time.sleep(10) 
            try:
                self.driver.close()
                self.driver = GraphDatabase.driver(self.uri, auth=self.auth)
                self.global_query_history.clear() 
                if self.seed_cypher:
                    with self.driver.session() as session:
                        session.run("MATCH (n) DETACH DELETE n")
                        session.run(self.seed_cypher)
            except Exception: pass
        except Exception as e:
            self.stats["failed"] += 1
            status_msg = f"Exception: {str(e)}"
            execution_output = "Unknown Error"

        self._write_log(f"[{self.stats['total_executed']}] Query: {query}\n--> Status: {status_msg}\n{'-'*60}")
        return is_success, status_msg, execution_output



class FalkorDBFuzzExecutor(BaseFuzzExecutor):
    def __init__(self, host="localhost", port=6379, password="", graph_name="graf_fuzz", log_file="fuzzer_falkordb.log", seed_cypher=""):
        super().__init__("FalkorDB", log_file, seed_cypher)
        self.host = host
        self.port = port
        self.password = password
        self.graph_name = graph_name
        
        self.db = FalkorDB(host=self.host, port=self.port, password=self.password)
        self.graph = self.db.select_graph(self.graph_name)
        
        self.container_name = "falkordb_fuzz_target" 
        self.initializer = None

    def close(self):
        self.db.connection.close()

    def _generate_poc_file(self, crashing_query: str, error_msg: str):
        
        poc_dir = os.path.join("crash_pocs", "falkordb")
        os.makedirs(poc_dir, exist_ok=True)
        timestamp = int(time.time())
        poc_filename = os.path.join(poc_dir, f"poc_crash_{timestamp}.redis")
        
        def wrap_query(cypher: str) -> str:
            cypher = cypher.strip()
            if not cypher: return ""
            # 去除反引号并确保分号结尾
            cypher = cypher.replace('`', '')
            if not cypher.endswith(';'): cypher += ';'
            escaped_cypher = cypher.replace('"', '\\"')
            return f'GRAPH.QUERY {self.graph_name} "{escaped_cypher}"'

        with open(poc_filename, "w", encoding="utf-8") as f:
            f.write(f"// FalkorDB Crash PoC\n")
            f.write(f"// Error: {error_msg}\n")
            f.write(f"// Port: {self.port}\n\n")

            if self.seed_cypher:
                f.write("// [1] 初始化建图语句 (Seed Graph Generation)\n")
                seed_lines = self.seed_cypher.split('\n') if isinstance(self.seed_cypher, str) else self.seed_cypher
                for line in seed_lines:
                    line = line.strip()
                    if not line: continue
                    if line.startswith('//'):
                        f.write(f"{line}\n")
                        continue
                    wrapped_line = wrap_query(line)
                    if wrapped_line: f.write(f"{wrapped_line}\n")
                f.write("\n")

            if self.global_query_history:
                f.write("// [2] 上游状态改变轨迹 (Upstream Execution History)\n")
                for hist_q in self.global_query_history:
                    wrapped_hist = wrap_query(hist_q)
                    if wrapped_hist: f.write(f"{wrapped_hist}\n")
                f.write("\n")
            
            f.write("// [3] 致命一击 (The Killing Query)\n")
            wrapped_crash = wrap_query(crashing_query)
            if wrapped_crash: f.write(f"{wrapped_crash}\n")

        print(f"\n [PoC 已导出] 格式: redis-cli 可执行标准脚本 -> {poc_filename}")

    def execute_single(self, query: str) -> Tuple[bool, str, str]:
        self.stats["total_executed"] += 1
        start_time = time.time()
        is_success, status_msg, execution_output = False, "", ""
        clean_query = query.strip().rstrip(';')
        
        try:
            res = self.graph.query(clean_query)
            elapsed_ms = (time.time() - start_time) * 1000
            returned_rows = len(res.result_set) if hasattr(res, 'result_set') and res.result_set else 0
            stats_str = str(res.statistics) if hasattr(res, 'statistics') and res.statistics else "{}"
            self.stats["passed"] += 1
            self.stats["total_time_ms"] += elapsed_ms
            is_success = True
            status_msg = f"Success ({elapsed_ms:.2f}ms)"
            execution_output = f"Rows: {returned_rows}, Stats: {stats_str}"
            self.global_query_history.append(query)
            
        except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError) as e:
            self.stats["failed"] += 1
            self.error_ledger["CRITICAL_DB_CRASH"] += 1
            self.bug_reports.append(query)
            status_msg = f"CRASH: {str(e)}"
            execution_output = "DATABASE CRASH DETECTED"
            
            self._generate_poc_file(query, str(e))
            
            target_container = getattr(self, 'container_name', 'falkordb_fuzz_target')
            print(f"\n捕获到内核崩溃！正在重启容器: {target_container} ...")
            
            try:
                subprocess.run(["docker", "restart", target_container], check=True, capture_output=True)
            except subprocess.CalledProcessError as sub_e:
                print(f"容器重启失败: {sub_e.stderr.decode().strip()}。熔断退出！")
                sys.exit(1)
                
            print("容器已拉起，等待数据库服务就绪...")
            db_ready = False
            for attempt in range(10): 
                time.sleep(2)
                try:
                    self.db = FalkorDB(host=self.host, port=self.port, password=self.password)
                    self.db.connection.ping()
                    self.graph = self.db.select_graph(self.graph_name)
                    db_ready = True
                    break
                except Exception: continue
                    
            if not db_ready:
                print("数据库无法恢复连通性，熔断退出！")
                sys.exit(1)
                
            print("   🌱 数据库已恢复，正在重新注入种子图谱...")
            try:
                if hasattr(self, 'initializer') and self.initializer:
                    self.initializer.reset_and_initialize()
                else:
                    print("未绑定 initializer，图数据库当前为空！")
            except Exception as init_e:
                print(f"种子图重置失败: {init_e}。熔断退出！")
                sys.exit(1)
                
            self.global_query_history.clear()
            print("环境重置完毕，Fuzzer 继续轰炸！\n")
            
        except Exception as e:
            self.stats["failed"] += 1
            status_msg = f"Exception: {str(e)}"
            execution_output = "Error"
            self.global_query_history.append(query)

        self._write_log(f"[{self.stats['total_executed']}] Query: {query}\n--> Status: {status_msg}\n{'-'*60}")
        return is_success, status_msg, execution_output



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
            status_msg = f"CRITICAL CRASH: Process exited with code {p.exitcode}"
            execution_output = "DATABASE CRASH DETECTED"
            self._generate_poc_file(query, status_msg)
            
            print(f"KùzuDB 进程暴毙，正在重新构建嵌入式图空间...")
            from GraphInitializer import KuzuSeedGenerator
            try:
                gen = KuzuSeedGenerator(self.db_path)
                gen.reset_and_initialize()
                self.global_query_history.clear()
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
                self.global_query_history.append(query)
            else:
                self.stats["failed"] += 1
                err_msg = return_dict.get("error_msg", "Unknown Exception")
                self.error_ledger["RuntimeError"] += 1
                status_msg = f"Error: {err_msg}"
                execution_output = "Semantic/Syntax Error"
                self.global_query_history.append(query)

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
                self.global_query_history.append(transpiled_query)
            else:
                self.stats["failed"] += 1
                self.error_ledger["NebulaError"] += 1
                status_msg = f"Error [{resp.error_code()}]: {resp.error_msg()}"
                execution_output = "Semantic/Syntax Error"
                self.global_query_history.append(transpiled_query)
                
        except (IOErrorException, InValidHostname, OutOfConnection) as e:
            self.stats["failed"] += 1
            self.error_ledger["CRITICAL_DB_CRASH"] += 1
            self.bug_reports.append(transpiled_query)
            status_msg = f"CRASH: {str(e)}"
            execution_output = "DATABASE CRASH DETECTED"
            self._generate_poc_file(transpiled_query, str(e))
            
            print(f"Nebula 连接丢失，重试中 (10s)...")
            time.sleep(10)
            try:
                self.pool.init([(self.host, self.port)], self.config)
                self.session = self.pool.get_session(self.user, self.password)
                self.session.execute(f"USE {self.space};")
                self.global_query_history.clear() 
            except Exception: pass
        except Exception as e:
            self.stats["failed"] += 1
            status_msg = f"Exception: {str(e)}"
            execution_output = "Unknown Error"

        self._write_log(f"[{self.stats['total_executed']}] Query: {transpiled_query}\n--> Status: {status_msg}\n{'-'*60}")
        return is_success, status_msg, execution_output