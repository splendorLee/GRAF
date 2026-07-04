# import math
# import sys
# import os
# import time
# import traceback
# import argparse  
# import textwrap 
# from dataclasses import dataclass, field
# from typing import Dict, Set, Tuple, List

# # ==========================================
# # 环境变量与路径配置
# # ==========================================
# current_dir = os.path.dirname(os.path.abspath(__file__))
# antlr_path = os.path.join(current_dir, "antlr4-cypher", "antlr4_cypher")
# if antlr_path not in sys.path:
#     sys.path.insert(0, antlr_path)

# # ==========================================
# # 导入自定义与第三方模块
# # ==========================================
# from antlr4 import InputStream, CommonTokenStream
# from antlr4.TokenStreamRewriter import TokenStreamRewriter
# from antlr4.error.ErrorListener import ErrorListener

# from CypherLexer import CypherLexer
# from CypherParser import CypherParser
# from CypherParserVisitor import CypherParserVisitor

# from GraphInitializer import MemgraphSeedGenerator, FalkorDBSeedGenerator, KuzuSeedGenerator, NebulaSeedGenerator
# from Instantiator import compile_and_instantiate
# from SkeletonFilter import GrafSkeletonFilter
# from FeedbackMonitor import FeedbackMonitor, FeedbackVector, ExecStatus, estimate_result_scale

# from GraphContext import MemgraphContextExtractor, FalkorDBContextExtractor, KuzuContextExtractor, NebulaContextExtractor
# from DB_Executor import MemgraphFuzzExecutor, FalkorDBFuzzExecutor, KuzuFuzzExecutor, NebulaFuzzExecutor

# # 引入工业级图感知变异器及上下文结构
# from GraphAwareMutator import (
#     GraphAwareMutator, 
#     SchemaMetadata, 
#     ValueDictionary, 
#     GlobalGraphState, 
#     compile_and_mutate
# )

# # ==========================================
# # 大屏监控 Dashboard 类 (定宽定高+精准对齐版)
# # ==========================================
# class FuzzDashboard:
#     def __init__(self, target_name):
#         self.start_time = time.time()
#         self.target_name = target_name
#         self.crashes_record = 0
#         # 🌟 初始化为固定5行的显示文本
#         self.current_query_display = self._format_query("等待初始化...") 

#     def _format_query(self, query):
#         """精准格式化查询语句：锁定 5 行，严格对齐缩进"""
#         if not query:
#             query = ""
            
#         # 1. 智能折行 (大屏总宽 67，左侧前缀占用 11，留给代码的宽度约为 54)
#         wrapped_lines = textwrap.wrap(query, width=54, break_long_words=True)
        
#         # 2. 限制最多 5 行，超出部分截断并添加省略号
#         if len(wrapped_lines) > 5:
#             wrapped_lines = wrapped_lines[:5]
#             # 确保最后一行加上省略号后不会超出边界
#             wrapped_lines[4] = wrapped_lines[4][:50] + "..."
            
#         # 3. 严格补齐到 5 行，防止下方边框跳动
#         display_lines = []
#         for i in range(5):
#             # 获取当前行文本，不足 5 行则为空字符串
#             text = wrapped_lines[i] if i < len(wrapped_lines) else ""
            
#             if i == 0:
#                 display_lines.append(f"当前执行 : {text}")
#             else:
#                 display_lines.append(f"           {text}")
                
#         # 用换行符拼接 5 行
#         return "\n".join(display_lines)

#     def update(self, drawn, filtered, executed, passed, exec_failed, crashes, current_q=None):
#         if current_q:
#             # 使用全新的格式化函数生成定高定宽的文本
#             self.current_query_display = self._format_query(current_q)

#         self.crashes_record = crashes

#         # 执行通过率只基于“实际执行”的数量进行计算
#         pass_rate = (passed / executed * 100) if executed > 0 else 0.0
#         elapsed = int(time.time() - self.start_time)
        
#         # \033[2J 清空屏幕，\033[H 将光标移至左上角
#         # 注意：下面的模板中去掉了硬编码的 "当前执行 : "，直接使用 self.current_query_display
#         screen = f"""\033[2J\033[H
# ===================================================================
#                            GRAF Fuzzer
# ===================================================================
# 攻击目标 : {self.target_name}
# 运行时间 : {elapsed} 秒
# 实际执行 : {executed} 次
# -------------------------------------------------------------------
# 执行成功 : {passed} 次 
# 执行失败 : {exec_failed} 次 
# 执行通过率: {pass_rate:.2f}%
# 发现崩溃 : {crashes} 次 
# -------------------------------------------------------------------
# {self.current_query_display}
# ===================================================================
# (按 Ctrl+C 随时安全退出，详细日志保存在 fuzz_verbose_{self.target_name.lower()}.log)
# """
#         sys.stdout.write(screen)
#         sys.stdout.flush()

# # ==========================================
# # 辅助函数定义
# # ==========================================
# def load_skeletons_from_file(filepath: str) -> List[str]:
#     if not os.path.exists(filepath):
#         raise FileNotFoundError(f"找不到骨架池文件: {filepath}")
        
#     with open(filepath, 'r', encoding='utf-8') as f:
#         content = f.read()
        
#     raw_queries = [q.strip() for q in content.split(';') if q.strip()]
#     return [f"{q};" for q in raw_queries]

# def estimate_safe_diameter(node_count: int, edge_count: int) -> int:
#     if node_count <= 1 or edge_count == 0:
#         return 1
#     avg_degree = edge_count / node_count
#     if avg_degree <= 1.0:
#         return min(node_count, 10)
#     try:
#         approx_d = math.ceil(math.log(node_count) / math.log(avg_degree))
#         return max(2, min(approx_d, 15))
#     except Exception:
#         return 5

# def apply_ast_mutation(executable_query: str, real_schema, real_state, strategy) -> str:
#     def safe_extract(obj, key, default=None):
#         if isinstance(obj, dict):
#             return obj.get(key, default)
#         return getattr(obj, key, default)

#     v_count = safe_extract(real_state, 'node_count', 0)
#     e_count = safe_extract(real_state, 'edge_count', 0)
#     dynamic_diameter = estimate_safe_diameter(v_count, e_count)

#     schema_ctx = SchemaMetadata(
#         labels=set(safe_extract(real_schema, 'labels', set())),
#         topology=safe_extract(real_schema, 'topology', {}),
#         properties=safe_extract(real_schema, 'properties', {})
#     )
    
#     obs_values = safe_extract(real_state, 'property_values', {})
#     if not obs_values:
#         obs_values = safe_extract(real_schema, 'property_values', {})
        
#     val_dict_ctx = ValueDictionary(observed_values=obs_values)
#     global_state_ctx = GlobalGraphState(node_count=v_count, edge_count=e_count, diameter=dynamic_diameter)

#     input_stream = InputStream(executable_query)
#     lexer = CypherLexer(input_stream)
#     lexer.removeErrorListeners() 
#     token_stream = CommonTokenStream(lexer)
#     parser = CypherParser(token_stream)
#     parser.removeErrorListeners()
#     parse_tree = parser.script() 

#     mutated_query = compile_and_mutate(
#         token_stream=token_stream, 
#         parse_tree=parse_tree, 
#         schema=schema_ctx, 
#         val_dict=val_dict_ctx, 
#         state=global_state_ctx,
#         strategy=strategy
#     )
    
#     return mutated_query

# # ==========================================
# # 主程序入口 (Main Pipeline)
# # ==========================================
# if __name__ == "__main__":
#     parser = argparse.ArgumentParser(description="GRAF Fuzzer - 跨引擎图数据库漏洞挖掘系统")
#     parser.add_argument(
#         "--target", 
#         type=str, 
#         required=True, 
#         help="指定目标引擎，可选值: 'memgraph', 'falkordb', 'kuzu', 'nebula'"
#     )
#     args = parser.parse_args()

#     TARGET_ENGINE = args.target.lower()
    
#     if TARGET_ENGINE not in ["memgraph", "falkordb", "kuzu", "nebula"]:
#         print(f"致命错误: 不支持的目标引擎 '{args.target}'。请使用 'memgraph', 'falkordb', 'kuzu', 'nebula'。")
#         sys.exit(1)

#     if TARGET_ENGINE == "kuzu":
#         POOL_FILE = "skeleton_pool_kuzu"
#     elif TARGET_ENGINE == "nebula":
#         POOL_FILE = "skeleton_pool_nebula"
#     else:
#         POOL_FILE = "skeleton_pool"

#     VERBOSE_LOG_FILE = f"fuzz_verbose_{TARGET_ENGINE}.log"
#     with open(VERBOSE_LOG_FILE, "w", encoding="utf-8") as f:
#         f.write(f"=== GRAF Fuzzer 详细运行日志 (Target: {TARGET_ENGINE.upper()}) ===\n\n")

#     def log_verbose(msg):
#         with open(VERBOSE_LOG_FILE, "a", encoding="utf-8") as file:
#             file.write(msg + "\n")

#     log_verbose(f"🚀 [GRAF Fuzzer] 目标引擎已设定为: {TARGET_ENGINE.upper()}")

#     # 基础设施装载
#     if TARGET_ENGINE == "memgraph":
#         URI = "bolt://localhost:7687"
#         USER = ""
#         PASSWORD = ""
#         generator = MemgraphSeedGenerator(URI, USER, PASSWORD)
#         generator.reset_and_initialize()
#         seed_cypher_text = getattr(generator, 'seed_cypher', '')
#         generator.close()
#         extractor = MemgraphContextExtractor(URI, USER, PASSWORD)
#         executor = MemgraphFuzzExecutor(URI, USER, PASSWORD, seed_cypher=seed_cypher_text)
        
#     elif TARGET_ENGINE == "falkordb":
#         HOST = "localhost"
#         PORT = 6380
#         PASSWORD = ""
#         GRAPH_NAME = "graf_fuzz"
#         generator = FalkorDBSeedGenerator(host=HOST, port=PORT, password=PASSWORD, graph_name=GRAPH_NAME)
#         generator.reset_and_initialize()
#         seed_cypher_text = getattr(generator, 'seed_cypher', '')
#         extractor = FalkorDBContextExtractor(host=HOST, port=PORT, password=PASSWORD, graph_name=GRAPH_NAME)
#         executor = FalkorDBFuzzExecutor(host=HOST, port=PORT, password=PASSWORD, graph_name=GRAPH_NAME, seed_cypher=seed_cypher_text)
#         executor.container_name = "falkordb_fuzz_target" 
#         executor.initializer = generator

#     elif TARGET_ENGINE == "kuzu":
#         DB_PATH = "./kuzu_fuzz_test"
#         generator = KuzuSeedGenerator(db_path=DB_PATH)
#         generator.reset_and_initialize()
#         seed_cypher_text = getattr(generator, 'seed_cypher', '')
#         generator.close()
#         extractor = KuzuContextExtractor(db_path=DB_PATH)
#         executor = KuzuFuzzExecutor(db_path=DB_PATH, seed_cypher=seed_cypher_text)

#     elif TARGET_ENGINE == "nebula":
#         HOST = "127.0.0.1"
#         PORT = 9669
#         USER = "root"
#         PASSWORD = "nebula"
#         SPACE = "graf_fuzz"
#         generator = NebulaSeedGenerator(host=HOST, port=PORT, user=USER, password=PASSWORD)
#         generator.reset_and_initialize()
#         seed_cypher_text = getattr(generator, 'seed_cypher', '')
#         generator.close()
#         extractor = NebulaContextExtractor(host=HOST, port=PORT, user=USER, password=PASSWORD, space=SPACE)
#         executor = NebulaFuzzExecutor(host=HOST, port=PORT, user=USER, password=PASSWORD, space=SPACE, seed_cypher=seed_cypher_text)

#     log_verbose("⏳ 正在提取运行时图上下文约束...")
#     real_schema, real_state = extractor.extract_context()
#     extractor.close()
    
#     filter_engine = GrafSkeletonFilter()
#     monitor = FeedbackMonitor(seed_cypher=seed_cypher_text)
    
#     log_verbose("\n🚀 启动无限循环图变异测试...\n")
    
#     dashboard = FuzzDashboard(TARGET_ENGINE.upper())
#     stats_drawn = 0           # 抽取总数
#     stats_filtered = 0        # 拦截总数
#     stats_executed = 0        # 实际下发到数据库的执行数
#     stats_passed = 0          # 执行并获得结果
#     stats_exec_failed = 0     # 数据库拒绝/语法错误
#     stats_crashes = 0         # 引发引擎崩溃
    
#     try:
#         skeletons = load_skeletons_from_file(POOL_FILE)
#         seen_queries = set(skeletons) 
        
#         round_idx = 0                  
#         CONTEXT_REFRESH_INTERVAL = 500 
        
#         while True:
#             current_idx = round_idx % len(skeletons)
#             skeleton = skeletons[current_idx]
            
#             round_idx += 1
#             stats_drawn += 1  # 每次循环抽取出一条骨架
            
#             if round_idx > 0 and round_idx % CONTEXT_REFRESH_INTERVAL == 0:
#                 log_verbose("[环境同步] 正在重新提取数据库真实状态与规模...")
#                 if TARGET_ENGINE == "memgraph":
#                     temp_extractor = MemgraphContextExtractor(URI, USER, PASSWORD)
#                 elif TARGET_ENGINE == "falkordb":
#                     temp_extractor = FalkorDBContextExtractor(host=HOST, port=PORT, password=PASSWORD, graph_name=GRAPH_NAME)
#                 elif TARGET_ENGINE == "kuzu":
#                     temp_extractor = KuzuContextExtractor(db_path=DB_PATH)
#                 elif TARGET_ENGINE == "nebula":
#                     temp_extractor = NebulaContextExtractor(host=HOST, port=PORT, user=USER, password=PASSWORD, space=SPACE)
                
#                 real_schema, real_state = temp_extractor.extract_context()
#                 temp_extractor.close()
            
#             # [阶段 1] Skeleton Filter (拦截后严禁进入后续阶段)
#             filter_result = filter_engine.validate(skeleton)
#             if not filter_result.is_valid:
#                 log_verbose(f"拦截: {filter_result.reason}\n")
#                 stats_filtered += 1
#                 # 刷新屏幕后直接跳入下一次循环，绝对不参与实例化和变异
#                 dashboard.update(stats_drawn, stats_filtered, stats_executed, stats_passed, stats_exec_failed, stats_crashes)
#                 continue
                
#             try:
#                 # [阶段 2] 实例化
#                 executable_query, errors = compile_and_instantiate(skeleton, real_schema, real_state, target_engine=TARGET_ENGINE)                
#                 formatted_base = " ".join(executable_query.split())
#                 log_verbose(f"基础查询 (Q0): {formatted_base}")
                
#                 # [阶段 3] 变异
#                 mutated_query = apply_ast_mutation(formatted_base, real_schema, real_state, monitor.current_strategy)
#                 formatted_mut = " ".join(mutated_query.split())
#                 log_verbose(f"AST变异 (Q_mut): {formatted_mut}")

#                 # [阶段 4] 靶机执行验证与全量轨迹留存
#                 query_to_log = formatted_mut if formatted_mut.endswith(';') else f"{formatted_mut};"
#                 try:
#                     with open(f"fuzzing_execution_trace_{TARGET_ENGINE}.cypher", "a", encoding="utf-8") as trace_file:
#                         trace_file.write(f"{query_to_log}\n")
#                 except Exception:
#                     pass

#                 stats_executed += 1
                
#                 # 🌟 核心修改：在向数据库发送查询之前，先刷新一次大屏，展示即将执行的长语句
#                 dashboard.update(stats_drawn, stats_filtered, stats_executed, stats_passed, stats_exec_failed, stats_crashes, current_q=formatted_mut)
                
#                 start_time = time.time()
#                 is_success, msg, execution_output = executor.execute_single(formatted_mut)
#                 exec_time_ms = (time.time() - start_time) * 1000

#                 # [阶段 5] 反馈解析
#                 status = ExecStatus.SUCCESS
#                 if not is_success:
#                     msg_lower = msg.lower()
#                     if any(err in msg_lower for err in ["clienterror", "parsing error", "syntax error", "extraneous input"]):
#                         status = ExecStatus.ERROR
#                     elif any(keyword in msg_lower for keyword in ["crash", "connection refused", "connection reset", "closed", "broken pipe", "socket", "service unavailable", "assertion failed"]):
#                         status = ExecStatus.CRASH
#                     elif "timeout" in msg_lower:
#                         status = ExecStatus.TIMEOUT
#                     else:
#                         status = ExecStatus.ERROR

#                 scale_r = estimate_result_scale(execution_output)
            
#                 feedback_vec = FeedbackVector(
#                     execution_time_ms=exec_time_ms,
#                     result_scale=scale_r,
#                     status=status,
#                     raw_query=formatted_mut
#                 )
                
#                 new_strategy, is_interesting = monitor.process_feedback(feedback_vec)
                
#                 # [阶段 6] 种子池进化
#                 if is_interesting and formatted_mut not in seen_queries:
#                     skeletons.append(formatted_mut)
#                     seen_queries.add(formatted_mut)
#                     log_verbose(f"[种子池进化] 捕获高价值用例！已追加至队列尾部")
                
#                 # 更新精准统计分类
#                 if status == ExecStatus.CRASH:
#                     stats_crashes += 1
#                     log_verbose(f"触发引擎崩溃: {msg}")
#                 elif is_success:
#                     stats_passed += 1
#                     log_verbose(f"执行状态: Success ({exec_time_ms:.2f}ms, Scale: {scale_r})")
#                 else:
#                     stats_exec_failed += 1
#                     log_verbose(f"执行失败: {msg}")

#                 log_verbose("-" * 60 + "\n")
                
#                 dashboard.update(stats_drawn, stats_filtered, stats_executed, stats_passed, stats_exec_failed, stats_crashes)
                    
#             except Exception as e:
#                 # 若在此代码块内抛出异常（如变异或实例化引擎崩溃），记为执行失败
#                 stats_executed += 1
#                 stats_exec_failed += 1
#                 log_verbose(f"严重内部崩溃发生！\n{traceback.format_exc()}\n" + "-" * 60 + "\n")
#                 dashboard.update(stats_drawn, stats_filtered, stats_executed, stats_passed, stats_exec_failed, stats_crashes)

#     except KeyboardInterrupt:
#         print("\n\n测试终止 (Ctrl+C)！")        
#     finally:
#         executor.close()



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
from dataclasses import dataclass, field
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
    parser.add_argument("--skeleton-pool", help="覆盖默认 skeleton 池文件路径")
    parser.add_argument("--max-iterations", type=int, default=0, help="最大循环次数；0 表示持续运行")
    parser.add_argument("--context-refresh-interval", type=int, default=500, help="重新提取图上下文的间隔轮数")
    parser.add_argument("--seed", type=int, help="固定随机种子，便于复现测试")
    parser.add_argument("--crash-policy", choices=["legacy", "strict"], default="strict", help="Crash classification policy: legacy follows the uploaded project; strict reduces false positives")
    parser.add_argument("--skeleton-filter-mode", choices=["strict", "legacy"], default="strict", help="Strict mode rejects skeletons with static semantic hazards before instantiation")
    parser.add_argument("--init-mode", choices=["reset", "reuse"], default="reset", help="Startup database initialization mode. reset clears and seeds; reuse only checks connectivity")
    parser.add_argument("--reseed-interval", type=int, default=0, help="Periodically clear and re-seed the target after this many executed queries; 0 disables periodic reseeding")
    parser.add_argument("--init-delete-batch-size", type=int, default=1000, help="Nodes deleted per batch during Memgraph/Neo4j initialization and recovery")
    parser.add_argument("--init-delete-max-batches", type=int, default=1000, help="Maximum delete batches before aborting Memgraph/Neo4j initialization")
    parser.add_argument("--memgraph-uri", default="bolt://localhost:7687", help="Memgraph Bolt URI")
    parser.add_argument("--memgraph-container", default="memgraph_fuzz_target", help="Memgraph Docker container name")
    parser.add_argument("--memgraph-ready-timeout", type=int, default=60, help="Seconds to wait for Memgraph Bolt readiness after restart")
    parser.add_argument("--memgraph-recovery-retries", type=int, default=3, help="Memgraph container restart/reconnect attempts after crash-like disconnects")
    parser.add_argument("--neo4j-uri", default="bolt://localhost:7687", help="Neo4j Bolt URI")
    parser.add_argument("--neo4j-user", default="neo4j", help="Neo4j username")
    parser.add_argument("--neo4j-password", default="testpassword", help="Neo4j password")
    parser.add_argument("--neo4j-database", default="neo4j", help="Neo4j database name")
    parser.add_argument("--neo4j-container", default="neo4j_fuzz_target", help="Neo4j Docker container name")
    parser.add_argument("--neo4j-ready-timeout", type=int, default=90, help="Seconds to wait for Neo4j Bolt readiness after startup/restart")
    parser.add_argument("--neo4j-recovery-retries", type=int, default=3, help="Neo4j container restart/reconnect attempts after crash-like disconnects")
    parser.add_argument("--neo4j-query-timeout", type=int, default=60, help="Neo4j server-side transaction timeout per query in seconds; 0 disables it")
    parser.add_argument("--falkordb-query-timeout", type=int, default=60, help="Seconds before a FalkorDB query is killed and the container is reset")
    return parser


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
from SkeletonFilter import GrafSkeletonFilter
from FeedbackMonitor import FeedbackMonitor, FeedbackVector, ExecStatus, estimate_result_scale

from GraphContext import MemgraphContextExtractor, Neo4jContextExtractor, FalkorDBContextExtractor, KuzuContextExtractor, NebulaContextExtractor
from DB_Executor import ExecutionOutcome, MemgraphFuzzExecutor, Neo4jFuzzExecutor, FalkorDBFuzzExecutor, KuzuFuzzExecutor, NebulaFuzzExecutor

# 引入工业级图感知变异器及上下文结构
from GraphAwareMutator import (
    GraphAwareMutator, 
    SchemaMetadata, 
    ValueDictionary, 
    GlobalGraphState, 
    compile_and_mutate,
    harden_query_shape
)


class FuzzDashboard:
    def __init__(self, target_name):
        self.start_time = time.time()
        self.target_name = target_name
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

        pass_rate = (passed / executed * 100) if executed > 0 else 0.0
        elapsed = int(time.time() - self.start_time)
        
        screen = f"""\033[2J\033[H
===================================================================
                           GRAF Fuzzer
===================================================================
攻击目标 : {self.target_name}
运行时间 : {elapsed} 秒
实际执行 : {executed} 次
-------------------------------------------------------------------
执行成功 : {passed} 次 
执行失败 : {exec_failed} 次 
执行通过率: {pass_rate:.2f}%
发现崩溃 : {crashes} 次 
资源耗尽 : {resource_exhaustions} 次
-------------------------------------------------------------------
{self.current_query_display}
===================================================================
(按 Ctrl+C 随时安全退出，详细日志保存在 fuzz_verbose_{self.target_name.lower()}.log)
"""
        sys.stdout.write(screen)
        sys.stdout.flush()


def load_skeletons_from_file(filepath: str) -> List[str]:
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"找不到骨架池文件: {filepath}")
        
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
        
    raw_queries = [q.strip() for q in content.split(';') if q.strip()]
    return [f"{q};" for q in raw_queries]

def estimate_safe_diameter(node_count: int, edge_count: int) -> int:
    if node_count <= 1 or edge_count == 0:
        return 1
    avg_degree = edge_count / node_count
    if avg_degree <= 1.0:
        return min(node_count, 10)
    try:
        approx_d = math.ceil(math.log(node_count) / math.log(avg_degree))
        return max(2, min(approx_d, 15))
    except Exception:
        return 5

def normalize_topology_by_source(topology) -> Dict[str, List[Tuple[str, str]]]:
    normalized: Dict[str, List[Tuple[str, str]]] = {}
    if not topology:
        return normalized

    for key, value in topology.items():
        if isinstance(value, dict):
            pairs = value.items()
        else:
            pairs = value

        for item in pairs:
            if not isinstance(item, (tuple, list)) or len(item) != 2:
                continue

            first, second = item
            if isinstance(first, str) and isinstance(second, str):
                src_label, dst_label = first, second
                rel_type = key
            else:
                continue

            normalized.setdefault(src_label, []).append((rel_type, dst_label))

    return normalized

def apply_ast_mutation(
    executable_query: str,
    real_schema,
    real_state,
    strategy,
) -> str:
    def safe_extract(obj, key, default=None):
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)

    v_count = safe_extract(real_state, 'node_count', safe_extract(real_state, 'total_nodes', 0))
    e_count = safe_extract(real_state, 'edge_count', safe_extract(real_state, 'total_edges', 0))
    dynamic_diameter = estimate_safe_diameter(v_count, e_count)

    topology = safe_extract(real_schema, 'topology', {})
    schema_ctx = SchemaMetadata(
        labels=set(safe_extract(real_schema, 'labels', set())),
        topology=normalize_topology_by_source(topology),
        properties=safe_extract(real_schema, 'properties', {})
    )
    
    obs_values = safe_extract(real_state, 'property_values', {})
    if not obs_values:
        obs_values = safe_extract(real_schema, 'property_values', {})
        
    val_dict_ctx = ValueDictionary(observed_values=obs_values)
    global_state_ctx = GlobalGraphState(node_count=v_count, edge_count=e_count, diameter=dynamic_diameter)

    input_stream = InputStream(executable_query)
    lexer = CypherLexer(input_stream)
    lexer.removeErrorListeners() 
    token_stream = CommonTokenStream(lexer)
    parser = CypherParser(token_stream)
    parser.removeErrorListeners()
    parse_tree = parser.script() 

    mutated_query = compile_and_mutate(
        token_stream=token_stream, 
        parse_tree=parse_tree, 
        schema=schema_ctx, 
        val_dict=val_dict_ctx, 
        state=global_state_ctx,
        strategy=strategy
    )
    
    return harden_query_shape(mutated_query, global_state_ctx, strategy)


if __name__ == "__main__":
    parser = build_arg_parser()
    args = parser.parse_args()

    TARGET_ENGINE = args.target.lower()
    if args.seed is not None:
        random.seed(args.seed)
    
    if TARGET_ENGINE not in ["memgraph", "neo4j", "falkordb", "kuzu", "nebula"]:
        print(f"致命错误: 不支持的目标引擎 '{args.target}'。请使用 'memgraph', 'neo4j', 'falkordb', 'kuzu', 'nebula'。")
        sys.exit(1)

    if TARGET_ENGINE == "kuzu":
        POOL_FILE = "skeleton_pool_kuzu"
    elif TARGET_ENGINE == "nebula":
        POOL_FILE = "skeleton_pool_nebula"
    else:
        POOL_FILE = "skeleton_pool"
    if args.skeleton_pool:
        POOL_FILE = args.skeleton_pool

    VERBOSE_LOG_FILE = f"fuzz_verbose_{TARGET_ENGINE}.log"
    with open(VERBOSE_LOG_FILE, "w", encoding="utf-8") as f:
        f.write(f"=== GRAF Fuzzer 详细运行日志 (Target: {TARGET_ENGINE.upper()}) ===\n\n")

    def log_verbose(msg):
        with open(VERBOSE_LOG_FILE, "a", encoding="utf-8") as file:
            file.write(msg + "\n")

    log_verbose(f"🚀 [GRAF Fuzzer] 目标引擎已设定为: {TARGET_ENGINE.upper()}")

    if TARGET_ENGINE == "memgraph":
        URI = args.memgraph_uri
        USER = ""
        PASSWORD = ""
        generator = MemgraphSeedGenerator(
            URI,
            USER,
            PASSWORD,
            ready_timeout_s=args.memgraph_ready_timeout,
            delete_batch_size=args.init_delete_batch_size,
            delete_max_batches=args.init_delete_max_batches,
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
            container_name=args.memgraph_container,
            ready_timeout_s=args.memgraph_ready_timeout,
            recovery_retries=args.memgraph_recovery_retries,
            delete_batch_size=args.init_delete_batch_size,
            delete_max_batches=args.init_delete_max_batches,
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
            container_name=args.neo4j_container,
            ready_timeout_s=args.neo4j_ready_timeout,
            auto_resolve_uri=neo4j_auto_uri,
            recovery_retries=args.neo4j_recovery_retries,
            delete_batch_size=args.init_delete_batch_size,
            delete_max_batches=args.init_delete_max_batches,
            query_timeout_s=args.neo4j_query_timeout,
            crash_policy=args.crash_policy,
        )
        
    elif TARGET_ENGINE == "falkordb":
        HOST = "localhost"
        PORT = 6380
        PASSWORD = ""
        GRAPH_NAME = "graf_fuzz"
        generator = FalkorDBSeedGenerator(host=HOST, port=PORT, password=PASSWORD, graph_name=GRAPH_NAME)
        generator.reset_and_initialize()
        seed_cypher_text = getattr(generator, 'seed_cypher', '')
        extractor = FalkorDBContextExtractor(host=HOST, port=PORT, password=PASSWORD, graph_name=GRAPH_NAME)
        executor = FalkorDBFuzzExecutor(
            host=HOST,
            port=PORT,
            password=PASSWORD,
            graph_name=GRAPH_NAME,
            seed_cypher=seed_cypher_text,
            query_timeout_s=args.falkordb_query_timeout,
        )
        executor.container_name = "falkordb_fuzz_target" 
        executor.initializer = generator

    elif TARGET_ENGINE == "kuzu":
        DB_PATH = "./kuzu_fuzz_test"
        generator = KuzuSeedGenerator(db_path=DB_PATH)
        generator.reset_and_initialize()
        seed_cypher_text = getattr(generator, 'seed_cypher', '')
        generator.close()
        extractor = KuzuContextExtractor(db_path=DB_PATH)
        executor = KuzuFuzzExecutor(db_path=DB_PATH, seed_cypher=seed_cypher_text)

    elif TARGET_ENGINE == "nebula":
        HOST = "127.0.0.1"
        PORT = 9669
        USER = "root"
        PASSWORD = "nebula"
        SPACE = "graf_fuzz"
        generator = NebulaSeedGenerator(host=HOST, port=PORT, user=USER, password=PASSWORD)
        generator.reset_and_initialize()
        seed_cypher_text = getattr(generator, 'seed_cypher', '')
        generator.close()
        extractor = NebulaContextExtractor(host=HOST, port=PORT, user=USER, password=PASSWORD, space=SPACE)
        executor = NebulaFuzzExecutor(host=HOST, port=PORT, user=USER, password=PASSWORD, space=SPACE, seed_cypher=seed_cypher_text)
        executor.container_name = "nebula-docker-compose-graphd-1"

    log_verbose("正在提取运行时图上下文约束...")
    real_schema, real_state = extractor.extract_context()
    extractor.close()
    
    filter_engine = GrafSkeletonFilter(
        target_engine=TARGET_ENGINE,
        strict=args.skeleton_filter_mode == "strict",
    )
    monitor = FeedbackMonitor(seed_cypher=seed_cypher_text)
    
    log_verbose("\n启动无限循环图变异测试...\n")
    
    dashboard = FuzzDashboard(TARGET_ENGINE.upper())
    stats_drawn = 0           
    stats_filtered = 0        
    stats_executed = 0        
    stats_passed = 0          
    stats_exec_failed = 0     
    stats_crashes = 0         
    stats_resource_exhaustions = 0
    last_submitted_query = None
    recorded_oob_disconnects = set()

    def refresh_context_once():
        if TARGET_ENGINE == "memgraph":
            return MemgraphContextExtractor(URI, USER, PASSWORD)
        if TARGET_ENGINE == "neo4j":
            current_uri = getattr(executor, "uri", URI)
            return Neo4jContextExtractor(current_uri, USER, PASSWORD, database=DATABASE)
        if TARGET_ENGINE == "falkordb":
            return FalkorDBContextExtractor(host=HOST, port=PORT, password=PASSWORD, graph_name=GRAPH_NAME)
        if TARGET_ENGINE == "kuzu":
            return KuzuContextExtractor(db_path=DB_PATH)
        if TARGET_ENGINE == "nebula":
            return NebulaContextExtractor(host=HOST, port=PORT, user=USER, password=PASSWORD, space=SPACE)
        raise RuntimeError(f"Unsupported target for context refresh: {TARGET_ENGINE}")

    def periodic_reseed_and_refresh():
        if not hasattr(executor, "reset_to_seed"):
            log_verbose(f"[周期初始化] {TARGET_ENGINE} 暂未实现轻量重灌种子图，跳过。")
            return real_schema, real_state

        log_verbose(f"[周期初始化] 已执行 {stats_executed} 条查询，开始清空并重灌种子图...")
        try:
            executor.reset_to_seed()
        except Exception:
            if TARGET_ENGINE not in {"neo4j", "memgraph", "falkordb"}:
                raise
            log_verbose(f"[周期初始化] 轻量重置失败，尝试恢复流程。\n{traceback.format_exc()}")
            if hasattr(executor, "_reconnect_and_reseed"):
                executor._reconnect_and_reseed()
            elif hasattr(executor, "_recover_container_and_seed"):
                executor._recover_container_and_seed()
            else:
                raise

        if TARGET_ENGINE == "neo4j":
            globals()["URI"] = getattr(executor, "uri", URI)

        temp_extractor = None
        try:
            temp_extractor = refresh_context_once()
            refreshed_schema, refreshed_state = temp_extractor.extract_context()
            log_verbose("[周期初始化] 重灌后上下文刷新成功")
            return refreshed_schema, refreshed_state
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
    
    try:
        skeletons = load_skeletons_from_file(POOL_FILE)
        seen_queries = set(skeletons) 
        
        round_idx = 0                  
        CONTEXT_REFRESH_INTERVAL = args.context_refresh_interval 
        
        while True:
            if args.max_iterations and round_idx >= args.max_iterations:
                log_verbose(f"[停止] 达到最大循环次数: {args.max_iterations}")
                break

            current_idx = round_idx % len(skeletons)
            skeleton = skeletons[current_idx]
            
            round_idx += 1
            stats_drawn += 1  
            
            if round_idx > 0 and round_idx % CONTEXT_REFRESH_INTERVAL == 0:
                log_verbose("[环境同步] 正在重新提取数据库真实状态与规模...")

                temp_extractor = None
                try:
                    temp_extractor = refresh_context_once()
                    real_schema, real_state = temp_extractor.extract_context()
                except Exception as refresh_exc:
                    if TARGET_ENGINE not in {"neo4j", "memgraph"}:
                        raise
                    oob_result = record_out_of_band_disconnect(
                        "context_refresh",
                        refresh_exc,
                        last_submitted_query,
                        stats_executed,
                    )
                    if oob_result is not None:
                        stats_crashes += 1
                    log_verbose(f"[环境同步] {TARGET_ENGINE} 上下文刷新失败，尝试恢复连接...\n{traceback.format_exc()}")
                    try:
                        if temp_extractor:
                            temp_extractor.close()
                        executor._reconnect_and_reseed()
                        URI = getattr(executor, "uri", URI)
                        temp_extractor = refresh_context_once()
                        real_schema, real_state = temp_extractor.extract_context()
                        log_verbose(f"[环境同步] {TARGET_ENGINE} 恢复后上下文刷新成功")
                    except Exception:
                        log_verbose(f"[环境同步] {TARGET_ENGINE} 恢复后仍无法刷新上下文，继续使用旧上下文。\n{traceback.format_exc()}")
                finally:
                    if temp_extractor:
                        temp_extractor.close()
            
            filter_result = filter_engine.validate(skeleton)
            if not filter_result.is_valid:
                log_verbose(f"拦截: {filter_result.reason}\n")
                stats_filtered += 1
                dashboard.update(stats_drawn, stats_filtered, stats_executed, stats_passed, stats_exec_failed, stats_crashes, stats_resource_exhaustions)
                continue
                
            try:
                executable_query, errors = compile_and_instantiate(skeleton, real_schema, real_state, target_engine=TARGET_ENGINE)                
                formatted_base = " ".join(executable_query.split())
                log_verbose(f"基础查询 (Q0): {formatted_base}")
                
                try:
                    mutated_query = apply_ast_mutation(
                        formatted_base,
                        real_schema,
                        real_state,
                        monitor.current_strategy,
                    )
                except Exception:
                    log_verbose(f"[变异回退] AST 变异失败，使用基础查询继续执行。\n{traceback.format_exc()}")
                    mutated_query = formatted_base
                formatted_mut = " ".join(mutated_query.split())
                log_verbose(f"AST变异 (Q_mut): {formatted_mut}")

                query_to_log = formatted_mut if formatted_mut.endswith(';') else f"{formatted_mut};"
                try:
                    with open(f"fuzzing_execution_trace_{TARGET_ENGINE}.cypher", "a", encoding="utf-8") as trace_file:
                        trace_file.write(f"{query_to_log}\n")
                except Exception:
                    pass

                stats_executed += 1
                
                dashboard.update(stats_drawn, stats_filtered, stats_executed, stats_passed, stats_exec_failed, stats_crashes, stats_resource_exhaustions, current_q=formatted_mut)
                
                start_time = time.time()
                last_submitted_query = formatted_mut
                if hasattr(executor, "set_execution_context"):
                    executor.set_execution_context(
                        target=TARGET_ENGINE,
                        round_idx=round_idx,
                        stats_drawn=stats_drawn,
                        stats_executed=stats_executed,
                        seed=args.seed,
                        skeleton=skeleton,
                        base_query=formatted_base,
                        mutated_query=formatted_mut,
                        context_refresh_interval=args.context_refresh_interval,
                        reseed_interval=args.reseed_interval,
                        mutation_strategy=monitor.current_strategy,
                    )
                is_success, msg, execution_output = executor.execute_single(formatted_mut)
                if TARGET_ENGINE == "neo4j":
                    URI = getattr(executor, "uri", URI)
                exec_time_ms = (time.time() - start_time) * 1000

                execution_result = getattr(executor, "last_execution", None)
                if execution_result is not None:
                    msg = execution_result.status_message()
                    execution_output = execution_result.output
                    if execution_result.outcome == ExecutionOutcome.SUCCESS:
                        status = ExecStatus.SUCCESS
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
                        elif msg.startswith(("REJECTED:", "RUNTIME_ERROR:")):
                            status = ExecStatus.ERROR
                        elif any(err in msg_lower for err in ["clienterror", "parsing error", "syntax error", "extraneous input"]):
                            status = ExecStatus.ERROR
                        else:
                            status = ExecStatus.ERROR

                scale_r = estimate_result_scale(execution_output)
            
                feedback_vec = FeedbackVector(
                    execution_time_ms=exec_time_ms,
                    result_scale=scale_r,
                    status=status,
                    raw_query=formatted_mut
                )
                
                new_strategy, is_interesting = monitor.process_feedback(feedback_vec)

                if monitor.should_promote_seed(feedback_vec, is_interesting) and formatted_mut not in seen_queries:
                    skeletons.append(formatted_mut)
                    seen_queries.add(formatted_mut)
                    log_verbose(f"[种子池进化] 捕获高价值用例！已追加至队列尾部")
                elif is_interesting:
                    log_verbose(f"[反馈抑制] 高延迟/异常候选不进入主种子池: {monitor.classify_latency(feedback_vec).value}")
                
                if status == ExecStatus.CRASH:
                    stats_crashes += 1
                    log_verbose(f"触发引擎崩溃: {msg}")
                elif status == ExecStatus.RESOURCE_EXHAUSTION:
                    stats_resource_exhaustions += 1
                    log_verbose(f"触发资源耗尽候选: {msg}")
                elif is_success:
                    stats_passed += 1
                    log_verbose(f"执行状态: Success ({exec_time_ms:.2f}ms, Scale: {scale_r})")
                else:
                    stats_exec_failed += 1
                    log_verbose(f"执行失败: {msg}")

                if args.reseed_interval > 0 and stats_executed > 0 and stats_executed % args.reseed_interval == 0:
                    real_schema, real_state = periodic_reseed_and_refresh()

                log_verbose("-" * 60 + "\n")
                
                dashboard.update(stats_drawn, stats_filtered, stats_executed, stats_passed, stats_exec_failed, stats_crashes, stats_resource_exhaustions)
                    
            except Exception as e:
                stats_executed += 1
                stats_exec_failed += 1
                log_verbose(f"严重内部崩溃发生！\n{traceback.format_exc()}\n" + "-" * 60 + "\n")
                dashboard.update(stats_drawn, stats_filtered, stats_executed, stats_passed, stats_exec_failed, stats_crashes, stats_resource_exhaustions)

    except KeyboardInterrupt:
        print("\n\n测试终止 (Ctrl+C)！")        
    finally:
        executor.close()
