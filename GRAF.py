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
from dataclasses import dataclass, field
from typing import Dict, Set, Tuple, List


current_dir = os.path.dirname(os.path.abspath(__file__))
antlr_path = os.path.join(current_dir, "antlr4-cypher", "antlr4_cypher")
if antlr_path not in sys.path:
    sys.path.insert(0, antlr_path)


from antlr4 import InputStream, CommonTokenStream
from antlr4.TokenStreamRewriter import TokenStreamRewriter
from antlr4.error.ErrorListener import ErrorListener

from CypherLexer import CypherLexer
from CypherParser import CypherParser
from CypherParserVisitor import CypherParserVisitor

from GraphInitializer import MemgraphSeedGenerator, FalkorDBSeedGenerator, KuzuSeedGenerator, NebulaSeedGenerator
from Instantiator import compile_and_instantiate
from SkeletonFilter import GrafSkeletonFilter
from FeedbackMonitor import FeedbackMonitor, FeedbackVector, ExecStatus, estimate_result_scale

from GraphContext import MemgraphContextExtractor, FalkorDBContextExtractor, KuzuContextExtractor, NebulaContextExtractor
from DB_Executor import MemgraphFuzzExecutor, FalkorDBFuzzExecutor, KuzuFuzzExecutor, NebulaFuzzExecutor

# 引入工业级图感知变异器及上下文结构
from GraphAwareMutator import (
    GraphAwareMutator, 
    SchemaMetadata, 
    ValueDictionary, 
    GlobalGraphState, 
    compile_and_mutate
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

    def update(self, drawn, filtered, executed, passed, exec_failed, crashes, current_q=None):
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

def apply_ast_mutation(executable_query: str, real_schema, real_state, strategy) -> str:
    def safe_extract(obj, key, default=None):
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)

    v_count = safe_extract(real_state, 'node_count', 0)
    e_count = safe_extract(real_state, 'edge_count', 0)
    dynamic_diameter = estimate_safe_diameter(v_count, e_count)

    schema_ctx = SchemaMetadata(
        labels=set(safe_extract(real_schema, 'labels', set())),
        topology=safe_extract(real_schema, 'topology', {}),
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
    
    return mutated_query


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GRAF Fuzzer - 跨引擎图数据库漏洞挖掘系统")
    parser.add_argument(
        "--target", 
        type=str, 
        required=True, 
        help="指定目标引擎，可选值: 'memgraph', 'falkordb', 'kuzu', 'nebula'"
    )
    args = parser.parse_args()

    TARGET_ENGINE = args.target.lower()
    
    if TARGET_ENGINE not in ["memgraph", "falkordb", "kuzu", "nebula"]:
        print(f"致命错误: 不支持的目标引擎 '{args.target}'。请使用 'memgraph', 'falkordb', 'kuzu', 'nebula'。")
        sys.exit(1)

    if TARGET_ENGINE == "kuzu":
        POOL_FILE = "skeleton_pool_kuzu"
    elif TARGET_ENGINE == "nebula":
        POOL_FILE = "skeleton_pool_nebula"
    else:
        POOL_FILE = "skeleton_pool"

    VERBOSE_LOG_FILE = f"fuzz_verbose_{TARGET_ENGINE}.log"
    with open(VERBOSE_LOG_FILE, "w", encoding="utf-8") as f:
        f.write(f"=== GRAF Fuzzer 详细运行日志 (Target: {TARGET_ENGINE.upper()}) ===\n\n")

    def log_verbose(msg):
        with open(VERBOSE_LOG_FILE, "a", encoding="utf-8") as file:
            file.write(msg + "\n")

    log_verbose(f"🚀 [GRAF Fuzzer] 目标引擎已设定为: {TARGET_ENGINE.upper()}")

    if TARGET_ENGINE == "memgraph":
        URI = "bolt://localhost:7687"
        USER = ""
        PASSWORD = ""
        generator = MemgraphSeedGenerator(URI, USER, PASSWORD)
        generator.reset_and_initialize()
        seed_cypher_text = getattr(generator, 'seed_cypher', '')
        generator.close()
        extractor = MemgraphContextExtractor(URI, USER, PASSWORD)
        executor = MemgraphFuzzExecutor(URI, USER, PASSWORD, seed_cypher=seed_cypher_text)
        executor.container_name = "memgraph_fuzz_target"
        
    elif TARGET_ENGINE == "falkordb":
        HOST = "localhost"
        PORT = 6380
        PASSWORD = ""
        GRAPH_NAME = "graf_fuzz"
        generator = FalkorDBSeedGenerator(host=HOST, port=PORT, password=PASSWORD, graph_name=GRAPH_NAME)
        generator.reset_and_initialize()
        seed_cypher_text = getattr(generator, 'seed_cypher', '')
        extractor = FalkorDBContextExtractor(host=HOST, port=PORT, password=PASSWORD, graph_name=GRAPH_NAME)
        executor = FalkorDBFuzzExecutor(host=HOST, port=PORT, password=PASSWORD, graph_name=GRAPH_NAME, seed_cypher=seed_cypher_text)
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
    
    filter_engine = GrafSkeletonFilter()
    monitor = FeedbackMonitor(seed_cypher=seed_cypher_text)
    
    log_verbose("\n启动无限循环图变异测试...\n")
    
    dashboard = FuzzDashboard(TARGET_ENGINE.upper())
    stats_drawn = 0           
    stats_filtered = 0        
    stats_executed = 0        
    stats_passed = 0          
    stats_exec_failed = 0     
    stats_crashes = 0         
    
    try:
        skeletons = load_skeletons_from_file(POOL_FILE)
        seen_queries = set(skeletons) 
        
        round_idx = 0                  
        CONTEXT_REFRESH_INTERVAL = 500 
        
        while True:
            current_idx = round_idx % len(skeletons)
            skeleton = skeletons[current_idx]
            
            round_idx += 1
            stats_drawn += 1  
            
            if round_idx > 0 and round_idx % CONTEXT_REFRESH_INTERVAL == 0:
                log_verbose("[环境同步] 正在重新提取数据库真实状态与规模...")
                if TARGET_ENGINE == "memgraph":
                    temp_extractor = MemgraphContextExtractor(URI, USER, PASSWORD)
                elif TARGET_ENGINE == "falkordb":
                    temp_extractor = FalkorDBContextExtractor(host=HOST, port=PORT, password=PASSWORD, graph_name=GRAPH_NAME)
                elif TARGET_ENGINE == "kuzu":
                    temp_extractor = KuzuContextExtractor(db_path=DB_PATH)
                elif TARGET_ENGINE == "nebula":
                    temp_extractor = NebulaContextExtractor(host=HOST, port=PORT, user=USER, password=PASSWORD, space=SPACE)
                
                real_schema, real_state = temp_extractor.extract_context()
                temp_extractor.close()
            
            filter_result = filter_engine.validate(skeleton)
            if not filter_result.is_valid:
                log_verbose(f"拦截: {filter_result.reason}\n")
                stats_filtered += 1
                dashboard.update(stats_drawn, stats_filtered, stats_executed, stats_passed, stats_exec_failed, stats_crashes)
                continue
                
            try:
                executable_query, errors = compile_and_instantiate(skeleton, real_schema, real_state, target_engine=TARGET_ENGINE)                
                formatted_base = " ".join(executable_query.split())
                log_verbose(f"基础查询 (Q0): {formatted_base}")
                
                mutated_query = apply_ast_mutation(formatted_base, real_schema, real_state, monitor.current_strategy)
                formatted_mut = " ".join(mutated_query.split())
                log_verbose(f"AST变异 (Q_mut): {formatted_mut}")

                query_to_log = formatted_mut if formatted_mut.endswith(';') else f"{formatted_mut};"
                try:
                    with open(f"fuzzing_execution_trace_{TARGET_ENGINE}.cypher", "a", encoding="utf-8") as trace_file:
                        trace_file.write(f"{query_to_log}\n")
                except Exception:
                    pass

                stats_executed += 1
                
                dashboard.update(stats_drawn, stats_filtered, stats_executed, stats_passed, stats_exec_failed, stats_crashes, current_q=formatted_mut)
                
                start_time = time.time()
                is_success, msg, execution_output = executor.execute_single(formatted_mut)
                exec_time_ms = (time.time() - start_time) * 1000

                status = ExecStatus.SUCCESS
                if not is_success:
                    msg_lower = msg.lower()
                    if any(err in msg_lower for err in ["clienterror", "parsing error", "syntax error", "extraneous input"]):
                        status = ExecStatus.ERROR
                    elif any(keyword in msg_lower for keyword in ["crash", "connection refused", "connection reset", "closed", "broken pipe", "socket", "service unavailable", "assertion failed"]):
                        status = ExecStatus.CRASH
                    elif "timeout" in msg_lower:
                        status = ExecStatus.TIMEOUT
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
                
                if is_interesting and formatted_mut not in seen_queries:
                    skeletons.append(formatted_mut)
                    seen_queries.add(formatted_mut)
                    log_verbose(f"[种子池进化] 捕获高价值用例！已追加至队列尾部")
                
                if status == ExecStatus.CRASH:
                    stats_crashes += 1
                    log_verbose(f"触发引擎崩溃: {msg}")
                elif is_success:
                    stats_passed += 1
                    log_verbose(f"执行状态: Success ({exec_time_ms:.2f}ms, Scale: {scale_r})")
                else:
                    stats_exec_failed += 1
                    log_verbose(f"执行失败: {msg}")

                log_verbose("-" * 60 + "\n")
                
                dashboard.update(stats_drawn, stats_filtered, stats_executed, stats_passed, stats_exec_failed, stats_crashes)
                    
            except Exception as e:
                stats_executed += 1
                stats_exec_failed += 1
                log_verbose(f"严重内部崩溃发生！\n{traceback.format_exc()}\n" + "-" * 60 + "\n")
                dashboard.update(stats_drawn, stats_filtered, stats_executed, stats_passed, stats_exec_failed, stats_crashes)

    except KeyboardInterrupt:
        print("\n\n测试终止 (Ctrl+C)！")        
    finally:
        executor.close()