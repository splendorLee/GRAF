import os
import time
from enum import Enum
from dataclasses import dataclass
from typing import Tuple

class ExecStatus(Enum):
    SUCCESS = "SUCCESS"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"
    CRASH = "CRASH"

@dataclass
class FeedbackVector:
    execution_time_ms: float
    result_scale: int       # 规模估算值 |R|，而非精确行数
    status: ExecStatus
    raw_query: str = ""

@dataclass
class MutationStrategy:
    topology_rate: float = 0.3      
    depth_scale_factor: float = 1.0 
    predicate_rate: float = 0.3     
    clause_rate: float = 0.2        
    
    def clamp(self):
        self.topology_rate = max(0.05, min(0.95, self.topology_rate))
        self.predicate_rate = max(0.05, min(0.95, self.predicate_rate))
        self.clause_rate = max(0.05, min(0.95, self.clause_rate))
        self.depth_scale_factor = max(0.1, min(1.0, self.depth_scale_factor))


def estimate_result_scale(execution_output) -> int:
    """
    轻量级体积估算：完全容忍驱动层返回的脏数据、Warning 字典或嵌套的 C++ 绑定图实体。
    采用 O(1) 基础探测 + 字符串物理体积评估，严防解析崩溃。
    """
    if not execution_output:
        return 0

    scale = 0
    try:
        if isinstance(execution_output, list):
            scale = len(execution_output)
        elif hasattr(execution_output, '__len__'):
            scale = len(execution_output)
        else:
            scale = 1  

        raw_str = str(execution_output)
        str_volume = len(raw_str) // 500
        scale += str_volume

        return scale

    except Exception:
        return 1

class FeedbackMonitor:
    def __init__(self, seed_cypher: str = ""):
        self.current_strategy = MutationStrategy()
        self.high_value_seeds = []
        
        self.seed_cypher = seed_cypher
        self.execution_history = []  
        
        self.RAPID_EXEC_THRESHOLD_MS = 15.0    
        self.SEVERE_LATENCY_THRESHOLD_MS = 2500.0  
        
        self.poc_dir = "crash_pocs"
        os.makedirs(self.poc_dir, exist_ok=True)

    def process_feedback(self, feedback: FeedbackVector) -> tuple[MutationStrategy, bool]:
        is_interesting = False     

        if feedback.status == ExecStatus.CRASH:
            print(f"[Monitor] 捕获引擎崩溃/致命断开！正在生成完整复现场景...")
            self.high_value_seeds.append(feedback.raw_query)
            self._save_poc(feedback.raw_query)
            is_interesting = True
            return self.current_strategy, is_interesting

        if feedback.status == ExecStatus.SUCCESS:
            self.execution_history.append(feedback.raw_query)
        elif feedback.status == ExecStatus.ERROR:
            try:
                with open("mutation_rejected_errors.log", "a", encoding="utf-8") as f:
                    f.write(f"---\n时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n 拦截: 靶机语义/语法拒绝\n 语句: {feedback.raw_query}\n")
            except Exception:
                pass


        if feedback.status == ExecStatus.SUCCESS and feedback.result_scale == 0 and feedback.execution_time_ms < self.RAPID_EXEC_THRESHOLD_MS:
            self.current_strategy.predicate_rate += 0.15
            self.current_strategy.topology_rate -= 0.05
            

        elif feedback.execution_time_ms > self.SEVERE_LATENCY_THRESHOLD_MS or feedback.status == ExecStatus.TIMEOUT:
            if feedback.status == ExecStatus.TIMEOUT or feedback.result_scale < 50:
                self.current_strategy.topology_rate -= 0.25
                self.current_strategy.depth_scale_factor *= 0.6
                is_interesting = True
                

        else:
            self.current_strategy.predicate_rate = (self.current_strategy.predicate_rate + 0.3) / 2
            self.current_strategy.topology_rate = (self.current_strategy.topology_rate + 0.3) / 2
            self.current_strategy.depth_scale_factor = min(1.0, self.current_strategy.depth_scale_factor + 0.15)
            
            if feedback.status == ExecStatus.SUCCESS and feedback.execution_time_ms > (self.SEVERE_LATENCY_THRESHOLD_MS * 0.8):
                is_interesting = True

        self.current_strategy.clamp()
        return self.current_strategy, is_interesting

    def _save_poc(self, crash_query: str):
        timestamp = int(time.time() * 1000)
        filename = os.path.join(self.poc_dir, f"poc_crash_{timestamp}.cypher")
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write("// ==========================================================\n")
                f.write(f"// Memgraph Fuzzing Crash PoC (Timestamp: {timestamp})\n")
                f.write("// ==========================================================\n\n")
                
                f.write("// [0] 清空数据库环境 (Clean Database)\n")
                f.write("MATCH (n) DETACH DELETE n;\n\n")
                
                f.write("// [1] 初始化建图语句 (Seed Graph Generation)\n")

                raw_seeds = [s.strip() for s in self.seed_cypher.split(';') if s.strip()]
                for seed_stmt in raw_seeds:
                    f.write(f"{seed_stmt};\n")
                f.write("\n")
                
                f.write("// [2] 上游状态改变轨迹 (Upstream Execution History)\n")
                for q in self.execution_history:
                    safe_q = q if q.strip().endswith(';') else f"{q};"
                    f.write(f"{safe_q}\n")
                f.write("\n")
                
                f.write("// [3] 触发崩溃的致死语句 (Crash Triggering Query)\n")
                safe_crash_q = crash_query if crash_query.strip().endswith(';') else f"{crash_query};"
                f.write(f"{safe_crash_q}\n")
                
            print(f"[Monitor] 完整环境 PoC 已固化至: {filename}")
        except Exception as e:
            print(f"[Monitor] PoC 固化失败: {e}")