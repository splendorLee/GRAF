import time
from enum import Enum
from dataclasses import dataclass
from typing import Tuple

class ExecStatus(Enum):
    SUCCESS = "SUCCESS"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"
    RESOURCE_EXHAUSTION = "RESOURCE_EXHAUSTION"
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
    max_limit: int = 1000
    max_path_bound: int = 8
    allow_expensive_aggregation: bool = True
    allow_topology_expansion: bool = True
    
    def clamp(self):
        self.topology_rate = max(0.05, min(0.95, self.topology_rate))
        self.predicate_rate = max(0.05, min(0.95, self.predicate_rate))
        self.clause_rate = max(0.05, min(0.95, self.clause_rate))
        self.depth_scale_factor = max(0.1, min(1.0, self.depth_scale_factor))
        self.max_limit = max(1, min(1000, int(self.max_limit)))
        self.max_path_bound = max(1, min(12, int(self.max_path_bound)))


class LatencyBand(Enum):
    FAST = "FAST_LT_10S"
    SLOW = "SLOW_10S_60S"
    TIMEOUT = "TIMEOUT_GT_60S"
    ERROR = "ERROR_OR_CRASH"


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
        self.FAST_QUERY_THRESHOLD_MS = 10_000.0
        self.SLOW_QUERY_THRESHOLD_MS = 60_000.0
        self.SEVERE_LATENCY_THRESHOLD_MS = self.SLOW_QUERY_THRESHOLD_MS

    def classify_latency(self, feedback: FeedbackVector) -> LatencyBand:
        if feedback.status in {ExecStatus.CRASH, ExecStatus.ERROR, ExecStatus.RESOURCE_EXHAUSTION}:
            return LatencyBand.ERROR
        if feedback.status == ExecStatus.TIMEOUT or feedback.execution_time_ms > self.SLOW_QUERY_THRESHOLD_MS:
            return LatencyBand.TIMEOUT
        if feedback.execution_time_ms >= self.FAST_QUERY_THRESHOLD_MS:
            return LatencyBand.SLOW
        return LatencyBand.FAST

    def should_promote_seed(self, feedback: FeedbackVector, is_interesting: bool) -> bool:
        return is_interesting and self.classify_latency(feedback) == LatencyBand.FAST

    def process_feedback(self, feedback: FeedbackVector) -> tuple[MutationStrategy, bool]:
        is_interesting = False     
        latency_band = self.classify_latency(feedback)

        if feedback.status == ExecStatus.CRASH:
            print(f"[Monitor] 捕获引擎崩溃/致命断开；复现证据由目标执行器负责落盘。")
            self.high_value_seeds.append(feedback.raw_query)
            is_interesting = True
            return self.current_strategy, is_interesting

        if feedback.status == ExecStatus.RESOURCE_EXHAUSTION:
            print("[Monitor] 捕获资源耗尽候选；复现包由目标执行器负责落盘。")
            self.high_value_seeds.append(feedback.raw_query)
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

        if latency_band == LatencyBand.SLOW:
            self.current_strategy.topology_rate *= 0.6
            self.current_strategy.clause_rate *= 0.6
            self.current_strategy.depth_scale_factor *= 0.55
            self.current_strategy.max_path_bound = min(self.current_strategy.max_path_bound, 4)
            self.current_strategy.max_limit = min(self.current_strategy.max_limit, 100)
            self.current_strategy.allow_expensive_aggregation = False
            self.current_strategy.allow_topology_expansion = False
            is_interesting = True

        elif latency_band == LatencyBand.TIMEOUT:
            self.current_strategy.topology_rate *= 0.35
            self.current_strategy.clause_rate *= 0.4
            self.current_strategy.predicate_rate += 0.1
            self.current_strategy.depth_scale_factor *= 0.35
            self.current_strategy.max_path_bound = min(self.current_strategy.max_path_bound, 2)
            self.current_strategy.max_limit = min(self.current_strategy.max_limit, 25)
            self.current_strategy.allow_expensive_aggregation = False
            self.current_strategy.allow_topology_expansion = False
            is_interesting = True

        elif feedback.status == ExecStatus.SUCCESS and feedback.result_scale == 0 and feedback.execution_time_ms < self.RAPID_EXEC_THRESHOLD_MS:
            self.current_strategy.predicate_rate += 0.15
            self.current_strategy.topology_rate -= 0.05
            

        else:
            self.current_strategy.predicate_rate = (self.current_strategy.predicate_rate + 0.3) / 2
            self.current_strategy.topology_rate = (self.current_strategy.topology_rate + 0.3) / 2
            self.current_strategy.depth_scale_factor = min(1.0, self.current_strategy.depth_scale_factor + 0.15)
            self.current_strategy.max_limit = min(1000, max(self.current_strategy.max_limit, 250) + 25)
            self.current_strategy.max_path_bound = min(8, max(self.current_strategy.max_path_bound, 4) + 1)
            self.current_strategy.allow_expensive_aggregation = True
            self.current_strategy.allow_topology_expansion = True
            
            if feedback.status == ExecStatus.SUCCESS and feedback.execution_time_ms > (self.FAST_QUERY_THRESHOLD_MS * 0.8):
                is_interesting = True

        self.current_strategy.clamp()
        return self.current_strategy, is_interesting
