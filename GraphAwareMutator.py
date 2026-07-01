import random
import re
from typing import Dict, List, Any, Set
from dataclasses import dataclass, field
from antlr4.TokenStreamRewriter import TokenStreamRewriter
from CypherParserVisitor import CypherParserVisitor


@dataclass
class SchemaMetadata:
    labels: Set[str] = field(default_factory=set)
    topology: Dict[str, List[tuple[str, str]]] = field(default_factory=dict)
    properties: Dict[str, List[str]] = field(default_factory=dict)

@dataclass
class ValueDictionary:
    observed_values: Dict[str, List[Any]] = field(default_factory=dict)
    
    def get_mutated_value(self, prop_name: str) -> str:
        strategies = ["NULL", "-9223372036854775807", "9223372036854775807", "-1e308", "'\" OR 1=1 --'", "''"]
        if prop_name in self.observed_values and random.random() < 0.6:
            val = random.choice(self.observed_values[prop_name])
            return f"'{val}'" if isinstance(val, str) else str(val)
        return random.choice(strategies)

@dataclass
class GlobalGraphState:
    node_count: int = 0
    edge_count: int = 0
    diameter: int = 5
    
    def calculate_max_limit(self) -> int:
        return max(10, min(1000, (self.node_count + self.edge_count) // 10))

class GraphAwareMutator(CypherParserVisitor):
    def __init__(self, token_stream, schema: SchemaMetadata, val_dict: ValueDictionary, state: GlobalGraphState):
        super().__init__()
        self.rewriter = TokenStreamRewriter(token_stream)
        self.schema = schema
        self.val_dict = val_dict
        self.state = state
        
        self.scope_vars: Dict[str, str] = {}
        self.MUTATION_RATE = 1.0 


    def visitNodePattern(self, ctx):
        self.visitChildren(ctx)
        text = ctx.getText()
        # 匹配形如 (n:Person) 或 (n:`Person`)
        match = re.search(r'\(\s*([a-zA-Z0-9_]+)\s*:\s*`?([a-zA-Z0-9_]+)`?', text)
        if match:
            self.scope_vars[match.group(1)] = match.group(2)
        return None


    def visitMatchSt(self, ctx):
        self.visitChildren(ctx)
        
        text = ctx.getText().upper()
        if text.startswith("MATCH") and not text.startswith("OPTIONAL"):
            if random.random() < self.MUTATION_RATE and self.scope_vars:
                src_var = random.choice(list(self.scope_vars.keys()))
                src_label = self.scope_vars[src_var]
                
                raw_edges = self.schema.topology.get(src_label, [])
                
                if isinstance(raw_edges, dict):
                    valid_edges = list(raw_edges.items())
                else:
                    valid_edges = list(raw_edges)
                
                if valid_edges:
                    edge_info = random.choice(valid_edges)
                    if isinstance(edge_info, tuple) and len(edge_info) == 2:
                        rel_type, target_label = edge_info
                        new_var = f"m_mut_{random.randint(100, 999)}"
                        mut_cypher = f" OPTIONAL MATCH ({src_var})-[:`{rel_type}`]->({new_var}:`{target_label}`)"
                        
                        if ctx.stop:
                            self.rewriter.insertAfterToken(ctx.stop, mut_cypher)
                            self.scope_vars[new_var] = target_label
                            # print(f"[变异] 拓扑延伸 -> 附加 {new_var}:{target_label}")
        return None


    def visitWhere(self, ctx):
        self.visitChildren(ctx)
        
        if random.random() < self.MUTATION_RATE and self.scope_vars:
            target_var = random.choice(list(self.scope_vars.keys()))
            target_label = self.scope_vars[target_var]
            
            raw_props = self.schema.properties.get(target_label, [])
            if isinstance(raw_props, dict):
                available_props = list(raw_props.keys())
            else:
                available_props = list(raw_props)
            
            if available_props:
                prop = random.choice(available_props)
                mutated_val = self.val_dict.get_mutated_value(prop)
                
                if mutated_val == "NULL":
                    op = random.choice(["IS", "IS NOT"])
                else:
                    op = random.choice(["=", "<>", ">", "<", "<=", ">="])
                    
                pred = f" AND {target_var}.{prop} {op} {mutated_val}"
                
                if ctx.stop:
                    self.rewriter.insertAfterToken(ctx.stop, pred)
                    # print(f"[变异] 谓词注入 -> 追加 {target_var}.{prop} {op} {mutated_val}")
        return None


    def visitReturnSt(self, ctx):
        if random.random() < self.MUTATION_RATE and len(self.scope_vars) >= 2:
            vars_list = list(self.scope_vars.keys())
            var1, var2 = vars_list[0], vars_list[1]
            c_mut_var = f"c_mut_{random.randint(10, 99)}"
            agg_func = random.choice(["count", "collect", "max"])
            
            with_inj = f" WITH *, {agg_func}({var2}) AS {c_mut_var} "
            
            if ctx.start:
                self.rewriter.insertBeforeToken(ctx.start, with_inj)
                # print(f"[变异] 管道截断 -> 插入 WITH * 聚合")
                
        return self.visitChildren(ctx)


    def visitLimitSt(self, ctx):
        self.visitChildren(ctx)
        if random.random() < self.MUTATION_RATE:
            safe_limit = self.state.calculate_max_limit()
            # 整体替换 LIMIT 子句为安全值
            if ctx.start and ctx.stop:
                self.rewriter.replaceRange(ctx.start.tokenIndex, ctx.stop.tokenIndex, f"LIMIT {safe_limit}")
                # print(f"[变异] 体积控制 -> LIMIT {safe_limit}")
        return None

    def visitRangeLit(self, ctx):
        self.visitChildren(ctx)
        if random.random() < self.MUTATION_RATE:
            text = ctx.getText()
            match = re.search(r'\.\.(\d+)', text)
            if match:
                upper = int(match.group(1))
                safe_bound = min(upper, self.state.diameter)
                new_text = re.sub(r'\.\.\d+', f"..{safe_bound}", text)
                if ctx.start and ctx.stop:
                    self.rewriter.replaceRange(ctx.start.tokenIndex, ctx.stop.tokenIndex, new_text)
                    # print(f"[变异] 深度控制 -> {new_text}")
        return None


def compile_and_mutate(token_stream, parse_tree, schema: SchemaMetadata, val_dict: ValueDictionary, state: GlobalGraphState, strategy=None) -> str:
    # 初始化变异器
    mutator = GraphAwareMutator(token_stream, schema, val_dict, state)
    
    # 将反馈监控器的动态策略 (Strategy) 注入到变异器中
    if strategy:
        mutator.MUTATION_RATE = (strategy.topology_rate + strategy.predicate_rate + strategy.clause_rate) / 3.0
        
        # 动态缩放图的遍历深度
        mutator.state.diameter = max(1, int(mutator.state.diameter * strategy.depth_scale_factor))
        
    # 触发标准 AST 游走
    mutator.visit(parse_tree)
    
    return mutator.rewriter.getDefaultText()