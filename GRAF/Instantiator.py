import sys
import os
import re
import random
import traceback
from typing import Tuple, List, Dict, Set

current_dir = os.path.dirname(os.path.abspath(__file__))
antlr_path = os.path.join(current_dir, "antlr4_cypher", "antlr4_cypher")
if antlr_path not in sys.path:
    sys.path.insert(0, antlr_path)

from antlr4 import InputStream, CommonTokenStream
from antlr4.TokenStreamRewriter import TokenStreamRewriter
from antlr4.error.ErrorListener import ErrorListener

from GraphContext import SchemaMetadata, GlobalGraphState
from CypherLexer import CypherLexer
from CypherParser import CypherParser
from CypherParserVisitor import CypherParserVisitor

class SilentErrorListener(ErrorListener):
    def __init__(self):
        self.errors = []
    def syntaxError(self, recognizer, offendingSymbol, line, column, msg, e):
        self.errors.append(f"Line {line}:{column} {msg}")


class TypeAwareMutator:
    def __init__(self, schema_M: SchemaMetadata):
        self.schema_M = schema_M
        
        self.bva_dict = {
            "INTEGER": ["0", "1", "-1", "42", "2147483647", "-2147483648"],
            "FLOAT": ["0.0", "1.0", "-1.0", "3.14159", "999.99", "-999.99"],
            "STRING": ['""', '"*"', '" "', '"A"', '"\' OR 1=1"', '"admin"'],
            "BOOLEAN": ["true", "false"]
        }
        
        self.global_prop_pool = []
        if self.schema_M and self.schema_M.properties:
            for entity, props in self.schema_M.properties.items():
                if isinstance(props, dict):
                    for prop_name, prop_type in props.items():
                        self.global_prop_pool.append((str(prop_name), str(prop_type)))

    def get_random_property_global(self) -> Tuple[str, str]:
        if not self.global_prop_pool:
            return "id", "INTEGER" 
        return random.choice(self.global_prop_pool)

    def get_valid_property_for_label(self, label: str) -> Tuple[str, str]:
        if not self.schema_M or not self.schema_M.properties:
            return "id", "INTEGER"
        if label and label in self.schema_M.properties and self.schema_M.properties[label]:
            prop_name = random.choice(list(self.schema_M.properties[label].keys()))
            prop_type = self.schema_M.properties[label][prop_name]
            return prop_name, prop_type
        if self.global_prop_pool:
            return random.choice(self.global_prop_pool)
        return "id", "INTEGER"

    def generate_value(self, target_type: str = None) -> str:
        if not target_type or target_type not in self.bva_dict:
            target_type = random.choice(list(self.bva_dict.keys()))
            
        val = random.choice(self.bva_dict[target_type])
        if "*" in val and '"' in val:
            parts = val.split("*")
            if len(parts) == 2 and parts[1].strip().isdigit():
                return '"' + (parts[0].replace('"', '').strip() * int(parts[1].strip())) + '"'
        return val

    def generate_list(self, target_type: str = None, strict: bool = False) -> str:
        if not target_type or target_type not in self.bva_dict:
            target_type = random.choice(list(self.bva_dict.keys()))
        length = random.randint(1, 4)
        
        if strict:
            vals = [self.generate_value(target_type) for _ in range(length)]
        else:
            vals = [self.generate_value(target_type) if random.random() < 0.8 else self.generate_value() for _ in range(length)]
        return f"[{', '.join(vals)}]"


class LexicalFallbackEngine:
    def __init__(self, schema_M, symbol_table, mutator: TypeAwareMutator, strict_mode: bool):
        self.schema_M = schema_M
        self.symbol_table = symbol_table 
        self.mutator = mutator
        self.strict_mode = strict_mode
        
        self.label_registry = {}
        self.rel_registry = {}
        self.prop_name_registry = {}
        self.prop_type_registry = {}

    def _infer_type_from_schema(self, prop_name: str) -> str:
        if prop_name.lower() == "id": return "INTEGER"
        if self.schema_M and self.schema_M.properties:
            for props in self.schema_M.properties.values():
                if prop_name in props: return props[prop_name]
        return "STRING"

    def sweep(self, query: str) -> str:
        available_vars = list(self.symbol_table.keys())

        if self.strict_mode:
            def repl_label(match):
                lbl_id = match.group(1)
                if lbl_id not in self.label_registry:
                    self.label_registry[lbl_id] = random.choice(list(self.schema_M.labels)) if self.schema_M and self.schema_M.labels else "Node"
                return self.label_registry[lbl_id]
            query = re.sub(r'`?\$LABEL_(\d+)`?', repl_label, query)

            def repl_rel(match):
                rel_id = match.group(1)
                if rel_id not in self.rel_registry:
                    self.rel_registry[rel_id] = random.choice(list(self.schema_M.topology.keys())) if self.schema_M and self.schema_M.topology else "REL"
                return self.rel_registry[rel_id]
            query = re.sub(r'`?\$REL_TYPE_(\d+)`?', repl_rel, query)

            def repl_prop_access(match):
                var_name, prop_id = match.group(1), match.group(2)
                if prop_id not in self.prop_name_registry:
                    label = self.symbol_table.get(var_name)
                    prop_name, prop_type = self.mutator.get_valid_property_for_label(label)
                    self.prop_name_registry[prop_id] = prop_name
                    self.prop_type_registry[prop_id] = prop_type
                return f"{var_name}.{self.prop_name_registry[prop_id]}"
            query = re.sub(r'\b([a-zA-Z0-9_]+)\.`?\$PROP_(\d+)`?', repl_prop_access, query)

            def repl_prop_standalone(match):
                prop_id = match.group(1)
                if prop_id not in self.prop_name_registry:
                    prop_name, prop_type = self.mutator.get_valid_property_for_label(None)
                    self.prop_name_registry[prop_id] = prop_name
                    self.prop_type_registry[prop_id] = prop_type
                return self.prop_name_registry[prop_id]
            query = re.sub(r'`?\$PROP_(\d+)`?', repl_prop_standalone, query)

            for match in re.finditer(r'\b([a-zA-Z0-9_]+)\s*[:=]\s*`?\$VALUE_(\d+)`?', query):
                prop_name, val_id = match.group(1), match.group(2)
                if val_id not in self.prop_type_registry:
                    self.prop_type_registry[val_id] = self._infer_type_from_schema(prop_name)
                    
            for match in re.finditer(r'\b([a-zA-Z0-9_]+)\s*(?:IN|in)\s*`?\$LIST_(\d+)`?', query):
                prop_name, list_id = match.group(1), match.group(2)
                if list_id not in self.prop_type_registry:
                    self.prop_type_registry[list_id] = self._infer_type_from_schema(prop_name)

            query = re.sub(r'`?\$VALUE_(\d+)`?', lambda m: self.mutator.generate_value(self.prop_type_registry.get(m.group(1))), query)
            query = re.sub(r'`?\$LIST_(\d+)`?', lambda m: self.mutator.generate_list(self.prop_type_registry.get(m.group(1)), strict=True), query)
            
        else:
            query = re.sub(r'`?\$LABEL_\d+`?', lambda m: random.choice(list(self.schema_M.labels)) if self.schema_M and self.schema_M.labels else "Node", query)
            query = re.sub(r'`?\$REL_TYPE_\d+`?', lambda m: random.choice(list(self.schema_M.topology.keys())) if self.schema_M and self.schema_M.topology else "REL", query)
            query = re.sub(r'`?\$PROP_\d+`?', lambda m: self.mutator.get_random_property_global()[0], query)
            query = re.sub(r'`?\$VALUE_\d+`?', lambda m: self.mutator.generate_value(), query)
            query = re.sub(r'`?\$LIST_\d+`?', lambda m: self.mutator.generate_list(strict=False), query)

        query = re.sub(r'`?\$PREDICATE_FOR_([A-Za-z0-9_]+)`?', r'\1 IS NOT NULL', query)
        query = re.sub(r'`?\$RETURN_EXPR_FOR_([A-Za-z0-9_]+)`?', r'\1', query)
        query = re.sub(r'`?\$PREDICATE_\d+`?', lambda m: f"({random.choice(available_vars)} IS NOT NULL)" if available_vars else "1=1", query)
        query = re.sub(r'`?\$RETURN_EXPR_\d+`?', lambda m: random.choice(available_vars) if available_vars else "count(*)", query)
        
        return query

class GrafASTCompiler(CypherParserVisitor):
    def __init__(self, schema_M, rewriter: TokenStreamRewriter, strict_mode: bool):
        self.schema_M = schema_M
        self.rewriter = rewriter
        self.mutator = TypeAwareMutator(self.schema_M)
        self.strict_mode = strict_mode
        self.symbol_table = {}       
        self.context_memory = {}     
        self.replaced_tokens = set() 
        self.label_registry = {}
        self.rel_registry = {}
        self.prop_type_registry = {} 

    def _safe_replace_range(self, start_idx, stop_idx, text):
        if start_idx is None or stop_idx is None or start_idx < 0: return
        self.rewriter.replaceRange(start_idx, stop_idx, text)
        for i in range(start_idx, stop_idx + 1):
            self.replaced_tokens.add(i)

    def visitUnwind(self, ctx):
        var_name = ctx.variable().getText() if getattr(ctx, "variable", None) and ctx.variable() else None
        if var_name: self.symbol_table[var_name] = "SCALAR"
        return self.visitChildren(ctx)

    def visitAliasedReturnItem(self, ctx):
        var_name = ctx.variable().getText() if getattr(ctx, "variable", None) and ctx.variable() else None
        if var_name: self.symbol_table[var_name] = "ANY"
        return self.visitChildren(ctx)

    def visitPatternPart(self, ctx):
        var_name = ctx.variable().getText() if getattr(ctx, "variable", None) and ctx.variable() else None
        if var_name: self.symbol_table[var_name] = "PATH"
        return self.visitChildren(ctx)

    def visitPatternElement(self, ctx):
        nodes, rels = [], []
        if getattr(ctx, "nodePattern", None) and ctx.nodePattern(): 
            nodes.append(ctx.nodePattern())
        chains = getattr(ctx, "patternElementChain", lambda: [])()
        if not isinstance(chains, list): chains = [chains] if chains else []
            
        for chain in chains:
            rels.append(chain.relationshipPattern())
            nodes.append(chain.nodePattern())
            
        for i in range(len(rels)):
            if i + 1 >= len(nodes): break
            ln, rel, rn = nodes[i], rels[i], nodes[i+1]
            l_var = ln.symbol().getText() if getattr(ln, "symbol", None) and ln.symbol() else None
            r_var = rn.symbol().getText() if getattr(rn, "symbol", None) and rn.symbol() else None
            detail = getattr(rel, "relationDetail", lambda: None)()
            rel_var = detail.symbol().getText() if detail and getattr(detail, "symbol", None) and detail.symbol() else None
            
            l_type = self.context_memory.get(id(ln)) or (self.symbol_table.get(l_var) if l_var else None)
            r_type = self.context_memory.get(id(rn)) or (self.symbol_table.get(r_var) if r_var else None)
            
            valid_triplets = []
            if self.schema_M and self.schema_M.topology:
                for r_t, pairs in self.schema_M.topology.items():
                    for src, dst in pairs:
                        if l_type and l_type != "NODE" and src != l_type: continue
                        if r_type and r_type != "NODE" and dst != r_type: continue
                        valid_triplets.append((src, r_t, dst))
                    
            if not valid_triplets: 
                fallback_l = random.choice(list(self.schema_M.labels)) if self.schema_M and self.schema_M.labels else "Node"
                fallback_r = random.choice(list(self.schema_M.topology.keys())) if self.schema_M and self.schema_M.topology else "REL"
                valid_triplets = [(fallback_l, fallback_r, fallback_l)]
                
            chosen_src, chosen_rel, chosen_dst = random.choice(valid_triplets)
            
            if l_var: self.symbol_table[l_var] = chosen_src
            self.context_memory[id(ln)] = chosen_src
            if rel_var: self.symbol_table[rel_var] = chosen_rel
            self.context_memory[id(rel)] = chosen_rel
            if r_var: self.symbol_table[r_var] = chosen_dst
            self.context_memory[id(rn)] = chosen_dst
            
        return self.visitChildren(ctx)

    def visitNodePattern(self, ctx):
        var_name = ctx.symbol().getText() if getattr(ctx, "symbol", None) and ctx.symbol() else None
        labels_ctx = getattr(ctx, "nodeLabels", lambda: None)()
        
        if labels_ctx and "$LABEL_" in labels_ctx.getText():
            match = re.search(r'\$LABEL_(\d+)', labels_ctx.getText())
            if match:
                lbl_id = match.group(1)
                if lbl_id not in self.label_registry:
                    self.label_registry[lbl_id] = random.choice(list(self.schema_M.labels)) if self.schema_M and self.schema_M.labels else "Node"
                chosen_label = self.label_registry[lbl_id]
            else:
                chosen_label = random.choice(list(self.schema_M.labels)) if self.schema_M and self.schema_M.labels else "Node"
            
            self._safe_replace_range(labels_ctx.start.tokenIndex, labels_ctx.stop.tokenIndex, f":`{chosen_label}`")
            if var_name: self.symbol_table[var_name] = chosen_label
        return self.visitChildren(ctx)

    def visitRelationshipPattern(self, ctx):
        detail = getattr(ctx, "relationDetail", lambda: None)()
        if detail:
            rel_type_ctx = getattr(detail, "relationshipTypes", lambda: None)()
            if rel_type_ctx and "$REL_TYPE_" in rel_type_ctx.getText():
                match = re.search(r'\$REL_TYPE_(\d+)', rel_type_ctx.getText())
                if match:
                    rel_id = match.group(1)
                    if rel_id not in self.rel_registry:
                        self.rel_registry[rel_id] = random.choice(list(self.schema_M.topology.keys())) if self.schema_M and self.schema_M.topology else "REL"
                    chosen_rel = self.rel_registry[rel_id]
                else:
                    chosen_rel = random.choice(list(self.schema_M.topology.keys())) if self.schema_M and self.schema_M.topology else "REL"
                self._safe_replace_range(rel_type_ctx.start.tokenIndex, rel_type_ctx.stop.tokenIndex, f":`{chosen_rel}`")
        return self.visitChildren(ctx)

    def visitSymbol(self, ctx):
        raw_text = ctx.getText()
        token_idx = ctx.start.tokenIndex
        if token_idx in self.replaced_tokens: return self.visitChildren(ctx)
            
        if raw_text.startswith('`$') and raw_text.endswith('`'):
            ph = raw_text[2:-1] 
            available_vars = list(self.symbol_table.keys())
            
            if ph.startswith("LABEL_"):
                suffix = ph.split("_")[1] if "_" in ph else "1"
                if suffix not in self.label_registry: self.label_registry[suffix] = random.choice(list(self.schema_M.labels)) if self.schema_M and self.schema_M.labels else "Node"
                self.rewriter.replaceIndex(token_idx, self.label_registry[suffix])
            elif ph.startswith("REL_TYPE_"):
                suffix = ph.split("_")[2] if "TYPE_" in ph else "1"
                if suffix not in self.rel_registry: self.rel_registry[suffix] = random.choice(list(self.schema_M.topology.keys())) if self.schema_M and self.schema_M.topology else "REL"
                self.rewriter.replaceIndex(token_idx, self.rel_registry[suffix])
            
            elif ph.startswith("PROP_") and not self.strict_mode:
                prop_name, prop_type = self.mutator.get_random_property_global()
                suffix = ph.split("_")[1] if "_" in ph else "1"
                self.prop_type_registry[suffix] = prop_type
                self.rewriter.replaceIndex(token_idx, prop_name) 
            elif ph.startswith("VALUE_") and not self.strict_mode:
                suffix = ph.split("_")[1] if "_" in ph else "1"
                self.rewriter.replaceIndex(token_idx, self.mutator.generate_value(self.prop_type_registry.get(suffix)))
            elif ph.startswith("LIST_") and not self.strict_mode:
                suffix = ph.split("_")[1] if "_" in ph else "1"
                self.rewriter.replaceIndex(token_idx, self.mutator.generate_list(self.prop_type_registry.get(suffix), strict=False))
                
            elif ph.startswith("PREDICATE_FOR_"):
                target = ph.replace("PREDICATE_FOR_", "")
                self.rewriter.replaceIndex(token_idx, f"{target if target else 'v'} IS NOT NULL")
            elif ph.startswith("RETURN_EXPR_FOR_"):
                target = ph.replace("RETURN_EXPR_FOR_", "")
                self.rewriter.replaceIndex(token_idx, target if target else 'v')
            elif ph.startswith("PREDICATE_"):
                var = random.choice(available_vars) if available_vars else "1"
                self.rewriter.replaceIndex(token_idx, f"({var} IS NOT NULL)" if var != "1" else "1=1")
            elif ph.startswith("RETURN_EXPR_"):
                var = random.choice(available_vars) if available_vars else "*"
                self.rewriter.replaceIndex(token_idx, random.choice([var, f"count({var})", f"collect({var})"]) if var != "*" else "count(*)")

        return self.visitChildren(ctx)


def compile_and_instantiate(llm_skeleton_str: str, schema_M: SchemaMetadata, state_G: GlobalGraphState, target_engine: str = "memgraph") -> Tuple[str, List[str]]:
    strict_mode = target_engine.lower() in ["kuzu", "nebula"]
    is_nebula = target_engine.lower() == "nebula"
    sanitized = llm_skeleton_str

    if is_nebula:
        nebula_banned_patterns = [
            r'\bCREATE\b', r'\bMERGE\b', r'\bSET\b', r'\bDELETE\b', 
            r'\bREMOVE\b', r'\bDETACH\b', r'\bapoc\.', r'\bYIELD\b'
        ]
        for pattern in nebula_banned_patterns:
            if re.search(pattern, sanitized, re.IGNORECASE):
                return "YIELD 1 AS `neutralized_dummy`;", ["Nebula DML Neutralized"]
        
        sanitized = re.sub(r'\{\s*[a-zA-Z0-9_]+\s*:\s*v\d+\s*\}', '', sanitized)
    
    sanitized = re.sub(r'\bUNWIND\s+\$VALUE_(\d+)\b', r'UNWIND $LIST_\1', sanitized)
    sanitized = re.sub(r'\bIN\s+([a-zA-Z0-9_]*\.*\$PROP_\d+)\b', r'IN [\1]', sanitized)
    sanitized = re.sub(r'\b(v\d+)\.\$PROP_\d+\b', r'\1', sanitized)
    sanitized = re.sub(r'\$DEPTH_\d+', lambda m: str(random.randint(1, 3)), sanitized) # Nebula 多跳非常脆弱，降低深度
    
    total_nodes = state_G.total_nodes if state_G else 0
    max_limit = max(5, total_nodes // 10) if total_nodes > 0 else 5
    sanitized = re.sub(r'\$N_\d+', lambda m: str(random.randint(1, max_limit)), sanitized)
    sanitized = re.sub(r'(\$[A-Z_]+[A-Za-z0-9_]*)', r'`\1`', sanitized)

    error_listener = SilentErrorListener()
    lexer = CypherLexer(InputStream(sanitized))
    lexer.removeErrorListeners()
    lexer.addErrorListener(error_listener)
    token_stream = CommonTokenStream(lexer)
    token_stream.fill()  
    parser = CypherParser(token_stream)
    parser.removeErrorListeners()
    parser.addErrorListener(error_listener)
    
    try:
        if hasattr(parser, 'script'): tree = parser.script()
        elif hasattr(parser, 'oC_Cypher'): tree = parser.oC_Cypher()
        else: tree = parser.query() 
        
        rewriter = TokenStreamRewriter(token_stream)
        compiler = GrafASTCompiler(schema_M, rewriter, strict_mode)
        compiler.visit(tree)
        final_query = rewriter.getDefaultText()
    except Exception as ast_e:
        error_listener.errors.append(f"AST Fatal Exception: {str(ast_e)}")
        final_query = sanitized
        compiler = None

    if strict_mode or error_listener.errors:
        fallback_mutator = TypeAwareMutator(schema_M)
        fallback_symbols = compiler.symbol_table if compiler else {}
        fallback_engine = LexicalFallbackEngine(schema_M, fallback_symbols, fallback_mutator, strict_mode)
        if compiler:
            fallback_engine.label_registry = compiler.label_registry
            fallback_engine.rel_registry = compiler.rel_registry
            
        final_query = fallback_engine.sweep(final_query)
        
    final_query = re.sub(r'`(\$[A-Z_]+[A-Za-z0-9_]*)`', r'\1', final_query)


    if is_nebula:
        result = []
        in_string = False
        str_char = ''
        i = 0
        while i < len(final_query):
            c = final_query[i]
            if c in ('"', "'"):
                if not in_string:
                    in_string = True
                    str_char = c
                elif str_char == c and (i == 0 or final_query[i-1] != '\\'):
                    in_string = False
            
            if not in_string and c == '=':
                prev_c = final_query[i-1] if i > 0 else ''
                next_c = final_query[i+1] if i < len(final_query)-1 else ''
                if prev_c not in ('<', '>', '!', '=') and next_c != '=':
                    result.append('==')
                    i += 1
                    continue
            result.append(c)
            i += 1
        final_query = "".join(result)
        
        match = re.search(r'(ORDER\s+BY\s+)(.*)', final_query, re.IGNORECASE)
        if match:
            prefix = final_query[:match.start(2)]
            suffix = match.group(2)
            suffix = re.sub(r'\b([a-zA-Z0-9_]+)\.[a-zA-Z0-9_]+\b', r'\1', suffix)
            final_query = prefix + suffix

    return final_query, error_listener.errors
