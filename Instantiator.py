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
from graf.target_queries import prepare_target_query

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
            for entity, props in sorted(self.schema_M.properties.items()):
                if isinstance(props, dict):
                    for prop_name, prop_type in sorted(props.items()):
                        self.global_prop_pool.append((str(prop_name), self.normalize_type(prop_type)))

    @staticmethod
    def normalize_type(value: str) -> str:
        text = str(value or "").upper()
        if "BOOL" in text:
            return "BOOLEAN"
        if any(token in text for token in ("INT", "LONG")):
            return "INTEGER"
        if any(token in text for token in ("FLOAT", "DOUBLE", "DECIMAL", "NUMBER")):
            return "FLOAT"
        if any(token in text for token in ("STR", "TEXT", "CHAR")):
            return "STRING"
        return text if text in {"INTEGER", "FLOAT", "STRING", "BOOLEAN"} else "STRING"

    def get_random_property_global(self) -> Tuple[str, str]:
        if not self.global_prop_pool:
            return "id", "INTEGER" 
        return random.choice(self.global_prop_pool)

    def get_valid_property_for_label(self, label: str, allowed_types: Set[str] = None) -> Tuple[str, str]:
        if not self.schema_M or not self.schema_M.properties:
            return "id", "INTEGER"
        if label and label in self.schema_M.properties and self.schema_M.properties[label]:
            candidates = [
                (str(prop_name), self.normalize_type(prop_type))
                for prop_name, prop_type in sorted(self.schema_M.properties[label].items())
            ]
            if allowed_types:
                normalized_allowed = {self.normalize_type(item) for item in allowed_types}
                typed = [item for item in candidates if item[1] in normalized_allowed]
                if typed:
                    candidates = typed
            prop_name, prop_type = random.choice(candidates)
            return prop_name, prop_type
        if self.global_prop_pool:
            candidates = self.global_prop_pool
            if allowed_types:
                normalized_allowed = {self.normalize_type(item) for item in allowed_types}
                typed = [item for item in candidates if item[1] in normalized_allowed]
                if typed:
                    candidates = typed
            return random.choice(candidates)
        return "id", "INTEGER"

    def generate_value(self, target_type: str = None) -> str:
        target_type = self.normalize_type(target_type) if target_type else None
        if not target_type or target_type not in self.bva_dict:
            target_type = random.choice(sorted(self.bva_dict))
            
        val = random.choice(self.bva_dict[target_type])
        if "*" in val and '"' in val:
            parts = val.split("*")
            if len(parts) == 2 and parts[1].strip().isdigit():
                return '"' + (parts[0].replace('"', '').strip() * int(parts[1].strip())) + '"'
        return val

    def generate_list(self, target_type: str = None, strict: bool = False) -> str:
        target_type = self.normalize_type(target_type) if target_type else None
        if not target_type or target_type not in self.bva_dict:
            target_type = random.choice(sorted(self.bva_dict))
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
            for _owner, props in sorted(self.schema_M.properties.items()):
                if prop_name in props: return props[prop_name]
        return "STRING"

    def sweep(self, query: str) -> str:
        available_vars = sorted(self.symbol_table)

        if self.strict_mode:
            def repl_label(match):
                lbl_id = match.group(1)
                if lbl_id not in self.label_registry:
                    self.label_registry[lbl_id] = random.choice(sorted(self.schema_M.labels)) if self.schema_M and self.schema_M.labels else "Node"
                return self.label_registry[lbl_id]
            query = re.sub(r'`?\$LABEL_(\d+)`?', repl_label, query)

            def repl_rel(match):
                rel_id = match.group(1)
                if rel_id not in self.rel_registry:
                    self.rel_registry[rel_id] = random.choice(sorted(self.schema_M.topology)) if self.schema_M and self.schema_M.topology else "REL"
                return self.rel_registry[rel_id]
            query = re.sub(r'`?\$REL_(\d+)`?', repl_rel, query)

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
            query = re.sub(r'`?\$LABEL_\d+`?', lambda m: random.choice(sorted(self.schema_M.labels)) if self.schema_M and self.schema_M.labels else "Node", query)
            query = re.sub(r'`?\$REL_\d+`?', lambda m: random.choice(sorted(self.schema_M.topology)) if self.schema_M and self.schema_M.topology else "REL", query)
            query = re.sub(r'`?\$PROP_\d+`?', lambda m: self.mutator.get_random_property_global()[0], query)
            query = re.sub(r'`?\$VALUE_\d+`?', lambda m: self.mutator.generate_value(), query)
            query = re.sub(r'`?\$LIST_\d+`?', lambda m: self.mutator.generate_list(strict=False), query)

        query = re.sub(r'`?\$PREDICATE_FOR_([A-Za-z0-9_]+)`?', r'\1 IS NOT NULL', query)
        query = re.sub(r'`?\$RETURN_EXPR_FOR_([A-Za-z0-9_]+)`?', r'\1', query)
        query = re.sub(r'`?\$PREDICATE_\d+`?', lambda m: f"({random.choice(available_vars)} IS NOT NULL)" if available_vars else "1=1", query)
        query = re.sub(r'`?\$RETURN_EXPR_\d+`?', lambda m: random.choice(available_vars) if available_vars else "count(*)", query)
        
        return query

class GrafASTCompiler(CypherParserVisitor):
    def __init__(
        self,
        schema_M,
        rewriter: TokenStreamRewriter,
        strict_mode: bool,
        property_type_hints=None,
        value_property_links=None,
        list_property_links=None,
    ):
        self.schema_M = schema_M
        self.rewriter = rewriter
        self.mutator = TypeAwareMutator(self.schema_M)
        self.strict_mode = strict_mode
        self.symbol_table = {}       
        self.context_memory = {}     
        self.replaced_tokens = set() 
        self.label_registry = {}
        self.rel_registry = {}
        self.prop_name_registry = {}
        self.prop_type_registry = {}
        self.property_type_hints = property_type_hints or {}
        self.value_property_links = value_property_links or {}
        self.list_property_links = list_property_links or {}

    def _safe_replace_range(self, start_idx, stop_idx, text):
        if start_idx is None or stop_idx is None or start_idx < 0: return
        self.rewriter.replaceRange(start_idx, stop_idx, text)
        for i in range(start_idx, stop_idx + 1):
            self.replaced_tokens.add(i)

    def visitUnwindSt(self, ctx):
        expression_ctx = ctx.expression() if getattr(ctx, "expression", None) else None
        if expression_ctx:
            self.visit(expression_ctx)
        var_name = ctx.symbol().getText() if getattr(ctx, "symbol", None) and ctx.symbol() else None
        if var_name: self.symbol_table[var_name] = "SCALAR"
        return None

    def visitProjectionItem(self, ctx):
        result = self.visitChildren(ctx)
        var_name = ctx.symbol().getText() if getattr(ctx, "symbol", None) and ctx.symbol() else None
        if var_name: self.symbol_table[var_name] = "ANY"
        return result

    def visitWithSt(self, ctx):
        incoming = dict(self.symbol_table)
        projection_body = ctx.projectionBody() if getattr(ctx, "projectionBody", None) else None
        if projection_body:
            self.visit(projection_body)

        projected = {}
        projection_items = projection_body.projectionItems() if projection_body else None
        if projection_items and getattr(projection_items, "MULT", None) and projection_items.MULT():
            projected.update(incoming)
        items = projection_items.projectionItem() if projection_items and getattr(projection_items, "projectionItem", None) else []
        if items and not isinstance(items, list):
            items = [items]
        for item in items or []:
            alias_ctx = item.symbol() if getattr(item, "symbol", None) else None
            expression_ctx = item.expression() if getattr(item, "expression", None) else None
            expression = expression_ctx.getText().strip('`') if expression_ctx else ""
            if alias_ctx:
                alias = alias_ctx.getText().strip('`')
                projected[alias] = incoming.get(expression, "ANY")
            elif expression in incoming:
                projected[expression] = incoming[expression]

        self.symbol_table = projected
        where_ctx = ctx.where() if getattr(ctx, "where", None) else None
        if where_ctx:
            self.visit(where_ctx)
        return None

    def visitPatternPart(self, ctx):
        var_name = ctx.symbol().getText() if getattr(ctx, "symbol", None) and ctx.symbol() else None
        if var_name: self.symbol_table[var_name] = "PATH"
        return self.visitChildren(ctx)

    def visitPatternElem(self, ctx):
        nodes, rels = [], []
        if getattr(ctx, "nodePattern", None) and ctx.nodePattern(): 
            nodes.append(ctx.nodePattern())
        chains = getattr(ctx, "patternElemChain", lambda: [])()
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
            
            def node_constraint(node, variable):
                remembered = self.context_memory.get(id(node)) or (self.symbol_table.get(variable) if variable else None)
                if remembered and remembered not in {"NODE", "SCALAR", "ANY"}:
                    return remembered
                labels_ctx = getattr(node, "nodeLabels", lambda: None)()
                if not labels_ctx:
                    return None
                text = labels_ctx.getText()
                placeholder = re.search(r'\$LABEL_(\d+)', text)
                if placeholder:
                    return self.label_registry.get(placeholder.group(1))
                literal = re.search(r':`?([A-Za-z_][A-Za-z0-9_]*)`?', text)
                return literal.group(1) if literal else None

            def relationship_constraint(pattern):
                relation_detail = getattr(pattern, "relationDetail", lambda: None)()
                type_ctx = getattr(relation_detail, "relationshipTypes", lambda: None)() if relation_detail else None
                if not type_ctx:
                    return None
                text = type_ctx.getText()
                placeholder = re.search(r'\$REL_(\d+)', text)
                if placeholder:
                    return self.rel_registry.get(placeholder.group(1))
                literal = re.search(r':`?([A-Za-z_][A-Za-z0-9_]*)`?', text)
                return literal.group(1) if literal else None

            l_type = node_constraint(ln, l_var)
            r_type = node_constraint(rn, r_var)
            rel_constraint = relationship_constraint(rel)
            rel_text = rel.getText()
            reverse = rel_text.startswith("<-")
            undirected = not reverse and not rel_text.endswith("->")
            
            valid_triplets = []
            if self.schema_M and self.schema_M.topology:
                for r_t, pairs in sorted(self.schema_M.topology.items()):
                    for src, dst in sorted(pairs):
                        orientations = [(dst, r_t, src)] if reverse else [(src, r_t, dst)]
                        if undirected:
                            orientations.append((dst, r_t, src))
                        for left_label, rel_name, right_label in orientations:
                            if l_type and left_label != l_type: continue
                            if r_type and right_label != r_type: continue
                            if rel_constraint and rel_name != rel_constraint: continue
                            valid_triplets.append((left_label, rel_name, right_label))
                    
            if not valid_triplets: 
                if self.schema_M and self.schema_M.topology:
                    for fallback_rel, pairs in sorted(self.schema_M.topology.items()):
                        for fallback_src, fallback_dst in sorted(pairs):
                            valid_triplets.append((fallback_src, fallback_rel, fallback_dst))
                if not valid_triplets:
                    valid_triplets = [("Node", "REL", "Node")]

            valid_triplets = sorted(set(valid_triplets))
            chosen_src, chosen_rel, chosen_dst = random.choice(valid_triplets)
            
            if l_var: self.symbol_table[l_var] = chosen_src
            self.context_memory[id(ln)] = chosen_src
            if rel_var: self.symbol_table[rel_var] = chosen_rel
            self.context_memory[id(rel)] = chosen_rel
            if r_var: self.symbol_table[r_var] = chosen_dst
            self.context_memory[id(rn)] = chosen_dst

            for node, chosen_label in ((ln, chosen_src), (rn, chosen_dst)):
                labels_ctx = getattr(node, "nodeLabels", lambda: None)()
                if labels_ctx:
                    placeholder = re.search(r'\$LABEL_(\d+)', labels_ctx.getText())
                    if placeholder:
                        self.label_registry.setdefault(placeholder.group(1), chosen_label)
            rel_type_ctx = getattr(detail, "relationshipTypes", lambda: None)() if detail else None
            if rel_type_ctx:
                placeholder = re.search(r'\$REL_(\d+)', rel_type_ctx.getText())
                if placeholder:
                    self.rel_registry.setdefault(placeholder.group(1), chosen_rel)
            
        return self.visitChildren(ctx)

    def visitNodePattern(self, ctx):
        var_name = ctx.symbol().getText() if getattr(ctx, "symbol", None) and ctx.symbol() else None
        labels_ctx = getattr(ctx, "nodeLabels", lambda: None)()
        
        if labels_ctx and "$LABEL_" in labels_ctx.getText():
            match = re.search(r'\$LABEL_(\d+)', labels_ctx.getText())
            if match:
                lbl_id = match.group(1)
                if lbl_id not in self.label_registry:
                    self.label_registry[lbl_id] = random.choice(sorted(self.schema_M.labels)) if self.schema_M and self.schema_M.labels else "Node"
                chosen_label = self.label_registry[lbl_id]
            else:
                chosen_label = random.choice(sorted(self.schema_M.labels)) if self.schema_M and self.schema_M.labels else "Node"
            
            self._safe_replace_range(labels_ctx.start.tokenIndex, labels_ctx.stop.tokenIndex, f":`{chosen_label}`")
            if var_name: self.symbol_table[var_name] = chosen_label
        return self.visitChildren(ctx)

    def visitRelationshipPattern(self, ctx):
        detail = getattr(ctx, "relationDetail", lambda: None)()
        if detail:
            rel_type_ctx = getattr(detail, "relationshipTypes", lambda: None)()
            if rel_type_ctx and "$REL_" in rel_type_ctx.getText():
                match = re.search(r'\$REL_(\d+)', rel_type_ctx.getText())
                if match:
                    rel_id = match.group(1)
                    if rel_id not in self.rel_registry:
                        self.rel_registry[rel_id] = random.choice(sorted(self.schema_M.topology)) if self.schema_M and self.schema_M.topology else "REL"
                    chosen_rel = self.rel_registry[rel_id]
                else:
                    chosen_rel = random.choice(sorted(self.schema_M.topology)) if self.schema_M and self.schema_M.topology else "REL"
                self._safe_replace_range(rel_type_ctx.start.tokenIndex, rel_type_ctx.stop.tokenIndex, f":`{chosen_rel}`")
        return self.visitChildren(ctx)

    def visitSymbol(self, ctx):
        raw_text = ctx.getText()
        token_idx = ctx.start.tokenIndex
        if token_idx in self.replaced_tokens: return self.visitChildren(ctx)
            
        if raw_text.startswith('`$') and raw_text.endswith('`'):
            ph = raw_text[2:-1] 
            available_vars = sorted(self.symbol_table)
            
            if ph.startswith("LABEL_"):
                suffix = ph.split("_")[1] if "_" in ph else "1"
                if suffix not in self.label_registry: self.label_registry[suffix] = random.choice(sorted(self.schema_M.labels)) if self.schema_M and self.schema_M.labels else "Node"
                self.rewriter.replaceIndex(token_idx, self.label_registry[suffix])
            elif ph.startswith("REL_"):
                suffix = ph.split("_")[1]
                if suffix not in self.rel_registry: self.rel_registry[suffix] = random.choice(sorted(self.schema_M.topology)) if self.schema_M and self.schema_M.topology else "REL"
                self.rewriter.replaceIndex(token_idx, self.rel_registry[suffix])
            
            elif ph.startswith("PROP_"):
                suffix = ph.split("_")[1] if "_" in ph else "1"
                if suffix not in self.prop_name_registry:
                    property_ctx = ctx.parentCtx.parentCtx if getattr(ctx, "parentCtx", None) else None
                    owner_match = re.match(
                        r'(`(?:``|[^`])+`|[A-Za-z_][A-Za-z0-9_]*)\s*\.',
                        property_ctx.getText() if property_ctx else "",
                    )
                    owner = owner_match.group(1).strip('`') if owner_match else None
                    owner_type = self.symbol_table.get(owner) if owner else None
                    prop_name, prop_type = self.mutator.get_valid_property_for_label(
                        owner_type,
                        self.property_type_hints.get(suffix),
                    )
                    self.prop_name_registry[suffix] = prop_name
                    self.prop_type_registry[suffix] = prop_type
                self.rewriter.replaceIndex(token_idx, self.prop_name_registry[suffix])
            elif ph.startswith("VALUE_"):
                suffix = ph.split("_")[1] if "_" in ph else "1"
                linked_property = self.value_property_links.get(suffix, suffix)
                self.rewriter.replaceIndex(token_idx, self.mutator.generate_value(self.prop_type_registry.get(linked_property)))
            elif ph.startswith("LIST_"):
                suffix = ph.split("_")[1] if "_" in ph else "1"
                linked_property = self.list_property_links.get(suffix, suffix)
                self.rewriter.replaceIndex(
                    token_idx,
                    self.mutator.generate_list(self.prop_type_registry.get(linked_property), strict=self.strict_mode),
                )
                
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


def compile_and_instantiate(llm_skeleton_str: str, schema_M: SchemaMetadata, state_G: GlobalGraphState, target_engine: str = "memgraph", *, allow_target_dialect: bool = False) -> Tuple[str, List[str]]:
    strict_mode = target_engine.lower() in ["kuzu", "nebula"]
    is_nebula = target_engine.lower() == "nebula"
    sanitized = llm_skeleton_str
    if re.search(r'\$REL_TYPE_\d+\b', sanitized):
        return sanitized, ["Deprecated $REL_TYPE_i placeholder; use $REL_i"]
    if (is_nebula and re.search(r'\$REL_\d+\b', sanitized) and
            not (schema_M and any(schema_M.topology.values()))):
        return sanitized, [
            "No observed NebulaGraph edge topology; cannot bind $REL_i and endpoint labels. "
            "Seed the dedicated graph and verify context extraction before retrying"
        ]

    if is_nebula and not allow_target_dialect:
        nebula_banned_patterns = [
            r'\bCREATE\b', r'\bMERGE\b', r'\bSET\b', r'\bDELETE\b', 
            r'\bREMOVE\b', r'\bDETACH\b', r'\bapoc\.', r'\bYIELD\b'
        ]
        for pattern in nebula_banned_patterns:
            if re.search(pattern, sanitized, re.IGNORECASE):
                return sanitized, ["Nebula unsupported query shape"]
        
        sanitized = re.sub(r'\{\s*[a-zA-Z0-9_]+\s*:\s*v\d+\s*\}', '', sanitized)
    
    if not allow_target_dialect:
        sanitized = re.sub(r'\bUNWIND\s+\$VALUE_(\d+)\b', r'UNWIND $LIST_\1', sanitized)
        sanitized = re.sub(r'\bIN\s+([a-zA-Z0-9_]*\.*\$PROP_\d+)\b', r'IN [\1]', sanitized)
        sanitized = re.sub(r'\b(v\d+)\.\$PROP_\d+\b', r'\1', sanitized)

    # Build placeholder dependency edges before concrete bounds are expanded.
    # This makes property selection drive literal/list construction instead of
    # choosing each placeholder independently.
    property_type_hints = {}
    value_property_links = {}
    list_property_links = {}

    def add_hint(prop_id, *types):
        property_type_hints.setdefault(str(prop_id), set()).update(types)

    prop_pattern = r'`?\$PROP_(\d+)`?'
    value_pattern = r'`?\$VALUE_(\d+)`?'
    list_pattern = r'`?\$LIST_(\d+)`?'
    comparator = r'(?:<=|>=|<>|=|<|>)'
    for match in re.finditer(prop_pattern + r'\s*' + comparator + r'\s*' + value_pattern, sanitized, re.IGNORECASE):
        value_property_links[match.group(2)] = match.group(1)
    for match in re.finditer(value_pattern + r'\s*' + comparator + r'\s*' + prop_pattern, sanitized, re.IGNORECASE):
        value_property_links[match.group(1)] = match.group(2)
    for match in re.finditer(prop_pattern + r'\s+IN\s+' + list_pattern, sanitized, re.IGNORECASE):
        list_property_links[match.group(2)] = match.group(1)
    for match in re.finditer(prop_pattern + r'\s*' + comparator + r'\s*`?\$N_\d+`?', sanitized, re.IGNORECASE):
        add_hint(match.group(1), "INTEGER", "FLOAT")
    for match in re.finditer(r'`?\$N_\d+`?\s*' + comparator + r'\s*' + prop_pattern, sanitized, re.IGNORECASE):
        add_hint(match.group(1), "INTEGER", "FLOAT")
    for match in re.finditer(prop_pattern + r'\s*' + comparator + r'\s*(true|false)\b', sanitized, re.IGNORECASE):
        add_hint(match.group(1), "BOOLEAN")
    for match in re.finditer(prop_pattern + r'''\s*''' + comparator + r'''\s*(?:'(?:\\.|[^'])*'|"(?:\\.|[^"])*")''', sanitized):
        add_hint(match.group(1), "STRING")
    for match in re.finditer(prop_pattern + r'\s*' + comparator + r'\s*-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b', sanitized, re.IGNORECASE):
        literal = match.group(0)
        add_hint(match.group(1), "FLOAT" if re.search(r'[.eE]', literal) else "INTEGER")

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
        
        if allow_target_dialect and error_listener.errors:
            # Generic ANTLR grammar cannot parse every target extension.
            # Preserve the source shape and bind placeholders lexically;
            # the target EXPLAIN makes the final admission decision.
            final_query = sanitized
            compiler = None
        else:
            rewriter = TokenStreamRewriter(token_stream)
            compiler = GrafASTCompiler(
                schema_M,
                rewriter,
                strict_mode,
                property_type_hints=property_type_hints,
                value_property_links=value_property_links,
                list_property_links=list_property_links,
            )
            compiler.visit(tree)
            final_query = rewriter.getDefaultText()
    except Exception as ast_e:
        error_listener.errors.append(f"AST Fatal Exception: {str(ast_e)}")
        final_query = sanitized
        compiler = None

    if strict_mode or error_listener.errors:
        fallback_mutator = TypeAwareMutator(schema_M)
        fallback_symbols = compiler.symbol_table if compiler else {}
        fallback_engine = LexicalFallbackEngine(schema_M, fallback_symbols, fallback_mutator,
                                                strict_mode or (allow_target_dialect and compiler is None))
        if compiler:
            fallback_engine.label_registry = compiler.label_registry
            fallback_engine.rel_registry = compiler.rel_registry
            fallback_engine.prop_name_registry = compiler.prop_name_registry
            fallback_engine.prop_type_registry = compiler.prop_type_registry
            
        final_query = fallback_engine.sweep(final_query)
        
    final_query = re.sub(r'`(\$[A-Z_]+[A-Za-z0-9_]*)`', r'\1', final_query)


    if is_nebula:
        final_query = prepare_target_query("nebula", final_query)

    if allow_target_dialect and not re.search(r'\$[A-Z][A-Z0-9_]*', final_query):
        # Local parse diagnostics are advisory in this mode; EXPLAIN is
        # authoritative for this particular concrete binding.
        error_listener.errors.clear()
    return final_query, error_listener.errors
