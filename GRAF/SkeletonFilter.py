import sys
import os
import re
from dataclasses import dataclass
from typing import Tuple, List
current_dir = os.path.dirname(os.path.abspath(__file__))
antlr_path = os.path.join(current_dir, "antlr4_cypher", "antlr4_cypher")
if antlr_path not in sys.path:
    sys.path.insert(0, antlr_path)

from antlr4 import InputStream, CommonTokenStream
from antlr4.error.ErrorListener import ErrorListener
from CypherLexer import CypherLexer
from CypherParser import CypherParser


class StrictErrorListener(ErrorListener):
    def __init__(self):
        super().__init__()
        self.errors = []

    def syntaxError(self, recognizer, offendingSymbol, line, column, msg, e):
        self.errors.append(f"Line {line}:{column} - {msg}")

@dataclass
class FilterResult:
    is_valid: bool
    reason: str
    error_details: List[str] = None


class GrafSkeletonFilter:
    def __init__(self, target_engine: str = "generic", strict: bool = True):
        self.target_engine = (target_engine or "generic").lower()
        self.strict = strict
        # 允许存在的合法占位符白名单 (前缀)
        self.valid_placeholder_prefixes = {
            "$LABEL_", "$REL_TYPE_", "$DEPTH_", "$N_", 
            "$PROP_", "$VALUE_", "$PREDICATE_", "$RETURN_EXPR_", 
            "$PREDICATE_FOR_", "$RETURN_EXPR_FOR_", "$LIST_",
        }

    def validate(self, skeleton_str: str) -> FilterResult:
        skeleton_str = skeleton_str.strip()
        
        if not skeleton_str:
            return FilterResult(False, "Empty skeleton")

        if "$" not in skeleton_str:
            return FilterResult(False, "No placeholders found (Not a valid fuzzing template)")

        extracted_placeholders = re.findall(r'\$[A-Z_0-9]+', skeleton_str)
        for ph in extracted_placeholders:
            is_valid_ph = any(ph.startswith(prefix) for prefix in self.valid_placeholder_prefixes)
            if not is_valid_ph:
                return FilterResult(False, f"Hallucinated placeholder detected: {ph}")

        if re.search(r'\$DEPTH_\d+\s*\.\.\s*\$DEPTH_\d+', skeleton_str):
             return FilterResult(False, "Nested/Invalid depth format (e.g., $DEPTH_1..$DEPTH_2)")

        semantic_errors = self._static_semantic_errors(skeleton_str)
        if semantic_errors:
            return FilterResult(False, "Static semantic rejection", semantic_errors)

        mocked_query = self._mock_placeholders_for_parse(skeleton_str)

        error_listener = StrictErrorListener()
        
        lexer = CypherLexer(InputStream(mocked_query))
        lexer.removeErrorListeners()
        lexer.addErrorListener(error_listener)
        
        token_stream = CommonTokenStream(lexer)
        token_stream.fill()
        
        parser = CypherParser(token_stream)
        parser.removeErrorListeners()
        parser.addErrorListener(error_listener)
        
        if hasattr(parser, 'script'):
            tree = parser.script()
        elif hasattr(parser, 'oC_Cypher'):
            tree = parser.oC_Cypher()
        else:
            tree = parser.query()

        if error_listener.errors:
            return FilterResult(False, "Syntax Error or Unsupported Dialect", error_listener.errors)


        if "cartesian product" in skeleton_str.lower(): 
            pass 

        return FilterResult(True, "Valid Skeleton")

    def _mock_placeholders_for_parse(self, query: str) -> str:
        mocked = query
        mocked = re.sub(r'\$DEPTH_\d+', '1', mocked)
        mocked = re.sub(r'\$N_\d+', '1', mocked)
        mocked = re.sub(r'\$PREDICATE_FOR_([A-Za-z_][A-Za-z0-9_]*)', r'\1 IS NOT NULL', mocked)
        mocked = re.sub(r'\$RETURN_EXPR_FOR_([A-Za-z_][A-Za-z0-9_]*)', r'\1', mocked)
        mocked = re.sub(r'\$PREDICATE_\d+', 'true', mocked)
        mocked = re.sub(r'\$RETURN_EXPR_\d+', '1', mocked)
        mocked = re.sub(r'\$LABEL_\d+', 'Node', mocked)
        mocked = re.sub(r'\$REL_TYPE_\d+', 'REL', mocked)
        mocked = re.sub(r'\$PROP_\d+', 'prop', mocked)
        mocked = re.sub(r'\$LIST_\d+', '[1, 2]', mocked)
        mocked = re.sub(r'\$VALUE_\d+', '1', mocked)
        return mocked

    def _split_top_level_csv(self, text: str) -> List[str]:
        items = []
        buf = []
        depth = 0
        quote = ""
        for ch in text:
            if quote:
                buf.append(ch)
                if ch == quote:
                    quote = ""
                continue
            if ch in ("'", '"'):
                quote = ch
                buf.append(ch)
                continue
            if ch in "([{":
                depth += 1
            elif ch in ")]}" and depth > 0:
                depth -= 1
            if ch == "," and depth == 0:
                item = "".join(buf).strip()
                if item:
                    items.append(item)
                buf = []
            else:
                buf.append(ch)
        item = "".join(buf).strip()
        if item:
            items.append(item)
        return items

    def _bound_symbols(self, query: str):
        path_vars = set(re.findall(r'\b(?:MATCH|OPTIONAL\s+MATCH)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=', query, re.IGNORECASE))
        node_vars = set(re.findall(r'(?<![A-Za-z0-9_])\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?=[:{\)])', query))
        rel_vars = set(re.findall(r'\[\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?=[:{\]*\]])', query))
        aliases = set(re.findall(r'\bAS\s+([A-Za-z_][A-Za-z0-9_]*)\b', query, re.IGNORECASE))
        unwind_vars = set(re.findall(r'\bUNWIND\b.*?\bAS\s+([A-Za-z_][A-Za-z0-9_]*)\b', query, re.IGNORECASE))
        return path_vars, node_vars, rel_vars, aliases | unwind_vars

    def _return_simple_identifiers(self, query: str) -> List[str]:
        identifiers = []
        for match in re.finditer(
            r'\bRETURN\s+(.*?)(?=\b(?:ORDER\s+BY|SKIP|LIMIT|UNION|WITH|MATCH|CREATE|MERGE|SET|DELETE|DETACH|FOREACH|CALL)\b|$)',
            query,
            re.IGNORECASE | re.DOTALL,
        ):
            clause = re.sub(r'^\s*DISTINCT\s+', '', match.group(1).strip(), flags=re.IGNORECASE)
            for item in self._split_top_level_csv(clause):
                item = re.sub(r'\s+AS\s+[A-Za-z_][A-Za-z0-9_]*\s*$', '', item, flags=re.IGNORECASE).strip()
                if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', item):
                    identifiers.append(item)
        return identifiers

    def _target_specific_errors(self, query: str) -> List[str]:
        errors = []
        q = query.lower()
        if self.target_engine == "falkordb":
            unsupported = {
                r'\bapoc\.': "APOC procedures are not available on FalkorDB",
                r'=~': "FalkorDB regex operator =~ is not supported",
                r'\bpoint\s*\(': "point() is not portable to FalkorDB",
                r'\bdistance\s*\(': "distance() is not portable to FalkorDB",
                r'\bcall\s+db\.': "db.* procedures are not portable to FalkorDB",
                r'\b(?:NOT\s+)?EXISTS\s*\{': "EXISTS subquery is not portable to FalkorDB/bundled parser",
            }
            for pattern, reason in unsupported.items():
                if re.search(pattern, query, re.IGNORECASE):
                    errors.append(reason)
        elif self.target_engine == "memgraph":
            unsupported = {
                r'\bapoc\.map\.merge\b': "apoc.map.merge is not portable to Memgraph",
                r'\bpercentileCont\s*\(': "percentileCont is not portable to Memgraph",
                r'\bpercentileDisc\s*\(': "percentileDisc is not portable to Memgraph",
            }
            for pattern, reason in unsupported.items():
                if re.search(pattern, query, re.IGNORECASE):
                    errors.append(reason)
        if "return *" in q and not re.search(r'\b(MATCH|CREATE|MERGE|WITH|UNWIND)\b', query, re.IGNORECASE):
            errors.append("RETURN * without variables in scope")
        return errors

    def _static_semantic_errors(self, query: str) -> List[str]:
        if not self.strict:
            return []

        errors = []
        mocked = self._mock_placeholders_for_parse(query)
        path_vars, node_vars, rel_vars, aliases = self._bound_symbols(query)
        bound = path_vars | node_vars | rel_vars | aliases

        errors.extend(self._target_specific_errors(query))

        if re.search(r'\bCREATE\s+[A-Za-z_][A-Za-z0-9_]*\s*=', query, re.IGNORECASE):
            errors.append("CREATE cannot bind a path variable")

        for rel_var, _tail in re.findall(r'\[\s*([A-Za-z_][A-Za-z0-9_]*)\s*:[^\]]*(\*)', query):
            if rel_var:
                errors.append(f"Relationship variable `{rel_var}` is bound on a variable-length relationship")

        for func, var in re.findall(r'\b(nodes|relationships|length)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)', query, re.IGNORECASE):
            if var not in path_vars:
                errors.append(f"{func}({var}) expects `{var}` to be a bound path variable")

        for var in re.findall(r'\btype\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)', query, re.IGNORECASE):
            if var in node_vars:
                errors.append(f"type({var}) is invalid because `{var}` is a node variable")

        for var in self._return_simple_identifiers(query):
            if var not in bound and not var.startswith("$"):
                errors.append(f"RETURN references unbound identifier `{var}`")

        for delete_match in re.finditer(r'(?<!DETACH\s)\bDELETE\s+([^;]+?)(?=\bWITH\b|\bRETURN\b|$)', query, re.IGNORECASE):
            for item in self._split_top_level_csv(delete_match.group(1)):
                var = item.strip()
                if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', var) and var in node_vars:
                    errors.append(f"DELETE node variable `{var}` without DETACH can fail on connected nodes")

        list_context_patterns = (
            r'\bUNWIND\s+\$VALUE_\d+\b',
            r'\bFOREACH\s*\([^|]*\bIN\s+\$VALUE_\d+\b',
            r'\b[A-Za-z_][A-Za-z0-9_$.]*\s+IN\s+\$VALUE_\d+\b',
        )
        for pattern in list_context_patterns:
            if re.search(pattern, query, re.IGNORECASE):
                errors.append("Scalar $VALUE placeholder used in list context; use $LIST instead")
                break

        if "$VALUE_" in query and re.search(r'\b(STARTS\s+WITH|ENDS\s+WITH|CONTAINS)\s+\$VALUE_\d+', query, re.IGNORECASE):
            errors.append("String operator uses untyped $VALUE placeholder")

        if re.search(r'\b(avg|sum|round|ceil|floor)\s*\([^)]*\$PROP_\d+', query, re.IGNORECASE):
            errors.append("Numeric function uses untyped $PROP placeholder")

        if re.search(r'\bWITH\s+\*\s*,', mocked, re.IGNORECASE):
            errors.append("WITH * plus aggregation can violate Cypher grouping rules")

        return sorted(set(errors))
