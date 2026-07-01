import sys
import os
import re
from dataclasses import dataclass
from typing import Tuple, List
current_dir = os.path.dirname(os.path.abspath(__file__))
antlr_path = os.path.join(current_dir, "antlr4-cypher", "antlr4_cypher")
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
    def __init__(self):
        # 允许存在的合法占位符白名单 (前缀)
        self.valid_placeholder_prefixes = {
            "$LABEL_", "$REL_TYPE_", "$DEPTH_", "$N_", 
            "$PROP_", "$VALUE_", "$PREDICATE_", "$RETURN_EXPR_", 
            "$PREDICATE_FOR_", "$RETURN_EXPR_FOR_"
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


        mocked_query = skeleton_str
        
        mocked_query = re.sub(r'\$DEPTH_\d+', '1', mocked_query)
        mocked_query = re.sub(r'\$N_\d+', '1', mocked_query)
        
        mocked_query = re.sub(r'(\$[A-Z_]+[A-Za-z0-9_]*)', r'`\1`', mocked_query)

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


