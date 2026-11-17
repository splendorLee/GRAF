from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional, Type


def _ensure_parser_path() -> None:
    root = Path(__file__).resolve().parents[1]
    parser_path = root / "antlr4_cypher" / "antlr4_cypher"
    if str(parser_path) not in sys.path:
        sys.path.insert(0, str(parser_path))


_ensure_parser_path()

from antlr4 import CommonTokenStream, InputStream, ParserRuleContext  # noqa: E402
from antlr4.error.ErrorListener import ErrorListener  # noqa: E402
from CypherLexer import CypherLexer  # noqa: E402
from CypherParser import CypherParser  # noqa: E402

from .dialects import DialectCapabilities
from .model import ClauseScope, SchemaView, ValueType, VariableBinding


class CollectingErrorListener(ErrorListener):
    def __init__(self) -> None:
        super().__init__()
        self.errors: list[tuple[int, int, str]] = []

    def syntaxError(self, recognizer, offendingSymbol, line, column, msg, e):  # noqa: N802
        self.errors.append((int(line), int(column), str(msg)))


@dataclass
class ParseBundle:
    query: str
    token_stream: CommonTokenStream
    tree: Any
    errors: list[tuple[int, int, str]] = field(default_factory=list)


def parse_query(query: str) -> ParseBundle:
    listener = CollectingErrorListener()
    lexer = CypherLexer(InputStream(query))
    lexer.removeErrorListeners()
    lexer.addErrorListener(listener)
    stream = CommonTokenStream(lexer)
    stream.fill()
    parser = CypherParser(stream)
    parser.removeErrorListeners()
    parser.addErrorListener(listener)
    try:
        tree = parser.script()
    except Exception as exc:  # defensive: generated parsers can throw on recovery bugs
        listener.errors.append((0, 0, f"parser exception: {type(exc).__name__}: {exc}"))
        tree = None
    return ParseBundle(query=query, token_stream=stream, tree=tree, errors=list(listener.errors))


def walk_contexts(root: Any) -> Iterator[ParserRuleContext]:
    if root is None:
        return
    stack = [root]
    while stack:
        current = stack.pop()
        if isinstance(current, ParserRuleContext):
            yield current
        children = []
        if hasattr(current, "getChildCount"):
            for index in range(current.getChildCount()):
                child = current.getChild(index)
                if isinstance(child, ParserRuleContext):
                    children.append(child)
        stack.extend(reversed(children))


def ancestors(ctx: Any) -> Iterator[Any]:
    current = getattr(ctx, "parentCtx", None)
    while current is not None:
        yield current
        current = getattr(current, "parentCtx", None)


def inside_context(ctx: Any, context_type: Type[Any]) -> bool:
    return any(isinstance(parent, context_type) for parent in ancestors(ctx))


def context_char_range(ctx: Any) -> tuple[int, int]:
    start = getattr(getattr(ctx, "start", None), "start", -1)
    stop = getattr(getattr(ctx, "stop", None), "stop", -1)
    if start is None or stop is None:
        return -1, -1
    return int(start), int(stop) + 1


def context_text(query: str, ctx: Any) -> str:
    start, end = context_char_range(ctx)
    return query[start:end] if start >= 0 and end >= start else ""


def split_top_level(text: str, delimiter: str = ",") -> list[str]:
    items: list[str] = []
    buffer: list[str] = []
    depths = {"(": 0, "[": 0, "{": 0}
    closing = {")": "(", "]": "[", "}": "{"}
    quote = ""
    escaped = False
    index = 0
    while index < len(text):
        char = text[index]
        if quote:
            buffer.append(char)
            if escaped:
                escaped = False
            elif char == "\\" and quote in {"'", '"'}:
                escaped = True
            elif char == quote:
                if quote == "`" and index + 1 < len(text) and text[index + 1] == "`":
                    buffer.append(text[index + 1])
                    index += 1
                else:
                    quote = ""
            index += 1
            continue
        if char in {"'", '"', "`"}:
            quote = char
            buffer.append(char)
        elif char in depths:
            depths[char] += 1
            buffer.append(char)
        elif char in closing:
            opener = closing[char]
            depths[opener] = max(0, depths[opener] - 1)
            buffer.append(char)
        elif char == delimiter and not any(depths.values()):
            item = "".join(buffer).strip()
            if item:
                items.append(item)
            buffer = []
        else:
            buffer.append(char)
        index += 1
    item = "".join(buffer).strip()
    if item:
        items.append(item)
    return items


def split_top_level_keyword(text: str, keyword: str) -> list[str]:
    keyword_upper = keyword.upper()
    parts: list[str] = []
    start = 0
    round_depth = square_depth = curly_depth = 0
    quote = ""
    escaped = False
    index = 0
    while index < len(text):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\" and quote in {"'", '"'}:
                escaped = True
            elif char == quote:
                quote = ""
            index += 1
            continue
        if char in {"'", '"', "`"}:
            quote = char
            index += 1
            continue
        if char == "(":
            round_depth += 1
        elif char == ")":
            round_depth = max(0, round_depth - 1)
        elif char == "[":
            square_depth += 1
        elif char == "]":
            square_depth = max(0, square_depth - 1)
        elif char == "{":
            curly_depth += 1
        elif char == "}":
            curly_depth = max(0, curly_depth - 1)
        if not (round_depth or square_depth or curly_depth):
            segment = text[index : index + len(keyword)]
            before = text[index - 1] if index else " "
            after = text[index + len(keyword)] if index + len(keyword) < len(text) else " "
            if segment.upper() == keyword_upper and not (before.isalnum() or before == "_") and not (after.isalnum() or after == "_"):
                parts.append(text[start:index].strip())
                index += len(keyword)
                start = index
                continue
        index += 1
    if parts:
        parts.append(text[start:].strip())
    return [part for part in parts if part]


def identifier_text(text: str) -> str:
    value = text.strip()
    if len(value) >= 2 and value[0] == "`" and value[-1] == "`":
        return value[1:-1].replace("``", "`")
    return value


def fresh_identifier(existing: Iterable[str], prefix: str) -> str:
    occupied = set(existing)
    index = 1
    while True:
        candidate = f"{prefix}{index}"
        if candidate not in occupied:
            return candidate
        index += 1


def find_top_level_keyword(text: str, keyword: str) -> int:
    keyword_upper = keyword.upper()
    quote = ""
    depths = [0, 0, 0]
    index = 0
    while index <= len(text) - len(keyword):
        char = text[index]
        if quote:
            if char == quote and (index == 0 or text[index - 1] != "\\"):
                quote = ""
            index += 1
            continue
        if char in {"'", '"', "`"}:
            quote = char
            index += 1
            continue
        if char == "(": depths[0] += 1
        elif char == ")": depths[0] = max(0, depths[0] - 1)
        elif char == "[": depths[1] += 1
        elif char == "]": depths[1] = max(0, depths[1] - 1)
        elif char == "{": depths[2] += 1
        elif char == "}": depths[2] = max(0, depths[2] - 1)
        if not any(depths):
            segment = text[index : index + len(keyword)]
            before = text[index - 1] if index else " "
            after = text[index + len(keyword)] if index + len(keyword) < len(text) else " "
            if segment.upper() == keyword_upper and not (before.isalnum() or before == "_") and not (after.isalnum() or after == "_"):
                return index
        index += 1
    return -1


@dataclass
class QueryDocument:
    query: str
    parse: ParseBundle
    schema: SchemaView
    dialect: DialectCapabilities
    scopes: list[ClauseScope] = field(default_factory=list)
    complex_scope: bool = False

    @classmethod
    def build(cls, query: str, schema: SchemaView, dialect: DialectCapabilities) -> "QueryDocument":
        bundle = parse_query(query)
        document = cls(query=query, parse=bundle, schema=schema, dialect=dialect)
        if not bundle.errors and bundle.tree is not None:
            analyzer = ScopeAnalyzer(document)
            document.scopes = analyzer.analyze()
            document.complex_scope = analyzer.complex_scope
        return document

    def contexts(self, context_type: Type[Any], *, include_nested: bool = False) -> list[Any]:
        values: list[Any] = []
        for ctx in walk_contexts(self.parse.tree):
            if not isinstance(ctx, context_type):
                continue
            if not include_nested and inside_context(ctx, CypherParser.SubqueryExistContext):
                continue
            values.append(ctx)
        return values

    def text(self, ctx: Any) -> str:
        return context_text(self.query, ctx)

    def frame_for(self, ctx: Any) -> Optional[ClauseScope]:
        start = getattr(getattr(ctx, "start", None), "tokenIndex", -1)
        candidates = [frame for frame in self.scopes if frame.start_token <= start <= frame.stop_token]
        if candidates:
            return min(candidates, key=lambda frame: frame.stop_token - frame.start_token)
        earlier = [frame for frame in self.scopes if frame.start_token <= start]
        return earlier[-1] if earlier else None

    @property
    def all_variables(self) -> set[str]:
        result: set[str] = set()
        for frame in self.scopes:
            result.update(frame.before)
            result.update(frame.after)
        return result


class ScopeAnalyzer:
    CLAUSE_TYPES = (
        CypherParser.MatchStContext,
        CypherParser.UnwindStContext,
        CypherParser.WithStContext,
        CypherParser.ReturnStContext,
        CypherParser.CreateStContext,
        CypherParser.MergeStContext,
        CypherParser.DeleteStContext,
        CypherParser.SetStContext,
        CypherParser.RemoveStContext,
        CypherParser.QueryCallStContext,
    )

    def __init__(self, document: QueryDocument) -> None:
        self.document = document
        self.complex_scope = False

    def analyze(self) -> list[ClauseScope]:
        clauses: list[Any] = []
        for ctx in walk_contexts(self.document.parse.tree):
            if not isinstance(ctx, self.CLAUSE_TYPES):
                continue
            if inside_context(ctx, CypherParser.SubqueryExistContext):
                self.complex_scope = True
                continue
            clauses.append(ctx)
        clauses.sort(key=lambda item: item.start.tokenIndex)

        frames: list[ClauseScope] = []
        current: dict[str, VariableBinding] = {}
        active_union: Optional[int] = None
        for ctx in clauses:
            union_parent = next((parent for parent in ancestors(ctx) if isinstance(parent, CypherParser.UnionStContext)), None)
            union_key = union_parent.start.tokenIndex if union_parent is not None else None
            if union_key is not None and union_key != active_union:
                current = {}
                active_union = union_key
                self.complex_scope = True

            kind = type(ctx).__name__.removesuffix("Context")
            before = dict(current)
            after = self._apply_clause(ctx, before)
            frames.append(
                ClauseScope(
                    clause_kind=kind,
                    start_token=ctx.start.tokenIndex,
                    stop_token=ctx.stop.tokenIndex,
                    before=before,
                    after=after,
                    context=ctx,
                )
            )
            current = after
        return frames

    def _apply_clause(self, ctx: Any, before: dict[str, VariableBinding]) -> dict[str, VariableBinding]:
        if isinstance(ctx, CypherParser.WithStContext):
            return self._project_with(ctx, before)
        after = dict(before)
        if isinstance(ctx, (CypherParser.MatchStContext, CypherParser.CreateStContext, CypherParser.MergeStContext)):
            after.update(self._pattern_bindings(ctx))
        elif isinstance(ctx, CypherParser.UnwindStContext):
            symbol = ctx.symbol()
            if symbol:
                name = identifier_text(symbol.getText())
                after[name] = VariableBinding(name, ValueType.ANY, origin_token=ctx.start.tokenIndex)
        elif isinstance(ctx, CypherParser.QueryCallStContext):
            yield_items = ctx.yieldItems()
            if yield_items:
                for item in yield_items.yieldItem():
                    symbols = item.symbol()
                    symbols = symbols if isinstance(symbols, list) else [symbols]
                    if symbols:
                        name = identifier_text(symbols[-1].getText())
                        after[name] = VariableBinding(name, ValueType.ANY, origin_token=ctx.start.tokenIndex)
        return after

    def _pattern_bindings(self, clause_ctx: Any) -> dict[str, VariableBinding]:
        result: dict[str, VariableBinding] = {}
        for node in walk_contexts(clause_ctx):
            if node is not clause_ctx and isinstance(node, self.CLAUSE_TYPES):
                continue
            if isinstance(node, CypherParser.NodePatternContext):
                symbol_ctx = node.symbol() if hasattr(node, "symbol") else None
                if not symbol_ctx:
                    continue
                name = identifier_text(symbol_ctx.getText())
                labels_ctx = node.nodeLabels() if hasattr(node, "nodeLabels") else None
                label = None
                if labels_ctx:
                    labels = labels_ctx.name()
                    labels = labels if isinstance(labels, list) else [labels]
                    label = identifier_text(labels[0].getText()) if labels else None
                result[name] = VariableBinding(
                    name=name,
                    value_type=ValueType.NODE,
                    entity_name=label,
                    nullable=isinstance(clause_ctx, CypherParser.MatchStContext)
                    and clause_ctx.OPTIONAL() is not None,
                    origin_token=node.start.tokenIndex,
                )
            elif isinstance(node, CypherParser.RelationshipPatternContext):
                detail = node.relationDetail() if hasattr(node, "relationDetail") else None
                symbol_ctx = detail.symbol() if detail and hasattr(detail, "symbol") else None
                if not symbol_ctx:
                    continue
                rel_type = None
                type_ctx = detail.relationshipTypes() if hasattr(detail, "relationshipTypes") else None
                if type_ctx:
                    types = type_ctx.name()
                    types = types if isinstance(types, list) else [types]
                    rel_type = identifier_text(types[0].getText()) if types else None
                name = identifier_text(symbol_ctx.getText())
                result[name] = VariableBinding(name, ValueType.RELATIONSHIP, rel_type, origin_token=node.start.tokenIndex)
            elif isinstance(node, CypherParser.PatternPartContext):
                symbol_ctx = node.symbol() if hasattr(node, "symbol") else None
                if symbol_ctx:
                    name = identifier_text(symbol_ctx.getText())
                    result[name] = VariableBinding(name, ValueType.PATH, origin_token=node.start.tokenIndex)
        return result

    def _project_with(self, ctx: Any, before: dict[str, VariableBinding]) -> dict[str, VariableBinding]:
        projection_items = ctx.projectionBody().projectionItems()
        result: dict[str, VariableBinding] = {}
        if projection_items.MULT() is not None:
            result.update(before)
        items = projection_items.projectionItem()
        items = items if isinstance(items, list) else [items]
        for item in items:
            alias_ctx = item.symbol()
            expression = item.expression()
            if alias_ctx:
                alias = identifier_text(alias_ctx.getText())
                binding = self._binding_for_expression(expression, alias, before, ctx.start.tokenIndex)
                result[alias] = binding
                continue
            access = self._simple_property_expression(expression)
            if access and access[1] is None and access[0] in before:
                result[access[0]] = before[access[0]]
        return result

    def _binding_for_expression(
        self,
        expression: Any,
        alias: str,
        before: dict[str, VariableBinding],
        token: int,
    ) -> VariableBinding:
        access = self._simple_property_expression(expression)
        if access and access[1] is None and access[0] in before:
            original = before[access[0]]
            return VariableBinding(alias, original.value_type, original.entity_name, original.nullable, token)
        if access and access[1] is not None:
            variable, prop = access
            owner = before.get(variable).entity_name if variable in before else None
            value_type = self.document.schema.properties.get(owner or "", {}).get(prop, ValueType.ANY)
            return VariableBinding(alias, value_type, origin_token=token)
        return VariableBinding(alias, ValueType.ANY, origin_token=token)

    @staticmethod
    def _simple_property_expression(expression: Any) -> Optional[tuple[str, Optional[str]]]:
        for candidate in walk_contexts(expression):
            if not isinstance(candidate, CypherParser.PropertyExpressionContext):
                continue
            if (
                candidate.start.tokenIndex != expression.start.tokenIndex
                or candidate.stop.tokenIndex != expression.stop.tokenIndex
            ):
                continue
            atom = candidate.atom()
            symbol = atom.symbol() if atom and hasattr(atom, "symbol") else None
            if symbol is None or ScopeAnalyzer._numeric_symbol(symbol):
                return None
            names = candidate.name()
            names = names if isinstance(names, list) else ([names] if names else [])
            if len(names) > 1:
                return None
            return (
                identifier_text(symbol.getText()),
                identifier_text(names[0].getText()) if names else None,
            )
        return None

    @staticmethod
    def _numeric_symbol(symbol: Any) -> bool:
        raw = symbol.getText()
        return bool(raw) and not raw.startswith("`") and (raw[0].isdigit() or raw[0] in {"+", "-"})
