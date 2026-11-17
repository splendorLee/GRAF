"""Typed query and mutation intermediate representations.

This module is the trust boundary between mutation planning and source-code
generation.  Operators are deliberately unable to submit arbitrary character
edits: they can only emit the closed set of typed operations declared here.
Every operation is anchored to a parser node and compiled with ANTLR's token
rewriter after parent and node fingerprints have been verified.
"""

from __future__ import annotations

import ast
import dataclasses
import enum
import hashlib
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Iterable, Iterator, Mapping, Optional, Sequence, Union

from antlr4.TokenStreamRewriter import TokenStreamRewriter
from CypherLexer import CypherLexer
from CypherParser import CypherParser

from .cypher import QueryDocument, ancestors, identifier_text, inside_context, parse_query, walk_contexts
from .model import ClauseScope, OperatorKind, ValueType, query_digest, stable_json


IR_VERSION = "graf.mutation-ir/v1"


def source_digest(source: str) -> str:
    """Return a whitespace-sensitive digest used for optimistic concurrency."""

    return hashlib.sha256(source.encode("utf-8")).hexdigest()


class IRNodeKind(str, enum.Enum):
    MATCH_CLAUSE = "match_clause"
    RETURN_CLAUSE = "return_clause"
    WITH_CLAUSE = "with_clause"
    UNWIND_CLAUSE = "unwind_clause"
    UPDATE_CLAUSE = "update_clause"
    PATTERN = "pattern"
    PATTERN_PART = "pattern_part"
    NODE_PATTERN = "node_pattern"
    RELATIONSHIP_PATTERN = "relationship_pattern"
    RELATIONSHIP_TYPE = "relationship_type"
    PATH_RANGE = "path_range"
    WHERE_CLAUSE = "where_clause"
    EXPRESSION = "expression"
    LIMIT_CLAUSE = "limit_clause"
    FUNCTION_CALL = "function_call"
    FUNCTION_ARGUMENT = "function_argument"
    LITERAL = "literal"
    SYMBOL = "symbol"


class RelationshipDirection(str, enum.Enum):
    OUTGOING = "outgoing"
    INCOMING = "incoming"
    UNDIRECTED = "undirected"


class LiteralRole(str, enum.Enum):
    GENERAL = "general"
    PATH_RANGE = "path_range"
    LIMIT = "limit"
    SKIP = "skip"
    UNWIND_RANGE = "unwind_range"


@dataclass(frozen=True)
class NodeAnchor:
    node_id: str
    kind: IRNodeKind
    start_token: int
    stop_token: int
    source_sha256: str


@dataclass(frozen=True)
class SymbolOccurrenceIR:
    anchor: NodeAnchor
    name: str


@dataclass(frozen=True)
class NodePatternIR:
    anchor: NodeAnchor
    variable: Optional[str]
    labels: tuple[str, ...] = ()


@dataclass(frozen=True)
class PathRangeIR:
    anchor: NodeAnchor
    lower: Optional[int]
    upper: Optional[int]
    explicit_range: bool


@dataclass(frozen=True)
class RelationshipPatternIR:
    anchor: NodeAnchor
    type_anchor: Optional[NodeAnchor]
    variable: Optional[str]
    relationship_types: tuple[str, ...]
    direction: RelationshipDirection
    left: NodePatternIR
    right: NodePatternIR
    path_range: Optional[PathRangeIR]

    @property
    def source(self) -> NodePatternIR:
        return self.right if self.direction == RelationshipDirection.INCOMING else self.left

    @property
    def target(self) -> NodePatternIR:
        return self.left if self.direction == RelationshipDirection.INCOMING else self.right


@dataclass(frozen=True)
class PatternPartIR:
    anchor: NodeAnchor
    path_variable: Optional[str]
    nodes: tuple[NodePatternIR, ...]
    relationships: tuple[RelationshipPatternIR, ...]
    bound_variables: frozenset[str]


@dataclass(frozen=True)
class PatternIR:
    anchor: NodeAnchor
    parts: tuple[PatternPartIR, ...]


@dataclass(frozen=True)
class WhereIR:
    anchor: NodeAnchor
    expression: NodeAnchor
    conjunction_terms: tuple[NodeAnchor, ...]


@dataclass(frozen=True)
class MatchClauseIR:
    anchor: NodeAnchor
    pattern: PatternIR
    where: Optional[WhereIR]
    optional: bool


@dataclass(frozen=True)
class ReturnClauseIR:
    anchor: NodeAnchor


@dataclass(frozen=True)
class LimitIR:
    anchor: NodeAnchor
    expression: NodeAnchor
    value: Optional[int]


@dataclass(frozen=True)
class UnwindRangeIR:
    unwind_anchor: NodeAnchor
    function_anchor: NodeAnchor
    start_argument: NodeAnchor
    end_argument: NodeAnchor
    start_value: int
    end_value: int


@dataclass(frozen=True)
class LiteralSiteIR:
    anchor: NodeAnchor
    raw: str
    value: Any
    actual_type: ValueType
    role: LiteralRole
    variable: Optional[str] = None
    owner: Optional[str] = None
    property_name: Optional[str] = None
    comparison_operator: Optional[str] = None
    expected_type: ValueType = ValueType.ANY
    quote: str = "'"


@dataclass(frozen=True)
class QueryIR:
    """A parser-derived, immutable-by-convention view of one query."""

    document: QueryDocument = field(repr=False)
    version: str = IR_VERSION
    parent_sha256: str = ""
    parent_query_digest: str = ""
    anchors: Mapping[str, NodeAnchor] = field(default_factory=dict)
    matches: tuple[MatchClauseIR, ...] = ()
    wheres: tuple[WhereIR, ...] = ()
    returns: tuple[ReturnClauseIR, ...] = ()
    limits: tuple[LimitIR, ...] = ()
    unwind_ranges: tuple[UnwindRangeIR, ...] = ()
    literals: tuple[LiteralSiteIR, ...] = ()
    symbols: tuple[SymbolOccurrenceIR, ...] = ()
    _contexts: Mapping[str, Any] = field(default_factory=dict, repr=False)

    @property
    def query(self) -> str:
        return self.document.query

    @property
    def schema(self):
        return self.document.schema

    @property
    def dialect(self):
        return self.document.dialect

    @property
    def scopes(self) -> list[ClauseScope]:
        return self.document.scopes

    @property
    def complex_scope(self) -> bool:
        return self.document.complex_scope

    @property
    def all_variables(self) -> set[str]:
        return self.document.all_variables

    def source(self, anchor: NodeAnchor) -> str:
        self.assert_anchor(anchor)
        start = self.document.parse.token_stream.get(anchor.start_token).start
        stop = self.document.parse.token_stream.get(anchor.stop_token).stop
        return self.query[start : stop + 1]

    def context(self, anchor: NodeAnchor) -> Any:
        self.assert_anchor(anchor)
        return self._contexts[anchor.node_id]

    def frame_for(self, anchor: NodeAnchor) -> Optional[ClauseScope]:
        return self.document.frame_for(self.context(anchor))

    def assert_anchor(self, anchor: NodeAnchor) -> None:
        current = self.anchors.get(anchor.node_id)
        if current is None:
            raise MutationIRCompileError("ANCHOR_NOT_FOUND", f"unknown IR anchor {anchor.node_id}")
        if current != anchor:
            raise MutationIRCompileError("ANCHOR_MISMATCH", f"IR anchor changed: {anchor.node_id}")
        if source_digest(self._source_unchecked(anchor)) != anchor.source_sha256:
            raise MutationIRCompileError("ANCHOR_SOURCE_MISMATCH", f"source changed for IR anchor {anchor.node_id}")

    def _source_unchecked(self, anchor: NodeAnchor) -> str:
        start_token = self.document.parse.token_stream.get(anchor.start_token)
        stop_token = self.document.parse.token_stream.get(anchor.stop_token)
        return self.query[start_token.start : stop_token.stop + 1]

    def symbol_occurs_outside(self, name: str, anchor: NodeAnchor) -> bool:
        return any(
            item.name == name
            and not (anchor.start_token <= item.anchor.start_token <= anchor.stop_token)
            for item in self.symbols
        )


class QueryIRBuilder:
    """Build typed mutation sites from the generated Cypher parse tree."""

    def __init__(self) -> None:
        self._document: Optional[QueryDocument] = None
        self._anchors: dict[str, NodeAnchor] = {}
        self._contexts: dict[str, Any] = {}

    def build(self, document: QueryDocument) -> QueryIR:
        if document.parse.tree is None or document.parse.errors:
            raise ValueError("QueryIR requires a successfully parsed QueryDocument")
        self._document = document
        self._anchors = {}
        self._contexts = {}

        symbols = tuple(self._build_symbols())
        where_by_start = {
            ctx.start.tokenIndex: self._build_where(ctx)
            for ctx in document.contexts(CypherParser.WhereContext)
        }
        wheres = tuple(where_by_start[key] for key in sorted(where_by_start))
        matches = tuple(
            self._build_match(ctx, where_by_start)
            for ctx in document.contexts(CypherParser.MatchStContext)
        )
        returns = tuple(
            ReturnClauseIR(self._anchor(ctx, IRNodeKind.RETURN_CLAUSE))
            for ctx in document.contexts(CypherParser.ReturnStContext)
        )
        limits = tuple(self._build_limit(ctx) for ctx in document.contexts(CypherParser.LimitStContext, include_nested=True))
        unwind_ranges = tuple(self._build_unwind_ranges())
        literals = tuple(self._build_literals(unwind_ranges))
        return QueryIR(
            document=document,
            parent_sha256=source_digest(document.query),
            parent_query_digest=query_digest(document.query),
            anchors=MappingProxyType(dict(self._anchors)),
            matches=matches,
            wheres=wheres,
            returns=returns,
            limits=limits,
            unwind_ranges=unwind_ranges,
            literals=literals,
            symbols=symbols,
            _contexts=MappingProxyType(dict(self._contexts)),
        )

    @property
    def document(self) -> QueryDocument:
        if self._document is None:
            raise RuntimeError("builder is not active")
        return self._document

    def _anchor(self, ctx: Any, kind: IRNodeKind) -> NodeAnchor:
        start = int(ctx.start.tokenIndex)
        stop = int(ctx.stop.tokenIndex)
        token_start = self.document.parse.token_stream.get(start).start
        token_stop = self.document.parse.token_stream.get(stop).stop
        source = self.document.query[token_start : token_stop + 1]
        fingerprint = source_digest(source)
        material = f"{kind.value}:{start}:{stop}:{fingerprint}"
        node_id = hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]
        anchor = NodeAnchor(node_id, kind, start, stop, fingerprint)
        existing = self._anchors.get(node_id)
        if existing is not None and existing != anchor:
            raise ValueError(f"IR anchor collision for {node_id}")
        self._anchors[node_id] = anchor
        self._contexts[node_id] = ctx
        return anchor

    def _build_symbols(self) -> Iterator[SymbolOccurrenceIR]:
        for ctx in self.document.contexts(CypherParser.SymbolContext, include_nested=True):
            yield SymbolOccurrenceIR(
                self._anchor(ctx, IRNodeKind.SYMBOL),
                identifier_text(ctx.getText()),
            )

    def _build_match(self, ctx: Any, where_by_start: Mapping[int, WhereIR]) -> MatchClauseIR:
        pattern_where = ctx.patternWhere()
        pattern_ctx = pattern_where.pattern()
        parts = tuple(self._build_pattern_part(part) for part in self._as_list(pattern_ctx.patternPart()))
        where_ctx = pattern_where.where()
        where = where_by_start.get(where_ctx.start.tokenIndex) if where_ctx else None
        optional = ctx.OPTIONAL() is not None
        return MatchClauseIR(
            self._anchor(ctx, IRNodeKind.MATCH_CLAUSE),
            PatternIR(self._anchor(pattern_ctx, IRNodeKind.PATTERN), parts),
            where,
            optional,
        )

    def _build_pattern_part(self, ctx: Any) -> PatternPartIR:
        elem = ctx.patternElem()
        path_symbol = ctx.symbol()
        path_variable = identifier_text(path_symbol.getText()) if path_symbol else None
        nodes: list[NodePatternIR] = []
        relationships: list[RelationshipPatternIR] = []

        first_node_ctx = elem.nodePattern() if hasattr(elem, "nodePattern") else None
        if first_node_ctx is not None:
            previous = self._build_node(first_node_ctx)
            nodes.append(previous)
            for chain in self._as_list(elem.patternElemChain()):
                current = self._build_node(chain.nodePattern())
                nodes.append(current)
                relationships.append(self._build_relationship(chain.relationshipPattern(), previous, current))
                previous = current
        else:
            # Function-based and parenthesized pattern elements are represented
            # as opaque typed parts and are intentionally not topology sites.
            for node_ctx in walk_contexts(elem):
                if isinstance(node_ctx, CypherParser.NodePatternContext):
                    nodes.append(self._build_node(node_ctx))

        bound = {node.variable for node in nodes if node.variable}
        bound.update(rel.variable for rel in relationships if rel.variable)
        if path_variable:
            bound.add(path_variable)
        return PatternPartIR(
            self._anchor(ctx, IRNodeKind.PATTERN_PART),
            path_variable,
            tuple(nodes),
            tuple(relationships),
            frozenset(bound),
        )

    def _build_node(self, ctx: Any) -> NodePatternIR:
        symbol = ctx.symbol()
        labels_ctx = ctx.nodeLabels()
        labels = tuple(identifier_text(name.getText()) for name in self._as_list(labels_ctx.name())) if labels_ctx else ()
        return NodePatternIR(
            self._anchor(ctx, IRNodeKind.NODE_PATTERN),
            identifier_text(symbol.getText()) if symbol else None,
            labels,
        )

    def _build_relationship(self, ctx: Any, left: NodePatternIR, right: NodePatternIR) -> RelationshipPatternIR:
        detail = ctx.relationDetail()
        variable: Optional[str] = None
        rel_types: tuple[str, ...] = ()
        type_anchor: Optional[NodeAnchor] = None
        path_range: Optional[PathRangeIR] = None
        if detail:
            symbol = detail.symbol()
            variable = identifier_text(symbol.getText()) if symbol else None
            types_ctx = detail.relationshipTypes()
            if types_ctx:
                names = self._as_list(types_ctx.name())
                rel_types = tuple(identifier_text(name.getText()) for name in names)
                if len(names) == 1:
                    type_anchor = self._anchor(names[0], IRNodeKind.RELATIONSHIP_TYPE)
            range_ctx = detail.rangeLit()
            if range_ctx:
                path_range = self._build_path_range(range_ctx)
        direction = RelationshipDirection.UNDIRECTED
        if ctx.LT() is not None:
            direction = RelationshipDirection.INCOMING
        elif ctx.GT() is not None:
            direction = RelationshipDirection.OUTGOING
        return RelationshipPatternIR(
            self._anchor(ctx, IRNodeKind.RELATIONSHIP_PATTERN),
            type_anchor,
            variable,
            rel_types,
            direction,
            left,
            right,
            path_range,
        )

    def _build_path_range(self, ctx: Any) -> PathRangeIR:
        tokens = self._significant_tokens(ctx)
        integer_values = [int(token.text) for token in tokens if token.type == CypherLexer.Integer]
        explicit_range = any(token.type == CypherLexer.RANGE for token in tokens)
        if explicit_range:
            range_index = next(index for index, token in enumerate(tokens) if token.type == CypherLexer.RANGE)
            before = [int(token.text) for token in tokens[:range_index] if token.type == CypherLexer.Integer]
            after = [int(token.text) for token in tokens[range_index + 1 :] if token.type == CypherLexer.Integer]
            lower = before[-1] if before else None
            upper = after[0] if after else None
        elif integer_values:
            lower = upper = integer_values[0]
        else:
            lower = upper = None
        return PathRangeIR(self._anchor(ctx, IRNodeKind.PATH_RANGE), lower, upper, explicit_range)

    def _build_where(self, ctx: Any) -> WhereIR:
        expression = ctx.expression()
        terms: tuple[NodeAnchor, ...] = ()
        xor_items = self._as_list(expression.xorExpression())
        if len(xor_items) == 1:
            and_items = self._as_list(xor_items[0].andExpression())
            if len(and_items) == 1:
                not_items = self._as_list(and_items[0].notExpression())
                if len(not_items) > 1:
                    terms = tuple(self._anchor(item, IRNodeKind.EXPRESSION) for item in not_items)
        return WhereIR(
            self._anchor(ctx, IRNodeKind.WHERE_CLAUSE),
            self._anchor(expression, IRNodeKind.EXPRESSION),
            terms,
        )

    def _build_limit(self, ctx: Any) -> LimitIR:
        expression = ctx.expression()
        return LimitIR(
            self._anchor(ctx, IRNodeKind.LIMIT_CLAUSE),
            self._anchor(expression, IRNodeKind.EXPRESSION),
            self._integer_constant(expression),
        )

    def _build_unwind_ranges(self) -> Iterator[UnwindRangeIR]:
        for unwind in self.document.contexts(CypherParser.UnwindStContext):
            for invocation in walk_contexts(unwind.expression()):
                if not isinstance(invocation, CypherParser.FunctionInvocationContext):
                    continue
                name = ".".join(
                    identifier_text(symbol.getText())
                    for symbol in self._as_list(invocation.invocationName().symbol())
                ).lower()
                if name != "range":
                    continue
                chain = invocation.expressionChain()
                arguments = self._as_list(chain.expression()) if chain else []
                if len(arguments) < 2:
                    continue
                start_value = self._integer_constant(arguments[0])
                end_value = self._integer_constant(arguments[1])
                if start_value is None or end_value is None:
                    continue
                yield UnwindRangeIR(
                    self._anchor(unwind, IRNodeKind.UNWIND_CLAUSE),
                    self._anchor(invocation, IRNodeKind.FUNCTION_CALL),
                    self._anchor(arguments[0], IRNodeKind.FUNCTION_ARGUMENT),
                    self._anchor(arguments[1], IRNodeKind.FUNCTION_ARGUMENT),
                    start_value,
                    end_value,
                )

    def _build_literals(self, unwind_ranges: Sequence[UnwindRangeIR]) -> Iterator[LiteralSiteIR]:
        contexts: dict[tuple[int, int], Any] = {}
        for ctx in self.document.contexts(CypherParser.LiteralContext, include_nested=True):
            contexts[(ctx.start.tokenIndex, ctx.stop.tokenIndex)] = ctx
        for ctx in self.document.contexts(CypherParser.AtomContext, include_nested=True):
            if self._parse_numeric_text(self.document.text(ctx)) is not None:
                contexts[(ctx.start.tokenIndex, ctx.stop.tokenIndex)] = ctx
        # The bundled grammar admits an unsigned decimal such as ``1.0`` as a
        # numeric-looking propertyExpression (``1`` ``.`` ``0``).  Recognize
        # that parser node by numeric conversion, not by a source regex.
        for ctx in self.document.contexts(CypherParser.PropertyExpressionContext, include_nested=True):
            if self._parse_numeric_text(self.document.text(ctx)) is not None:
                contexts[(ctx.start.tokenIndex, ctx.stop.tokenIndex)] = ctx

        for _key, ctx in sorted(contexts.items()):
            scalar = self._parse_scalar(ctx)
            if scalar is None:
                continue
            value, actual_type, quote = scalar
            anchor = self._anchor(ctx, IRNodeKind.LITERAL)
            role = LiteralRole.GENERAL
            if inside_context(ctx, CypherParser.RangeLitContext):
                role = LiteralRole.PATH_RANGE
            elif inside_context(ctx, CypherParser.LimitStContext):
                role = LiteralRole.LIMIT
            elif hasattr(CypherParser, "SkipStContext") and inside_context(ctx, CypherParser.SkipStContext):
                role = LiteralRole.SKIP
            elif any(
                item.start_argument.start_token <= anchor.start_token <= item.end_argument.stop_token
                for item in unwind_ranges
            ):
                role = LiteralRole.UNWIND_RANGE

            variable = owner = property_name = operator = None
            expected_type = actual_type
            comparison = next(
                (parent for parent in ancestors(ctx) if isinstance(parent, CypherParser.ComparisonExpressionContext)),
                None,
            )
            if comparison is not None:
                operands = self._as_list(comparison.addSubExpression())
                signs = self._as_list(comparison.comparisonSigns())
                literal_index = next(
                    (
                        index
                        for index, operand in enumerate(operands)
                        if operand.start.tokenIndex <= ctx.start.tokenIndex <= operand.stop.tokenIndex
                    ),
                    None,
                )
                other_index: Optional[int] = None
                sign_index: Optional[int] = None
                if literal_index is not None and len(operands) == 2 and len(signs) == 1:
                    other_index = 1 - literal_index
                    sign_index = 0
                if other_index is not None:
                    access = self._property_access(operands[other_index])
                    if access:
                        variable, property_name = access
                        operator = signs[sign_index].getText() if sign_index is not None else None
                        frame = self.document.frame_for(ctx)
                        visible = {}
                        if frame:
                            visible = frame.after if frame.clause_kind in {"MatchSt", "WithSt"} else frame.before
                        owner = visible.get(variable).entity_name if variable in visible else None
                        expected_type = self.document.schema.properties.get(owner or "", {}).get(property_name, actual_type)
                        if expected_type == ValueType.ANY:
                            expected_type = actual_type

            yield LiteralSiteIR(
                anchor=anchor,
                raw=self.document.text(ctx),
                value=value,
                actual_type=actual_type,
                role=role,
                variable=variable,
                owner=owner,
                property_name=property_name,
                comparison_operator=operator,
                expected_type=expected_type,
                quote=quote,
            )

    def _property_access(self, ctx: Any) -> Optional[tuple[str, str]]:
        for candidate in walk_contexts(ctx):
            if not isinstance(candidate, CypherParser.PropertyExpressionContext):
                continue
            if candidate.start.tokenIndex != ctx.start.tokenIndex or candidate.stop.tokenIndex != ctx.stop.tokenIndex:
                continue
            names = self._as_list(candidate.name())
            atom = candidate.atom()
            symbol = atom.symbol() if atom and hasattr(atom, "symbol") else None
            if (
                symbol is not None
                and not self._numeric_symbol(symbol)
                and len(names) == 1
            ):
                return identifier_text(symbol.getText()), identifier_text(names[0].getText())
        return None

    def _parse_scalar(self, ctx: Any) -> Optional[tuple[Any, ValueType, str]]:
        tokens = self._significant_tokens(ctx)
        numeric = self._parse_numeric_text(self.document.text(ctx))
        if numeric is not None:
            value, value_type = numeric
            return value, value_type, "'"
        if len(tokens) != 1:
            return None
        token = tokens[0]
        raw = token.text
        if token.type in {CypherLexer.STRING_LITERAL, CypherLexer.CHAR_LITERAL}:
            quote = raw[0] if raw and raw[0] in {"'", '"'} else "'"
            try:
                value = ast.literal_eval(raw)
            except (ValueError, SyntaxError):
                value = raw[1:-1] if len(raw) >= 2 else raw
            return value, ValueType.STRING, quote
        if token.type == CypherLexer.TRUE:
            return True, ValueType.BOOLEAN, "'"
        if token.type == CypherLexer.FALSE:
            return False, ValueType.BOOLEAN, "'"
        if token.type == CypherLexer.NULL_W:
            return None, ValueType.NULL, "'"
        return None

    @staticmethod
    def _parse_numeric_text(raw: str) -> Optional[tuple[Any, ValueType]]:
        value = raw.strip().replace(" ", "")
        if not value or value.startswith("`"):
            return None
        try:
            if any(marker in value.lower() for marker in (".", "e")):
                return float(value), ValueType.FLOAT
            lowered = value.lower().lstrip("+-")
            base = 16 if lowered.startswith("0x") else (8 if lowered.startswith("0o") else 10)
            return int(value, base), ValueType.INTEGER
        except ValueError:
            return None

    @staticmethod
    def _numeric_symbol(symbol: Any) -> bool:
        raw = symbol.getText()
        return bool(raw) and not raw.startswith("`") and (raw[0].isdigit() or raw[0] in {"+", "-"})

    def _integer_constant(self, ctx: Any) -> Optional[int]:
        tokens = self._significant_tokens(ctx)
        if len(tokens) == 1 and tokens[0].type == CypherLexer.Integer:
            return int(tokens[0].text)
        if len(tokens) == 1 and tokens[0].type == CypherLexer.DIGIT:
            raw = tokens[0].text.lower()
            if not any(marker in raw for marker in (".", "e")):
                try:
                    return int(raw)
                except ValueError:
                    return None
        if (
            len(tokens) == 2
            and tokens[0].type in {CypherLexer.PLUS, CypherLexer.SUB}
            and tokens[1].type == CypherLexer.Integer
        ):
            value = int(tokens[1].text)
            return -value if tokens[0].type == CypherLexer.SUB else value
        return None

    def _significant_tokens(self, ctx: Any) -> list[Any]:
        return [
            self.document.parse.token_stream.get(index)
            for index in range(ctx.start.tokenIndex, ctx.stop.tokenIndex + 1)
            if self.document.parse.token_stream.get(index).type != CypherLexer.SP
        ]

    @staticmethod
    def _as_list(value: Any) -> list[Any]:
        if value is None:
            return []
        return value if isinstance(value, list) else [value]


# ---------------------------------------------------------------------------
# Typed expression and clause construction IR


@dataclass(frozen=True)
class ExistingExpressionIR:
    anchor: NodeAnchor


@dataclass(frozen=True)
class VariableExpressionIR:
    name: str


@dataclass(frozen=True)
class PropertyExpressionIR:
    variable: str
    property_name: str


@dataclass(frozen=True)
class LiteralExpressionIR:
    value: Any
    value_type: ValueType
    quote: str = "'"


@dataclass(frozen=True)
class ComparisonExpressionIR:
    left: "ExpressionIR"
    operator: str
    right: "ExpressionIR"


@dataclass(frozen=True)
class NullCheckExpressionIR:
    operand: "ExpressionIR"
    negated: bool = True


@dataclass(frozen=True)
class ConjunctionExpressionIR:
    terms: tuple["ExpressionIR", ...]


@dataclass(frozen=True)
class FunctionExpressionIR:
    name: str
    arguments: tuple["ExpressionIR", ...]


@dataclass(frozen=True)
class CountAllExpressionIR:
    pass


@dataclass(frozen=True)
class ListExpressionIR:
    items: tuple["ExpressionIR", ...]


ExpressionIR = Union[
    ExistingExpressionIR,
    VariableExpressionIR,
    PropertyExpressionIR,
    LiteralExpressionIR,
    ComparisonExpressionIR,
    NullCheckExpressionIR,
    ConjunctionExpressionIR,
    FunctionExpressionIR,
    CountAllExpressionIR,
    ListExpressionIR,
]


@dataclass(frozen=True)
class ProjectionItemIR:
    expression: ExpressionIR
    alias: Optional[str] = None


@dataclass(frozen=True)
class OptionalMatchClauseIR:
    source_variable: str
    relationship_type: str
    target_variable: str
    target_label: str


@dataclass(frozen=True)
class WithClauseIR:
    projections: tuple[ProjectionItemIR, ...]


@dataclass(frozen=True)
class UnwindClauseIR:
    expression: ExpressionIR
    alias: str


ClauseIR = Union[OptionalMatchClauseIR, WithClauseIR, UnwindClauseIR]


# ---------------------------------------------------------------------------
# Closed mutation operation set


@dataclass(frozen=True)
class InsertClausesAfterOp:
    anchor: NodeAnchor
    clauses: tuple[ClauseIR, ...]


@dataclass(frozen=True)
class InsertClausesBeforeOp:
    anchor: NodeAnchor
    clauses: tuple[ClauseIR, ...]


@dataclass(frozen=True)
class ReplaceRelationshipTypeOp:
    target: NodeAnchor
    expected: str
    replacement: str


@dataclass(frozen=True)
class RemovePatternPartOp:
    pattern: NodeAnchor
    removed_part: NodeAnchor
    retained_parts: tuple[NodeAnchor, ...]


@dataclass(frozen=True)
class ReplacePathRangeOp:
    target: NodeAnchor
    lower: Optional[int]
    upper: Optional[int]
    explicit_range: bool


@dataclass(frozen=True)
class ReplaceLimitOp:
    target: NodeAnchor
    value: int


@dataclass(frozen=True)
class InsertLimitOp:
    return_clause: NodeAnchor
    value: int


@dataclass(frozen=True)
class ReplaceFunctionArgumentOp:
    function: NodeAnchor
    target: NodeAnchor
    argument_index: int
    value: int


@dataclass(frozen=True)
class ReplaceWherePredicateOp:
    target: NodeAnchor
    predicate: ExpressionIR


@dataclass(frozen=True)
class RemoveWhereOp:
    target: NodeAnchor


@dataclass(frozen=True)
class InsertWhereOp:
    match_clause: NodeAnchor
    predicate: ExpressionIR


@dataclass(frozen=True)
class ReplaceLiteralOp:
    target: NodeAnchor
    literal: LiteralExpressionIR


MutationOperation = Union[
    InsertClausesAfterOp,
    InsertClausesBeforeOp,
    ReplaceRelationshipTypeOp,
    RemovePatternPartOp,
    ReplacePathRangeOp,
    ReplaceLimitOp,
    InsertLimitOp,
    ReplaceFunctionArgumentOp,
    ReplaceWherePredicateOp,
    RemoveWhereOp,
    InsertWhereOp,
    ReplaceLiteralOp,
]


@dataclass(frozen=True)
class NodePrecondition:
    node_id: str
    kind: IRNodeKind
    start_token: int
    stop_token: int
    source_sha256: str

    @classmethod
    def from_anchor(cls, anchor: NodeAnchor) -> "NodePrecondition":
        return cls(
            anchor.node_id,
            anchor.kind,
            anchor.start_token,
            anchor.stop_token,
            anchor.source_sha256,
        )


def iter_anchors(value: Any) -> Iterator[NodeAnchor]:
    if isinstance(value, NodeAnchor):
        yield value
        return
    if dataclasses.is_dataclass(value):
        for item in dataclasses.fields(value):
            yield from iter_anchors(getattr(value, item.name))
        return
    if isinstance(value, Mapping):
        for item in value.values():
            yield from iter_anchors(item)
        return
    if isinstance(value, (tuple, list, set, frozenset)):
        for item in value:
            yield from iter_anchors(item)


@dataclass(frozen=True)
class MutationProgram:
    ir_version: str
    parent_sha256: str
    operator: OperatorKind
    action: str
    operations: tuple[MutationOperation, ...]
    preconditions: tuple[NodePrecondition, ...]
    program_id: str

    @classmethod
    def create(
        cls,
        query_ir: QueryIR,
        operator: OperatorKind,
        action: str,
        operations: Iterable[MutationOperation],
    ) -> "MutationProgram":
        operation_tuple = tuple(operations)
        if not operation_tuple:
            raise ValueError("mutation program must contain at least one operation")
        anchors = {
            anchor.node_id: anchor
            for operation in operation_tuple
            for anchor in iter_anchors(operation)
        }
        preconditions = tuple(
            NodePrecondition.from_anchor(anchors[node_id])
            for node_id in sorted(anchors)
        )
        program_id = mutation_program_id(
            IR_VERSION,
            query_ir.parent_sha256,
            operator,
            action,
            operation_tuple,
            preconditions,
        )
        return cls(
            IR_VERSION,
            query_ir.parent_sha256,
            operator,
            action,
            operation_tuple,
            preconditions,
            program_id,
        )


def mutation_program_id(
    ir_version: str,
    parent_sha256: str,
    operator: OperatorKind,
    action: str,
    operations: Sequence[MutationOperation],
    preconditions: Sequence[NodePrecondition],
) -> str:
    material = stable_json(
        {
            "ir_version": ir_version,
            "parent_sha256": parent_sha256,
            "operator": operator,
            "action": action,
            "operations": tuple(operations),
            "preconditions": tuple(preconditions),
        }
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]


@dataclass(frozen=True)
class MutationCandidate:
    operator: OperatorKind
    action: str
    program: MutationProgram
    site_token: int
    metadata: Mapping[str, Any] = field(default_factory=dict)
    estimated_cost_delta: int = 0

    @classmethod
    def create(
        cls,
        query_ir: QueryIR,
        operator: OperatorKind,
        action: str,
        operation: MutationOperation,
        site_token: int,
        metadata: Optional[Mapping[str, Any]] = None,
        estimated_cost_delta: int = 0,
    ) -> "MutationCandidate":
        return cls(
            operator=operator,
            action=action,
            program=MutationProgram.create(query_ir, operator, action, (operation,)),
            site_token=site_token,
            metadata=dict(metadata or {}),
            estimated_cost_delta=estimated_cost_delta,
        )


class MutationIRCodecError(ValueError):
    pass


class MutationIRCodec:
    """Strict decoder for persisted mutation programs.

    Encoding uses :func:`graf.model.to_jsonable`, which adds ``ir_type``
    discriminators.  Decoding is intentionally allow-list based: unknown IR
    types or missing fields are rejected rather than dynamically imported.
    """

    @classmethod
    def decode_program(cls, payload: Mapping[str, Any]) -> MutationProgram:
        cls._expect_type(payload, "MutationProgram")
        try:
            operations = tuple(cls._decode_operation(item) for item in cls._sequence(payload, "operations"))
            preconditions = tuple(
                cls._decode_precondition(item)
                for item in cls._sequence(payload, "preconditions")
            )
            program = MutationProgram(
                ir_version=str(payload["ir_version"]),
                parent_sha256=str(payload["parent_sha256"]),
                operator=OperatorKind(str(payload["operator"])),
                action=str(payload["action"]),
                operations=operations,
                preconditions=preconditions,
                program_id=str(payload["program_id"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, MutationIRCodecError):
                raise
            raise MutationIRCodecError(f"invalid MutationProgram payload: {exc}") from exc
        expected = mutation_program_id(
            program.ir_version,
            program.parent_sha256,
            program.operator,
            program.action,
            program.operations,
            program.preconditions,
        )
        if program.program_id != expected:
            raise MutationIRCodecError("mutation program integrity check failed")
        return program

    @classmethod
    def _decode_anchor(cls, payload: Mapping[str, Any]) -> NodeAnchor:
        cls._expect_type(payload, "NodeAnchor")
        try:
            return NodeAnchor(
                node_id=str(payload["node_id"]),
                kind=IRNodeKind(str(payload["kind"])),
                start_token=int(payload["start_token"]),
                stop_token=int(payload["stop_token"]),
                source_sha256=str(payload["source_sha256"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise MutationIRCodecError(f"invalid NodeAnchor payload: {exc}") from exc

    @classmethod
    def _decode_precondition(cls, payload: Mapping[str, Any]) -> NodePrecondition:
        cls._expect_type(payload, "NodePrecondition")
        try:
            return NodePrecondition(
                node_id=str(payload["node_id"]),
                kind=IRNodeKind(str(payload["kind"])),
                start_token=int(payload["start_token"]),
                stop_token=int(payload["stop_token"]),
                source_sha256=str(payload["source_sha256"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise MutationIRCodecError(f"invalid NodePrecondition payload: {exc}") from exc

    @classmethod
    def _decode_expression(cls, payload: Mapping[str, Any]) -> ExpressionIR:
        ir_type = cls._type_name(payload)
        if ir_type == "ExistingExpressionIR":
            return ExistingExpressionIR(cls._decode_anchor(cls._mapping(payload, "anchor")))
        if ir_type == "VariableExpressionIR":
            return VariableExpressionIR(str(payload["name"]))
        if ir_type == "PropertyExpressionIR":
            return PropertyExpressionIR(str(payload["variable"]), str(payload["property_name"]))
        if ir_type == "LiteralExpressionIR":
            return LiteralExpressionIR(
                payload.get("value"),
                ValueType(str(payload["value_type"])),
                str(payload.get("quote", "'")),
            )
        if ir_type == "ComparisonExpressionIR":
            return ComparisonExpressionIR(
                cls._decode_expression(cls._mapping(payload, "left")),
                str(payload["operator"]),
                cls._decode_expression(cls._mapping(payload, "right")),
            )
        if ir_type == "NullCheckExpressionIR":
            return NullCheckExpressionIR(
                cls._decode_expression(cls._mapping(payload, "operand")),
                bool(payload.get("negated", True)),
            )
        if ir_type == "ConjunctionExpressionIR":
            return ConjunctionExpressionIR(
                tuple(cls._decode_expression(item) for item in cls._sequence(payload, "terms"))
            )
        if ir_type == "FunctionExpressionIR":
            return FunctionExpressionIR(
                str(payload["name"]),
                tuple(cls._decode_expression(item) for item in cls._sequence(payload, "arguments")),
            )
        if ir_type == "CountAllExpressionIR":
            return CountAllExpressionIR()
        if ir_type == "ListExpressionIR":
            return ListExpressionIR(
                tuple(cls._decode_expression(item) for item in cls._sequence(payload, "items"))
            )
        raise MutationIRCodecError(f"unknown expression IR type {ir_type!r}")

    @classmethod
    def _decode_projection(cls, payload: Mapping[str, Any]) -> ProjectionItemIR:
        cls._expect_type(payload, "ProjectionItemIR")
        alias = payload.get("alias")
        return ProjectionItemIR(
            cls._decode_expression(cls._mapping(payload, "expression")),
            str(alias) if alias is not None else None,
        )

    @classmethod
    def _decode_clause(cls, payload: Mapping[str, Any]) -> ClauseIR:
        ir_type = cls._type_name(payload)
        if ir_type == "OptionalMatchClauseIR":
            return OptionalMatchClauseIR(
                str(payload["source_variable"]),
                str(payload["relationship_type"]),
                str(payload["target_variable"]),
                str(payload["target_label"]),
            )
        if ir_type == "WithClauseIR":
            return WithClauseIR(
                tuple(cls._decode_projection(item) for item in cls._sequence(payload, "projections"))
            )
        if ir_type == "UnwindClauseIR":
            return UnwindClauseIR(
                cls._decode_expression(cls._mapping(payload, "expression")),
                str(payload["alias"]),
            )
        raise MutationIRCodecError(f"unknown clause IR type {ir_type!r}")

    @classmethod
    def _decode_operation(cls, payload: Mapping[str, Any]) -> MutationOperation:
        ir_type = cls._type_name(payload)
        if ir_type == "InsertClausesAfterOp":
            return InsertClausesAfterOp(
                cls._decode_anchor(cls._mapping(payload, "anchor")),
                tuple(cls._decode_clause(item) for item in cls._sequence(payload, "clauses")),
            )
        if ir_type == "InsertClausesBeforeOp":
            return InsertClausesBeforeOp(
                cls._decode_anchor(cls._mapping(payload, "anchor")),
                tuple(cls._decode_clause(item) for item in cls._sequence(payload, "clauses")),
            )
        if ir_type == "ReplaceRelationshipTypeOp":
            return ReplaceRelationshipTypeOp(
                cls._decode_anchor(cls._mapping(payload, "target")),
                str(payload["expected"]),
                str(payload["replacement"]),
            )
        if ir_type == "RemovePatternPartOp":
            return RemovePatternPartOp(
                cls._decode_anchor(cls._mapping(payload, "pattern")),
                cls._decode_anchor(cls._mapping(payload, "removed_part")),
                tuple(cls._decode_anchor(item) for item in cls._sequence(payload, "retained_parts")),
            )
        if ir_type == "ReplacePathRangeOp":
            lower = payload.get("lower")
            upper = payload.get("upper")
            return ReplacePathRangeOp(
                cls._decode_anchor(cls._mapping(payload, "target")),
                int(lower) if lower is not None else None,
                int(upper) if upper is not None else None,
                bool(payload["explicit_range"]),
            )
        if ir_type == "ReplaceLimitOp":
            return ReplaceLimitOp(
                cls._decode_anchor(cls._mapping(payload, "target")),
                int(payload["value"]),
            )
        if ir_type == "InsertLimitOp":
            return InsertLimitOp(
                cls._decode_anchor(cls._mapping(payload, "return_clause")),
                int(payload["value"]),
            )
        if ir_type == "ReplaceFunctionArgumentOp":
            return ReplaceFunctionArgumentOp(
                cls._decode_anchor(cls._mapping(payload, "function")),
                cls._decode_anchor(cls._mapping(payload, "target")),
                int(payload["argument_index"]),
                int(payload["value"]),
            )
        if ir_type == "ReplaceWherePredicateOp":
            return ReplaceWherePredicateOp(
                cls._decode_anchor(cls._mapping(payload, "target")),
                cls._decode_expression(cls._mapping(payload, "predicate")),
            )
        if ir_type == "RemoveWhereOp":
            return RemoveWhereOp(cls._decode_anchor(cls._mapping(payload, "target")))
        if ir_type == "InsertWhereOp":
            return InsertWhereOp(
                cls._decode_anchor(cls._mapping(payload, "match_clause")),
                cls._decode_expression(cls._mapping(payload, "predicate")),
            )
        if ir_type == "ReplaceLiteralOp":
            literal = cls._decode_expression(cls._mapping(payload, "literal"))
            if not isinstance(literal, LiteralExpressionIR):
                raise MutationIRCodecError("ReplaceLiteralOp requires LiteralExpressionIR")
            return ReplaceLiteralOp(
                cls._decode_anchor(cls._mapping(payload, "target")),
                literal,
            )
        raise MutationIRCodecError(f"unknown mutation operation IR type {ir_type!r}")

    @staticmethod
    def _type_name(payload: Mapping[str, Any]) -> str:
        if not isinstance(payload, Mapping):
            raise MutationIRCodecError("IR node must be a mapping")
        ir_type = payload.get("ir_type")
        if not isinstance(ir_type, str) or not ir_type:
            raise MutationIRCodecError("IR node is missing its ir_type discriminator")
        return ir_type

    @classmethod
    def _expect_type(cls, payload: Mapping[str, Any], expected: str) -> None:
        actual = cls._type_name(payload)
        if actual != expected:
            raise MutationIRCodecError(f"expected {expected}, got {actual}")

    @staticmethod
    def _mapping(payload: Mapping[str, Any], key: str) -> Mapping[str, Any]:
        value = payload.get(key)
        if not isinstance(value, Mapping):
            raise MutationIRCodecError(f"{key} must be an IR mapping")
        return value

    @staticmethod
    def _sequence(payload: Mapping[str, Any], key: str) -> list[Mapping[str, Any]]:
        value = payload.get(key)
        if not isinstance(value, list) or any(not isinstance(item, Mapping) for item in value):
            raise MutationIRCodecError(f"{key} must be a list of IR mappings")
        return value


class MutationIRCompileError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class MutationIRCompilerConfig:
    max_output_bytes: int = 1_000_000
    max_growth_bytes: int = 65_536
    max_operations: int = 16
    require_round_trip_parse: bool = True


@dataclass(frozen=True)
class _Rewrite:
    start: int
    stop: int
    text: str
    mode: str


class MutationIRRenderer:
    ALLOWED_COMPARISON_OPERATORS = frozenset({"=", "<>", "<", ">", "<=", ">="})

    def __init__(self, query_ir: QueryIR) -> None:
        self.query_ir = query_ir

    def expression(self, value: ExpressionIR) -> str:
        if isinstance(value, ExistingExpressionIR):
            return self.query_ir.source(value.anchor)
        if isinstance(value, VariableExpressionIR):
            return self.query_ir.dialect.quote(value.name)
        if isinstance(value, PropertyExpressionIR):
            return f"{self.query_ir.dialect.quote(value.variable)}.{self.query_ir.dialect.quote(value.property_name)}"
        if isinstance(value, LiteralExpressionIR):
            return self.literal(value)
        if isinstance(value, ComparisonExpressionIR):
            if value.operator not in self.ALLOWED_COMPARISON_OPERATORS:
                raise MutationIRCompileError("INVALID_OPERATOR", f"unsupported comparison operator {value.operator!r}")
            return f"{self.expression(value.left)} {value.operator} {self.expression(value.right)}"
        if isinstance(value, NullCheckExpressionIR):
            return f"{self.expression(value.operand)} IS {'NOT ' if value.negated else ''}NULL"
        if isinstance(value, ConjunctionExpressionIR):
            if len(value.terms) < 2:
                raise MutationIRCompileError("INVALID_EXPRESSION", "conjunction requires at least two terms")
            return " AND ".join(f"({self.expression(term)})" for term in value.terms)
        if isinstance(value, FunctionExpressionIR):
            if not value.name or not all(part.replace("_", "a").isalnum() for part in value.name.split(".")):
                raise MutationIRCompileError("INVALID_FUNCTION", f"invalid function name {value.name!r}")
            return f"{value.name}({', '.join(self.expression(arg) for arg in value.arguments)})"
        if isinstance(value, CountAllExpressionIR):
            return "count(*)"
        if isinstance(value, ListExpressionIR):
            return f"[{', '.join(self.expression(item) for item in value.items)}]"
        raise MutationIRCompileError("UNKNOWN_EXPRESSION", f"unsupported expression IR {type(value).__name__}")

    def literal(self, value: LiteralExpressionIR) -> str:
        if value.value_type == ValueType.STRING:
            quote = value.quote if value.quote in {"'", '"'} else "'"
            escaped = str(value.value).replace("\\", "\\\\").replace(quote, "\\" + quote)
            escaped = escaped.replace("\x00", "\\u0000")
            return f"{quote}{escaped}{quote}"
        if value.value_type == ValueType.BOOLEAN:
            return "true" if bool(value.value) else "false"
        if value.value_type == ValueType.INTEGER:
            if isinstance(value.value, bool):
                raise MutationIRCompileError("INVALID_LITERAL", "boolean is not an integer mutation literal")
            return str(int(value.value))
        if value.value_type == ValueType.FLOAT:
            number = float(value.value)
            if number != number or number in {float("inf"), float("-inf")}:
                raise MutationIRCompileError("INVALID_LITERAL", "non-finite floating point literal")
            return repr(number)
        raise MutationIRCompileError("INVALID_LITERAL", f"unsupported literal type {value.value_type.value}")

    def clause(self, value: ClauseIR) -> str:
        quote = self.query_ir.dialect.quote
        if isinstance(value, OptionalMatchClauseIR):
            return (
                f"OPTIONAL MATCH ({quote(value.source_variable)})"
                f"-[:{quote(value.relationship_type)}]->"
                f"({quote(value.target_variable)}:{quote(value.target_label)})"
            )
        if isinstance(value, WithClauseIR):
            if not value.projections:
                raise MutationIRCompileError("INVALID_CLAUSE", "WITH requires a projection")
            rendered = []
            for item in value.projections:
                text = self.expression(item.expression)
                if item.alias:
                    text += f" AS {quote(item.alias)}"
                rendered.append(text)
            return f"WITH {', '.join(rendered)}"
        if isinstance(value, UnwindClauseIR):
            return f"UNWIND {self.expression(value.expression)} AS {quote(value.alias)}"
        raise MutationIRCompileError("UNKNOWN_CLAUSE", f"unsupported clause IR {type(value).__name__}")


class MutationIRCompiler:
    """Validate and atomically compile a typed mutation program."""

    def __init__(self, config: Optional[MutationIRCompilerConfig] = None) -> None:
        self.config = config or MutationIRCompilerConfig()

    def apply(self, query_ir: QueryIR, program: MutationProgram) -> str:
        self._validate_program(query_ir, program)
        renderer = MutationIRRenderer(query_ir)
        rewrites = [self._compile_operation(query_ir, renderer, operation) for operation in program.operations]
        self._validate_rewrites(rewrites)

        rewriter = TokenStreamRewriter(query_ir.document.parse.token_stream)
        for rewrite in rewrites:
            if rewrite.mode == "replace":
                rewriter.replaceRange(rewrite.start, rewrite.stop, rewrite.text)
            elif rewrite.mode == "before":
                rewriter.insertBeforeIndex(rewrite.start, rewrite.text)
            elif rewrite.mode == "after":
                rewriter.insertAfter(rewrite.stop, rewrite.text)
            else:  # defensive: all modes originate in this module
                raise MutationIRCompileError("UNKNOWN_REWRITE", rewrite.mode)
        child = rewriter.getDefaultText()
        if child == query_ir.query:
            raise MutationIRCompileError("NO_CHANGE", "mutation program produced no source change")
        child_size = len(child.encode("utf-8"))
        parent_size = len(query_ir.query.encode("utf-8"))
        if child_size > self.config.max_output_bytes or child_size - parent_size > self.config.max_growth_bytes:
            raise MutationIRCompileError("OUTPUT_LIMIT", f"compiled query is too large ({child_size} bytes)")
        if self.config.require_round_trip_parse:
            parsed = parse_query(child)
            if parsed.tree is None or parsed.errors:
                detail = "; ".join(f"{line}:{column} {message}" for line, column, message in parsed.errors[:3])
                raise MutationIRCompileError("ROUND_TRIP_PARSE", detail or "compiled query did not parse")
        return child

    def _validate_program(self, query_ir: QueryIR, program: MutationProgram) -> None:
        if program.ir_version != IR_VERSION:
            raise MutationIRCompileError("IR_VERSION", f"unsupported mutation IR version {program.ir_version!r}")
        if program.parent_sha256 != query_ir.parent_sha256 or source_digest(query_ir.query) != query_ir.parent_sha256:
            raise MutationIRCompileError("PARENT_CHANGED", "mutation parent does not match the planned query")
        if not program.operations:
            raise MutationIRCompileError("EMPTY_PROGRAM", "mutation program contains no operations")
        if len(program.operations) > self.config.max_operations:
            raise MutationIRCompileError(
                "OPERATION_LIMIT",
                f"mutation program has {len(program.operations)} operations; limit is {self.config.max_operations}",
            )
        if not program.action or len(program.action) > 128:
            raise MutationIRCompileError("INVALID_ACTION", "mutation action must contain 1-128 characters")
        if not isinstance(program.operator, OperatorKind):
            raise MutationIRCompileError("INVALID_OPERATOR_KIND", "mutation program has an invalid operator kind")
        allowed_operations: dict[OperatorKind, tuple[type, ...]] = {
            OperatorKind.TOPOLOGY: (
                InsertClausesAfterOp,
                ReplaceRelationshipTypeOp,
                RemovePatternPartOp,
            ),
            OperatorKind.DEPTH_VOLUME: (
                ReplacePathRangeOp,
                ReplaceLimitOp,
                InsertLimitOp,
                ReplaceFunctionArgumentOp,
            ),
            OperatorKind.PREDICATE: (
                ReplaceWherePredicateOp,
                RemoveWhereOp,
                InsertWhereOp,
            ),
            OperatorKind.CLAUSE: (InsertClausesBeforeOp,),
            OperatorKind.VALUE: (ReplaceLiteralOp,),
        }
        if any(not isinstance(operation, allowed_operations[program.operator]) for operation in program.operations):
            raise MutationIRCompileError(
                "OPERATOR_OPERATION_MISMATCH",
                f"{program.operator.value} program contains an incompatible operation",
            )
        declared = {item.node_id: item for item in program.preconditions}
        referenced = {anchor.node_id: anchor for operation in program.operations for anchor in iter_anchors(operation)}
        if set(declared) != set(referenced):
            raise MutationIRCompileError("PRECONDITION_SET", "operation anchors and preconditions differ")
        for node_id, anchor in referenced.items():
            expected = NodePrecondition.from_anchor(anchor)
            if declared[node_id] != expected:
                raise MutationIRCompileError("PRECONDITION_MISMATCH", f"invalid precondition for {node_id}")
            query_ir.assert_anchor(anchor)
        expected_program_id = mutation_program_id(
            program.ir_version,
            program.parent_sha256,
            program.operator,
            program.action,
            program.operations,
            program.preconditions,
        )
        if program.program_id != expected_program_id:
            raise MutationIRCompileError("PROGRAM_ID", "mutation program integrity check failed")

    def _compile_operation(
        self,
        query_ir: QueryIR,
        renderer: MutationIRRenderer,
        operation: MutationOperation,
    ) -> _Rewrite:
        if isinstance(operation, InsertClausesAfterOp):
            self._require_kind(operation.anchor, IRNodeKind.MATCH_CLAUSE)
            if not operation.clauses or any(not isinstance(clause, OptionalMatchClauseIR) for clause in operation.clauses):
                raise MutationIRCompileError(
                    "INVALID_CLAUSE_SEQUENCE",
                    "topology insertion requires one or more OPTIONAL MATCH clauses",
                )
            text = " " + " ".join(renderer.clause(clause) for clause in operation.clauses)
            return _Rewrite(operation.anchor.stop_token, operation.anchor.stop_token, text, "after")
        if isinstance(operation, InsertClausesBeforeOp):
            self._require_kind(operation.anchor, IRNodeKind.RETURN_CLAUSE)
            if not operation.clauses or any(
                not isinstance(clause, (WithClauseIR, UnwindClauseIR))
                for clause in operation.clauses
            ):
                raise MutationIRCompileError(
                    "INVALID_CLAUSE_SEQUENCE",
                    "pipeline insertion requires typed WITH/UNWIND clauses",
                )
            text = " ".join(renderer.clause(clause) for clause in operation.clauses) + " "
            return _Rewrite(operation.anchor.start_token, operation.anchor.start_token, text, "before")
        if isinstance(operation, ReplaceRelationshipTypeOp):
            self._require_kind(operation.target, IRNodeKind.RELATIONSHIP_TYPE)
            current = identifier_text(query_ir.source(operation.target))
            if current != operation.expected:
                raise MutationIRCompileError("EXPECTED_VALUE", f"relationship type is {current!r}, expected {operation.expected!r}")
            return _Rewrite(
                operation.target.start_token,
                operation.target.stop_token,
                query_ir.dialect.quote(operation.replacement),
                "replace",
            )
        if isinstance(operation, RemovePatternPartOp):
            self._require_kind(operation.pattern, IRNodeKind.PATTERN)
            self._require_kind(operation.removed_part, IRNodeKind.PATTERN_PART)
            for retained in operation.retained_parts:
                self._require_kind(retained, IRNodeKind.PATTERN_PART)
            if operation.removed_part in operation.retained_parts:
                raise MutationIRCompileError("INVALID_PATTERN_EDIT", "removed pattern part is also retained")
            if not operation.retained_parts:
                raise MutationIRCompileError("INVALID_PATTERN_EDIT", "MATCH pattern cannot become empty")
            text = ", ".join(query_ir.source(anchor) for anchor in operation.retained_parts)
            return _Rewrite(operation.pattern.start_token, operation.pattern.stop_token, text, "replace")
        if isinstance(operation, ReplacePathRangeOp):
            self._require_kind(operation.target, IRNodeKind.PATH_RANGE)
            if operation.lower is not None and operation.lower < 0:
                raise MutationIRCompileError("INVALID_RANGE", "path lower bound must be non-negative")
            if operation.upper is not None and operation.upper < 0:
                raise MutationIRCompileError("INVALID_RANGE", "path upper bound must be non-negative")
            if operation.lower is not None and operation.upper is not None and operation.lower > operation.upper:
                raise MutationIRCompileError("INVALID_RANGE", "path lower bound exceeds upper bound")
            if any(
                value is not None and value > 2**63 - 1
                for value in (operation.lower, operation.upper)
            ):
                raise MutationIRCompileError("INVALID_RANGE", "path bound exceeds signed 64-bit range")
            if operation.explicit_range:
                text = f"*{'' if operation.lower is None else operation.lower}..{'' if operation.upper is None else operation.upper}"
            elif operation.lower is None:
                text = "*"
            else:
                text = f"*{operation.lower}"
            return _Rewrite(operation.target.start_token, operation.target.stop_token, text, "replace")
        if isinstance(operation, ReplaceLimitOp):
            self._require_kind(operation.target, IRNodeKind.LIMIT_CLAUSE)
            if operation.value < 1 or operation.value > 2**63 - 1:
                raise MutationIRCompileError("INVALID_LIMIT", "LIMIT must be positive")
            return _Rewrite(operation.target.start_token, operation.target.stop_token, f"LIMIT {operation.value}", "replace")
        if isinstance(operation, InsertLimitOp):
            self._require_kind(operation.return_clause, IRNodeKind.RETURN_CLAUSE)
            if operation.value < 1 or operation.value > 2**63 - 1:
                raise MutationIRCompileError("INVALID_LIMIT", "LIMIT must be positive")
            return _Rewrite(operation.return_clause.stop_token, operation.return_clause.stop_token, f" LIMIT {operation.value}", "after")
        if isinstance(operation, ReplaceFunctionArgumentOp):
            self._require_kind(operation.function, IRNodeKind.FUNCTION_CALL)
            self._require_kind(operation.target, IRNodeKind.FUNCTION_ARGUMENT)
            function = query_ir.context(operation.function)
            chain = function.expressionChain() if hasattr(function, "expressionChain") else None
            arguments = QueryIRBuilder._as_list(chain.expression()) if chain else []
            if operation.argument_index < 0 or operation.argument_index >= len(arguments):
                raise MutationIRCompileError("ARGUMENT_INDEX", "function argument index is out of range")
            if operation.value < -(2**63) or operation.value > 2**63 - 1:
                raise MutationIRCompileError("INVALID_ARGUMENT", "integer argument exceeds signed 64-bit range")
            expected = arguments[operation.argument_index]
            if expected.start.tokenIndex != operation.target.start_token or expected.stop.tokenIndex != operation.target.stop_token:
                raise MutationIRCompileError("ARGUMENT_ANCHOR", "function argument anchor does not match its index")
            return _Rewrite(operation.target.start_token, operation.target.stop_token, str(int(operation.value)), "replace")
        if isinstance(operation, ReplaceWherePredicateOp):
            self._require_kind(operation.target, IRNodeKind.WHERE_CLAUSE)
            return _Rewrite(
                operation.target.start_token,
                operation.target.stop_token,
                f"WHERE {renderer.expression(operation.predicate)}",
                "replace",
            )
        if isinstance(operation, RemoveWhereOp):
            self._require_kind(operation.target, IRNodeKind.WHERE_CLAUSE)
            return _Rewrite(operation.target.start_token, operation.target.stop_token, "", "replace")
        if isinstance(operation, InsertWhereOp):
            self._require_kind(operation.match_clause, IRNodeKind.MATCH_CLAUSE)
            return _Rewrite(
                operation.match_clause.stop_token,
                operation.match_clause.stop_token,
                f" WHERE {renderer.expression(operation.predicate)}",
                "after",
            )
        if isinstance(operation, ReplaceLiteralOp):
            self._require_kind(operation.target, IRNodeKind.LITERAL)
            return _Rewrite(
                operation.target.start_token,
                operation.target.stop_token,
                renderer.literal(operation.literal),
                "replace",
            )
        raise MutationIRCompileError("UNKNOWN_OPERATION", f"unsupported mutation operation {type(operation).__name__}")

    @staticmethod
    def _require_kind(anchor: NodeAnchor, expected: IRNodeKind) -> None:
        if anchor.kind != expected:
            raise MutationIRCompileError(
                "ANCHOR_KIND",
                f"operation requires {expected.value}, got {anchor.kind.value}",
            )

    @staticmethod
    def _validate_rewrites(rewrites: Sequence[_Rewrite]) -> None:
        for index, left in enumerate(rewrites):
            for right in rewrites[index + 1 :]:
                if left.mode == "replace" and right.mode == "replace":
                    overlap = left.start <= right.stop and right.start <= left.stop
                elif left.mode == "replace":
                    point = right.start if right.mode == "before" else right.stop
                    overlap = left.start <= point <= left.stop
                elif right.mode == "replace":
                    point = left.start if left.mode == "before" else left.stop
                    overlap = right.start <= point <= right.stop
                else:
                    overlap = (left.mode, left.start, left.stop) == (right.mode, right.start, right.stop)
                if overlap:
                    raise MutationIRCompileError("REWRITE_CONFLICT", "mutation operations overlap")
