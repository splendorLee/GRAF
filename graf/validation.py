from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional, Protocol

from .cypher import QueryDocument, identifier_text, inside_context, walk_contexts
from .dialects import DialectCapabilities, get_dialect
from .ir import QueryIR, QueryIRBuilder
from .model import SchemaView, ValidationIssue, ValidationResult, ValueType
from .skeleton_lexical import split_statements
from .target_validation import TargetCheckStatus
from CypherParser import CypherParser


class TargetCompileCheck(Protocol):
    def __call__(self, query: str) -> tuple[bool, str]: ...


PLACEHOLDER_PATTERN = re.compile(r"\$[A-Z][A-Z0-9_]*")
@dataclass(frozen=True)
class ValidationPolicy:
    require_no_placeholders: bool = True
    enforce_scope: bool = True
    enforce_static_types: bool = True
    target_compile_required: bool = False
    max_query_bytes: int = 1_000_000


class ValidationPipeline:
    """Fail-closed validation for parent and mutated Cypher queries.

    Local validation is deterministic and side-effect free.  An optional target
    checker performs EXPLAIN/compile validation through the selected engine
    adapter; the checker must never execute the query.
    """

    def __init__(
        self,
        target: str,
        schema: SchemaView,
        *,
        policy: Optional[ValidationPolicy] = None,
        target_check: Optional[TargetCompileCheck] = None,
    ) -> None:
        self.dialect: DialectCapabilities = get_dialect(target)
        self.schema = schema
        self.policy = policy or ValidationPolicy()
        self.target_check = target_check

    def validate(self, query: str) -> ValidationResult:
        issues: list[ValidationIssue] = []
        encoded_size = len((query or "").encode("utf-8", errors="replace"))
        if encoded_size > self.policy.max_query_bytes:
            issues.append(
                ValidationIssue(
                    "local",
                    "QUERY_TOO_LARGE",
                    f"query has {encoded_size} bytes; limit is {self.policy.max_query_bytes}",
                )
            )
            return ValidationResult(False, issues, normalized_query=query)

        if self.policy.require_no_placeholders:
            unresolved = sorted(set(PLACEHOLDER_PATTERN.findall(query or "")))
            if unresolved:
                issues.append(
                    ValidationIssue(
                        "local",
                        "UNRESOLVED_PLACEHOLDER",
                        f"unresolved placeholders: {', '.join(unresolved[:20])}",
                    )
                )

        for pattern, message in self.dialect.unsupported_patterns:
            if pattern.search(query or ""):
                issues.append(ValidationIssue("dialect", "UNSUPPORTED_FEATURE", message))

        document = QueryDocument.build(query, self.schema, self.dialect)
        if document.parse.errors and self.dialect.name == "nebula" and not issues:
            # nGQL is only partly covered by the bundled Cypher grammar. A
            # typed, positive target compile result may admit the concrete
            # query as an unmutated parent. Never use a best-effort boolean
            # check here: timeouts and infrastructure faults must fail closed.
            checker = getattr(self.target_check, "check", None)
            if callable(checker):
                try:
                    single_statement = len(split_statements(query)) == 1
                except ValueError:
                    single_statement = False
                if single_statement:
                    try:
                        native_result = checker(query)
                    except Exception as exc:
                        native_result = None
                        issues.append(ValidationIssue(
                            "target", "TARGET_CHECK_EXCEPTION",
                            f"{type(exc).__name__}: {exc}",
                        ))
                    if native_result is not None and native_result.status is TargetCheckStatus.ACCEPTED:
                        return ValidationResult(
                            True, normalized_query=query, target_checked=True,
                            target_message=native_result.message, native_only=True,
                        )
        for line, column, message in document.parse.errors:
            issues.append(ValidationIssue("parse", "SYNTAX_ERROR", message, line=line, column=column))

        query_ir: Optional[QueryIR] = None
        if not document.parse.errors:
            try:
                query_ir = QueryIRBuilder().build(document)
            except Exception as exc:
                issues.append(
                    ValidationIssue(
                        "local",
                        "IR_ANALYSIS_ERROR",
                        f"typed query analysis failed: {type(exc).__name__}: {exc}",
                    )
                )
            if self.policy.enforce_scope:
                issues.extend(self._scope_issues(document))
            if self.policy.enforce_static_types and query_ir is not None:
                issues.extend(self._type_issues(document, query_ir))

        if issues:
            return ValidationResult(False, self._dedupe(issues), normalized_query=query)

        target_checked = False
        target_message = ""
        if self.target_check is not None:
            target_checked = True
            try:
                accepted, target_message = self.target_check(query)
            except Exception as exc:
                accepted = False
                target_message = f"compile checker exception: {type(exc).__name__}: {exc}"
            if not accepted:
                issues.append(ValidationIssue("target", "TARGET_COMPILE_REJECTED", target_message))
        elif self.policy.target_compile_required:
            issues.append(
                ValidationIssue(
                    "target",
                    "TARGET_CHECK_UNAVAILABLE",
                    "target compile validation is required but no checker is configured",
                )
            )

        return ValidationResult(
            valid=not issues,
            issues=self._dedupe(issues),
            normalized_query=query,
            target_checked=target_checked,
            target_message=target_message,
        )

    def _scope_issues(self, document: QueryDocument) -> list[ValidationIssue]:
        issues: list[ValidationIssue] = []
        for frame in document.scopes:
            ctx = frame.context
            if isinstance(ctx, CypherParser.MatchStContext):
                visible = frame.after
            elif isinstance(ctx, CypherParser.WithStContext):
                # WITH projection expressions see the incoming scope.  Its
                # attached WHERE sees the outgoing projection; validate both.
                visible = frame.before
            elif isinstance(ctx, CypherParser.ReturnStContext):
                visible = frame.before
            else:
                visible = frame.after

            for property_ctx in self._property_expressions(ctx):
                access = self._property_access(property_ctx)
                if access is None:
                    continue
                variable, _properties = access
                property_visible = visible
                if isinstance(ctx, CypherParser.WithStContext) and inside_context(
                    property_ctx, CypherParser.WhereContext
                ):
                    property_visible = frame.after
                if variable not in property_visible:
                    issues.append(
                        ValidationIssue(
                            "scope",
                            "UNBOUND_PROPERTY_OWNER",
                            f"variable `{variable}` is not visible in {frame.clause_kind}",
                        )
                    )

            if isinstance(ctx, CypherParser.ReturnStContext):
                projection_items = ctx.projectionBody().projectionItems().projectionItem()
                projection_items = projection_items if isinstance(projection_items, list) else [projection_items]
                for item in projection_items:
                    name = self._simple_symbol(item.expression())
                    if name is not None and name not in frame.before:
                        issues.append(
                            ValidationIssue(
                                "scope",
                                "RETURN_UNBOUND_VARIABLE",
                                f"RETURN references `{name}` outside the current scope",
                            )
                        )
        return issues

    def _type_issues(self, document: QueryDocument, query_ir: QueryIR) -> list[ValidationIssue]:
        issues: list[ValidationIssue] = []
        for frame in document.scopes:
            visible = frame.after if isinstance(frame.context, CypherParser.MatchStContext) else frame.before
            for invocation in walk_contexts(frame.context):
                if not isinstance(invocation, CypherParser.FunctionInvocationContext):
                    continue
                function = ".".join(
                    identifier_text(symbol.getText())
                    for symbol in self._as_list(invocation.invocationName().symbol())
                ).lower()
                if function not in {"max", "min", "sum", "avg"}:
                    continue
                chain = invocation.expressionChain()
                arguments = self._as_list(chain.expression()) if chain else []
                variable = self._simple_symbol(arguments[0]) if len(arguments) == 1 else None
                if variable is None:
                    continue
                binding = visible.get(variable)
                if binding and binding.value_type in {ValueType.NODE, ValueType.RELATIONSHIP, ValueType.PATH}:
                    issues.append(
                        ValidationIssue(
                            "type",
                            "INVALID_AGGREGATE_ARGUMENT",
                            f"{function}() cannot safely aggregate {binding.value_type.value.lower()} `{variable}`",
                        )
                    )

        for site in query_ir.literals:
            if not site.variable or not site.property_name or not site.comparison_operator:
                continue
            expected = site.expected_type
            actual = site.actual_type
            if expected not in {ValueType.ANY, actual} and not (
                expected in {ValueType.INTEGER, ValueType.FLOAT}
                and actual in {ValueType.INTEGER, ValueType.FLOAT}
            ):
                issues.append(
                    ValidationIssue(
                        "type",
                        "LITERAL_TYPE_MISMATCH",
                        f"`{site.variable}`.`{site.property_name}` is {expected.value}, but literal is {actual.value}",
                    )
                )
            if site.comparison_operator in {"<", ">", "<=", ">="} and expected in {
                ValueType.BOOLEAN,
                ValueType.LIST,
                ValueType.MAP,
            }:
                issues.append(
                    ValidationIssue(
                        "type",
                        "UNORDERED_COMPARISON",
                        f"operator {site.comparison_operator} is invalid for {expected.value} property `{site.property_name}`",
                    )
                )
        return issues

    @staticmethod
    def _property_expressions(root: object) -> list[object]:
        return [
            ctx
            for ctx in walk_contexts(root)
            if isinstance(ctx, CypherParser.PropertyExpressionContext)
            and not inside_context(ctx, CypherParser.SubqueryExistContext)
        ]

    @classmethod
    def _property_access(cls, ctx: object) -> Optional[tuple[str, tuple[str, ...]]]:
        atom = ctx.atom() if hasattr(ctx, "atom") else None
        symbol = atom.symbol() if atom and hasattr(atom, "symbol") else None
        if symbol is None or cls._numeric_symbol(symbol):
            return None
        names = ctx.name() if hasattr(ctx, "name") else []
        names = names if isinstance(names, list) else ([names] if names else [])
        if not names:
            return None
        return identifier_text(symbol.getText()), tuple(identifier_text(name.getText()) for name in names)

    @classmethod
    def _simple_symbol(cls, expression: object) -> Optional[str]:
        for property_ctx in walk_contexts(expression):
            if not isinstance(property_ctx, CypherParser.PropertyExpressionContext):
                continue
            if (
                property_ctx.start.tokenIndex != expression.start.tokenIndex
                or property_ctx.stop.tokenIndex != expression.stop.tokenIndex
            ):
                continue
            atom = property_ctx.atom()
            symbol = atom.symbol() if atom and hasattr(atom, "symbol") else None
            names = cls._as_list(property_ctx.name())
            if symbol is not None and not cls._numeric_symbol(symbol) and not names:
                return identifier_text(symbol.getText())
        return None

    @staticmethod
    def _numeric_symbol(symbol: object) -> bool:
        raw = symbol.getText()
        return bool(raw) and not raw.startswith("`") and (raw[0].isdigit() or raw[0] in {"+", "-"})

    @staticmethod
    def _as_list(value: object) -> list:
        if value is None:
            return []
        return value if isinstance(value, list) else [value]

    @staticmethod
    def _dedupe(issues: list[ValidationIssue]) -> list[ValidationIssue]:
        seen: set[tuple] = set()
        result: list[ValidationIssue] = []
        for issue in issues:
            key = (issue.stage, issue.code, issue.message, issue.line, issue.column)
            if key not in seen:
                seen.add(key)
                result.append(issue)
        return result
