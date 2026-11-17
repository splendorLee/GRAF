"""Schema-aware mutation planners that emit typed Mutation IR programs.

No operator in this module performs source offsets, regular-expression
matching, or free-form query editing. Parser-derived sites come from
``QueryIR`` and source generation is delegated to ``MutationIRCompiler``.
"""

from __future__ import annotations

import math
import random
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Optional

from CypherParser import CypherParser

from .cypher import fresh_identifier
from .ir import (
    ComparisonExpressionIR,
    ConjunctionExpressionIR,
    CountAllExpressionIR,
    ExistingExpressionIR,
    FunctionExpressionIR,
    InsertClausesAfterOp,
    InsertClausesBeforeOp,
    InsertLimitOp,
    InsertWhereOp,
    ListExpressionIR,
    LiteralExpressionIR,
    LiteralRole,
    MutationCandidate,
    MutationIRRenderer,
    NullCheckExpressionIR,
    OptionalMatchClauseIR,
    ProjectionItemIR,
    PropertyExpressionIR,
    QueryIR,
    RelationshipDirection,
    RemovePatternPartOp,
    RemoveWhereOp,
    ReplaceFunctionArgumentOp,
    ReplaceLimitOp,
    ReplaceLiteralOp,
    ReplacePathRangeOp,
    ReplaceRelationshipTypeOp,
    ReplaceWherePredicateOp,
    UnwindClauseIR,
    VariableExpressionIR,
    WithClauseIR,
)
from .model import (
    GraphStats,
    MutationDirective,
    OperatorKind,
    SchemaView,
    ValueType,
    VariableBinding,
)


@dataclass(frozen=True)
class OperatorContext:
    schema: SchemaView
    graph: GraphStats
    directive: MutationDirective
    rng: random.Random
    max_path_bound: int = 12
    max_limit: int = 10_000
    anomalous_string_length: int = 1_024


class MutationOperator(ABC):
    kind: OperatorKind

    @abstractmethod
    def candidates(self, query_ir: QueryIR, context: OperatorContext) -> list[MutationCandidate]:
        raise NotImplementedError

    def candidate(
        self,
        query_ir: QueryIR,
        action: str,
        operation: Any,
        site_token: int,
        metadata: Optional[dict[str, Any]] = None,
        *,
        estimated_cost_delta: int = 0,
    ) -> MutationCandidate:
        return MutationCandidate.create(
            query_ir,
            self.kind,
            action,
            operation,
            site_token,
            metadata,
            estimated_cost_delta,
        )


class LiteralFactory:
    """Generate typed, portable values without rendering source text."""

    BOUNDARIES: dict[ValueType, tuple[Any, ...]] = {
        ValueType.INTEGER: (0, 1, -1, 2**31 - 1, -(2**31), 2**63 - 1, -(2**63) + 1),
        ValueType.FLOAT: (0.0, 1.0, -1.0, 1e-308, -1e-308, 1e308, -1e308),
        ValueType.STRING: ("", " ", "A", "' OR 1=1", "𝄞", "\n\t"),
        ValueType.BOOLEAN: (True, False),
    }

    def values(
        self,
        owner: Optional[str],
        prop: Optional[str],
        value_type: ValueType,
        context: OperatorContext,
        *,
        quote: str = "'",
    ) -> list[tuple[LiteralExpressionIR, str]]:
        values: list[tuple[Any, str]] = []
        if owner and prop:
            values.extend((value, "observed") for value in context.schema.observed_for(owner, prop))
        values.extend((value, "boundary") for value in self.BOUNDARIES.get(value_type, ()))
        if value_type == ValueType.STRING:
            values.append(("A" * context.anomalous_string_length, "anomalous"))
        elif value_type == ValueType.INTEGER:
            values.extend(((2**63 - 2, "anomalous"), (-(2**63) + 2, "anomalous")))
        elif value_type == ValueType.FLOAT:
            values.extend(((1.7976931348623157e308, "anomalous"), (-1.7976931348623157e308, "anomalous")))

        result: list[tuple[LiteralExpressionIR, str]] = []
        seen: set[tuple[str, str]] = set()
        for raw, source in values:
            normalized = self._normalize(raw, value_type)
            if normalized is None:
                continue
            literal = LiteralExpressionIR(normalized, value_type, quote)
            key = (value_type.value, repr(normalized))
            if key not in seen:
                seen.add(key)
                result.append((literal, source))
        return result

    @staticmethod
    def _normalize(value: Any, value_type: ValueType) -> Optional[Any]:
        if value_type == ValueType.BOOLEAN:
            if isinstance(value, str):
                if value.lower() == "true":
                    return True
                if value.lower() == "false":
                    return False
                return None
            return bool(value)
        if value_type == ValueType.INTEGER:
            if isinstance(value, bool):
                return None
            try:
                return int(value)
            except (TypeError, ValueError, OverflowError):
                return None
        if value_type == ValueType.FLOAT:
            try:
                number = float(value)
            except (TypeError, ValueError, OverflowError):
                return None
            if math.isnan(number):
                return None
            if math.isinf(number):
                return math.copysign(1.7976931348623157e308, number)
            return number
        if value_type == ValueType.STRING:
            return str(value)
        return None


def _property_predicates(
    scope: dict[str, VariableBinding],
    context: OperatorContext,
    *,
    prefer_observed: bool,
) -> list[tuple[Any, dict[str, Any]]]:
    factory = LiteralFactory()
    candidates: list[tuple[Any, dict[str, Any]]] = []
    for variable, binding in sorted(scope.items()):
        if binding.value_type not in {ValueType.NODE, ValueType.RELATIONSHIP} or not binding.entity_name:
            continue
        for prop in context.schema.properties_for(binding.entity_name):
            property_expression = PropertyExpressionIR(variable, prop.name)
            base_metadata = {
                "variable": variable,
                "owner": binding.entity_name,
                "property": prop.name,
                "value_type": prop.value_type.value,
            }
            if prop.value_type in {ValueType.LIST, ValueType.MAP, ValueType.ANY}:
                candidates.append(
                    (
                        NullCheckExpressionIR(property_expression, negated=True),
                        {**base_metadata, "source": "nullness"},
                    )
                )
                continue
            values = factory.values(binding.entity_name, prop.name, prop.value_type, context)
            if prefer_observed:
                values.sort(key=lambda item: 0 if item[1] == "observed" else 1)
            operators = ("=", "<>", "<", ">=") if prop.value_type in {ValueType.INTEGER, ValueType.FLOAT} else ("=", "<>")
            for literal, source in values[:4]:
                for operator in operators:
                    candidates.append(
                        (
                            ComparisonExpressionIR(property_expression, operator, literal),
                            {**base_metadata, "source": source, "operator": operator},
                        )
                    )
    return candidates


class TopologyMutationOperator(MutationOperator):
    kind = OperatorKind.TOPOLOGY

    def candidates(self, query_ir: QueryIR, context: OperatorContext) -> list[MutationCandidate]:
        result: list[MutationCandidate] = []
        for match in query_ir.matches:
            frame = query_ir.frame_for(match.anchor)
            if not frame:
                continue

            if query_ir.dialect.supports_optional_match:
                for variable, binding in sorted(frame.after.items()):
                    if binding.value_type != ValueType.NODE or not binding.entity_name:
                        continue
                    for edge in context.schema.topology_by_source.get(binding.entity_name, ()):
                        new_var = fresh_identifier(query_ir.all_variables, "__graf_n")
                        clause = OptionalMatchClauseIR(variable, edge.relationship_type, new_var, edge.target_label)
                        result.append(
                            self.candidate(
                                query_ir,
                                "extend",
                                InsertClausesAfterOp(match.anchor, (clause,)),
                                match.anchor.stop_token,
                                {
                                    "source_variable": variable,
                                    "source_label": binding.entity_name,
                                    "relationship_type": edge.relationship_type,
                                    "target_label": edge.target_label,
                                    "new_variable": new_var,
                                },
                                estimated_cost_delta=1,
                            )
                        )

            for part in match.pattern.parts:
                for relationship in part.relationships:
                    if (
                        relationship.direction == RelationshipDirection.UNDIRECTED
                        or relationship.type_anchor is None
                        or len(relationship.relationship_types) != 1
                        or not relationship.source.variable
                        or not relationship.target.variable
                    ):
                        continue
                    source_variable = relationship.source.variable
                    target_variable = relationship.target.variable
                    source_binding = frame.after.get(source_variable)
                    target_binding = frame.after.get(target_variable)
                    source_label = source_binding.entity_name if source_binding else None
                    target_label = target_binding.entity_name if target_binding else None
                    if not source_label or not target_label:
                        continue
                    old_type = relationship.relationship_types[0]
                    for edge in context.schema.topology_by_pair.get((source_label, target_label), ()):
                        if edge.relationship_type == old_type:
                            continue
                        result.append(
                            self.candidate(
                                query_ir,
                                "reconnect_type",
                                ReplaceRelationshipTypeOp(relationship.type_anchor, old_type, edge.relationship_type),
                                relationship.type_anchor.start_token,
                                {
                                    "source_variable": source_variable,
                                    "target_variable": target_variable,
                                    "source_label": source_label,
                                    "target_label": target_label,
                                    "old_relationship_type": old_type,
                                    "new_relationship_type": edge.relationship_type,
                                },
                            )
                        )

            if len(match.pattern.parts) > 1:
                for part_index, part in enumerate(match.pattern.parts):
                    newly_bound = set(part.bound_variables).difference(frame.before)
                    retained = tuple(item for index, item in enumerate(match.pattern.parts) if index != part_index)
                    surviving = set().union(*(set(item.bound_variables) for item in retained))
                    truly_removed = newly_bound.difference(surviving)
                    if any(query_ir.symbol_occurs_outside(variable, part.anchor) for variable in truly_removed):
                        continue
                    result.append(
                        self.candidate(
                            query_ir,
                            "remove_pattern_part",
                            RemovePatternPartOp(
                                match.pattern.anchor,
                                part.anchor,
                                tuple(item.anchor for item in retained),
                            ),
                            part.anchor.start_token,
                            {"removed_variables": sorted(truly_removed), "part_index": part_index},
                            estimated_cost_delta=-1,
                        )
                    )
        return self._filter_by_directive(result, context.directive)

    @staticmethod
    def _filter_by_directive(candidates: list[MutationCandidate], directive: MutationDirective) -> list[MutationCandidate]:
        if directive in {MutationDirective.DECREASE_COST, MutationDirective.LOCALIZE}:
            preferred = [candidate for candidate in candidates if candidate.estimated_cost_delta <= 0]
            return preferred or candidates
        if directive == MutationDirective.INCREASE_COST:
            preferred = [candidate for candidate in candidates if candidate.estimated_cost_delta > 0]
            return preferred or candidates
        return candidates


class DepthVolumeMutationOperator(MutationOperator):
    kind = OperatorKind.DEPTH_VOLUME

    def candidates(self, query_ir: QueryIR, context: OperatorContext) -> list[MutationCandidate]:
        candidates: list[MutationCandidate] = []
        cap = max(
            1,
            min(
                context.max_path_bound,
                query_ir.dialect.max_path_bound,
                max(2, context.graph.estimated_diameter * 2),
            ),
        )
        ranges = [
            relationship.path_range
            for match in query_ir.matches
            for part in match.pattern.parts
            for relationship in part.relationships
            if relationship.path_range is not None
        ]
        for path_range in ranges:
            for lower, upper, explicit, delta in self._range_replacements(path_range, cap, context.directive):
                operation = ReplacePathRangeOp(path_range.anchor, lower, upper, explicit)
                renderer_text = self._range_text(lower, upper, explicit)
                if renderer_text == query_ir.source(path_range.anchor).replace(" ", ""):
                    continue
                candidates.append(
                    self.candidate(
                        query_ir,
                        "path_bound",
                        operation,
                        path_range.anchor.start_token,
                        {"old": query_ir.source(path_range.anchor), "new": renderer_text, "cap": cap},
                        estimated_cost_delta=delta,
                    )
                )

        for limit in query_ir.limits:
            if limit.value is None:
                continue
            values: list[tuple[int, int]] = []
            if context.directive in {MutationDirective.DECREASE_COST, MutationDirective.LOCALIZE}:
                values.append((max(1, limit.value // 2), -1))
            elif context.directive == MutationDirective.INCREASE_COST:
                values.append((min(context.max_limit, max(limit.value + 1, limit.value * 2)), 1))
            else:
                values.extend(
                    (
                        (max(1, limit.value // 2), -1),
                        (min(context.max_limit, max(limit.value + 1, limit.value * 2)), 1),
                    )
                )
            for value, delta in values:
                if value == limit.value:
                    continue
                candidates.append(
                    self.candidate(
                        query_ir,
                        "limit",
                        ReplaceLimitOp(limit.anchor, value),
                        limit.anchor.start_token,
                        {"old": limit.value, "new": value},
                        estimated_cost_delta=delta,
                    )
                )

        if not query_ir.limits and context.directive in {
            MutationDirective.EXPLORE,
            MutationDirective.RELAX,
            MutationDirective.DECREASE_COST,
            MutationDirective.LOCALIZE,
        }:
            value = min(context.max_limit, context.graph.safe_limit)
            for return_clause in query_ir.returns:
                candidates.append(
                    self.candidate(
                        query_ir,
                        "insert_limit",
                        InsertLimitOp(return_clause.anchor, value),
                        return_clause.anchor.stop_token,
                        {"new": value},
                        estimated_cost_delta=-1,
                    )
                )

        for unwind in query_ir.unwind_ranges:
            width = max(0, unwind.end_value - unwind.start_value)
            if context.directive in {MutationDirective.DECREASE_COST, MutationDirective.LOCALIZE}:
                new_end, delta = unwind.start_value + max(1, width // 2), -1
            else:
                new_end = min(
                    unwind.start_value + max(2, width * 2),
                    unwind.start_value + context.max_limit,
                )
                delta = 1
            if new_end == unwind.end_value:
                continue
            candidates.append(
                self.candidate(
                    query_ir,
                    "unwind_range",
                    ReplaceFunctionArgumentOp(unwind.function_anchor, unwind.end_argument, 1, new_end),
                    unwind.end_argument.start_token,
                    {"old_end": unwind.end_value, "new_end": new_end},
                    estimated_cost_delta=delta,
                )
            )
        return candidates

    @staticmethod
    def _range_replacements(path_range, cap: int, directive: MutationDirective) -> list[tuple[Optional[int], Optional[int], bool, int]]:
        lower, upper = path_range.lower, path_range.upper
        if lower is None and upper is None and not path_range.explicit_range:
            upper_value = min(cap, 2 if directive == MutationDirective.DECREASE_COST else cap)
            return [(1, upper_value, True, 0)]
        if not path_range.explicit_range and lower is not None:
            current = max(1, lower)
            if directive in {MutationDirective.DECREASE_COST, MutationDirective.LOCALIZE}:
                return [(max(1, current - 1), None, False, -1)]
            if directive == MutationDirective.INCREASE_COST:
                return [(min(cap, current + 1), None, False, 1)]
            return [
                (max(1, current - 1), None, False, -1),
                (min(cap, current + 1), None, False, 1),
            ]
        normalized_lower = max(1, lower if lower is not None else 1)
        normalized_upper = max(normalized_lower, upper if upper is not None else cap)
        if directive in {MutationDirective.DECREASE_COST, MutationDirective.LOCALIZE}:
            return [(normalized_lower, max(normalized_lower, normalized_upper - 1), True, -1)]
        if directive == MutationDirective.INCREASE_COST:
            return [(normalized_lower, min(cap, normalized_upper + 1), True, 1)]
        return [
            (normalized_lower, max(normalized_lower, normalized_upper - 1), True, -1),
            (normalized_lower, min(cap, normalized_upper + 1), True, 1),
        ]

    @staticmethod
    def _range_text(lower: Optional[int], upper: Optional[int], explicit: bool) -> str:
        if explicit:
            return f"*{'' if lower is None else lower}..{'' if upper is None else upper}"
        return "*" if lower is None else f"*{lower}"


class PredicateMutationOperator(MutationOperator):
    kind = OperatorKind.PREDICATE

    def candidates(self, query_ir: QueryIR, context: OperatorContext) -> list[MutationCandidate]:
        candidates: list[MutationCandidate] = []
        for where in query_ir.wheres:
            frame = query_ir.frame_for(where.anchor)
            if not frame:
                continue
            scope = frame.after if frame.clause_kind in {"MatchSt", "WithSt"} else frame.before
            if context.directive in {
                MutationDirective.RELAX,
                MutationDirective.DECREASE_COST,
                MutationDirective.LOCALIZE,
            }:
                if len(where.conjunction_terms) > 1:
                    for index in range(len(where.conjunction_terms)):
                        retained = tuple(
                            ExistingExpressionIR(anchor)
                            for position, anchor in enumerate(where.conjunction_terms)
                            if position != index
                        )
                        predicate = retained[0] if len(retained) == 1 else ConjunctionExpressionIR(retained)
                        candidates.append(
                            self.candidate(
                                query_ir,
                                "relax_conjunct",
                                ReplaceWherePredicateOp(where.anchor, predicate),
                                where.anchor.start_token,
                                {"removed_index": index, "term_count": len(where.conjunction_terms)},
                                estimated_cost_delta=1,
                            )
                        )
                candidates.append(
                    self.candidate(
                        query_ir,
                        "remove_where",
                        RemoveWhereOp(where.anchor),
                        where.anchor.start_token,
                        {"old_expression": query_ir.source(where.expression)},
                        estimated_cost_delta=1,
                    )
                )

            generated = _property_predicates(
                scope,
                context,
                prefer_observed=context.directive == MutationDirective.RELAX,
            )
            for predicate, metadata in generated[:24]:
                if context.directive == MutationDirective.RELAX:
                    action = "replace_observed"
                    replacement = predicate
                    cost_delta = 0
                else:
                    action = "append_conjunct"
                    replacement = ConjunctionExpressionIR((ExistingExpressionIR(where.expression), predicate))
                    cost_delta = -1
                candidates.append(
                    self.candidate(
                        query_ir,
                        action,
                        ReplaceWherePredicateOp(where.anchor, replacement),
                        where.anchor.start_token,
                        metadata,
                        estimated_cost_delta=cost_delta,
                    )
                )

        if context.directive not in {MutationDirective.RELAX, MutationDirective.LOCALIZE}:
            for match in query_ir.matches:
                if match.where:
                    continue
                frame = query_ir.frame_for(match.anchor)
                if not frame:
                    continue
                generated = _property_predicates(frame.after, context, prefer_observed=False)
                for predicate, metadata in generated[:16]:
                    candidates.append(
                        self.candidate(
                            query_ir,
                            "insert_where",
                            InsertWhereOp(match.anchor, predicate),
                            match.anchor.stop_token,
                            metadata,
                            estimated_cost_delta=-1,
                        )
                    )
        return candidates


class ClauseInsertionMutationOperator(MutationOperator):
    kind = OperatorKind.CLAUSE

    def candidates(self, query_ir: QueryIR, context: OperatorContext) -> list[MutationCandidate]:
        candidates: list[MutationCandidate] = []
        if not query_ir.dialect.supports_with_aggregation:
            return candidates
        for return_clause in query_ir.returns:
            frame = query_ir.frame_for(return_clause.anchor)
            if not frame or not frame.before:
                continue
            variables = sorted(frame.before)
            prior_with_tokens = [
                scope.start_token
                for scope in query_ir.scopes
                if isinstance(scope.context, CypherParser.WithStContext)
                and scope.start_token < return_clause.anchor.start_token
            ]
            if prior_with_tokens:
                last_with_token = max(prior_with_tokens)
                has_post_with_update = any(
                    isinstance(
                        scope.context,
                        (
                            CypherParser.CreateStContext,
                            CypherParser.MergeStContext,
                            CypherParser.DeleteStContext,
                            CypherParser.SetStContext,
                            CypherParser.RemoveStContext,
                        ),
                    )
                    and last_with_token < scope.start_token < return_clause.anchor.start_token
                    for scope in query_ir.scopes
                )
                if has_post_with_update:
                    continue
                unit_alias = fresh_identifier(query_ir.all_variables, "__graf_unit")
                clause = UnwindClauseIR(
                    ListExpressionIR((LiteralExpressionIR(0, ValueType.INTEGER),)),
                    unit_alias,
                )
                candidates.append(
                    self.candidate(
                        query_ir,
                        "unit_unwind_barrier",
                        InsertClausesBeforeOp(return_clause.anchor, (clause,)),
                        return_clause.anchor.start_token,
                        {"alias": unit_alias, "cardinality": 1},
                    )
                )
                continue

            passthrough = WithClauseIR(
                tuple(ProjectionItemIR(VariableExpressionIR(variable)) for variable in variables)
            )
            candidates.append(
                self.candidate(
                    query_ir,
                    "pipeline_split",
                    InsertClausesBeforeOp(return_clause.anchor, (passthrough,)),
                    return_clause.anchor.start_token,
                    {"variables": variables},
                )
            )

            count_alias = fresh_identifier(query_ir.all_variables, "__graf_count")
            grouped = WithClauseIR(
                tuple(ProjectionItemIR(VariableExpressionIR(variable)) for variable in variables)
                + (ProjectionItemIR(CountAllExpressionIR(), count_alias),)
            )
            candidates.append(
                self.candidate(
                    query_ir,
                    "grouped_aggregation",
                    InsertClausesBeforeOp(return_clause.anchor, (grouped,)),
                    return_clause.anchor.start_token,
                    {"variables": variables, "alias": count_alias},
                    estimated_cost_delta=1,
                )
            )

            materialized = next(
                (
                    variable
                    for variable in variables
                    if not frame.before[variable].nullable
                    and frame.before[variable].value_type
                    in {ValueType.NODE, ValueType.RELATIONSHIP, ValueType.ANY}
                ),
                None,
            )
            if materialized:
                array_alias = fresh_identifier(query_ir.all_variables | {count_alias}, "__graf_arr")
                remaining = [variable for variable in variables if variable != materialized]
                materialize = WithClauseIR(
                    tuple(ProjectionItemIR(VariableExpressionIR(variable)) for variable in remaining)
                    + (
                        ProjectionItemIR(
                            FunctionExpressionIR("collect", (VariableExpressionIR(materialized),)),
                            array_alias,
                        ),
                    )
                )
                unwind = UnwindClauseIR(VariableExpressionIR(array_alias), materialized)
                candidates.append(
                    self.candidate(
                        query_ir,
                        "materialize_unwind",
                        InsertClausesBeforeOp(return_clause.anchor, (materialize, unwind)),
                        return_clause.anchor.start_token,
                        {
                            "materialized_variable": materialized,
                            "array_alias": array_alias,
                            "group_variables": remaining,
                        },
                        estimated_cost_delta=1,
                    )
                )

        if context.directive in {MutationDirective.DECREASE_COST, MutationDirective.LOCALIZE}:
            candidates = [candidate for candidate in candidates if candidate.action == "pipeline_split"]
        return candidates


class ValueMutationOperator(MutationOperator):
    kind = OperatorKind.VALUE

    def candidates(self, query_ir: QueryIR, context: OperatorContext) -> list[MutationCandidate]:
        candidates: list[MutationCandidate] = []
        factory = LiteralFactory()
        renderer = MutationIRRenderer(query_ir)
        for site in query_ir.literals:
            if site.role != LiteralRole.GENERAL:
                continue
            if site.actual_type not in {
                ValueType.INTEGER,
                ValueType.FLOAT,
                ValueType.STRING,
                ValueType.BOOLEAN,
            }:
                continue
            value_type = site.expected_type if site.expected_type != ValueType.ANY else site.actual_type
            values = factory.values(site.owner, site.property_name, value_type, context, quote=site.quote)
            if context.directive == MutationDirective.RELAX:
                values.sort(key=lambda item: 0 if item[1] == "observed" else 1)
            for literal, source in values:
                rendered = renderer.literal(literal)
                if rendered == site.raw:
                    continue
                candidates.append(
                    self.candidate(
                        query_ir,
                        "replace_literal",
                        ReplaceLiteralOp(site.anchor, literal),
                        site.anchor.start_token,
                        {
                            "old": site.raw,
                            "new": rendered,
                            "value_type": value_type.value,
                            "literal_source": source,
                            "variable": site.variable,
                            "owner": site.owner,
                            "property": site.property_name,
                        },
                    )
                )
        return candidates


DEFAULT_OPERATORS: tuple[MutationOperator, ...] = (
    TopologyMutationOperator(),
    DepthVolumeMutationOperator(),
    PredicateMutationOperator(),
    ClauseInsertionMutationOperator(),
    ValueMutationOperator(),
)
