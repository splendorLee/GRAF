"""Compatibility facade for the enterprise GRAF mutation engine.

The original module performed parse-tree visits followed by unrestricted regex
rewrites. It is intentionally replaced, not layered: callers using the legacy
``compile_and_mutate`` API now receive the same validated, single-operator
behavior as the enterprise pipeline.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Set

from graf.engine import EnterpriseMutationEngine, MutationEngineConfig
from graf.model import GraphStats, MutationDirective, MutationResult, OperatorKind, SchemaView
from graf.validation import ValidationPipeline, ValidationPolicy


@dataclass
class SchemaMetadata:
    labels: Set[str] = field(default_factory=set)
    topology: Dict[str, List[tuple[str, str]]] = field(default_factory=dict)
    properties: Dict[str, Any] = field(default_factory=dict)
    property_values: Dict[str, Dict[str, List[Any]]] = field(default_factory=dict)


@dataclass
class ValueDictionary:
    observed_values: Dict[str, List[Any]] = field(default_factory=dict)


@dataclass
class GlobalGraphState:
    node_count: int = 0
    edge_count: int = 0
    diameter: int = 5

    def calculate_max_limit(self) -> int:
        return GraphStats(self.node_count, self.edge_count, self.diameter).safe_limit


def harden_query_shape(query: str, state: GlobalGraphState, strategy: Any = None) -> str:
    """Deprecated compatibility hook; validated AST operators now own shaping."""

    del state, strategy
    return query


class GraphAwareMutator:
    """Compatibility object exposing a detailed mutation operation."""

    def __init__(self, target: str = "generic") -> None:
        self.target = target

    def mutate(
        self,
        query: str,
        schema: Any,
        state: Any,
        *,
        strategy: Any = None,
        seed: Optional[int] = None,
    ) -> MutationResult:
        return compile_and_mutate_detailed(
            query,
            schema,
            state,
            target=self.target,
            strategy=strategy,
            seed=seed,
        )


def _query_from_token_stream(token_stream: Any) -> str:
    token_stream.fill()
    return token_stream.getText(0, len(token_stream.tokens) - 1)


def _legacy_weights(strategy: Any) -> dict[OperatorKind, float]:
    defaults = {
        OperatorKind.TOPOLOGY: 0.24,
        OperatorKind.DEPTH_VOLUME: 0.20,
        OperatorKind.PREDICATE: 0.20,
        OperatorKind.CLAUSE: 0.16,
        OperatorKind.VALUE: 0.20,
    }
    if strategy is None:
        return defaults
    explicit = getattr(strategy, "operator_weights", None)
    if isinstance(explicit, Mapping):
        for key, value in explicit.items():
            kind = key if isinstance(key, OperatorKind) else OperatorKind(str(key))
            defaults[kind] = max(0.0, float(value))
        return defaults
    defaults[OperatorKind.TOPOLOGY] = max(0.0, float(getattr(strategy, "topology_rate", defaults[OperatorKind.TOPOLOGY])))
    defaults[OperatorKind.PREDICATE] = max(0.0, float(getattr(strategy, "predicate_rate", defaults[OperatorKind.PREDICATE])))
    defaults[OperatorKind.CLAUSE] = max(0.0, float(getattr(strategy, "clause_rate", defaults[OperatorKind.CLAUSE])))
    return defaults


def _legacy_directive(strategy: Any) -> MutationDirective:
    if strategy is None:
        return MutationDirective.EXPLORE
    value = getattr(strategy, "directive", None)
    if value:
        try:
            return value if isinstance(value, MutationDirective) else MutationDirective(str(value))
        except ValueError:
            pass
    if not getattr(strategy, "allow_topology_expansion", True) or not getattr(strategy, "allow_expensive_aggregation", True):
        return MutationDirective.DECREASE_COST
    return MutationDirective.EXPLORE


def _merge_observed_values(schema_view: SchemaView, val_dict: Optional[ValueDictionary]) -> None:
    if not val_dict:
        return
    for prop, values in val_dict.observed_values.items():
        for owner, owner_properties in schema_view.properties.items():
            if prop in owner_properties:
                schema_view.observed_values[(owner, prop)] = tuple(values)


def compile_and_mutate_detailed(
    query: str,
    schema: Any,
    state: Any,
    *,
    target: str = "generic",
    strategy: Any = None,
    seed: Optional[int] = None,
    validator: Optional[ValidationPipeline] = None,
    val_dict: Optional[ValueDictionary] = None,
) -> MutationResult:
    schema_view = schema if isinstance(schema, SchemaView) else SchemaView.from_legacy(schema, state)
    _merge_observed_values(schema_view, val_dict)
    graph = state if isinstance(state, GraphStats) else GraphStats.from_legacy(state)
    validation = validator or ValidationPipeline(
        target,
        schema_view,
        policy=ValidationPolicy(target_compile_required=False),
    )
    engine = EnterpriseMutationEngine(
        target=target,
        schema=schema_view,
        graph=graph,
        validator=validation,
        config=MutationEngineConfig(
            max_attempts=int(getattr(strategy, "max_attempts", 12)) if strategy else 12,
            max_path_bound=int(getattr(strategy, "max_path_bound", 12)) if strategy else 12,
            max_limit=int(getattr(strategy, "max_limit", 10_000)) if strategy else 10_000,
        ),
    )
    resolved_seed = int(seed if seed is not None else random.getrandbits(63))
    return engine.mutate(
        query,
        seed=resolved_seed,
        directive=_legacy_directive(strategy),
        weights=_legacy_weights(strategy),
    )


def compile_and_mutate(
    token_stream: Any,
    parse_tree: Any,
    schema: SchemaMetadata,
    val_dict: ValueDictionary,
    state: GlobalGraphState,
    strategy: Any = None,
) -> str:
    del parse_tree
    query = _query_from_token_stream(token_stream)
    result = compile_and_mutate_detailed(
        query,
        schema,
        state,
        strategy=strategy,
        val_dict=val_dict,
    )
    return result.query
