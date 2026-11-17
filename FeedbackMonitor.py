"""Compatibility layer for the enterprise per-seed feedback scheduler."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Mapping, Optional

from graf.feedback import (
    EnterpriseFeedbackMonitor,
    ExecStatus,
    FeedbackConfig,
    FeedbackVector,
    MutationPlan,
    estimate_result_scale,
)
from graf.model import MutationDirective, MutationResult, OperatorKind


class LatencyBand(str, Enum):
    FAST = "FAST"
    SLOW = "SLOW"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR_OR_CRASH"


@dataclass
class MutationStrategy:
    operator_weights: dict[OperatorKind, float] = field(default_factory=dict)
    directive: MutationDirective = MutationDirective.EXPLORE
    enabled_operators: tuple[OperatorKind, ...] = tuple(OperatorKind)
    seed_id: str = ""
    generation: int = 0
    max_attempts: int = 12
    max_limit: int = 10_000
    max_path_bound: int = 12
    # Legacy projections are retained for external integrations, but the engine
    # never averages them into one mutation probability.
    topology_rate: float = 0.24
    predicate_rate: float = 0.20
    clause_rate: float = 0.16
    depth_scale_factor: float = 1.0
    mutation_rate_scale: float = 1.0
    allow_expensive_aggregation: bool = True
    allow_topology_expansion: bool = True

    @classmethod
    def from_plan(cls, plan: MutationPlan) -> "MutationStrategy":
        weights = dict(plan.weights)
        return cls(
            operator_weights=weights,
            directive=plan.directive,
            enabled_operators=plan.enabled,
            seed_id=plan.seed_id,
            generation=plan.generation,
            topology_rate=weights.get(OperatorKind.TOPOLOGY, 0.0),
            predicate_rate=weights.get(OperatorKind.PREDICATE, 0.0),
            clause_rate=weights.get(OperatorKind.CLAUSE, 0.0),
            allow_expensive_aggregation=OperatorKind.CLAUSE in plan.enabled,
            allow_topology_expansion=OperatorKind.TOPOLOGY in plan.enabled,
        )

    def clamp(self) -> None:
        self.max_attempts = max(1, min(100, int(self.max_attempts)))
        self.max_limit = max(1, min(1_000_000, int(self.max_limit)))
        self.max_path_bound = max(1, min(64, int(self.max_path_bound)))


class FeedbackMonitor:
    def __init__(self, seed_cypher: str = "", config: Optional[FeedbackConfig] = None):
        self.seed_cypher = seed_cypher
        self.core = EnterpriseFeedbackMonitor(config)
        initial_plan = self.core.plan(seed_cypher or "RETURN 1")
        self.current_strategy = MutationStrategy.from_plan(initial_plan)
        self.high_value_seeds = self.core.localization_queue
        self.last_mutation: Optional[MutationResult] = None

    def plan_for(self, query: str, seed_id: str = "") -> MutationStrategy:
        self.current_strategy = MutationStrategy.from_plan(self.core.plan(query, seed_id))
        return self.current_strategy

    def record_mutation(self, result: MutationResult) -> None:
        self.last_mutation = result
        self.core.record_mutation(result)

    def classify_latency(self, feedback: FeedbackVector) -> LatencyBand:
        if feedback.status in {ExecStatus.CRASH, ExecStatus.RESOURCE_EXHAUSTION, ExecStatus.ERROR, ExecStatus.REJECTED}:
            return LatencyBand.ERROR
        if feedback.status == ExecStatus.TIMEOUT or feedback.execution_time_ms >= self.core.config.severe_threshold_ms:
            return LatencyBand.TIMEOUT
        if feedback.execution_time_ms >= self.core.config.slow_threshold_ms:
            return LatencyBand.SLOW
        return LatencyBand.FAST

    def should_promote_seed(
        self,
        feedback: FeedbackVector,
        is_interesting: bool,
        mutation: Optional[MutationResult] = None,
    ) -> bool:
        return self.core.should_promote(feedback, mutation or self.last_mutation, is_interesting)

    def inherit_seed_policy(self, parent_seed_id: str, child_seed_id: str) -> None:
        self.core.inherit_policy(parent_seed_id, child_seed_id)

    def process_feedback(
        self,
        feedback: FeedbackVector,
        mutation: Optional[MutationResult] = None,
    ) -> tuple[MutationStrategy, bool]:
        effective_mutation = mutation or self.last_mutation
        plan, interesting = self.core.process_feedback(feedback, effective_mutation)
        self.current_strategy = MutationStrategy.from_plan(plan)
        return self.current_strategy, interesting

    def pop_localization_seed(self):
        return self.core.pop_localization_seed()

    def snapshot(self):
        return self.core.snapshot()


__all__ = [
    "EnterpriseFeedbackMonitor",
    "ExecStatus",
    "FeedbackConfig",
    "FeedbackMonitor",
    "FeedbackVector",
    "LatencyBand",
    "MutationStrategy",
    "estimate_result_scale",
]
