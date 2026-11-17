from __future__ import annotations

import collections
import enum
import math
import time
from dataclasses import dataclass, field
from typing import Any, Deque, Mapping, Optional

from .engine import DEFAULT_WEIGHTS
from .model import MutationDirective, MutationResult, MutationStatus, OperatorKind, query_digest, to_jsonable


class ExecStatus(str, enum.Enum):
    SUCCESS = "SUCCESS"
    REJECTED = "REJECTED"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"
    RESOURCE_EXHAUSTION = "RESOURCE_EXHAUSTION"
    CRASH = "CRASH"


@dataclass
class FeedbackVector:
    execution_time_ms: float
    result_scale: int
    status: ExecStatus
    raw_query: str = ""
    seed_id: str = ""
    error_code: str = ""


@dataclass
class OperatorHealth:
    attempts: int = 0
    applied: int = 0
    rejected: int = 0
    timeouts: int = 0
    crashes: int = 0
    successes: int = 0
    reward_total: float = 0.0
    circuit_open_until: int = 0
    recent: Deque[str] = field(default_factory=lambda: collections.deque(maxlen=100))

    @property
    def rejection_rate(self) -> float:
        decisive = self.applied + self.rejected
        return self.rejected / decisive if decisive else 0.0

    @property
    def mean_reward(self) -> float:
        return self.reward_total / self.successes if self.successes else 0.0


@dataclass
class SeedPolicy:
    seed_id: str
    directive: MutationDirective = MutationDirective.EXPLORE
    weights: dict[OperatorKind, float] = field(default_factory=lambda: dict(DEFAULT_WEIGHTS))
    generation: int = 0
    last_status: ExecStatus = ExecStatus.SUCCESS
    last_seen: float = field(default_factory=time.time)


@dataclass(frozen=True)
class MutationPlan:
    seed_id: str
    directive: MutationDirective
    weights: Mapping[OperatorKind, float]
    enabled: tuple[OperatorKind, ...]
    generation: int


@dataclass(frozen=True)
class FeedbackConfig:
    fast_empty_threshold_ms: float = 250.0
    slow_threshold_ms: float = 10_000.0
    severe_threshold_ms: float = 60_000.0
    circuit_min_attempts: int = 20
    circuit_rejection_threshold: float = 0.65
    circuit_cooldown_events: int = 100
    max_seed_states: int = 20_000
    localization_queue_size: int = 2_000
    promotion_reward_threshold: float = 0.35
    promotion_max_latency_ms: float = 8_000.0


class EnterpriseFeedbackMonitor:
    """Per-seed feedback and per-operator health with circuit breakers."""

    def __init__(self, config: Optional[FeedbackConfig] = None) -> None:
        self.config = config or FeedbackConfig()
        self.operator_health = {kind: OperatorHealth() for kind in OperatorKind}
        self.seed_policies: "collections.OrderedDict[str, SeedPolicy]" = collections.OrderedDict()
        self.localization_queue: Deque[dict[str, Any]] = collections.deque(maxlen=self.config.localization_queue_size)
        self.event_index = 0

    def plan(self, parent_query: str, seed_id: str = "") -> MutationPlan:
        resolved = seed_id or query_digest(parent_query)
        policy = self._seed_policy(resolved)
        enabled = tuple(
            kind
            for kind in OperatorKind
            if self.operator_health[kind].circuit_open_until <= self.event_index
            and policy.weights.get(kind, 0.0) > 0.0
        )
        if not enabled:
            # Fail open for liveness, but use only the least rejected operator.
            enabled = (min(OperatorKind, key=lambda item: self.operator_health[item].rejection_rate),)
        weights = self._ucb_weights(policy, enabled)
        return MutationPlan(resolved, policy.directive, weights, enabled, policy.generation)

    def record_mutation(self, result: MutationResult) -> None:
        self.event_index += 1
        if result.operator is None:
            return
        health = self.operator_health[result.operator]
        health.attempts += 1
        if result.status == MutationStatus.APPLIED:
            health.applied += 1
            health.recent.append("applied")
        elif result.status in {MutationStatus.REJECTED, MutationStatus.ERROR}:
            health.rejected += 1
            health.recent.append("rejected")
        else:
            health.recent.append("no_match")
        self._maybe_trip(result.operator)

    def process_feedback(self, feedback: FeedbackVector, mutation: Optional[MutationResult] = None) -> tuple[MutationPlan, bool]:
        self.event_index += 1
        seed_id = feedback.seed_id or (mutation.seed_id if mutation else "") or query_digest(feedback.raw_query)
        policy = self._seed_policy(seed_id)
        policy.last_status = feedback.status
        policy.last_seen = time.time()
        policy.generation += 1
        interesting = False

        operator = mutation.operator if mutation else None
        health = self.operator_health[operator] if operator else None
        if health and mutation and mutation.status == MutationStatus.APPLIED:
            # An applied mutation becomes an execution attempt only here.  This
            # prevents rejected candidates from polluting runtime rewards.
            if feedback.status == ExecStatus.SUCCESS:
                health.successes += 1
                reward = self._reward(feedback)
                health.reward_total += reward
                health.recent.append("success")
            elif feedback.status == ExecStatus.TIMEOUT:
                health.timeouts += 1
                health.recent.append("timeout")
            elif feedback.status in {ExecStatus.REJECTED, ExecStatus.ERROR}:
                health.rejected += 1
                health.recent.append("runtime_rejected")
            elif feedback.status in {ExecStatus.CRASH, ExecStatus.RESOURCE_EXHAUSTION}:
                health.crashes += 1
                health.recent.append("abnormal")
            self._maybe_trip(operator)

        if feedback.status in {ExecStatus.CRASH, ExecStatus.RESOURCE_EXHAUSTION}:
            policy.directive = MutationDirective.LOCALIZE
            policy.weights = self._normalize_weights(
                {
                    OperatorKind.TOPOLOGY: 0.10,
                    OperatorKind.DEPTH_VOLUME: 0.30,
                    OperatorKind.PREDICATE: 0.20,
                    OperatorKind.CLAUSE: 0.10,
                    OperatorKind.VALUE: 0.30,
                }
            )
            self.localization_queue.append(
                {
                    "seed_id": seed_id,
                    "mutation_id": mutation.mutation_id if mutation else "",
                    "query": feedback.raw_query,
                    "operator": operator.value if operator else None,
                    "status": feedback.status.value,
                    "timestamp": time.time(),
                }
            )
            interesting = True
        elif feedback.status == ExecStatus.TIMEOUT or feedback.execution_time_ms >= self.config.severe_threshold_ms:
            policy.directive = MutationDirective.DECREASE_COST
            policy.weights = self._normalize_weights(
                {
                    OperatorKind.TOPOLOGY: 0.05,
                    OperatorKind.DEPTH_VOLUME: 0.55,
                    OperatorKind.PREDICATE: 0.20,
                    OperatorKind.CLAUSE: 0.05,
                    OperatorKind.VALUE: 0.15,
                }
            )
            interesting = True
        elif feedback.status == ExecStatus.SUCCESS and feedback.result_scale == 0 and feedback.execution_time_ms <= self.config.fast_empty_threshold_ms:
            policy.directive = MutationDirective.RELAX
            policy.weights = self._normalize_weights(
                {
                    OperatorKind.TOPOLOGY: 0.25,
                    OperatorKind.DEPTH_VOLUME: 0.05,
                    OperatorKind.PREDICATE: 0.35,
                    OperatorKind.CLAUSE: 0.05,
                    OperatorKind.VALUE: 0.30,
                }
            )
        elif feedback.status == ExecStatus.SUCCESS and feedback.execution_time_ms >= self.config.slow_threshold_ms:
            policy.directive = MutationDirective.DECREASE_COST
            policy.weights = self._normalize_weights(
                {
                    OperatorKind.TOPOLOGY: 0.10,
                    OperatorKind.DEPTH_VOLUME: 0.45,
                    OperatorKind.PREDICATE: 0.20,
                    OperatorKind.CLAUSE: 0.10,
                    OperatorKind.VALUE: 0.15,
                }
            )
            interesting = True
        elif feedback.status in {ExecStatus.REJECTED, ExecStatus.ERROR}:
            policy.directive = MutationDirective.EXPLORE
            if operator:
                policy.weights[operator] = max(0.01, policy.weights.get(operator, 0.1) * 0.5)
                policy.weights = self._normalize_weights(policy.weights)
        else:
            policy.directive = MutationDirective.EXPLORE
            policy.weights = self._blend(policy.weights, DEFAULT_WEIGHTS, 0.20)
            if feedback.status == ExecStatus.SUCCESS and feedback.execution_time_ms >= self.config.slow_threshold_ms * 0.8:
                interesting = True

        return self.plan(feedback.raw_query, seed_id), interesting

    def pop_localization_seed(self) -> Optional[dict[str, Any]]:
        return self.localization_queue.popleft() if self.localization_queue else None

    def should_promote(
        self,
        feedback: FeedbackVector,
        mutation: Optional[MutationResult],
        interesting: bool,
    ) -> bool:
        """Admit productive children without feeding failures back as roots."""

        if not mutation or mutation.status != MutationStatus.APPLIED:
            return False
        if feedback.status != ExecStatus.SUCCESS or feedback.result_scale <= 0:
            return False
        if feedback.execution_time_ms > self.config.promotion_max_latency_ms:
            return False
        return interesting or self._reward(feedback) >= self.config.promotion_reward_threshold

    def inherit_policy(self, parent_seed_id: str, child_seed_id: str) -> None:
        """Carry learned guidance into a promoted child's lineage state."""

        if not child_seed_id or child_seed_id == parent_seed_id:
            return
        parent = self._seed_policy(parent_seed_id)
        child = SeedPolicy(
            seed_id=child_seed_id,
            directive=parent.directive,
            weights=dict(parent.weights),
            generation=parent.generation,
            last_status=parent.last_status,
            last_seen=time.time(),
        )
        self.seed_policies.pop(child_seed_id, None)
        self.seed_policies[child_seed_id] = child
        while len(self.seed_policies) > self.config.max_seed_states:
            self.seed_policies.popitem(last=False)

    def snapshot(self) -> dict[str, Any]:
        return {
            "event_index": self.event_index,
            "operators": {kind.value: to_jsonable(health) for kind, health in self.operator_health.items()},
            "seed_count": len(self.seed_policies),
            "localization_queue_size": len(self.localization_queue),
        }

    def _seed_policy(self, seed_id: str) -> SeedPolicy:
        if seed_id in self.seed_policies:
            policy = self.seed_policies.pop(seed_id)
            self.seed_policies[seed_id] = policy
            return policy
        policy = SeedPolicy(seed_id=seed_id)
        self.seed_policies[seed_id] = policy
        while len(self.seed_policies) > self.config.max_seed_states:
            self.seed_policies.popitem(last=False)
        return policy

    def _ucb_weights(self, policy: SeedPolicy, enabled: tuple[OperatorKind, ...]) -> dict[OperatorKind, float]:
        total_attempts = max(1, sum(self.operator_health[kind].attempts for kind in enabled))
        scores: dict[OperatorKind, float] = {}
        for kind in enabled:
            health = self.operator_health[kind]
            exploration = math.sqrt(2.0 * math.log(total_attempts + 1) / (health.attempts + 1))
            health_factor = max(0.05, 1.0 - health.rejection_rate)
            scores[kind] = max(0.001, policy.weights.get(kind, 0.0) * health_factor + 0.10 * exploration)
        return self._normalize_weights(scores)

    def _maybe_trip(self, operator: OperatorKind) -> None:
        health = self.operator_health[operator]
        recent = list(health.recent)
        rejected = sum(event in {"rejected", "runtime_rejected"} for event in recent)
        decisive = sum(event not in {"no_match"} for event in recent)
        rate = rejected / decisive if decisive else 0.0
        if decisive >= self.config.circuit_min_attempts and rate >= self.config.circuit_rejection_threshold:
            health.circuit_open_until = self.event_index + self.config.circuit_cooldown_events

    @staticmethod
    def _reward(feedback: FeedbackVector) -> float:
        if feedback.status != ExecStatus.SUCCESS:
            return 0.0
        latency_component = min(1.0, math.log1p(max(feedback.execution_time_ms, 0.0)) / math.log1p(10_000.0))
        result_component = min(1.0, math.log1p(max(feedback.result_scale, 0)) / math.log1p(1_000.0))
        nonempty_bonus = 0.25 if feedback.result_scale > 0 else 0.0
        return latency_component * 0.45 + result_component * 0.30 + nonempty_bonus

    @staticmethod
    def _normalize_weights(weights: Mapping[OperatorKind, float]) -> dict[OperatorKind, float]:
        cleaned = {kind: max(0.0, float(weights.get(kind, 0.0))) for kind in OperatorKind}
        total = sum(cleaned.values())
        if total <= 0:
            return dict(DEFAULT_WEIGHTS)
        return {kind: value / total for kind, value in cleaned.items()}

    @classmethod
    def _blend(
        cls,
        current: Mapping[OperatorKind, float],
        target: Mapping[OperatorKind, float],
        alpha: float,
    ) -> dict[OperatorKind, float]:
        return cls._normalize_weights(
            {kind: (1.0 - alpha) * current.get(kind, 0.0) + alpha * target.get(kind, 0.0) for kind in OperatorKind}
        )


def estimate_result_scale(execution_output: Any) -> int:
    if execution_output is None:
        return 0
    if isinstance(execution_output, str):
        rows = re_search_rows(execution_output)
        return rows if rows is not None else (0 if not execution_output else 1 + len(execution_output) // 1_000)
    if isinstance(execution_output, Mapping):
        for key in ("rows", "row_count", "result_count"):
            if key in execution_output:
                try:
                    return max(0, int(execution_output[key]))
                except (TypeError, ValueError):
                    pass
        return len(execution_output)
    if isinstance(execution_output, (list, tuple, set)):
        return len(execution_output)
    try:
        return len(execution_output)
    except Exception:
        return 1


def re_search_rows(text: str) -> Optional[int]:
    import re

    match = re.search(r"\bRows:\s*(\d+)", text, re.IGNORECASE)
    return int(match.group(1)) if match else None
