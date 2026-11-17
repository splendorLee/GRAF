from __future__ import annotations

import random
import traceback
from dataclasses import dataclass
from typing import Iterable, Mapping, Optional, Sequence

from .cypher import QueryDocument
from .dialects import get_dialect
from .ir import (
    IR_VERSION,
    MutationCandidate,
    MutationIRCompileError,
    MutationIRCompiler,
    MutationIRCompilerConfig,
    QueryIRBuilder,
)
from .model import (
    GraphStats,
    MutationDirective,
    MutationResult,
    MutationStatus,
    OperatorKind,
    SchemaView,
    ValidationResult,
    query_digest,
    to_jsonable,
)
from .operators import DEFAULT_OPERATORS, MutationOperator, OperatorContext
from .validation import ValidationPipeline


DEFAULT_WEIGHTS: dict[OperatorKind, float] = {
    OperatorKind.TOPOLOGY: 0.24,
    OperatorKind.DEPTH_VOLUME: 0.20,
    OperatorKind.PREDICATE: 0.20,
    OperatorKind.CLAUSE: 0.16,
    OperatorKind.VALUE: 0.20,
}


@dataclass(frozen=True)
class MutationEngineConfig:
    max_attempts: int = 12
    max_candidates_per_operator: int = 256
    max_path_bound: int = 12
    max_limit: int = 10_000
    anomalous_string_length: int = 1_024
    validate_parent: bool = True
    fail_closed: bool = True
    max_compiled_query_bytes: int = 1_000_000
    max_mutation_growth_bytes: int = 65_536


class EnterpriseMutationEngine:
    """One-edit mutation engine with deterministic validation and attribution."""

    def __init__(
        self,
        *,
        target: str,
        schema: SchemaView,
        graph: GraphStats,
        validator: ValidationPipeline,
        operators: Sequence[MutationOperator] = DEFAULT_OPERATORS,
        config: Optional[MutationEngineConfig] = None,
    ) -> None:
        self.target = target
        self.schema = schema
        self.graph = graph
        self.dialect = get_dialect(target)
        self.validator = validator
        self.config = config or MutationEngineConfig()
        self.operators = {operator.kind: operator for operator in operators}
        self.ir_compiler = MutationIRCompiler(
            MutationIRCompilerConfig(
                max_output_bytes=self.config.max_compiled_query_bytes,
                max_growth_bytes=self.config.max_mutation_growth_bytes,
                require_round_trip_parse=True,
            )
        )

    def refresh_context(self, schema: SchemaView, graph: GraphStats) -> None:
        self.schema = schema
        self.graph = graph
        self.validator.schema = schema

    def mutate(
        self,
        parent_query: str,
        *,
        seed: int,
        directive: MutationDirective = MutationDirective.EXPLORE,
        weights: Optional[Mapping[OperatorKind, float]] = None,
        enabled: Optional[Iterable[OperatorKind]] = None,
        seed_id: str = "",
    ) -> MutationResult:
        resolved_seed_id = seed_id or query_digest(parent_query)
        parent_validation = None
        if self.config.validate_parent:
            parent_validation = self.validator.validate(parent_query)
            if not parent_validation.valid:
                return MutationResult(
                    status=MutationStatus.REJECTED,
                    parent_query=parent_query,
                    query=parent_query,
                    seed_id=resolved_seed_id,
                    directive=directive,
                    validation=parent_validation,
                    metadata={"rejection_stage": "parent"},
                )
            if parent_validation.native_only:
                return MutationResult(
                    status=MutationStatus.NO_MATCH,
                    parent_query=parent_query,
                    query=parent_query,
                    seed_id=resolved_seed_id,
                    directive=directive,
                    validation=parent_validation,
                    metadata={"reason": "target_native_only", "target_checked": True},
                )

        document = QueryDocument.build(parent_query, self.schema, self.dialect)
        if document.parse.errors or document.parse.tree is None:
            validation = parent_validation or self.validator.validate(parent_query)
            return MutationResult(
                status=MutationStatus.REJECTED,
                parent_query=parent_query,
                query=parent_query,
                seed_id=resolved_seed_id,
                directive=directive,
                validation=validation,
                metadata={"rejection_stage": "parent_parse"},
            )
        try:
            # Builders contain short-lived indexing state; creating one per
            # request keeps the engine safe when callers serialize mutations
            # from multiple campaign workers.
            query_ir = QueryIRBuilder().build(document)
        except Exception as exc:
            return MutationResult(
                status=MutationStatus.ERROR,
                parent_query=parent_query,
                query=parent_query,
                seed_id=resolved_seed_id,
                directive=directive,
                metadata={
                    "rejection_stage": "ir_build",
                    "ir_version": IR_VERSION,
                    "error_type": type(exc).__name__,
                },
                error=f"{type(exc).__name__}: {exc}",
            )

        allowed = [kind for kind in (enabled or self.operators.keys()) if kind in self.operators]
        if not allowed:
            return MutationResult(
                MutationStatus.NO_MATCH,
                parent_query,
                parent_query,
                seed_id=resolved_seed_id,
                directive=directive,
                metadata={"reason": "no enabled operators"},
            )

        rng = random.Random(seed)
        effective_weights = dict(DEFAULT_WEIGHTS)
        if weights:
            for key, value in weights.items():
                kind = key if isinstance(key, OperatorKind) else OperatorKind(str(key))
                effective_weights[kind] = max(0.0, float(value))

        operator_context = OperatorContext(
            schema=self.schema,
            graph=self.graph,
            directive=directive,
            rng=rng,
            max_path_bound=self.config.max_path_bound,
            max_limit=self.config.max_limit,
            anomalous_string_length=self.config.anomalous_string_length,
        )

        candidate_cache: dict[OperatorKind, list[MutationCandidate]] = {}
        candidate_count = 0
        generation_errors: list[dict] = []
        for kind in allowed:
            try:
                generated = self.operators[kind].candidates(query_ir, operator_context)
                if len(generated) > self.config.max_candidates_per_operator:
                    rng.shuffle(generated)
                    generated = generated[: self.config.max_candidates_per_operator]
                candidate_cache[kind] = generated
                candidate_count += len(generated)
            except Exception as exc:
                candidate_cache[kind] = []
                generation_errors.append(
                    {
                        "operator": kind.value,
                        "error": f"{type(exc).__name__}: {exc}",
                        "traceback": traceback.format_exc(limit=8),
                    }
                )

        available = [kind for kind in allowed if candidate_cache.get(kind)]
        if not available:
            return MutationResult(
                MutationStatus.ERROR if generation_errors and self.config.fail_closed else MutationStatus.NO_MATCH,
                parent_query,
                parent_query,
                seed_id=resolved_seed_id,
                directive=directive,
                candidate_count=0,
                metadata={"generation_errors": generation_errors, "reason": "no applicable mutation site"},
                error=generation_errors[0]["error"] if generation_errors else "",
            )

        rejected_attempts: list[dict] = []
        seen_children: set[str] = set()
        attempts = 0
        while attempts < self.config.max_attempts and available:
            kind = self._weighted_choice(available, effective_weights, rng)
            operator_candidates = candidate_cache[kind]
            candidate = operator_candidates.pop(rng.randrange(len(operator_candidates)))
            if not operator_candidates:
                available.remove(kind)
            attempts += 1
            try:
                child = self.ir_compiler.apply(query_ir, candidate.program)
            except MutationIRCompileError as exc:
                rejected_attempts.append(
                    {
                        "operator": kind.value,
                        "action": candidate.action,
                        "stage": "ir_compile",
                        "code": exc.code,
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
                continue
            except Exception as exc:
                rejected_attempts.append(
                    {
                        "operator": kind.value,
                        "action": candidate.action,
                        "stage": "ir_compile",
                        "code": "INTERNAL_COMPILER_ERROR",
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
                continue
            child_digest = query_digest(child)
            if child == parent_query or child_digest in seen_children:
                rejected_attempts.append(
                    {"operator": kind.value, "action": candidate.action, "stage": "dedupe", "error": "no change or duplicate child"}
                )
                continue
            seen_children.add(child_digest)
            validation = self.validator.validate(child)
            if validation.valid:
                return MutationResult(
                    status=MutationStatus.APPLIED,
                    parent_query=parent_query,
                    query=child,
                    operator=kind,
                    action=candidate.action,
                    seed_id=resolved_seed_id,
                    attempt_count=attempts,
                    candidate_count=candidate_count,
                    directive=directive,
                    metadata={
                        "candidate": to_jsonable(candidate),
                        "ir_version": candidate.program.ir_version,
                        "program_id": candidate.program.program_id,
                        "rejected_attempts": rejected_attempts,
                        "complex_scope": query_ir.complex_scope,
                    },
                    validation=validation,
                )
            rejected_attempts.append(
                {
                    "operator": kind.value,
                    "action": candidate.action,
                    "stage": "validation",
                    "issues": [to_jsonable(issue) for issue in validation.issues],
                }
            )

        last_validation = None
        if rejected_attempts and rejected_attempts[-1].get("issues"):
            # The full ValidationResult belongs to a discarded child.  Preserve
            # its issues in metadata and return a concise rejected result.
            last_validation = ValidationResult(False, normalized_query=parent_query)
        return MutationResult(
            status=MutationStatus.REJECTED,
            parent_query=parent_query,
            query=parent_query,
            seed_id=resolved_seed_id,
            attempt_count=attempts,
            candidate_count=candidate_count,
            directive=directive,
            validation=last_validation,
            metadata={
                "rejection_stage": "mutation",
                "ir_version": IR_VERSION,
                "attempts": rejected_attempts,
                "generation_errors": generation_errors,
            },
            error="all mutation candidates were rejected by validation",
        )

    @staticmethod
    def _weighted_choice(
        kinds: Sequence[OperatorKind],
        weights: Mapping[OperatorKind, float],
        rng: random.Random,
    ) -> OperatorKind:
        values = [max(0.0, float(weights.get(kind, 0.0))) for kind in kinds]
        total = sum(values)
        if total <= 0:
            return kinds[rng.randrange(len(kinds))]
        needle = rng.random() * total
        cumulative = 0.0
        for kind, weight in zip(kinds, values):
            cumulative += weight
            if needle <= cumulative:
                return kind
        return kinds[-1]
