#!/usr/bin/env python3
"""Offline, reproducible quality gate for GRAF's five mutation families."""

from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from GraphContext import GlobalGraphState, SchemaMetadata  # noqa: E402
from Instantiator import compile_and_instantiate  # noqa: E402
from graf.admission import load_candidates  # noqa: E402
from graf.skeleton_paths import pool_path  # noqa: E402
from graf.engine import EnterpriseMutationEngine, MutationEngineConfig  # noqa: E402
from graf.ir import IR_VERSION  # noqa: E402
from graf.model import GraphStats, MutationStatus, OperatorKind, SchemaView  # noqa: E402
from graf.seed_profiles import (  # noqa: E402
    GraphSeedSpec,
    SeedPortfolioScheduler,
    seed_profile,
)
from graf.validation import ValidationPipeline, ValidationPolicy  # noqa: E402


def seed_context(
    spec: GraphSeedSpec | None = None,
) -> tuple[SchemaMetadata, GlobalGraphState]:
    """Project a typed seed spec into the legacy context adapter contract."""

    spec = spec or seed_profile("baseline")
    type_names = {
        "INTEGER": "int",
        "FLOAT": "float",
        "STRING": "string",
        "BOOLEAN": "bool",
    }
    properties = {
        owner: {key: type_names[value_type] for key, value_type in values.items()}
        for owner, values in {**spec.node_schema(), **spec.relationship_schema()}.items()
    }
    property_values: dict[str, dict[str, list]] = {
        owner: {key: [] for key in values}
        for owner, values in properties.items()
    }
    for node in spec.nodes:
        for key, value in node.properties:
            values = property_values[node.label][key]
            if value not in values:
                values.append(value)
    for edge in spec.edges:
        for key, value in edge.properties:
            values = property_values[edge.rel_type][key]
            if value not in values:
                values.append(value)

    topology: dict[str, set[tuple[str, str]]] = {}
    for source, rel_type, target in spec.topology_counts():
        topology.setdefault(rel_type, set()).add((source, target))
    schema = SchemaMetadata(
        labels=set(spec.node_counts()),
        topology=topology,
        properties=properties,
        property_values=property_values,
    )
    average_degree = (2 * len(spec.edges) / len(spec.nodes)) if spec.nodes else 0.0
    return schema, GlobalGraphState(
        total_nodes=len(spec.nodes),
        total_edges=len(spec.edges),
        avg_degree=average_degree,
    )


def load_skeletons(path: Path) -> list[str]:
    return load_candidates(path, input_format="lines")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, help="Default: target's admitted skeleton pool")
    parser.add_argument("--target", choices=["neo4j", "memgraph", "falkordb", "kuzu", "nebula"], default="falkordb")
    parser.add_argument("--sample-size", type=int, default=300, help="0 audits the complete pool")
    parser.add_argument("--seed", type=int, default=20261024)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    random.seed(args.seed)
    seed_scheduler = SeedPortfolioScheduler(args.seed)
    profile_runtimes = {}
    for profile in seed_scheduler.profiles:
        profile_schema, profile_state = seed_context(profile)
        profile_schema_view = SchemaView.from_legacy(profile_schema, profile_state)
        profile_validator = ValidationPipeline(
            args.target,
            profile_schema_view,
            policy=ValidationPolicy(target_compile_required=False),
        )
        profile_engine = EnterpriseMutationEngine(
            target=args.target,
            schema=profile_schema_view,
            graph=GraphStats.from_legacy(profile_state),
            validator=profile_validator,
            config=MutationEngineConfig(max_attempts=32),
        )
        profile_runtimes[profile.name] = (
            profile_schema,
            profile_state,
            profile_validator,
            profile_engine,
        )
    input_path = args.input or pool_path(args.target)
    all_skeletons = load_skeletons(input_path)
    if args.sample_size > 0 and args.sample_size < len(all_skeletons):
        selected_indices = sorted(random.Random(args.seed).sample(range(len(all_skeletons)), args.sample_size))
    else:
        selected_indices = list(range(len(all_skeletons)))

    counts: Counter[str] = Counter()
    operator_counts: dict[str, Counter[str]] = defaultdict(Counter)
    ir_operation_counts: dict[str, Counter[str]] = defaultdict(Counter)
    profile_counts: dict[str, Counter[str]] = defaultdict(Counter)
    profile_operator_counts: dict[str, dict[str, Counter[str]]] = defaultdict(
        lambda: defaultdict(Counter)
    )
    issue_counts: Counter[str] = Counter()
    examples: list[dict] = []
    for index in selected_indices:
        skeleton = all_skeletons[index]
        counts["sampled"] += 1
        selection = seed_scheduler.select(counts["sampled"] - 1)
        profile = selection.profile
        schema, state, validator, engine = profile_runtimes[profile.name]
        profile_counts[profile.name]["parents_assigned"] += 1
        query, diagnostics = compile_and_instantiate(
            skeleton, schema, state, target_engine=args.target, allow_target_dialect=True)
        if diagnostics:
            counts["instantiation_diagnostics"] += 1
        parent_validation = validator.validate(query)
        if not parent_validation.valid:
            counts["parent_rejected"] += 1
            profile_counts[profile.name]["parent_rejected"] += 1
            for issue in parent_validation.issues:
                issue_counts[f"parent:{issue.code}"] += 1
            if len(examples) < 20:
                examples.append(
                    {
                        "stage": "parent",
                        "index": index,
                        "query": query,
                        "issues": [issue.code for issue in parent_validation.issues],
                    }
                )
            continue
        counts["parent_valid"] += 1
        profile_counts[profile.name]["parent_valid"] += 1

        for offset, operator in enumerate(OperatorKind):
            result = engine.mutate(
                query,
                seed=(args.seed << 24) ^ (index << 4) ^ offset,
                enabled=[operator],
            )
            operator_counts[operator.value][result.status.value] += 1
            profile_operator_counts[profile.name][operator.value][result.status.value] += 1
            counts[f"children_{result.status.value}"] += 1
            if result.status == MutationStatus.APPLIED:
                candidate_payload = result.metadata.get("candidate", {})
                program_payload = candidate_payload.get("program", {}) if isinstance(candidate_payload, dict) else {}
                operations = program_payload.get("operations", []) if isinstance(program_payload, dict) else []
                contract_valid = (
                    result.metadata.get("ir_version") == IR_VERSION
                    and program_payload.get("ir_version") == IR_VERSION
                    and program_payload.get("ir_type") == "MutationProgram"
                    and bool(program_payload.get("program_id"))
                    and bool(operations)
                    and all(isinstance(item, dict) and item.get("ir_type", "").endswith("Op") for item in operations)
                )
                if contract_valid:
                    counts["ir_programs_applied"] += 1
                    for operation in operations:
                        ir_operation_counts[operator.value][operation["ir_type"]] += 1
                else:
                    counts["ir_contract_violations"] += 1
                child_validation = validator.validate(result.query)
                if not child_validation.valid:
                    counts["invalid_applied_child"] += 1
                    for issue in child_validation.issues:
                        issue_counts[f"child:{issue.code}"] += 1
                    if len(examples) < 20:
                        examples.append(
                            {
                                "stage": "child",
                                "index": index,
                                "operator": operator.value,
                                "query": result.query,
                                "issues": [issue.code for issue in child_validation.issues],
                            }
                        )

    parent_valid = counts["parent_valid"]
    operators = {}
    for operator in OperatorKind:
        values = dict(sorted(operator_counts[operator.value].items()))
        applied = operator_counts[operator.value][MutationStatus.APPLIED.value]
        operators[operator.value] = {
            **values,
            "applicability_rate": round(applied / parent_valid, 6) if parent_valid else 0.0,
        }
    resolved_input = input_path.resolve()
    try:
        report_input = str(resolved_input.relative_to(ROOT))
    except ValueError:
        report_input = str(resolved_input)
    assigned_counts = [profile_counts[profile.name]["parents_assigned"] for profile in seed_scheduler.profiles]
    portfolio_coverage_complete = (
        counts["sampled"] < len(seed_scheduler.profiles)
        or all(value > 0 for value in assigned_counts)
    )
    portfolio_balance_delta = max(assigned_counts, default=0) - min(assigned_counts, default=0)
    report = {
        "schema": "graf-enterprise-mutation-audit/v3",
        "target": args.target,
        "seed": args.seed,
        "input": report_input,
        "pool_size": len(all_skeletons),
        "counts": dict(sorted(counts.items())),
        "operators": operators,
        "seed_graph_portfolio": {
            "schema": "graf-seed-portfolio-audit/v1",
            "selection_mode": "automatic_deterministic_balanced",
            "profiles_per_cycle": len(seed_scheduler.profiles),
            "coverage_complete": portfolio_coverage_complete,
            "assignment_balance_delta": portfolio_balance_delta,
            "catalog": [profile.manifest() for profile in seed_scheduler.profiles],
            "usage": {
                profile.name: {
                    **dict(sorted(profile_counts[profile.name].items())),
                    "operators": {
                        operator.value: dict(
                            sorted(profile_operator_counts[profile.name][operator.value].items())
                        )
                        for operator in OperatorKind
                    },
                }
                for profile in seed_scheduler.profiles
            },
        },
        "issues": dict(issue_counts.most_common()),
        "examples": examples,
        "mutation_ir": {
            "version": IR_VERSION,
            "programs_applied": counts["ir_programs_applied"],
            "contract_violations": counts["ir_contract_violations"],
            "operation_types": sorted(
                {
                    key
                    for values in ir_operation_counts.values()
                    for key in values
                }
            ),
            "operations_by_family": {
                operator.value: dict(sorted(ir_operation_counts[operator.value].items()))
                for operator in OperatorKind
            },
        },
        "quality_gate": {
            "passed": (
                counts["invalid_applied_child"] == 0
                and counts["children_error"] == 0
                and counts["ir_contract_violations"] == 0
                and counts["ir_programs_applied"] == counts["children_applied"]
                and portfolio_coverage_complete
                and portfolio_balance_delta <= 1
            ),
            "invalid_applied_child": counts["invalid_applied_child"],
            "operator_internal_errors": counts["children_error"],
            "ir_contract_violations": counts["ir_contract_violations"],
            "seed_portfolio_coverage_complete": portfolio_coverage_complete,
            "seed_portfolio_assignment_balance_delta": portfolio_balance_delta,
        },
    }
    encoded = json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0 if report["quality_gate"]["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
