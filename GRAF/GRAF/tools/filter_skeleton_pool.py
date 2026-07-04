#!/usr/bin/env python3
import argparse
import csv
import os
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

def load_skeletons(path: Path):
    content = path.read_text(encoding="utf-8")
    return [f"{q.strip()};" for q in content.split(";") if q.strip()]


def write_skeletons(path: Path, skeletons):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(skeletons) + ("\n" if skeletons else ""), encoding="utf-8")


def parse_errors(query: str):
    try:
        from antlr4 import CommonTokenStream, InputStream
        from CypherLexer import CypherLexer
        from CypherParser import CypherParser
        from SkeletonFilter import StrictErrorListener
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "smoke parsing requires antlr4 runtime. Install it with: "
            "python -m pip install antlr4-python3-runtime"
        ) from exc

    listener = StrictErrorListener()
    lexer = CypherLexer(InputStream(query))
    lexer.removeErrorListeners()
    lexer.addErrorListener(listener)
    stream = CommonTokenStream(lexer)
    stream.fill()
    parser = CypherParser(stream)
    parser.removeErrorListeners()
    parser.addErrorListener(listener)
    try:
        if hasattr(parser, "script"):
            parser.script()
        elif hasattr(parser, "oC_Cypher"):
            parser.oC_Cypher()
        else:
            parser.query()
    except Exception as exc:
        listener.errors.append(f"parser exception: {type(exc).__name__}: {exc}")
    return listener.errors


def synthetic_context():
    from GraphContext import GlobalGraphState, SchemaMetadata

    schema = SchemaMetadata()
    schema.labels = {"Node", "Person", "City", "Tag"}
    schema.topology = {
        "REL": {("Node", "Node"), ("Person", "City"), ("Node", "Tag")},
        "KNOWS": {("Person", "Person")},
        "HAS": {("Node", "Tag")},
    }
    common_props = {
        "id": "INTEGER",
        "name": "STRING",
        "score": "FLOAT",
        "active": "BOOLEAN",
        "tags": "LIST",
    }
    for label in schema.labels:
        schema.properties[label] = dict(common_props)
    for rel in schema.topology:
        schema.properties[rel] = {
            "weight": "FLOAT",
            "since": "INTEGER",
            "name": "STRING",
            "active": "BOOLEAN",
        }
    state = GlobalGraphState(total_nodes=100, total_edges=180, avg_degree=3.6)
    return schema, state


def smoke_test(skeleton: str, target: str, samples: int):
    if samples <= 0:
        return []
    try:
        from Instantiator import compile_and_instantiate
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "smoke instantiation requires project parser dependencies. "
            "Install antlr4-python3-runtime and run from the GRAF repository root."
        ) from exc

    schema, state = synthetic_context()
    errors = []
    for i in range(samples):
        try:
            query, instantiate_errors = compile_and_instantiate(skeleton, schema, state, target_engine=target)
        except Exception as exc:
            errors.append(f"sample {i}: instantiation exception: {type(exc).__name__}: {exc}")
            continue
        if instantiate_errors:
            errors.append(f"sample {i}: instantiation errors: {' | '.join(instantiate_errors)}")
        if "$" in query:
            errors.append(f"sample {i}: unresolved placeholder remains")
        syntax_errors = parse_errors(query)
        if syntax_errors:
            errors.append(f"sample {i}: instantiated parse errors: {' | '.join(syntax_errors)}")
    return errors


def main():
    parser = argparse.ArgumentParser(description="Strictly filter a GRAF skeleton pool before fuzzing.")
    parser.add_argument("--input", default="skeleton_pool")
    parser.add_argument("--output", default="skeleton_pool.strict")
    parser.add_argument("--rejects", default="skeleton_pool.strict.rejects.csv")
    parser.add_argument("--target", default="falkordb", choices=["memgraph", "neo4j", "falkordb", "kuzu", "nebula", "generic"])
    parser.add_argument("--mode", choices=["strict", "legacy"], default="strict")
    parser.add_argument("--smoke-samples", type=int, default=3, help="Instantiate each surviving skeleton N times and parse-check the result")
    parser.add_argument("--seed", type=int, default=20260627)
    args = parser.parse_args()

    try:
        from SkeletonFilter import GrafSkeletonFilter
    except ModuleNotFoundError as exc:
        raise SystemExit(
            "Skeleton filtering requires antlr4 runtime. Install it with: "
            "python -m pip install antlr4-python3-runtime"
        ) from exc

    random.seed(args.seed)
    source = Path(args.input)
    skeletons = load_skeletons(source)
    filt = GrafSkeletonFilter(target_engine=args.target, strict=args.mode == "strict")

    accepted = []
    rejected = []

    for idx, skeleton in enumerate(skeletons, start=1):
        result = filt.validate(skeleton)
        reasons = []
        if not result.is_valid:
            reasons.append(result.reason)
            reasons.extend(result.error_details or [])
        else:
            reasons.extend(smoke_test(skeleton, args.target, args.smoke_samples))

        if reasons:
            rejected.append({
                "index": idx,
                "reason": " | ".join(reasons),
                "skeleton": " ".join(skeleton.split()),
            })
        else:
            accepted.append(skeleton)

    write_skeletons(Path(args.output), accepted)
    with open(args.rejects, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["index", "reason", "skeleton"])
        writer.writeheader()
        writer.writerows(rejected)

    total = len(skeletons)
    print(f"input={source} target={args.target} mode={args.mode} smoke_samples={args.smoke_samples}")
    print(f"accepted={len(accepted)} rejected={len(rejected)} total={total} accept_rate={(len(accepted) / total * 100 if total else 0):.2f}%")
    print(f"output={args.output}")
    print(f"rejects={args.rejects}")


if __name__ == "__main__":
    raise SystemExit(main())
