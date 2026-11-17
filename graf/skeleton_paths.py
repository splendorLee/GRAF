"""One canonical name and pool location for each supported target engine."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_GENERATED_DIR = ROOT / "generated_skeletons"
_NAMES = {
    "neo4j": ("neo4j", "Neo4j"),
    "memgraph": ("memgraph", "Memgraph"),
    "falkordb": ("falkordb", "FalkorDB"),
    "kuzu": ("kuzu", "KuzuDB"),
    "kuzudb": ("kuzu", "KuzuDB"),
    "nebula": ("nebula", "NebulaGraph"),
    "nebulagraph": ("nebula", "NebulaGraph"),
}


def target_name(value: str) -> tuple[str, str]:
    try:
        return _NAMES[value.strip().lower()]
    except (KeyError, AttributeError) as exc:
        raise ValueError(f"Unsupported target GDBMS: {value!r}") from exc


def raw_path(value: str, directory: Path = DEFAULT_GENERATED_DIR) -> Path:
    return Path(directory) / f"{target_name(value)[1]}_skeletons"


def pool_path(value: str, directory: Path = DEFAULT_GENERATED_DIR) -> Path:
    return Path(directory) / f"{target_name(value)[1]}_skeleton_pool"
