"""Typed, deterministic seed-graph portfolio for GRAF campaigns.

The fuzzer owns graph selection.  Operators and command-line callers never
name a concrete profile; a :class:`SeedPortfolioScheduler` rotates through a
coverage-balanced portfolio and records the selected immutable graph spec.

All target renderers consume the same :class:`GraphSeedSpec`, which prevents
the logical seed graph from drifting between Neo4j, Memgraph, FalkorDB, Kuzu,
and NebulaGraph.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Dict, Iterable, Mapping, Sequence, Tuple, Union


Scalar = Union[bool, int, float, str]
PropertyItems = Tuple[Tuple[str, Scalar], ...]
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SEED_SPEC_VERSION = 1


class SeedSpecError(ValueError):
    """Raised when a seed graph violates the portable graph contract."""


def _items(properties: Mapping[str, Scalar] | None = None, **values: Scalar) -> PropertyItems:
    merged: Dict[str, Scalar] = dict(properties or {})
    merged.update(values)
    return tuple(sorted(merged.items()))


def _scalar_type(value: Scalar) -> str:
    if isinstance(value, bool):
        return "BOOLEAN"
    if isinstance(value, int):
        return "INTEGER"
    if isinstance(value, float):
        return "FLOAT"
    if isinstance(value, str):
        return "STRING"
    raise SeedSpecError(f"unsupported seed property value: {type(value).__name__}")


def _validate_identifier(value: str, kind: str) -> None:
    if not _IDENTIFIER.fullmatch(value or ""):
        raise SeedSpecError(f"invalid {kind} identifier: {value!r}")


def _validate_properties(properties: PropertyItems, owner: str) -> None:
    keys = [key for key, _ in properties]
    if len(keys) != len(set(keys)):
        raise SeedSpecError(f"duplicate property key on {owner}")
    for key, value in properties:
        _validate_identifier(key, "property")
        _scalar_type(value)
        if isinstance(value, float) and not math.isfinite(value):
            raise SeedSpecError(f"non-finite float on {owner}.{key}")


@dataclass(frozen=True)
class SeedNode:
    key: str
    label: str
    properties: PropertyItems

    @classmethod
    def create(cls, seed_key: str, label: str, node_id: int, **properties: Scalar) -> "SeedNode":
        if "id" in properties:
            raise SeedSpecError("node id must be supplied through node_id, not properties")
        return cls(key=seed_key, label=label, properties=_items({"id": node_id}, **properties))

    def property_map(self) -> Dict[str, Scalar]:
        return dict(self.properties)


@dataclass(frozen=True)
class SeedEdge:
    key: str
    source: str
    target: str
    rel_type: str
    properties: PropertyItems = ()

    @classmethod
    def create(
        cls,
        key: str,
        source: str,
        target: str,
        rel_type: str,
        **properties: Scalar,
    ) -> "SeedEdge":
        return cls(key, source, target, rel_type, _items(properties))

    def property_map(self) -> Dict[str, Scalar]:
        return dict(self.properties)


@dataclass(frozen=True)
class GraphSeedSpec:
    """Target-neutral, immutable logical seed graph."""

    name: str
    description: str
    nodes: Tuple[SeedNode, ...]
    edges: Tuple[SeedEdge, ...]
    feature_tags: Tuple[str, ...]
    version: int = SEED_SPEC_VERSION

    def __post_init__(self) -> None:
        _validate_identifier(self.name, "profile")
        if self.version != SEED_SPEC_VERSION:
            raise SeedSpecError(f"unsupported seed spec version: {self.version}")
        if not self.nodes:
            raise SeedSpecError(f"seed profile {self.name!r} has no nodes")

        node_keys = [node.key for node in self.nodes]
        edge_keys = [edge.key for edge in self.edges]
        if len(node_keys) != len(set(node_keys)):
            raise SeedSpecError(f"duplicate node key in {self.name}")
        if len(edge_keys) != len(set(edge_keys)):
            raise SeedSpecError(f"duplicate edge key in {self.name}")

        node_by_key = {node.key: node for node in self.nodes}
        seen_ids = set()
        schemas: Dict[Tuple[str, str], str] = {}
        for node in self.nodes:
            if not node.key or len(node.key.encode("utf-8")) > 64:
                raise SeedSpecError(
                    f"node key must be 1..64 UTF-8 bytes for cross-engine portability: {node.key!r}"
                )
            _validate_identifier(node.label, "label")
            _validate_properties(node.properties, f"node {node.key}")
            properties = node.property_map()
            node_id = properties.get("id")
            if isinstance(node_id, bool) or not isinstance(node_id, int):
                raise SeedSpecError(f"node {node.key} must have an INTEGER id")
            if node_id in seen_ids:
                raise SeedSpecError(f"duplicate node id {node_id} in {self.name}")
            seen_ids.add(node_id)
            for prop, value in node.properties:
                self._merge_schema(schemas, (f"node:{node.label}", prop), value)

        for edge in self.edges:
            if not edge.key:
                raise SeedSpecError("edge key must not be empty")
            _validate_identifier(edge.rel_type, "relationship")
            _validate_properties(edge.properties, f"edge {edge.key}")
            if edge.source not in node_by_key or edge.target not in node_by_key:
                raise SeedSpecError(
                    f"edge {edge.key} references missing endpoint: {edge.source}->{edge.target}"
                )
            for prop, value in edge.properties:
                self._merge_schema(schemas, (f"edge:{edge.rel_type}", prop), value)

        if len(self.feature_tags) != len(set(self.feature_tags)):
            raise SeedSpecError(f"duplicate feature tag in {self.name}")
        for tag in self.feature_tags:
            _validate_identifier(tag, "feature tag")

    @staticmethod
    def _merge_schema(
        schemas: Dict[Tuple[str, str], str], key: Tuple[str, str], value: Scalar
    ) -> None:
        value_type = _scalar_type(value)
        previous = schemas.setdefault(key, value_type)
        if previous != value_type:
            raise SeedSpecError(
                f"inconsistent property type for {key[0]}.{key[1]}: {previous} vs {value_type}"
            )

    @property
    def fingerprint(self) -> str:
        payload = self.to_dict(include_fingerprint=False)
        canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def to_dict(self, *, include_fingerprint: bool = True) -> Dict[str, object]:
        payload: Dict[str, object] = {
            "schema": "graf-seed-spec/v1",
            "version": self.version,
            "name": self.name,
            "description": self.description,
            "feature_tags": list(self.feature_tags),
            "nodes": [
                {"key": node.key, "label": node.label, "properties": dict(node.properties)}
                for node in self.nodes
            ],
            "edges": [
                {
                    "key": edge.key,
                    "source": edge.source,
                    "target": edge.target,
                    "type": edge.rel_type,
                    "properties": dict(edge.properties),
                }
                for edge in self.edges
            ],
        }
        if include_fingerprint:
            payload["fingerprint"] = self.fingerprint
        return payload

    def node_counts(self) -> Dict[str, int]:
        return dict(sorted(Counter(node.label for node in self.nodes).items()))

    def relationship_counts(self) -> Dict[str, int]:
        return dict(sorted(Counter(edge.rel_type for edge in self.edges).items()))

    def topology_counts(self) -> Dict[Tuple[str, str, str], int]:
        nodes = {node.key: node for node in self.nodes}
        counter = Counter(
            (nodes[edge.source].label, edge.rel_type, nodes[edge.target].label)
            for edge in self.edges
        )
        return dict(sorted(counter.items()))

    def node_schema(self) -> Dict[str, Dict[str, str]]:
        result: Dict[str, Dict[str, str]] = defaultdict(dict)
        for node in self.nodes:
            for key, value in node.properties:
                result[node.label][key] = _scalar_type(value)
        return {label: dict(sorted(properties.items())) for label, properties in sorted(result.items())}

    def relationship_schema(self) -> Dict[str, Dict[str, str]]:
        result: Dict[str, Dict[str, str]] = defaultdict(dict)
        for edge in self.edges:
            for key, value in edge.properties:
                result[edge.rel_type][key] = _scalar_type(value)
            result.setdefault(edge.rel_type, {})
        return {rel: dict(sorted(properties.items())) for rel, properties in sorted(result.items())}

    def manifest(self) -> Dict[str, object]:
        topology = [
            {"source": source, "type": rel_type, "target": target, "count": count}
            for (source, rel_type, target), count in self.topology_counts().items()
        ]
        return {
            "schema": "graf-seed-manifest/v1",
            "profile": self.name,
            "fingerprint": self.fingerprint,
            "description": self.description,
            "feature_tags": list(self.feature_tags),
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "node_labels": self.node_counts(),
            "relationship_types": self.relationship_counts(),
            "topology": topology,
        }


@dataclass(frozen=True)
class SeedSelection:
    epoch: int
    cycle: int
    slot: int
    profile: GraphSeedSpec
    reason: str

    def to_dict(self) -> Dict[str, object]:
        result = self.profile.manifest()
        result.update(
            {
                "epoch": self.epoch,
                "cycle": self.cycle,
                "slot": self.slot,
                "selection_reason": self.reason,
            }
        )
        return result


class SeedPortfolioScheduler:
    """Pure deterministic scheduler with complete-profile coverage per cycle."""

    def __init__(
        self,
        campaign_seed: int,
        profiles: Sequence[GraphSeedSpec] | None = None,
    ) -> None:
        self.campaign_seed = int(campaign_seed)
        self.profiles = tuple(profiles or all_seed_profiles())
        if not self.profiles:
            raise SeedSpecError("seed portfolio is empty")
        names = [profile.name for profile in self.profiles]
        if len(names) != len(set(names)):
            raise SeedSpecError("seed portfolio contains duplicate profile names")

    def _cycle_order(self, cycle: int) -> Tuple[GraphSeedSpec, ...]:
        def score(profile: GraphSeedSpec) -> bytes:
            material = (
                f"graf-seed-schedule/v1:{self.campaign_seed}:{cycle}:{profile.name}:"
                f"{profile.fingerprint}"
            ).encode("utf-8")
            return hashlib.sha256(material).digest()

        return tuple(sorted(self.profiles, key=lambda profile: (score(profile), profile.name)))

    def select(self, epoch: int) -> SeedSelection:
        if epoch < 0:
            raise SeedSpecError("seed epoch must be >= 0")
        cycle, slot = divmod(epoch, len(self.profiles))
        profile = self._cycle_order(cycle)[slot]
        reason = "deterministic_portfolio_start" if epoch == 0 else "coverage_balanced_rotation"
        return SeedSelection(epoch, cycle, slot, profile, reason)


def _node(seed_key: str, label: str, node_id: int, **properties: Scalar) -> SeedNode:
    return SeedNode.create(seed_key, label, node_id, **properties)


def _edge(
    key: str, source: str, target: str, rel_type: str, **properties: Scalar
) -> SeedEdge:
    return SeedEdge.create(key, source, target, rel_type, **properties)


def _baseline() -> GraphSeedSpec:
    nodes = (
        _node("p1", "Person", 1, name="Alice", age=30, score=99.9),
        _node("p2", "Person", 2, name="Bob", age=-2147483648, score=0.0),
        _node("p3", "Person", 3, name="Charlie", age=2147483647, score=-1e308),
        _node("doc1", "Paper", 101, title="Graph Fuzzing", published=True),
        _node("doc2", "Paper", 102, title="' OR 1=1", published=False),
        _node("doc3", "Paper", 103, title="", published=True),
        _node("c1", "Conference", 1001, name="SIGMOD", year=2026),
        _node("c2", "Conference", 1002, name="S&P", year=2027),
    )
    edges = (
        _edge("w1", "p1", "doc1", "WROTE", contribution=0.9),
        _edge("w2", "p2", "doc1", "WROTE", contribution=0.1),
        _edge("w3", "p2", "doc2", "WROTE", contribution=1.0),
        _edge("w4", "p3", "doc3", "WROTE", contribution=1.0),
        _edge("pub1", "doc1", "c1", "PUBLISHED_IN", year=2026),
        _edge("pub2", "doc2", "c1", "PUBLISHED_IN", year=2026),
        _edge("pub3", "doc3", "c2", "PUBLISHED_IN", year=2027),
        _edge("k1", "p1", "p2", "KNOWS", since=2020),
        _edge("k2", "p2", "p3", "KNOWS", since=2021),
        _edge("k3", "p3", "p1", "KNOWS", since=2025),
    )
    return GraphSeedSpec(
        "baseline",
        "Small typed reference graph retained for regression comparability.",
        nodes,
        edges,
        ("typed_properties", "directed_cycle", "boundary_values"),
    )


def _motif_mix() -> GraphSeedSpec:
    nodes = tuple(
        _node(f"m{i}", "Person", i, name=f"motif_{i}", age=(i * 7) % 83, score=float(i % 11))
        for i in range(1, 24)
    )
    pairs = [
        (1, 2), (2, 3), (3, 1), (1, 1),
        (4, 5), (5, 4),
        (6, 7), (7, 8), (8, 9), (9, 10), (10, 11), (11, 6),
        (12, 13), (12, 14), (13, 15), (14, 15),
        (16, 17), (17, 18),
        (19, 20), (20, 19), (19, 21), (21, 19),
        (19, 22), (22, 19), (19, 23), (23, 19),
        (20, 21), (22, 23),
    ]
    edges = tuple(
        _edge(f"motif_e{i}", f"m{source}", f"m{target}", "KNOWS", since=2000 + i)
        for i, (source, target) in enumerate(pairs, 1)
    )
    return GraphSeedSpec(
        "motif_mix",
        "Disconnected motif corpus with a self-loop, reciprocal pair, triangle, cycle, diamond, path, and star.",
        nodes,
        edges,
        ("self_loop", "reciprocal_edges", "triangle", "cycle", "diamond", "disconnected"),
    )


def _schema_multirel() -> GraphSeedSpec:
    nodes = tuple(
        _node(f"s{i}", "Person", i, name=f"person_{i}", age=18 + (i % 61), score=i / 10.0)
        for i in range(1, 31)
    )
    edges = []
    for i in range(1, 31):
        target = 1 if i == 30 else i + 1
        edges.extend(
            [
                _edge(f"sm_k_{i}", f"s{i}", f"s{target}", "KNOWS", since=1990 + i),
                _edge(f"sm_l_{i}", f"s{i}", f"s{target}", "LIKES", weight=(i % 10) / 10.0),
                _edge(f"sm_b_{i}", f"s{i}", f"s{target}", "BLOCKS", active=(i % 2 == 0)),
            ]
        )
    return GraphSeedSpec(
        "schema_multirel",
        "Same endpoint schema connected by three independently typed relationship families.",
        nodes,
        tuple(edges),
        ("multi_relation_schema", "relationship_properties", "directed_cycle"),
    )


def _layered_path() -> GraphSeedSpec:
    nodes = [_node("src", "Source", 1, name="source")]
    layers = []
    next_id = 2
    for layer in range(5):
        current = []
        for lane in range(4):
            key = f"l{layer}_{lane}"
            current.append(key)
            nodes.append(_node(key, "LayerNode", next_id, layer=layer, lane=lane, score=float(layer * 4 + lane)))
            next_id += 1
        layers.append(current)
    nodes.append(_node("sink", "Sink", next_id, name="sink"))

    edges = []
    edge_id = 0
    for lane, target in enumerate(layers[0]):
        edge_id += 1
        edges.append(_edge(f"flow_{edge_id}", "src", target, "FLOW", weight=1.0, lane=lane))
    for left, right in zip(layers, layers[1:]):
        for source in left:
            for lane, target in enumerate(right):
                edge_id += 1
                edges.append(_edge(f"flow_{edge_id}", source, target, "FLOW", weight=1.0, lane=lane))
    for lane, source in enumerate(layers[-1]):
        edge_id += 1
        edges.append(_edge(f"flow_{edge_id}", source, "sink", "FLOW", weight=1.0, lane=lane))
    return GraphSeedSpec(
        "layered_path",
        "Five four-wide layers produce 1,024 distinct source-to-sink paths.",
        tuple(nodes),
        tuple(edges),
        ("path_explosion", "branching", "layered_dag", "high_path_cardinality"),
    )


def _degree_skew() -> GraphSeedSpec:
    nodes = [_node("hub", "Hub", 1, name="central", weight=1.0)]
    nodes.extend(
        _node(f"leaf{i}", "Leaf", i + 1, name=f"leaf_{i}", bucket=i % 8)
        for i in range(1, 65)
    )
    edges = []
    edge_id = 0
    for i in range(1, 65):
        edge_id += 1
        edges.append(_edge(f"link_{edge_id}", "hub", f"leaf{i}", "LINK", weight=1.0))
        edge_id += 1
        edges.append(_edge(f"link_{edge_id}", f"leaf{i}", "hub", "LINK", weight=0.5))
        edge_id += 1
        target = 1 if i == 64 else i + 1
        edges.append(_edge(f"link_{edge_id}", f"leaf{i}", f"leaf{target}", "LINK", weight=0.25))
    return GraphSeedSpec(
        "degree_skew",
        "Bidirectional 64-leaf hub plus a leaf ring stresses degree skew and cardinality estimation.",
        tuple(nodes),
        tuple(edges),
        ("high_degree", "degree_skew", "hub", "cycle"),
    )


def _dense_scc() -> GraphSeedSpec:
    nodes = tuple(
        _node(f"d{i}", "ClusterNode", i, cluster=0 if i <= 8 else 1, score=float(i))
        for i in range(1, 17)
    )
    pairs = []
    for component in (range(1, 9), range(9, 17)):
        for source in component:
            for target in component:
                if source != target:
                    pairs.append((source, target))
    pairs.extend([(1, 9), (9, 1), (4, 12), (12, 4)])
    edges = tuple(
        _edge(f"dense_{i}", f"d{source}", f"d{target}", "CONNECTS", weight=float((i % 7) + 1))
        for i, (source, target) in enumerate(pairs, 1)
    )
    return GraphSeedSpec(
        "dense_scc",
        "Two dense directed K8 components connected by four bridge edges.",
        nodes,
        edges,
        ("dense", "strongly_connected", "bridge_edges", "optimizer_stress"),
    )


def _theorem_mix() -> GraphSeedSpec:
    components = {}
    for node_id in range(1, 36):
        if node_id <= 5:
            component = "k23"
        elif node_id <= 9:
            component = "claw"
        elif node_id <= 15:
            component = "euler_cycle"
        elif node_id <= 25:
            component = "petersen"
        else:
            component = "disconnected_cycles"
        components[node_id] = component
    nodes = tuple(
        _node(f"v{i}", "Vertex", i, component=components[i], ordinal=i)
        for i in range(1, 36)
    )
    pairs = []
    pairs.extend((left, right) for left in (1, 2) for right in (3, 4, 5))
    pairs.extend([(6, 7), (6, 8), (6, 9), (6, 6)])
    cycle6 = [10, 11, 12, 13, 14, 15]
    for source, target in zip(cycle6, cycle6[1:] + cycle6[:1]):
        pairs.extend([(source, target), (target, source)])
    petersen_undirected = [
        (16, 17), (17, 18), (18, 19), (19, 20), (20, 16),
        (21, 23), (23, 25), (25, 22), (22, 24), (24, 21),
        (16, 21), (17, 22), (18, 23), (19, 24), (20, 25),
    ]
    for source, target in petersen_undirected:
        pairs.extend([(source, target), (target, source)])
    for cycle in ([26, 27, 28, 29, 30], [31, 32, 33, 34, 35]):
        for source, target in zip(cycle, cycle[1:] + cycle[:1]):
            pairs.extend([(source, target), (target, source)])
    edges = tuple(
        _edge(f"theorem_{i}", f"v{source}", f"v{target}", "LINK", weight=1.0)
        for i, (source, target) in enumerate(pairs, 1)
    )
    return GraphSeedSpec(
        "theorem_mix",
        "K2,3, claw, Euler cycle, Petersen graph, self-loop, and disconnected cycles.",
        nodes,
        edges,
        ("bipartite", "claw", "eulerian", "petersen", "self_loop", "disconnected"),
    )


def _property_cardinality() -> GraphSeedSpec:
    nodes = []
    for group in range(8):
        nodes.append(_node(f"g{group}", "Group", group + 1, name=f"group_{group}", bucket=group))
    next_id = 9
    for group in range(8):
        for position in range(6):
            properties: Dict[str, Scalar] = {
                "key": f"item_{group}_{position}",
                "category": f"c{position % 3}",
                "score": float((-1 if position % 2 else 1) * (group * 10 + position)),
            }
            if position != 1:
                properties["active"] = (position % 2 == 0)
            if position == 0:
                properties["text"] = ""
            elif position == 5:
                properties["text"] = "' OR 1=1"
            nodes.append(_node(f"i{group}_{position}", "Item", next_id, **properties))
            next_id += 1
    edges = []
    edge_id = 0
    for group in range(8):
        for position in range(6):
            item = f"i{group}_{position}"
            edge_id += 1
            edges.append(
                _edge(f"belongs_{edge_id}", item, f"g{group}", "BELONGS_TO", position=position)
            )
            if position < 5:
                edges.append(
                    _edge(f"next_{group}_{position}", item, f"i{group}_{position + 1}", "NEXT", distance=1)
                )
    return GraphSeedSpec(
        "property_cardinality",
        "Repeated, missing, empty, boundary, and low/high-cardinality properties across grouped chains.",
        tuple(nodes),
        tuple(edges),
        ("missing_properties", "boundary_values", "cardinality_skew", "grouped_chains"),
    )


def all_seed_profiles() -> Tuple[GraphSeedSpec, ...]:
    """Return the immutable built-in portfolio in stable catalog order."""

    return (
        _baseline(),
        _motif_mix(),
        _schema_multirel(),
        _layered_path(),
        _degree_skew(),
        _dense_scc(),
        _theorem_mix(),
        _property_cardinality(),
    )


def seed_profile(name: str) -> GraphSeedSpec:
    """Internal/test lookup; intentionally not exposed as a user configuration."""

    for profile in all_seed_profiles():
        if profile.name == name:
            return profile
    raise SeedSpecError(f"unknown internal seed profile: {name!r}")


def _cypher_literal(value: Scalar) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        # Kuzu's Cypher lexer rejects the optional '+' in Python's scientific
        # notation (for example ``-1e+308``), while all supported targets
        # accept the equivalent canonical form without it.
        return repr(value).replace("e+", "e").replace("E+", "E")
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _property_literal(properties: PropertyItems) -> str:
    return "{" + ", ".join(f"`{key}`: {_cypher_literal(value)}" for key, value in properties) + "}"


def render_shared_cypher(spec: GraphSeedSpec) -> Tuple[str, ...]:
    """Render independent OpenCypher statements with no cross-query variables."""

    nodes = {node.key: node for node in spec.nodes}
    statements = [
        f"CREATE (:`{node.label}` {_property_literal(node.properties)})"
        for node in spec.nodes
    ]
    for edge in spec.edges:
        source = nodes[edge.source]
        target = nodes[edge.target]
        source_id = source.property_map()["id"]
        target_id = target.property_map()["id"]
        rel_properties = f" {_property_literal(edge.properties)}" if edge.properties else ""
        statements.append(
            f"MATCH (s:`{source.label}` {{`id`: {source_id}}}), "
            f"(d:`{target.label}` {{`id`: {target_id}}}) "
            f"CREATE (s)-[:`{edge.rel_type}`{rel_properties}]->(d)"
        )
    return tuple(statements)


_KUZU_TYPES = {
    "BOOLEAN": "BOOLEAN",
    "INTEGER": "INT64",
    "FLOAT": "DOUBLE",
    "STRING": "STRING",
}


def render_kuzu(spec: GraphSeedSpec) -> Tuple[Tuple[str, ...], Tuple[str, ...]]:
    node_schema = spec.node_schema()
    relationship_schema = spec.relationship_schema()
    schema_statements = []
    for label, properties in node_schema.items():
        ordered = ["id"] + [key for key in properties if key != "id"]
        columns = ", ".join(f"`{key}` {_KUZU_TYPES[properties[key]]}" for key in ordered)
        schema_statements.append(
            f"CREATE NODE TABLE `{label}`({columns}, PRIMARY KEY (`id`))"
        )

    endpoint_groups: Dict[str, set[Tuple[str, str]]] = defaultdict(set)
    nodes = {node.key: node for node in spec.nodes}
    for edge in spec.edges:
        endpoint_groups[edge.rel_type].add((nodes[edge.source].label, nodes[edge.target].label))
    for rel_type, properties in relationship_schema.items():
        endpoints = sorted(endpoint_groups[rel_type])
        endpoint_sql = ", ".join(f"FROM `{source}` TO `{target}`" for source, target in endpoints)
        property_sql = "".join(
            f", `{key}` {_KUZU_TYPES[value_type]}" for key, value_type in properties.items()
        )
        group = " GROUP" if len(endpoints) > 1 else ""
        schema_statements.append(
            f"CREATE REL TABLE{group} `{rel_type}`({endpoint_sql}{property_sql})"
        )

    return tuple(schema_statements), render_shared_cypher(spec)


_NEBULA_TYPES = {
    "BOOLEAN": "bool",
    "INTEGER": "int",
    "FLOAT": "double",
    "STRING": "string",
}


def _ngql_literal(value: Scalar) -> str:
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    return _cypher_literal(value)


def render_nebula(
    spec: GraphSeedSpec, space: str
) -> Tuple[Tuple[str, ...], Tuple[str, ...]]:
    _validate_identifier(space, "NebulaGraph space")
    schema_statements = (
        f"DROP SPACE IF EXISTS `{space}`",
        f"CREATE SPACE IF NOT EXISTS `{space}`(vid_type=FIXED_STRING(64))",
        f"USE `{space}`",
        *(
            f"CREATE TAG IF NOT EXISTS `{label}`("
            + ", ".join(f"`{key}` {_NEBULA_TYPES[value_type]}" for key, value_type in properties.items())
            + ")"
            for label, properties in spec.node_schema().items()
        ),
        *(
            f"CREATE EDGE IF NOT EXISTS `{rel_type}`("
            + ", ".join(f"`{key}` {_NEBULA_TYPES[value_type]}" for key, value_type in properties.items())
            + ")"
            for rel_type, properties in spec.relationship_schema().items()
        ),
    )

    data_statements = [f"USE `{space}`"]
    node_groups: Dict[Tuple[str, Tuple[str, ...]], list[SeedNode]] = defaultdict(list)
    for node in spec.nodes:
        node_groups[(node.label, tuple(key for key, _ in node.properties))].append(node)
    for (label, property_names), group in sorted(node_groups.items()):
        columns = ", ".join(f"`{key}`" for key in property_names)
        values = []
        for node in group:
            property_map = node.property_map()
            row = ", ".join(_ngql_literal(property_map[key]) for key in property_names)
            values.append(f"{json.dumps(node.key)}:({row})")
        data_statements.append(
            f"INSERT VERTEX `{label}`({columns}) VALUES " + ", ".join(values)
        )

    edge_groups: Dict[Tuple[str, Tuple[str, ...]], list[SeedEdge]] = defaultdict(list)
    for edge in spec.edges:
        edge_groups[(edge.rel_type, tuple(key for key, _ in edge.properties))].append(edge)
    ranks: Dict[Tuple[str, str, str], int] = defaultdict(int)
    for (rel_type, property_names), group in sorted(edge_groups.items()):
        columns = ", ".join(f"`{key}`" for key in property_names)
        values = []
        for edge in group:
            triple = (edge.source, edge.target, edge.rel_type)
            rank = ranks[triple]
            ranks[triple] += 1
            property_map = edge.property_map()
            row = ", ".join(_ngql_literal(property_map[key]) for key in property_names)
            values.append(
                f"{json.dumps(edge.source)}->{json.dumps(edge.target)}@{rank}:({row})"
            )
        data_statements.append(
            f"INSERT EDGE `{rel_type}`({columns}) VALUES " + ", ".join(values)
        )
    return tuple(schema_statements), tuple(data_statements)


def statements_as_script(statements: Iterable[str]) -> str:
    return "\n".join(statement.rstrip(";") + ";" for statement in statements if statement.strip())

