from __future__ import annotations

import dataclasses
import enum
import hashlib
import json
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, MutableMapping, Optional


class ValueType(str, enum.Enum):
    INTEGER = "INTEGER"
    FLOAT = "FLOAT"
    STRING = "STRING"
    BOOLEAN = "BOOLEAN"
    LIST = "LIST"
    MAP = "MAP"
    NULL = "NULL"
    NODE = "NODE"
    RELATIONSHIP = "RELATIONSHIP"
    PATH = "PATH"
    ANY = "ANY"

    @classmethod
    def normalize(cls, value: Any) -> "ValueType":
        text = str(value or "ANY").upper()
        if "BOOL" in text:
            return cls.BOOLEAN
        if any(token in text for token in ("INT", "LONG")):
            return cls.INTEGER
        if any(token in text for token in ("FLOAT", "DOUBLE", "DECIMAL")):
            return cls.FLOAT
        if any(token in text for token in ("STRING", "TEXT", "CHAR")):
            return cls.STRING
        if "LIST" in text or "ARRAY" in text:
            return cls.LIST
        if "MAP" in text or "OBJECT" in text:
            return cls.MAP
        if "NODE" in text:
            return cls.NODE
        if "REL" in text or "EDGE" in text:
            return cls.RELATIONSHIP
        if "PATH" in text:
            return cls.PATH
        return cls.ANY


class OperatorKind(str, enum.Enum):
    TOPOLOGY = "topology"
    DEPTH_VOLUME = "depth_volume"
    PREDICATE = "predicate"
    CLAUSE = "clause"
    VALUE = "value"


class MutationDirective(str, enum.Enum):
    EXPLORE = "explore"
    RELAX = "relax"
    DECREASE_COST = "decrease_cost"
    INCREASE_COST = "increase_cost"
    LOCALIZE = "localize"


class MutationStatus(str, enum.Enum):
    APPLIED = "applied"
    NO_MATCH = "no_match"
    REJECTED = "rejected"
    ERROR = "error"


@dataclass(frozen=True)
class EdgeSpec:
    source_label: str
    relationship_type: str
    target_label: str


@dataclass(frozen=True)
class PropertySpec:
    owner: str
    name: str
    value_type: ValueType


@dataclass
class SchemaView:
    labels: set[str] = field(default_factory=set)
    edges: tuple[EdgeSpec, ...] = ()
    properties: dict[str, dict[str, ValueType]] = field(default_factory=dict)
    observed_values: dict[tuple[str, str], tuple[Any, ...]] = field(default_factory=dict)
    topology_by_source: dict[str, tuple[EdgeSpec, ...]] = field(default_factory=dict)
    topology_by_pair: dict[tuple[str, str], tuple[EdgeSpec, ...]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.edges = tuple(
            sorted(
                set(self.edges),
                key=lambda item: (item.source_label, item.relationship_type, item.target_label),
            )
        )
        self.properties = {
            owner: {name: values[name] for name in sorted(values)}
            for owner, values in sorted(self.properties.items())
        }
        self.observed_values = {
            key: tuple(values)
            for key, values in sorted(self.observed_values.items())
        }
        by_source: MutableMapping[str, list[EdgeSpec]] = {}
        by_pair: MutableMapping[tuple[str, str], list[EdgeSpec]] = {}
        for edge in self.edges:
            by_source.setdefault(edge.source_label, []).append(edge)
            by_pair.setdefault((edge.source_label, edge.target_label), []).append(edge)
        self.topology_by_source = {key: tuple(value) for key, value in sorted(by_source.items())}
        self.topology_by_pair = {key: tuple(value) for key, value in sorted(by_pair.items())}

    @classmethod
    def from_legacy(cls, schema: Any, state: Any = None) -> "SchemaView":
        def read(obj: Any, name: str, default: Any) -> Any:
            if obj is None:
                return default
            if isinstance(obj, Mapping):
                return obj.get(name, default)
            return getattr(obj, name, default)

        labels = {str(value) for value in read(schema, "labels", set()) if value}
        raw_topology = read(schema, "topology", {}) or {}
        edges: list[EdgeSpec] = []
        for key, raw_pairs in raw_topology.items():
            pairs = sorted(raw_pairs.items()) if isinstance(raw_pairs, Mapping) else sorted(raw_pairs or ())
            for pair in pairs or ():
                if not isinstance(pair, (tuple, list)) or len(pair) != 2:
                    continue
                first, second = str(pair[0]), str(pair[1])
                # Runtime extractors use rel_type -> {(source, target)}.  The
                # legacy mutator used source -> [(rel_type, target)].
                if key in labels:
                    source, rel_type, target = str(key), first, second
                else:
                    source, rel_type, target = first, str(key), second
                edges.append(EdgeSpec(source, rel_type, target))
                labels.update((source, target))

        properties: dict[str, dict[str, ValueType]] = {}
        for owner, raw_props in (read(schema, "properties", {}) or {}).items():
            owner_name = str(owner)
            properties[owner_name] = {}
            if isinstance(raw_props, Mapping):
                for name, value_type in raw_props.items():
                    properties[owner_name][str(name)] = ValueType.normalize(value_type)
            else:
                for name in raw_props or ():
                    properties[owner_name][str(name)] = ValueType.ANY

        observed: dict[tuple[str, str], tuple[Any, ...]] = {}
        raw_values = read(state, "property_values", None) or read(schema, "property_values", {}) or {}
        for owner_or_prop, nested in raw_values.items():
            if isinstance(nested, Mapping):
                for prop, values in nested.items():
                    if isinstance(values, set):
                        sequence = sorted(values, key=lambda item: (type(item).__name__, repr(item)))
                    else:
                        sequence = values if isinstance(values, (list, tuple)) else [values]
                    observed[(str(owner_or_prop), str(prop))] = tuple(sequence)
            else:
                if isinstance(nested, set):
                    sequence = sorted(nested, key=lambda item: (type(item).__name__, repr(item)))
                else:
                    sequence = nested if isinstance(nested, (list, tuple)) else [nested]
                for owner, owner_props in properties.items():
                    if str(owner_or_prop) in owner_props:
                        observed[(owner, str(owner_or_prop))] = tuple(sequence)

        unique_edges = tuple(
            sorted(
                set(edges),
                key=lambda item: (item.source_label, item.relationship_type, item.target_label),
            )
        )
        return cls(labels=labels, edges=unique_edges, properties=properties, observed_values=observed)

    def properties_for(self, owner: Optional[str]) -> tuple[PropertySpec, ...]:
        if not owner:
            return ()
        return tuple(
            PropertySpec(owner=owner, name=name, value_type=value_type)
            for name, value_type in sorted(self.properties.get(owner, {}).items())
        )

    def observed_for(self, owner: str, prop: str) -> tuple[Any, ...]:
        return self.observed_values.get((owner, prop), ())

    def to_snapshot(self) -> dict[str, Any]:
        return {
            "schema": "graf-enterprise-context/v1",
            "labels": sorted(self.labels),
            "edges": [
                {
                    "source_label": edge.source_label,
                    "relationship_type": edge.relationship_type,
                    "target_label": edge.target_label,
                }
                for edge in sorted(
                    self.edges,
                    key=lambda item: (item.source_label, item.relationship_type, item.target_label),
                )
            ],
            "properties": {
                owner: {name: value_type.value for name, value_type in sorted(properties.items())}
                for owner, properties in sorted(self.properties.items())
            },
            "observed_values": [
                {"owner": owner, "property": prop, "values": list(values)}
                for (owner, prop), values in sorted(self.observed_values.items())
            ],
        }

    @classmethod
    def from_snapshot(cls, snapshot: Mapping[str, Any]) -> "SchemaView":
        edges = tuple(
            EdgeSpec(
                str(item["source_label"]),
                str(item["relationship_type"]),
                str(item["target_label"]),
            )
            for item in snapshot.get("edges", ())
        )
        properties = {
            str(owner): {str(name): ValueType.normalize(value_type) for name, value_type in values.items()}
            for owner, values in snapshot.get("properties", {}).items()
        }
        observed = {
            (str(item["owner"]), str(item["property"])): tuple(item.get("values", ()))
            for item in snapshot.get("observed_values", ())
        }
        return cls(
            labels={str(label) for label in snapshot.get("labels", ())},
            edges=edges,
            properties=properties,
            observed_values=observed,
        )


@dataclass(frozen=True)
class GraphStats:
    node_count: int = 0
    edge_count: int = 0
    estimated_diameter: int = 5

    @classmethod
    def from_legacy(cls, state: Any) -> "GraphStats":
        def read(*names: str, default: int = 0) -> int:
            for name in names:
                if isinstance(state, Mapping) and name in state:
                    return int(state[name] or 0)
                if state is not None and hasattr(state, name):
                    return int(getattr(state, name) or 0)
            return default

        nodes = read("node_count", "total_nodes")
        edges = read("edge_count", "total_edges")
        explicit = read("diameter", "estimated_diameter")
        if explicit > 0:
            diameter = explicit
        elif nodes <= 1 or edges <= 0:
            diameter = 1
        else:
            # A conservative cap is preferable to pretending that log(V)/log(d)
            # is an exact graph diameter.  The value is only a mutation budget.
            avg_out = max(edges / max(nodes, 1), 1.0)
            diameter = max(2, min(nodes, int(round(nodes ** (1.0 / max(avg_out, 1.0)))) + 2, 16))
        return cls(max(nodes, 0), max(edges, 0), max(diameter, 1))

    @property
    def safe_limit(self) -> int:
        return max(10, min(10_000, max(self.node_count, 1) * 2))


@dataclass(frozen=True)
class VariableBinding:
    name: str
    value_type: ValueType = ValueType.ANY
    entity_name: Optional[str] = None
    nullable: bool = False
    origin_token: int = -1


@dataclass
class ClauseScope:
    clause_kind: str
    start_token: int
    stop_token: int
    before: dict[str, VariableBinding] = field(default_factory=dict)
    after: dict[str, VariableBinding] = field(default_factory=dict)
    context: Any = None


@dataclass(frozen=True)
class ValidationIssue:
    stage: str
    code: str
    message: str
    line: Optional[int] = None
    column: Optional[int] = None


@dataclass
class ValidationResult:
    valid: bool
    issues: list[ValidationIssue] = field(default_factory=list)
    normalized_query: str = ""
    target_checked: bool = False
    target_message: str = ""
    # The target compiled the statement, but the local Cypher grammar could
    # not build a safe AST. Such parents are executable without AST mutation.
    native_only: bool = False

    @classmethod
    def success(cls, query: str, *, target_checked: bool = False, target_message: str = "") -> "ValidationResult":
        return cls(True, normalized_query=query, target_checked=target_checked, target_message=target_message)


@dataclass
class MutationResult:
    status: MutationStatus
    parent_query: str
    query: str
    operator: Optional[OperatorKind] = None
    action: str = ""
    seed_id: str = ""
    mutation_id: str = ""
    attempt_count: int = 0
    candidate_count: int = 0
    directive: MutationDirective = MutationDirective.EXPLORE
    metadata: dict[str, Any] = field(default_factory=dict)
    validation: Optional[ValidationResult] = None
    error: str = ""

    def __post_init__(self) -> None:
        if not self.seed_id:
            self.seed_id = query_digest(self.parent_query)
        if not self.mutation_id:
            material = f"{self.seed_id}|{self.operator}|{self.action}|{self.query}"
            self.mutation_id = hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]

    @property
    def applied(self) -> bool:
        return self.status == MutationStatus.APPLIED

    def to_dict(self) -> dict[str, Any]:
        return to_jsonable(self)


def query_digest(query: str) -> str:
    canonical = " ".join((query or "").split())
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24]


def to_jsonable(value: Any) -> Any:
    if dataclasses.is_dataclass(value):
        payload = {
            field.name: to_jsonable(getattr(value, field.name))
            for field in dataclasses.fields(value)
        }
        # Mutation IR is persisted in journals and audit artifacts.  Preserve
        # its discriminated-union type across JSON instead of relying on the
        # in-memory Python class name, which would be lost after serialization.
        if type(value).__module__.endswith(".ir"):
            return {"ir_type": type(value).__name__, **payload}
        return payload
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (set, frozenset)):
        return [
            to_jsonable(item)
            for item in sorted(value, key=lambda item: (type(item).__name__, repr(item)))
        ]
    if isinstance(value, (list, tuple, deque)):
        return [to_jsonable(item) for item in value]
    return value


def stable_json(value: Any) -> str:
    return json.dumps(to_jsonable(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
