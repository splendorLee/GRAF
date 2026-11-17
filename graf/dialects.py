from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Pattern


@dataclass(frozen=True)
class DialectCapabilities:
    name: str
    identifier_quote: str = "`"
    supports_optional_match: bool = True
    supports_call_subquery: bool = False
    supports_exists_subquery: bool = False
    supports_with_aggregation: bool = True
    supports_variable_length: bool = True
    supports_explain: bool = True
    max_path_bound: int = 12
    unsupported_patterns: tuple[tuple[Pattern[str], str], ...] = ()

    def quote(self, identifier: str) -> str:
        quote = self.identifier_quote
        escaped = str(identifier).replace(quote, quote + quote)
        return f"{quote}{escaped}{quote}"


def _patterns(items: tuple[tuple[str, str], ...]) -> tuple[tuple[Pattern[str], str], ...]:
    return tuple((re.compile(pattern, re.IGNORECASE), message) for pattern, message in items)


_COMMON = _patterns(
    (
        (r"\bLOAD\s+CSV\b", "external I/O is disabled in the fuzzing profile"),
        (r"\bUSING\s+PERIODIC\s+COMMIT\b", "transactional bulk loading is disabled"),
    )
)


DIALECTS: dict[str, DialectCapabilities] = {
    "generic": DialectCapabilities("generic", unsupported_patterns=_COMMON),
    "neo4j": DialectCapabilities(
        "neo4j",
        supports_call_subquery=True,
        supports_exists_subquery=True,
        max_path_bound=16,
        unsupported_patterns=_COMMON,
    ),
    "memgraph": DialectCapabilities(
        "memgraph",
        supports_call_subquery=True,
        supports_exists_subquery=True,
        max_path_bound=12,
        unsupported_patterns=_COMMON
        + _patterns(((r"\bapoc\.", "APOC is not part of the Memgraph dialect profile"),)),
    ),
    "falkordb": DialectCapabilities(
        "falkordb",
        supports_call_subquery=False,
        supports_exists_subquery=False,
        max_path_bound=10,
        unsupported_patterns=_COMMON
        + _patterns(
            (
                (r"\bapoc\.", "APOC procedures are unavailable on FalkorDB"),
                (r"\bCALL\s*\{", "CALL subqueries are disabled for FalkorDB"),
                (r"\b(?:NOT\s+)?EXISTS\s*\{", "EXISTS subqueries are disabled for FalkorDB"),
            )
        ),
    ),
    "kuzu": DialectCapabilities(
        "kuzu",
        supports_call_subquery=False,
        supports_exists_subquery=False,
        max_path_bound=8,
        unsupported_patterns=_COMMON
        + _patterns(((r"\bapoc\.", "APOC procedures are unavailable on Kuzu"),)),
    ),
    "nebula": DialectCapabilities(
        "nebula",
        supports_optional_match=True,
        supports_call_subquery=False,
        supports_exists_subquery=False,
        supports_with_aggregation=True,
        max_path_bound=5,
        unsupported_patterns=_COMMON
        + _patterns(
            (
                (r"\bapoc\.", "APOC procedures are unavailable on NebulaGraph"),
                (r"\bDETACH\s+DELETE\b", "DETACH DELETE is outside the NebulaGraph profile"),
            )
        ),
    ),
}


def get_dialect(name: str) -> DialectCapabilities:
    return DIALECTS.get((name or "generic").lower(), DIALECTS["generic"])
