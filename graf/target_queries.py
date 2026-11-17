from __future__ import annotations

import re


def prepare_target_query(target: str, query: str) -> str:
    """Apply the minimum syntax-only adaptation required by a target.

    Validation and execution must see the same statement.  This adapter is
    deliberately forbidden from changing projections, ordering expressions,
    predicates, or other semantics.
    """

    if (target or "").lower() != "nebula":
        return query
    return _nebula_equality_syntax(query)


def _nebula_equality_syntax(query: str) -> str:
    """Translate Cypher equality ``=`` to nGQL ``==`` outside literals.

    Existing ``==``, ``!=``, ``<=``, ``>=`` and regex ``=~`` operators are
    retained. Quoted strings and backtick identifiers are copied byte-for-byte.
    """

    source = str(query or "")
    # nGQL update assignments and schema DEFAULT clauses use a single `=`.
    # Rewriting those statements as comparisons corrupts valid native DML.
    # LLM-produced native statements must already spell comparisons as `==`.
    if re.match(r"^\s*(?:UPDATE|UPSERT|INSERT|DELETE|CREATE|ALTER|DROP|REBUILD|CLEAR)\b",
                source, re.IGNORECASE):
        return source
    output: list[str] = []
    quote = ""
    escaped = False
    index = 0
    while index < len(source):
        char = source[index]
        if quote:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\" and quote in {"'", '"'}:
                escaped = True
            elif char == quote:
                quote = ""
            index += 1
            continue

        if char in {"'", '"', "`"}:
            quote = char
            output.append(char)
            index += 1
            continue

        if char == "=":
            previous = source[index - 1] if index else ""
            following = source[index + 1] if index + 1 < len(source) else ""
            if previous not in {"<", ">", "!", "="} and following not in {"=", "~"}:
                output.append("==")
                index += 1
                continue

        output.append(char)
        index += 1
    return "".join(output)
