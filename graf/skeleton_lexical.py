"""Target-neutral, mechanical checks for a single placeholder skeleton.

This lexer deliberately does not decide whether a target accepts a dialect.
Only the target's side-effect-free compile step can make that decision.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_INDEXED = re.compile(r"(?:LABEL|REL|DEPTH|N|PROP|VALUE|PREDICATE|RETURN_EXPR|LIST)_[1-9][0-9]*\Z")
_SCOPED = re.compile(r"(?:PREDICATE_FOR|RETURN_EXPR_FOR)_v[1-9][0-9]*\Z")
_WORD = re.compile(r"[A-Za-z_][A-Za-z_0-9]*")
_ROLE = re.compile(r"([nrpv])[1-9][0-9]*\Z")


@dataclass(frozen=True)
class MechanicalResult:
    accepted: bool
    reason: str = ""
    normalized: str = ""
    canonical: str = ""


def split_statements(content: str) -> list[str]:
    """Split a pool without treating semicolons in literals as delimiters."""
    statements, start, index = [], 0, 0
    quote = None
    line_comment = block_comment = False
    while index < len(content):
        char = content[index]
        following = content[index + 1] if index + 1 < len(content) else ""
        if line_comment:
            if char == "\n":
                line_comment = False
        elif block_comment:
            if char == "*" and following == "/":
                block_comment = False
                index += 1
        elif quote:
            if char == "\\" and quote != "`":
                index += 1
            elif char == quote:
                if following == quote:
                    index += 1
                else:
                    quote = None
        elif char == "/" and following in {"/", "*"}:
            line_comment = following == "/"
            block_comment = following == "*"
            index += 1
        elif char in {"'", '"', "`"}:
            quote = char
        elif char == ";":
            part = content[start:index].strip()
            if part:
                statements.append(part + ";")
            start = index + 1
        index += 1
    if quote or block_comment:
        raise ValueError("unterminated quoted literal or comment in pool")
    tail = content[start:].strip()
    if tail:
        statements.append(tail + ";")
    return statements


def check_skeleton(query: str, *, max_bytes: int = 20_000) -> MechanicalResult:
    """Check size, placeholder spelling, quoting and statement boundaries.

    Preserve string contents and identifier spelling. Renumber only known
    placeholder suffixes and generated n/r/p/v roles for diversity profiling.
    """
    source = (query or "").strip()
    if not source:
        return MechanicalResult(False, "empty skeleton")
    if len(source.encode("utf-8")) > max_bytes:
        return MechanicalResult(False, f"skeleton exceeds {max_bytes} bytes")
    tokens: list[str] = []
    index = 0
    semicolons = []
    placeholders = 0
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if char.isspace():
            index += 1
            continue
        if char == "/" and following in {"/", "*"}:
            if following == "/":
                end = source.find("\n", index + 2)
                index = len(source) if end < 0 else end
            else:
                end = source.find("*/", index + 2)
                if end < 0:
                    return MechanicalResult(False, "unterminated comment")
                index = end + 2
            continue
        if char in {"'", '"', "`"}:
            start = index
            quote = char
            index += 1
            terminated = False
            while index < len(source):
                if source[index] == "\\" and quote != "`":
                    index += 2
                elif source[index] == quote:
                    if index + 1 < len(source) and source[index + 1] == quote:
                        index += 2
                    else:
                        index += 1
                        terminated = True
                        break
                else:
                    index += 1
            if not terminated:
                return MechanicalResult(False, "unterminated quoted literal or identifier")
            token = source[start:index]
            if "$" in token:
                return MechanicalResult(False, "placeholder embedded in literal or quoted identifier")
            tokens.append(token)
            continue
        if char == "$":
            match = _WORD.match(source, index + 1)
            if not match or not (_INDEXED.fullmatch(match.group()) or _SCOPED.fullmatch(match.group())):
                return MechanicalResult(False, f"invalid or deprecated placeholder at offset {index}")
            if match.end() < len(source) and (source[match.end()].isalnum() or source[match.end()] == "_"):
                return MechanicalResult(False, "malformed placeholder boundary")
            tokens.append("$" + match.group())
            placeholders += 1
            index = match.end()
            continue
        match = _WORD.match(source, index)
        if match:
            tokens.append(match.group())
            index = match.end()
            continue
        if char == ";":
            semicolons.append(len(tokens))
        tokens.append(char)
        index += 1
    if tokens and tokens[0].upper() in {"EXPLAIN", "PROFILE"}:
        return MechanicalResult(False, "skeleton starts with EXPLAIN/PROFILE; expected an executable query")
    if not placeholders:
        return MechanicalResult(False, "no valid placeholder")
    if len(semicolons) > 1 or (semicolons and semicolons[0] != len(tokens) - 1):
        return MechanicalResult(False, "expected exactly one statement")
    normalized = source.rstrip(";").strip() + ";"
    groups: dict[str, dict[str, int]] = {}
    canonical = []
    for token in tokens:
        if token == ";":
            continue
        if token.startswith("$"):
            name = token[1:]
            if "_FOR_v" in name:
                group, suffix = name.rsplit("_v", 1)
                role_map = groups.setdefault("ROLE_v", {})
                suffix = str(role_map.setdefault("v" + suffix, len(role_map) + 1))
            else:
                group, suffix = name.rsplit("_", 1)
            mapping = groups.setdefault("PH_" + group, {})
            canonical.append(f"${group}_{mapping.setdefault(suffix, len(mapping) + 1)}")
        elif _ROLE.fullmatch(token):
            role = token[0]
            mapping = groups.setdefault("ROLE_" + role, {})
            canonical.append(f"{role}_{mapping.setdefault(token, len(mapping) + 1)}")
        else:
            canonical.append(token)
    return MechanicalResult(True, normalized=normalized, canonical=" ".join(canonical))
