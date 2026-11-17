from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import math
import os
import re
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit

from graf.skeleton_paths import DEFAULT_GENERATED_DIR, raw_path, target_name


class ProviderResponseError(RuntimeError):
    def __init__(self, message: str, *, retryable: bool = False,
                 retry_after: float = 0.0):
        super().__init__(message)
        self.retryable = retryable
        self.retry_after = retry_after


def _safe(value: object, api_key: str = "") -> str:
    message = str(value).replace(api_key, "[REDACTED]") if api_key else str(value)
    return re.sub(r"(?i)Bearer\s+\S+", "Bearer [REDACTED]", message)[:400]


def validated_retry_config(config: dict) -> dict:
    retries = config.get("max_retries", 8)
    if not isinstance(retries, int) or isinstance(retries, bool) or not 0 <= retries <= 100:
        raise ValueError("max_retries must be an integer between 0 and 100")
    values = {}
    for name, default in (("retry_initial_seconds", 30), ("retry_max_seconds", 300),
                          ("retry_max_wait_seconds", 1800)):
        try:
            value = float(config.get(name, default))
        except (ValueError, TypeError):
            raise ValueError(f"{name} must be a finite number") from None
        if not math.isfinite(value):
            raise ValueError(f"{name} must be a finite number")
        values[name] = value
    if not 0 < values["retry_initial_seconds"] <= values["retry_max_seconds"] <= 3600:
        raise ValueError("Invalid retry delay bounds")
    if not 0 <= values["retry_max_wait_seconds"] <= 86400:
        raise ValueError("Invalid retry wait budget")
    return {"max_retries": retries, **values}


def error_from_payload(payload: object, status: int, headers, api_key: str) -> ProviderResponseError:
    error = payload.get("error", payload) if isinstance(payload, dict) else {}
    code = error.get("code", "") if isinstance(error, dict) else ""
    code = _safe(code, api_key)
    transient = {"upstream_rate_limit", "rate_limit_exceeded", "resource_exhausted",
                 "overloaded", "server_overloaded", "service_unavailable"}
    permanent = {"insufficient_quota", "insufficient_balance", "invalid_api_key"}
    retryable = (status in {408, 429, 500, 502, 503, 504} or
                 status == 200 and code.casefold() in transient)
    if code.casefold() in permanent:
        retryable = False
    retry_after = 0.0
    if headers is not None:
        try:
            retry_after = max(0.0, float(headers.get("Retry-After", "0")))
        except (ValueError, TypeError):
            pass
    return ProviderResponseError(
        f"Provider HTTP {status}" + (f"; error_code={code}" if code else ""),
        retryable=retryable, retry_after=retry_after)


def request_with_retries(request: urllib.request.Request, config: dict, decoder) -> dict:
    attempts = config["max_retries"] + 1
    waited = 0.0
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(request, timeout=config["timeout_seconds"]) as reply:
                return decoder(reply)
        except urllib.error.HTTPError as error:
            try:
                raw = error.read(16384)
                try:
                    payload = json.loads(raw)
                except (ValueError, UnicodeDecodeError):
                    payload = {}
                failure = error_from_payload(payload, error.code, error.headers, config["api_key"])
            finally:
                error.close()
        except ProviderResponseError as error:
            failure = error
        except (urllib.error.URLError, TimeoutError):
            failure = ProviderResponseError("Provider transport or timeout error", retryable=True)
        if not failure.retryable or attempt == attempts - 1:
            raise ProviderResponseError(
                f"{_safe(failure, config['api_key'])}; attempts={attempt + 1}") from None
        delay = max(min(config["retry_initial_seconds"] * 2 ** attempt,
                        config["retry_max_seconds"]), failure.retry_after)
        if delay + waited > config["retry_max_wait_seconds"]:
            raise ProviderResponseError(
                f"{_safe(failure, config['api_key'])}; retry wait budget exhausted") from None
        print(f"Provider retry {attempt + 1}/{attempts - 1} after {delay:g}s: "
              f"{_safe(failure, config['api_key'])}", file=sys.stderr, flush=True)
        time.sleep(delay)
        waited += delay
    raise AssertionError("Retry loop exhausted")

CATEGORIES = (
    "Deep Path Traversals and Topological Patterns",
    "Aggregations, Grouping, and Ordering",
    "List Comprehensions and Pipeline Unwinding",
    "Predicate Functions and Graph Iterators",
    "Scalar, String, and Mathematical Built-in Functions",
    "Control Flow Subqueries and Branches",
    "Set Operations and Multiple Queries",
    "Property Mutation and Label DML",
    "Graph Topology DML",
    "Destructive DML and Cascading Deletions",
)
PROMPT_TEMPLATE = """Task: You are a graph database expert generating parameterized
Cypher skeletons for [gdbms].
Requirements:
1) Dialect Strictness: Output valid query skeletons strictly conform-
ing to the [gdbms] dialect. Do not use generic Cypher or Neo4j-
exclusive features unless officially supported by [gdbms].
2) Abstraction: Do NOT fill concrete data values. Use placeholders
exclusively. The skeleton generated in the current batch must not
duplicate what was generated previously.
3) Scope Tracking: Standardize identifiers strictly to ensure the
fuzzer can correctly trace data dependencies and variable scopes:
• Nodes: n1, n2, . . .
• Relationships: r1, r2, . . .
• Paths: p1, p2, . . .
• Aliases/Iterators: v1, v2, . . .
4) Placeholders: Use the following base placeholders and append
numeric suffixes (e.g., _1, _2) to represent distinct bindings:
• $LABEL_i, $REL_i: Node label and relationship type;
• $PROP_i, $VALUE_i: Properties and values;
• $N_i, $DEPTH_i: Numerics/range bound and path bounds;
• $PREDICATE_i:
Boolean condition over currently bound variables;
• $RETURN_EXPR_i:
Return expression over currently bound variables;
• $PREDICATE_FOR_v:
Condition scoped to iteration variable v;
• $RETURN_EXPR_FOR_v:
Expression scoped to iteration variable v.
Output: Generate **500** [gdbms]-compatible diversely Cypher skeletons
that focused on [structural complexity and grammatical diversity].
Output EXACTLY one skeleton per line."""

LINES_PER_CATEGORY = 500
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
FORMAT_VERSION = "graf-raw-ten-batches/v2"


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def render_prompt(gdbms: str, category: str) -> str:
    if category not in CATEGORIES:
        raise ValueError("Unknown category")
    if not isinstance(gdbms, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.+-]*", gdbms):
        raise ValueError("--gdbms must name the target DBMS, e.g. NebulaGraph")
    return (PROMPT_TEMPLATE.replace("[gdbms]", gdbms)
            .replace("[structural complexity and grammatical diversity]", category))


def load_config(path: Path) -> dict:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("Config must be a JSON object")
    for key in ("base_url", "api_key", "model"):
        if not isinstance(raw.get(key), str) or not raw[key].strip() or raw[key].startswith("YOUR_"):
            raise ValueError(f"Config requires a real {key}")
    if raw.get("api_mode", "chat_completions") != "chat_completions":
        raise ValueError("Only api_mode=chat_completions is supported")
    url = urlsplit(raw["base_url"].rstrip("/"))
    if ((url.scheme != "https" and
         not (url.scheme == "http" and url.hostname in {"localhost", "127.0.0.1"}))
            or not url.netloc or url.username or url.password or url.query or url.fragment):
        raise ValueError("base_url must be HTTPS or local HTTP, without credentials")
    if url.path.endswith(("/chat/completions", "/chat_completions")):
        raise ValueError("base_url must omit the chat completion path")
    suffix = raw.get("chat_completions_path", "/chat/completions")
    if (not isinstance(suffix, str) or
            not re.fullmatch(r"/[A-Za-z0-9_./~-]+", suffix) or
            "//" in suffix or any(part in {".", ".."} for part in suffix.split("/"))):
        raise ValueError("Invalid chat_completions_path")
    defaults = {"max_output_tokens": 32768, "timeout_seconds": 600,
                "max_requests": 1000, "max_stagnant_calls": 8}
    for key, default in defaults.items():
        value = raw.get(key, default)
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ValueError(f"{key} must be a positive integer")
    try:
        temperature = float(raw.get("temperature", 1.0))
    except (ValueError, TypeError):
        raise ValueError("temperature must be between 0 and 2") from None
    if not 0 <= temperature <= 2:
        raise ValueError("temperature must be between 0 and 2")
    return {**raw, "base_url": raw["base_url"].rstrip("/"),
            "chat_completions_path": suffix, "temperature": temperature,
            **{key: raw.get(key, default) for key, default in defaults.items()},
            **validated_retry_config(raw)}


def request_completion(config: dict, prompt: str) -> dict:
    """Send the rendered template as the sole user message."""
    payload = {"model": config["model"], "temperature": config["temperature"],
               "stream": False, "messages": [{"role": "user", "content": prompt}],
               "max_tokens": config["max_output_tokens"]}
    if config.get("reasoning_effort"):
        payload["reasoning_effort"] = config["reasoning_effort"]
    request = urllib.request.Request(
        config["base_url"] + config["chat_completions_path"],
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Authorization": "Bearer " + config["api_key"],
                 "Content-Type": "application/json"}, method="POST")

    def decode(response) -> dict:
        body = response.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            raise ProviderResponseError("Provider response exceeded 16 MiB")
        try:
            result = json.loads(body)
        except (ValueError, UnicodeDecodeError):
            raise ProviderResponseError("Provider returned invalid JSON", retryable=True) from None
        if not isinstance(result, dict):
            raise ProviderResponseError("Provider response must be a JSON object")
        if "error" in result:
            raise error_from_payload(result, 200, response.headers, config["api_key"])
        choices = result.get("choices")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
            raise ProviderResponseError("Provider response has no chat completion choice")
        return result

    return request_with_retries(request, config, decode)


def extract_lines(response: dict) -> list[str]:
    """Only split physical nonempty lines; never inspect or deduplicate Cypher."""
    choice = response["choices"][0]
    content = choice.get("message", {}).get("content")
    if not isinstance(content, str):
        raise ValueError("Model message content must be a string")
    reason = choice.get("finish_reason")
    if reason not in (None, "stop", "length", "max_tokens", "max_output_tokens"):
        raise ValueError(f"Model stopped without usable output: {reason}")
    normalized = content.replace("\r\n", "\n").replace("\r", "\n")
    if reason in ("length", "max_tokens", "max_output_tokens"):
        if normalized and not normalized.endswith(("\n", ";")):
            normalized = normalized.rsplit("\n", 1)[0] if "\n" in normalized else ""
    return [line.strip() for line in normalized.split("\n") if line.strip()]


def atomic(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


@contextmanager
def locked(directory: Path):
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / ".generator.lock").open("a+b") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError(f"Generation already running in {directory}") from None
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def manifest_for(config: dict, gdbms: str) -> dict:
    return {"format": FORMAT_VERSION, "gdbms": gdbms,
            "categories": list(CATEGORIES), "lines_per_category": LINES_PER_CATEGORY,
            "prompt_sha256": digest(PROMPT_TEMPLATE), "base_url": config["base_url"],
            "chat_completions_path": config["chat_completions_path"],
            "model": config["model"], "temperature": config["temperature"],
            "max_output_tokens": config["max_output_tokens"],
            "reasoning_effort": config.get("reasoning_effort")}


class State:
    def __init__(self, manifest: dict):
        self.manifest = manifest
        self.groups: list[list[str]] = [[] for _ in CATEGORIES]
        self.requests = 0
        self.usage = Counter()
        self.ignored_excess = 0
        self.stagnant = 0

    def replay(self, record: dict, path: Path) -> None:
        current = next((i for i, rows in enumerate(self.groups)
                        if len(rows) < LINES_PER_CATEGORY), None)
        if current is None:
            raise ValueError(f"Response after completion: {path}")
        prompt = render_prompt(self.manifest["gdbms"], CATEGORIES[current])
        if (record.get("index") != self.requests + 1 or
                record.get("category_index") != current or
                record.get("prompt_sha256") != digest(prompt)):
            raise ValueError(f"Response does not match active category: {path}")
        lines = extract_lines(record["response"])
        take = min(len(lines), LINES_PER_CATEGORY - len(self.groups[current]))
        self.groups[current].extend(lines[:take])
        self.requests += 1
        self.ignored_excess += len(lines) - take
        self.stagnant = 0 if take else self.stagnant + 1
        usage = record["response"].get("usage") or {}
        for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
            value = usage.get(key)
            if isinstance(value, int) and not isinstance(value, bool):
                self.usage[key] += value

    def publish(self, directory: Path, final: Path) -> dict:
        batches = directory / "batches"
        batches.mkdir(exist_ok=True)
        for index, rows in enumerate(self.groups, 1):
            path = batches / f"{index:02d}.cypher"
            if len(rows) == LINES_PER_CATEGORY:
                atomic(path, "\n".join(rows) + "\n")
            else:
                path.unlink(missing_ok=True)
        combined = [line for group in self.groups for line in group]
        atomic(directory / "raw.partial",
               "\n".join(combined) + ("\n" if combined else ""))
        complete = len(combined) == LINES_PER_CATEGORY * len(CATEGORIES)
        summary = {"status": "COMPLETE_RAW" if complete else "INCOMPLETE",
                   "gdbms": self.manifest["gdbms"],
                   "per_category": dict(zip(CATEGORIES, map(len, self.groups))),
                   "total_lines": len(combined),
                   "target_lines": LINES_PER_CATEGORY * len(CATEGORIES),
                   "requests": self.requests, "ignored_excess_lines": self.ignored_excess,
                   "usage": dict(self.usage), "deduplication": False,
                   "target_admission": False,
                   "raw_skeletons": str(final) if complete else None}
        atomic(directory / "summary.json",
               json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
        if complete:
            atomic(final, "\n".join(combined) + "\n")
        return summary


def run(config_path: Path, gdbms: str, work_dir: Path,
        *, requester=request_completion,
        generated_dir: Path = DEFAULT_GENERATED_DIR) -> dict:
    config = load_config(config_path)
    _, gdbms = target_name(gdbms)
    render_prompt(gdbms, CATEGORIES[0])
    final = raw_path(gdbms, generated_dir)
    manifest = manifest_for(config, gdbms)
    with locked(work_dir):
        saved = work_dir / "run.json"
        if saved.exists():
            if json.loads(saved.read_text(encoding="utf-8")) != manifest:
                raise ValueError("Generation settings changed; use another work directory")
        else:
            if list((work_dir / "responses").glob("*.json")):
                raise ValueError("Saved responses exist without run.json")
            atomic(saved, json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
        responses = work_dir / "responses"
        responses.mkdir(exist_ok=True)
        state = State(manifest)
        for index, path in enumerate(sorted(responses.glob("*.json")), 1):
            if path.name != f"{index:06d}.json":
                raise ValueError(f"Noncontiguous response log: {path}")
            state.replay(json.loads(path.read_text(encoding="utf-8")), path)
        summary = state.publish(work_dir, final)
        while summary["total_lines"] < summary["target_lines"]:
            if state.requests >= config["max_requests"]:
                raise RuntimeError("INCOMPLETE: max_requests reached; increase it and rerun")
            if state.stagnant >= config["max_stagnant_calls"]:
                raise RuntimeError("INCOMPLETE: repeated empty replies; inspect saved responses")
            category_index = next(i for i, rows in enumerate(state.groups)
                                  if len(rows) < LINES_PER_CATEGORY)
            prompt = render_prompt(gdbms, CATEGORIES[category_index])
            response = requester(config, prompt)
            extract_lines(response)
            record = {"index": state.requests + 1, "category_index": category_index,
                      "prompt_sha256": digest(prompt), "response": response}
            path = responses / f"{state.requests + 1:06d}.json"
            atomic(path, json.dumps(record, ensure_ascii=False, indent=2) + "\n")
            before = len(state.groups[category_index])
            state.replay(record, path)
            summary = state.publish(work_dir, final)
            print(f"batch={category_index + 1}/10 request={state.requests} "
                  f"added={len(state.groups[category_index]) - before} "
                  f"progress={len(state.groups[category_index])}/{LINES_PER_CATEGORY} "
                  f"total={summary['total_lines']}/{summary['target_lines']}", flush=True)
        return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--gdbms", required=True,
                        help="Target DBMS name to replace [gdbms] in the prompt")
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--generated-dir", type=Path, default=DEFAULT_GENERATED_DIR,
                        help="Directory for <GDBMS>_skeletons (default: project/generated_skeletons)")
    args = parser.parse_args(argv)
    print(json.dumps(run(args.config, args.gdbms, args.work_dir,
                         generated_dir=args.generated_dir),
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
