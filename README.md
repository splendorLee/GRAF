# GRAF: Graph-Aware Fuzzing for Graph Database Management Systems

Run all commands from this directory (the one containing `GRAF.py`). Use a
dedicated test database: admission with `--initialize-graph`, the default
fuzzer startup, and managed reseeding replace its contents.

## 1. Install dependencies

Use a Python environment supported by the selected target's client library.

```bash
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt  # optional, for development
python -m unittest discover -s tests -v
```

The bundled ANTLR lexer/parser requires `antlr4-python3-runtime==4.13.2`.
Only the client for the selected target needs to connect to a running DBMS.

## 2. Start the target GDBMS

Start only the target being tested. The following container names and ports
match the examples below. Set passwords outside the source tree; all examples
use a dedicated local test instance.

### Memgraph

```bash
docker run -d --name memgraph_fuzz_target --ulimit core=-1 \
  -m 4g --memory-swap 4g -p 7687:7687 \
  memgraph/memgraph:latest --memory-limit=3000
```

### Neo4j

```bash
export NEO4J_PASSWORD='testpassword'  # replace for your test instance
docker run -d --name neo4j_fuzz_target --ulimit core=-1 \
  -m 4g --memory-swap 4g -p 7474:7474 -p 7688:7687 \
  -e "NEO4J_AUTH=neo4j/${NEO4J_PASSWORD}" neo4j:5.26
```

### FalkorDB

```bash
docker run -d --name falkordb_fuzz_target --ulimit core=-1 \
  -m 4g --memory-swap 4g -p 6380:6379 falkordb/falkordb:edge
```

### KuzuDB

KuzuDB is embedded; no server is needed. The examples use
`./kuzu_fuzz_test` as its database path.

### NebulaGraph 3.8.0

Use the official [NebulaGraph Docker Compose repository](https://github.com/vesoft-inc/nebula-docker-compose/tree/v3.8.0).
Start its graphd, metad and storaged services and wait until the cluster is
ready. The `-p` option below fixes the graphd container name used by GRAF.

```bash
git clone --branch v3.8.0 https://github.com/vesoft-inc/nebula-docker-compose.git
cd nebula-docker-compose
docker compose -p nebula-docker-compose up -d
docker compose -p nebula-docker-compose ps
cd ..
export GRAF_NEBULA_PASSWORD='nebula'  # use the password configured for your cluster
```

This Compose configuration publishes graphd on `127.0.0.1:9669`. Verify
connectivity and credentials before admission. For an existing Compose
deployment, pass its actual graphd container name through `--nebula-container`
and its host, port, space and credentials through the corresponding options.

## 3. Generate 5,000 raw skeleton lines per target

Copy `llm_config.example.json` to `llm_config.json` and set `base_url`,
`api_key`, `model`, and inference settings. Do not commit the private config.
Each target gets its own resumable work directory:

```bash
cp llm_config.json llm_config.json
python generate_cypher_skeletons.py --config llm_config.json \
  --gdbms NebulaGraph --work-dir generation_runs/NebulaGraph
```

Replace `NebulaGraph` with `Memgraph`, `Neo4j`, `FalkorDB`, or `KuzuDB`
as needed. The ten fixed categories are generated sequentially. The generator
repeats the category prompt until it has collected exactly 500 nonempty
physical lines, then advances, producing exactly 5,000 **raw lines** at
`generated_skeletons/<GDBMS>_skeletons`. Generation intentionally does not
deduplicate or validate them; the admitted pool can contain fewer lines.

## 4. Admit skeletons on the selected target

Admission reads **one complete skeleton per physical line**, with or without
the final semicolon. Set a stable target build ID and campaign seed. When the
test graph has not already been initialized to that campaign's initial graph,
add `--initialize-graph`; this clears and reloads that dedicated graph.

```bash
export GRAF_SEED=20260624
export MEMGRAPH_BUILD_ID="$(docker inspect --format '{{.Image}}' memgraph_fuzz_target)"
export NEO4J_BUILD_ID="$(docker inspect --format '{{.Image}}' neo4j_fuzz_target)"
export FALKORDB_BUILD_ID="$(docker inspect --format '{{.Image}}' falkordb_fuzz_target)"
export NEBULA_BUILD_ID="$(docker inspect --format '{{.Image}}' nebula-docker-compose-graphd-1)"
export KUZU_BUILD_ID="$(python -c 'import importlib.metadata; print(importlib.metadata.version("kuzu"))')"
```

Run **only** the applicable command. For example, NebulaGraph:

```bash
python tools/filter_skeleton_pool.py --target NebulaGraph \
  --target-build-id "$NEBULA_BUILD_ID" --campaign-seed "$GRAF_SEED" \
  --initialize-graph --nebula-host 127.0.0.1 --nebula-port 9669 \
  --nebula-user root --nebula-password "$GRAF_NEBULA_PASSWORD" \
  --nebula-space graf_fuzz
```

The other four target commands:

```bash
python tools/filter_skeleton_pool.py --target Memgraph \
  --target-build-id "$MEMGRAPH_BUILD_ID" --campaign-seed "$GRAF_SEED" \
  --initialize-graph --memgraph-uri bolt://127.0.0.1:7687

python tools/filter_skeleton_pool.py --target Neo4j \
  --target-build-id "$NEO4J_BUILD_ID" --campaign-seed "$GRAF_SEED" \
  --initialize-graph --neo4j-uri bolt://127.0.0.1:7688 \
  --neo4j-user neo4j --neo4j-password "$NEO4J_PASSWORD" \
  --neo4j-database neo4j

python tools/filter_skeleton_pool.py --target FalkorDB \
  --target-build-id "$FALKORDB_BUILD_ID" --campaign-seed "$GRAF_SEED" \
  --initialize-graph --falkordb-host 127.0.0.1 --falkordb-port 6380 \
  --falkordb-graph graf_fuzz

python tools/filter_skeleton_pool.py --target KuzuDB \
  --target-build-id "$KUZU_BUILD_ID" --campaign-seed "$GRAF_SEED" \
  --initialize-graph --kuzu-db-path ./kuzu_fuzz_test
```

The admission gate applies mechanical placeholder/single-statement checks,
exact duplicate checks, three seeded instantiations using the live initial
graph, and target-native compilation (`EXPLAIN` or FalkorDB's `GRAPH.EXPLAIN`).
At least one binding must compile; target timeouts, suspected crashes and
infrastructure errors defer the candidate instead of counting as dialect
rejections. Accepted skeletons appear in
`generated_skeletons/<GDBMS>_skeleton_pool`. Beside the pool are
`.admission.json` (target build, source/pool hashes and counts) and
`.evidence.jsonl` (per-candidate and per-sample results); use
`--print-rejections` for detailed console diagnostics. If nothing qualifies,
the old certified pool is not replaced. The old `skeleton_pool.strict.*`
and `--mode strict` commands do not apply to this implementation.

## 5. Run a short test, then fuzz continuously

GRAF verifies the admission manifest and source/pool hashes **before** any
managed reset. `--seed` must select the same initial graph profile used during
admission; use the same value below. A smoke run of 20 rounds is useful before
setting `--max-iterations 0` for continuous operation.

### NebulaGraph

```bash
python GRAF.py --target nebula --target-build-id "$NEBULA_BUILD_ID" \
  --nebula-host 127.0.0.1 --nebula-port 9669 \
  --nebula-user root --nebula-password "$GRAF_NEBULA_PASSWORD" \
  --nebula-space graf_fuzz --nebula-container nebula-docker-compose-graphd-1 \
  --seed "$GRAF_SEED" --max-iterations 20
```

### Memgraph

```bash
python GRAF.py --target memgraph --target-build-id "$MEMGRAPH_BUILD_ID" \
  --memgraph-uri bolt://127.0.0.1:7687 \
  --memgraph-container memgraph_fuzz_target \
  --seed "$GRAF_SEED" --max-iterations 20
```

### Neo4j

```bash
python GRAF.py --target neo4j --target-build-id "$NEO4J_BUILD_ID" \
  --neo4j-uri bolt://127.0.0.1:7688 --neo4j-user neo4j \
  --neo4j-password "$NEO4J_PASSWORD" --neo4j-database neo4j \
  --neo4j-container neo4j_fuzz_target \
  --seed "$GRAF_SEED" --max-iterations 20
```

### FalkorDB

```bash
python GRAF.py --target falkordb --target-build-id "$FALKORDB_BUILD_ID" \
  --falkordb-host 127.0.0.1 --falkordb-port 6380 \
  --falkordb-graph graf_fuzz --falkordb-container falkordb_fuzz_target \
  --seed "$GRAF_SEED" --max-iterations 20
```

### KuzuDB

```bash
python GRAF.py --target kuzu --target-build-id "$KUZU_BUILD_ID" \
  --kuzu-db-path ./kuzu_fuzz_test \
  --seed "$GRAF_SEED" --max-iterations 20
```

By default, GRAF manages and rotates a seed graph after 500 **executed**
queries (`--reseed-interval 500`) and refreshes its graph context every 500
rounds (`--context-refresh-interval 500`). `--reseed-interval 0` disables
rotation. `--init-mode reuse` preserves an externally managed graph and
automatically disables managed rotation. The query timeout defaults to 120 s;
override with `--query-timeout 60` if desired. The default
`--target-compile-check required` checks each concrete parent and mutation
before execution. A NebulaGraph query accepted by its native compiler but
not parsed by the bundled Cypher grammar is tested as an unchanged parent;
AST mutation requires a locally parsed query. Compile success does not
guarantee runtime success.

## 6. Inspect outputs

Each run creates `runs/graf-enterprise-<target>-<UTC timestamp>/` unless
`--run-dir` is supplied. Key files:

```text
fuzz_verbose_<target>.log
fuzzer_<target>.log
fuzzing_execution_trace_<target>.cypher
journal.jsonl
artifacts/
evidence/crash_pocs/<target>/
evidence/timeout_cases/<target>/
evidence/runtime_bug_reports/<target>/
evidence/resource_exhaustion/<target>/
```

The evidence directories are created when needed. `--crash-policy strict` is
the default. A query error alone is not a confirmed crash; process/container
evidence is required. Timeouts and resource exhaustion are tracked separately,
and reportable Neo4j execution failures are saved as candidates, not counted
automatically as confirmed defects.

## Verification and limitations

```bash
make test
python tools/filter_skeleton_pool.py --target nebula --self-check
```

Unit tests mock the five target compilers and NebulaGraph's seed/context/run
request paths. End-to-end verification still needs the selected target and
its Python client. The offline admission result is specific to the sampled
bindings, seed context, and recorded build; after reseeding or graph mutation,
a previously admitted skeleton may fail to instantiate or execute.
