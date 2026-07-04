## GRAF: Graph-Context and Execution-State Guided Fuzzing for Graph Database Management Systems

GRAF tests graph database engines by generating graph-context-aware Cypher queries, mutating them with execution-state feedback, and recording abnormal executions.

### 1. Install Dependencies

```bash
python -m pip install \
  antlr4-python3-runtime \
  neo4j \
  redis \
  falkordb \
  kuzu \
  nebula3-python
```

### 2. Start a Target GDBMS

Start only the target you want to test.

#### Memgraph

```bash
docker rm -f memgraph_fuzz_target 2>/dev/null || true

docker run -d \
  --name memgraph_fuzz_target \
  --ulimit core=-1 \
  -m 4g \
  --memory-swap 4g \
  -p 7687:7687 \
  memgraph/memgraph:latest \
  --memory-limit=3000
```

#### Neo4j

```bash
docker rm -f neo4j_fuzz_target 2>/dev/null || true

docker run -d \
  --name neo4j_fuzz_target \
  --ulimit core=-1 \
  -m 4g \
  --memory-swap 4g \
  -p 7474:7474 \
  -p 7688:7687 \
  -e NEO4J_AUTH=neo4j/testpassword \
  neo4j:5.26
```

#### FalkorDB

```bash
docker rm -f falkordb_fuzz_target 2>/dev/null || true

docker run -d \
  --name falkordb_fuzz_target \
  --ulimit core=-1 \
  -m 4g \
  --memory-swap 4g \
  -p 6380:6379 \
  falkordb/falkordb:edge
```

#### KuzuDB

KuzuDB is embedded. No server is required.

#### NebulaGraph

```bash
git clone https://github.com/vesoft-inc/nebula-docker-compose.git
cd nebula-docker-compose
git checkout v3.8.0
docker compose down -v
docker compose up -d
```

### 3. Filter the Skeleton Pool

Before fuzzing, generate a target-specific strict skeleton pool. This removes skeletons that fail placeholder, syntax, scope, or target-compatibility checks.

```bash
for target in memgraph neo4j falkordb kuzu nebula; do
  python tools/filter_skeleton_pool.py \
    --input skeleton_pool \
    --output "skeleton_pool.strict.${target}" \
    --rejects "skeleton_pool.strict.${target}.rejects.csv" \
    --target "${target}" \
    --mode strict
done
```

Use the generated `skeleton_pool.strict.<target>` file with `--skeleton-pool`. Rejected skeletons are recorded in `skeleton_pool.strict.<target>.rejects.csv`.

### 4. Periodic Database Reset

For long-running tests, enable periodic reset on Memgraph, Neo4j, and FalkorDB. This clears the current graph, reloads the seed graph, and refreshes the runtime graph context. It prevents write queries from continuously increasing graph density and making later queries progressively slower.

```text
--reseed-interval 500
```

The default value is `0`, which disables periodic reset. If Neo4j becomes slow quickly, use a smaller value such as `200`.

### 5. Run GRAF

#### Memgraph

```bash
python GRAF.py \
  --target memgraph \
  --memgraph-uri bolt://localhost:7687 \
  --memgraph-container memgraph_fuzz_target \
  --skeleton-pool skeleton_pool.strict.memgraph \
  --reseed-interval 500 \
  --seed 20260624 \
  --max-iterations 0
```

#### Neo4j

```bash
python GRAF.py \
  --target neo4j \
  --neo4j-uri bolt://localhost:7688 \
  --neo4j-user neo4j \
  --neo4j-password testpassword \
  --neo4j-database neo4j \
  --neo4j-container neo4j_fuzz_target \
  --skeleton-pool skeleton_pool.strict.neo4j \
  --neo4j-query-timeout 60 \
  --reseed-interval 500 \
  --context-refresh-interval 500 \
  --seed 20260624 \
  --max-iterations 0
```

#### FalkorDB

```bash
python GRAF.py \
  --target falkordb \
  --skeleton-pool skeleton_pool.strict.falkordb \
  --falkordb-query-timeout 60 \
  --reseed-interval 500 \
  --seed 20260624 \
  --max-iterations 0
```

#### KuzuDB

```bash
python GRAF.py \
  --target kuzu \
  --skeleton-pool skeleton_pool.strict.kuzu \
  --seed 20260624 \
  --max-iterations 0
```

#### NebulaGraph

```bash
python GRAF.py \
  --target nebula \
  --skeleton-pool skeleton_pool.strict.nebula \
  --seed 20260624 \
  --max-iterations 0
```

### 6. Outputs

Runtime logs:

```text
fuzz_verbose_<target>.log
fuzzer_<target>.log
```

Saved cases:

```text
crash_pocs/
runtime_bug_reports/
resource_exhaustion/
timeout_cases/
```

GRAF uses `--crash-policy strict` by default. Runtime errors are not counted as crashes unless process or container evidence indicates a real fatal failure, such as OOM kill, abnormal exit, fatal log, assertion failure, abort, or core dump. Neo4j `Neo.DatabaseError.Statement.ExecutionFailed` cases are saved separately under `runtime_bug_reports/neo4j/` as reportable runtime bug candidates.
