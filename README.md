## GRAF： Graph-Aware Fuzzing for Graph Database Management Systems via LLM-Generated Query Skeletons
### 1、Environmental preparation
```bash
pip install antlr4-python3-runtime neo4j redis kuzu nebula3-python
```

### 2、Utilize carefully designed prompts to generate a large volume of query skeletons and save them in the `skeleton_pool`. Please note that different target engines have varying implementations of Cypher.

### 3、Construct diverse initial graph schemas and graph data tailored for different target databases, which are stored in `SeedGraph.py`.

### 4、Target graph databases installation
For Memgraph:
```bash
docker run -d \
  --name memgraph_fuzz_target \
  --ulimit core=-1 \
  -m 4g \
  --memory-swap 4g \
  -p 7687:7687 \
  memgraph/memgraph:latest \
  --memory-limit=3000
```

For FalkorDB:
```bash
docker run -d \
  --name falkordb_fuzz_target \
  --ulimit core=-1 \
  -p 6380:6379 \
  falkordb/falkordb:edge-alpine
```

For Kuzu:
Embedded architecture requires no configuration

For NebulaGraph:
```bash
git clone https://github.com/vesoft-inc/nebula-docker-compose.git
cd nebula-docker-compose
git checkout v3.8.0
docker compose down -v
docker compose up -d
```

### 5、Test execution
```bash
cd ./GRAF
python GRAF.py --target memgraph
python GRAF.py --target falkordb
python GRAF.py --target nebula
python GRAF.py --target kuzu
```