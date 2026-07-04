from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

try:
    from neo4j import GraphDatabase, Session
except ImportError:
    pass

try:
    from falkordb import FalkorDB
except ImportError:
    pass

try:
    import kuzu
except ImportError:
    pass

try:
    from nebula3.gclient.net import ConnectionPool
    from nebula3.Config import Config
except ImportError:
    pass


@dataclass
class SchemaMetadata:
    labels: Set[str] = field(default_factory=set)
    topology: Dict[str, Set[Tuple[str, str]]] = field(default_factory=dict)
    properties: Dict[str, Dict[str, str]] = field(default_factory=dict)

@dataclass
class GlobalGraphState:
    total_nodes: int = 0
    total_edges: int = 0
    avg_degree: float = 0.0


class MemgraphContextExtractor:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def extract_context(self) -> Tuple[SchemaMetadata, GlobalGraphState]:
        schema, state = SchemaMetadata(), GlobalGraphState()
        with self.driver.session() as session:
            self._extract_metadata_M(session, schema)
            self._extract_global_state_G(session, state)
        return schema, state

    def _extract_metadata_M(self, session, schema):
        res_labels = session.run("MATCH (n) UNWIND labels(n) AS label RETURN DISTINCT label")
        schema.labels = {record["label"] for record in res_labels}

        res_topo = session.run("""
            MATCH (a)-[r]->(b)
            UNWIND labels(a) AS src_label
            UNWIND labels(b) AS dst_label
            RETURN DISTINCT src_label, type(r) AS rel_type, dst_label
        """)
        for record in res_topo:
            rel_type = record["rel_type"]
            if rel_type not in schema.topology: schema.topology[rel_type] = set()
            schema.topology[rel_type].add((record["src_label"], record["dst_label"]))

        for label in schema.labels:
            schema.properties[label] = {}
            res_nodes = session.run(f"MATCH (n:`{label}`) RETURN n LIMIT 100")
            for record in res_nodes:
                if record["n"]:
                    for k, v in record["n"].items():
                        if k not in schema.properties[label]:
                            schema.properties[label][k] = self._map_type(v)

        for rel_type in schema.topology.keys():
            schema.properties[rel_type] = {}
            res_edges = session.run(f"MATCH ()-[r:`{rel_type}`]->() RETURN r LIMIT 100")
            for record in res_edges:
                if record["r"]:
                    for k, v in record["r"].items():
                        if k not in schema.properties[rel_type]:
                            schema.properties[rel_type][k] = self._map_type(v)

    def _map_type(self, value) -> str:
        if isinstance(value, int): return "INTEGER"
        if isinstance(value, float): return "FLOAT"
        if isinstance(value, bool): return "BOOLEAN"
        if isinstance(value, list): return "LIST"
        if isinstance(value, dict): return "MAP"
        return "STRING"

    def _extract_global_state_G(self, session, state):
        res_nodes = session.run("MATCH (n) RETURN count(n) AS total_nodes")
        state.total_nodes = res_nodes.single()["total_nodes"]
        res_edges = session.run("MATCH ()-[r]->() RETURN count(r) AS total_edges")
        state.total_edges = res_edges.single()["total_edges"]
        if state.total_nodes > 0:
            state.avg_degree = (state.total_edges * 2) / state.total_nodes


class Neo4jContextExtractor:
    def __init__(self, uri="bolt://localhost:7687", user="neo4j", password="testpassword", database="neo4j"):
        self.database = database
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def extract_context(self) -> Tuple[SchemaMetadata, GlobalGraphState]:
        schema, state = SchemaMetadata(), GlobalGraphState()
        with self.driver.session(database=self.database) as session:
            self._extract_metadata_M(session, schema)
            self._extract_global_state_G(session, state)
        return schema, state

    def _extract_metadata_M(self, session, schema):
        res_labels = session.run("MATCH (n) UNWIND labels(n) AS label RETURN DISTINCT label")
        schema.labels = {record["label"] for record in res_labels if record["label"]}

        res_topo = session.run("""
            MATCH (a)-[r]->(b)
            UNWIND labels(a) AS src_label
            UNWIND labels(b) AS dst_label
            RETURN DISTINCT src_label, type(r) AS rel_type, dst_label
            LIMIT 10000
        """)
        for record in res_topo:
            rel_type = record["rel_type"]
            if not rel_type:
                continue
            schema.topology.setdefault(rel_type, set()).add((record["src_label"], record["dst_label"]))

        self._extract_node_properties(session, schema)
        self._extract_relationship_properties(session, schema)

    def _extract_node_properties(self, session, schema):
        for label in schema.labels:
            schema.properties.setdefault(label, {})

        try:
            result = session.run("""
                CALL db.schema.nodeTypeProperties()
                YIELD nodeLabels, propertyName, propertyTypes
                RETURN nodeLabels, propertyName, propertyTypes
            """)
            for record in result:
                prop_name = record["propertyName"]
                prop_types = record["propertyTypes"] or []
                if not prop_name:
                    continue
                mapped_type = self._map_neo4j_type(prop_types[0] if prop_types else "STRING")
                for label in record["nodeLabels"] or []:
                    clean_label = str(label).strip(":`")
                    if clean_label in schema.labels:
                        schema.properties.setdefault(clean_label, {})[prop_name] = mapped_type
            return
        except Exception:
            pass

        for label in schema.labels:
            result = session.run(f"MATCH (n:`{label}`) RETURN n LIMIT 100")
            for record in result:
                node = record["n"]
                if not node:
                    continue
                for key, value in dict(node).items():
                    schema.properties.setdefault(label, {}).setdefault(key, self._map_value_type(value))

    def _extract_relationship_properties(self, session, schema):
        for rel_type in schema.topology.keys():
            schema.properties.setdefault(rel_type, {})

        try:
            result = session.run("""
                CALL db.schema.relTypeProperties()
                YIELD relType, propertyName, propertyTypes
                RETURN relType, propertyName, propertyTypes
            """)
            for record in result:
                rel_type = str(record["relType"]).strip(":`")
                prop_name = record["propertyName"]
                prop_types = record["propertyTypes"] or []
                if rel_type in schema.topology and prop_name:
                    schema.properties.setdefault(rel_type, {})[prop_name] = self._map_neo4j_type(prop_types[0] if prop_types else "STRING")
            return
        except Exception:
            pass

        for rel_type in schema.topology.keys():
            result = session.run(f"MATCH ()-[r:`{rel_type}`]->() RETURN r LIMIT 100")
            for record in result:
                rel = record["r"]
                if not rel:
                    continue
                for key, value in dict(rel).items():
                    schema.properties.setdefault(rel_type, {}).setdefault(key, self._map_value_type(value))

    def _map_neo4j_type(self, neo4j_type: str) -> str:
        t = str(neo4j_type).upper()
        if "BOOLEAN" in t:
            return "BOOLEAN"
        if "INTEGER" in t or "LONG" in t:
            return "INTEGER"
        if "FLOAT" in t or "DOUBLE" in t:
            return "FLOAT"
        if "LIST" in t:
            return "LIST"
        if "MAP" in t:
            return "MAP"
        return "STRING"

    def _map_value_type(self, value) -> str:
        if isinstance(value, bool):
            return "BOOLEAN"
        if isinstance(value, int):
            return "INTEGER"
        if isinstance(value, float):
            return "FLOAT"
        if isinstance(value, list):
            return "LIST"
        if isinstance(value, dict):
            return "MAP"
        return "STRING"

    def _extract_global_state_G(self, session, state):
        state.total_nodes = session.run("MATCH (n) RETURN count(n) AS total_nodes").single()["total_nodes"]
        state.total_edges = session.run("MATCH ()-[r]->() RETURN count(r) AS total_edges").single()["total_edges"]
        if state.total_nodes > 0:
            state.avg_degree = (state.total_edges * 2) / state.total_nodes

class FalkorDBContextExtractor:
    def __init__(self, host="localhost", port=6379, password="", graph_name="graf_fuzz"):
        self.db = FalkorDB(host=host, port=port, password=password)
        self.graph = self.db.select_graph(graph_name)

    def close(self):
        self.db.connection.close()

    def extract_context(self) -> Tuple[SchemaMetadata, GlobalGraphState]:
        schema, state = SchemaMetadata(), GlobalGraphState()
        self._extract_metadata_M(schema)
        self._extract_global_state_G(state)
        return schema, state

    def _extract_metadata_M(self, schema):
        res_labels = self.graph.query("MATCH (n) RETURN labels(n)")
        if res_labels.result_set:
            for row in res_labels.result_set:
                if row[0]:
                    for lbl in row[0]: schema.labels.add(lbl)

        res_topo = self.graph.query("MATCH (a)-[r]->(b) RETURN labels(a), type(r), labels(b) LIMIT 10000")
        if res_topo.result_set:
            for row in res_topo.result_set:
                src_labels, rel_type, dst_labels = row[0], row[1], row[2]
                if not src_labels or not dst_labels or not rel_type: continue
                if rel_type not in schema.topology: schema.topology[rel_type] = set()
                for src in src_labels:
                    for dst in dst_labels: schema.topology[rel_type].add((src, dst))

        for label in schema.labels:
            schema.properties[label] = {}
            res_nodes = self.graph.query(f"MATCH (n:`{label}`) RETURN n LIMIT 100")
            if res_nodes.result_set:
                for row in res_nodes.result_set:
                    node = row[0]
                    if hasattr(node, 'properties') and node.properties:
                        for k, v in node.properties.items():
                            if k not in schema.properties[label]:
                                schema.properties[label][k] = self._map_type(v)

        for rel_type in schema.topology.keys():
            schema.properties[rel_type] = {}
            res_edges = self.graph.query(f"MATCH ()-[r:`{rel_type}`]->() RETURN r LIMIT 100")
            if res_edges.result_set:
                for row in res_edges.result_set:
                    edge = row[0]
                    if hasattr(edge, 'properties') and edge.properties:
                        for k, v in edge.properties.items():
                            if k not in schema.properties[rel_type]:
                                schema.properties[rel_type][k] = self._map_type(v)

    def _map_type(self, value) -> str:
        if isinstance(value, int): return "INTEGER"
        if isinstance(value, float): return "FLOAT"
        if isinstance(value, bool): return "BOOLEAN"
        if isinstance(value, list): return "LIST"
        if isinstance(value, dict): return "MAP"
        return "STRING"

    def _extract_global_state_G(self, state):
        res_nodes = self.graph.query("MATCH (n) RETURN count(n)")
        if res_nodes.result_set: state.total_nodes = res_nodes.result_set[0][0]

        res_edges = self.graph.query("MATCH ()-[r]->() RETURN count(r)")
        if res_edges.result_set: state.total_edges = res_edges.result_set[0][0]
            
        if state.total_nodes > 0: state.avg_degree = (state.total_edges * 2) / state.total_nodes


class KuzuContextExtractor:
    def __init__(self, db_path="./kuzu_fuzz_test"):
        self.db = kuzu.Database(db_path)
        self.conn = kuzu.Connection(self.db)

    def close(self):
        del self.conn
        del self.db

    def extract_context(self) -> Tuple[SchemaMetadata, GlobalGraphState]:
        schema, state = SchemaMetadata(), GlobalGraphState()
        self._extract_metadata_M(schema)
        self._extract_global_state_G(state)
        return schema, state

    def _extract_metadata_M(self, schema):
        res = self.conn.execute("MATCH (n) RETURN DISTINCT label(n)")
        while res.has_next():
            schema.labels.add(res.get_next()[0])

        res = self.conn.execute("MATCH (a)-[r]->(b) RETURN DISTINCT label(a), label(r), label(b)")
        while res.has_next():
            row = res.get_next()
            src_label, rel_type, dst_label = row[0], row[1], row[2]
            if rel_type not in schema.topology: schema.topology[rel_type] = set()
            schema.topology[rel_type].add((src_label, dst_label))

        for label in schema.labels:
            schema.properties[label] = {}
            res = self.conn.execute(f"CALL table_info('{label}') RETURN *")
            while res.has_next():
                row = res.get_next()
                # row[1] = property_name, row[2] = data_type
                schema.properties[label][row[1]] = self._map_kuzu_type(row[2])

        for rel_type in schema.topology.keys():
            schema.properties[rel_type] = {}
            res = self.conn.execute(f"CALL table_info('{rel_type}') RETURN *")
            while res.has_next():
                row = res.get_next()
                schema.properties[rel_type][row[1]] = self._map_kuzu_type(row[2])

    def _map_kuzu_type(self, kuzu_type_str: str) -> str:
        t = kuzu_type_str.upper()
        if "INT" in t: return "INTEGER"
        if "DOUBLE" in t or "FLOAT" in t: return "FLOAT"
        if "BOOL" in t: return "BOOLEAN"
        return "STRING"

    def _extract_global_state_G(self, state):
        res = self.conn.execute("MATCH (n) RETURN count(n)")
        if res.has_next(): state.total_nodes = res.get_next()[0]

        res = self.conn.execute("MATCH ()-[r]->() RETURN count(r)")
        if res.has_next(): state.total_edges = res.get_next()[0]

        if state.total_nodes > 0: state.avg_degree = (state.total_edges * 2) / state.total_nodes



class NebulaContextExtractor:
    def __init__(self, host="127.0.0.1", port=9669, user="root", password="nebula", space="graf_fuzz"):
        self.config = Config()
        self.config.max_connection_pool_size = 2
        self.pool = ConnectionPool()
        self.pool.init([(host, port)], self.config)
        self.session = self.pool.get_session(user, password)
        self.session.execute(f"USE {space};")

    def close(self):
        self.session.release()
        self.pool.close()

    def extract_context(self) -> Tuple[SchemaMetadata, GlobalGraphState]:
        schema, state = SchemaMetadata(), GlobalGraphState()
        self._extract_metadata_M(schema)
        self._extract_global_state_G(state)
        return schema, state

    def _safe_extract_string(self, value_obj) -> str:
        if hasattr(value_obj, 'as_string'): return value_obj.as_string()
        if hasattr(value_obj, 'get_sVal'): return value_obj.get_sVal().decode('utf-8')
        return str(value_obj.value if hasattr(value_obj, 'value') else value_obj)

    def _safe_extract_int(self, value_obj) -> int:
        if hasattr(value_obj, 'as_int'): return value_obj.as_int()
        if hasattr(value_obj, 'get_iVal'): return value_obj.get_iVal()
        try:
            return int(value_obj.value if hasattr(value_obj, 'value') else value_obj)
        except:
            return 10 

    def _extract_metadata_M(self, schema):
        res = self.session.execute("SHOW TAGS;")
        if res.is_succeeded():
            for row in res.rows():
                schema.labels.add(self._safe_extract_string(row.values[0]))

        res = self.session.execute("MATCH (a)-[r]->(b) RETURN labels(a), type(r), labels(b) LIMIT 1000;")
        if res.is_succeeded():
            for row in res.rows():
                src_list = row.values[0].as_list() if hasattr(row.values[0], 'as_list') else []
                dst_list = row.values[2].as_list() if hasattr(row.values[2], 'as_list') else []
                src_tags = [self._safe_extract_string(val) for val in src_list]
                rel_type = self._safe_extract_string(row.values[1])
                dst_tags = [self._safe_extract_string(val) for val in dst_list]
                
                if rel_type not in schema.topology: schema.topology[rel_type] = set()
                for src in src_tags:
                    for dst in dst_tags:
                        schema.topology[rel_type].add((src, dst))

        for label in schema.labels:
            schema.properties[label] = {}
            res = self.session.execute(f"DESCRIBE TAG `{label}`;")
            if res.is_succeeded():
                for row in res.rows():
                    prop_name = self._safe_extract_string(row.values[0])
                    prop_type = self._safe_extract_string(row.values[1])
                    schema.properties[label][prop_name] = self._map_nebula_type(prop_type)

        for rel_type in schema.topology.keys():
            schema.properties[rel_type] = {}
            res = self.session.execute(f"DESCRIBE EDGE `{rel_type}`;")
            if res.is_succeeded():
                for row in res.rows():
                    prop_name = self._safe_extract_string(row.values[0])
                    prop_type = self._safe_extract_string(row.values[1])
                    schema.properties[rel_type][prop_name] = self._map_nebula_type(prop_type)

    def _map_nebula_type(self, nebula_type_str: str) -> str:
        t = nebula_type_str.upper()
        if "INT" in t: return "INTEGER"
        if "DOUBLE" in t or "FLOAT" in t: return "FLOAT"
        if "BOOL" in t: return "BOOLEAN"
        return "STRING"

    def _extract_global_state_G(self, state):
        res_nodes = self.session.execute("MATCH (n) RETURN count(n);")
        if res_nodes.is_succeeded() and res_nodes.row_size() > 0:
            state.total_nodes = self._safe_extract_int(res_nodes.rows()[0].values[0])
        else:
            state.total_nodes = 10
            
        res_edges = self.session.execute("MATCH ()-[r]->() RETURN count(r);")
        if res_edges.is_succeeded() and res_edges.row_size() > 0:
            state.total_edges = self._safe_extract_int(res_edges.rows()[0].values[0])
        else:
            state.total_edges = 15 
            
        if state.total_nodes > 0:
            state.avg_degree = (state.total_edges * 2) / state.total_nodes
