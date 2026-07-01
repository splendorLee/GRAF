import textwrap


SHARED_SEED_CYPHER = textwrap.dedent("""

// 创建 Person 节点
CREATE (p1:Person {id: 1, name: "Alice", age: 30, score: 99.9})
CREATE (p2:Person {id: 2, name: "Bob", age: -2147483648, score: 0.0})
CREATE (p3:Person {id: 3, name: "Charlie", age: 2147483647, score: -1e308})

// 创建 Paper 节点
CREATE (doc1:Paper {id: 101, title: "Graph Fuzzing", published: true})
CREATE (doc2:Paper {id: 102, title: "' OR 1=1", published: false})
CREATE (doc3:Paper {id: 103, title: "", published: true})

// 创建 Conference 节点
CREATE (c1:Conference {id: 1001, name: "SIGMOD", year: 2026})
CREATE (c2:Conference {id: 1002, name: "S&P", year: 2027})

// 构建多跳关系网
CREATE (p1)-[:WROTE {contribution: 0.9}]->(doc1)
CREATE (p2)-[:WROTE {contribution: 0.1}]->(doc1)
CREATE (p2)-[:WROTE {contribution: 1.0}]->(doc2)
CREATE (p3)-[:WROTE {contribution: 1.0}]->(doc3)

CREATE (doc1)-[:PUBLISHED_IN {year: 2026}]->(c1)
CREATE (doc2)-[:PUBLISHED_IN {year: 2026}]->(c1)
CREATE (doc3)-[:PUBLISHED_IN {year: 2027}]->(c2)

// 构建自环和循环引用
CREATE (p1)-[:KNOWS {since: 2020}]->(p2)
CREATE (p2)-[:KNOWS {since: 2021}]->(p3)
CREATE (p3)-[:KNOWS {since: 2025}]->(p1)
""")


KUZU_SCHEMA = [
    "CREATE NODE TABLE Person(id INT64, name STRING, age INT64, score DOUBLE, PRIMARY KEY (id));",
    "CREATE NODE TABLE Paper(id INT64, title STRING, published BOOLEAN, PRIMARY KEY (id));",
    "CREATE NODE TABLE Conference(id INT64, name STRING, year INT64, PRIMARY KEY (id));",
    "CREATE REL TABLE WROTE(FROM Person TO Paper, contribution DOUBLE);",
    "CREATE REL TABLE PUBLISHED_IN(FROM Paper TO Conference, year INT64);",
    "CREATE REL TABLE KNOWS(FROM Person TO Person, since INT64);"
]

KUZU_DATA = [
    'CREATE (p1:Person {id: 1, name: "Alice", age: 30, score: 99.9});',
    'CREATE (p2:Person {id: 2, name: "Bob", age: -2147483648, score: 0.0});',
    'CREATE (p3:Person {id: 3, name: "Charlie", age: 2147483647, score: -1e308});',
    'CREATE (doc1:Paper {id: 101, title: "Graph Fuzzing", published: true});',
    'CREATE (doc2:Paper {id: 102, title: "\' OR 1=1", published: false});',
    'CREATE (doc3:Paper {id: 103, title: "", published: true});',
    'CREATE (c1:Conference {id: 1001, name: "SIGMOD", year: 2026});',
    'CREATE (c2:Conference {id: 1002, name: "S&P", year: 2027});',
    
    'MATCH (p:Person {id: 1}), (d:Paper {id: 101}) CREATE (p)-[:WROTE {contribution: 0.9}]->(d);',
    'MATCH (p:Person {id: 2}), (d:Paper {id: 101}) CREATE (p)-[:WROTE {contribution: 0.1}]->(d);',
    'MATCH (p:Person {id: 2}), (d:Paper {id: 102}) CREATE (p)-[:WROTE {contribution: 1.0}]->(d);',
    'MATCH (p:Person {id: 3}), (d:Paper {id: 103}) CREATE (p)-[:WROTE {contribution: 1.0}]->(d);',
    
    'MATCH (d:Paper {id: 101}), (c:Conference {id: 1001}) CREATE (d)-[:PUBLISHED_IN {year: 2026}]->(c);',
    'MATCH (d:Paper {id: 102}), (c:Conference {id: 1001}) CREATE (d)-[:PUBLISHED_IN {year: 2026}]->(c);',
    'MATCH (d:Paper {id: 103}), (c:Conference {id: 1002}) CREATE (d)-[:PUBLISHED_IN {year: 2027}]->(c);',
    
    'MATCH (p1:Person {id: 1}), (p2:Person {id: 2}) CREATE (p1)-[:KNOWS {since: 2020}]->(p2);',
    'MATCH (p1:Person {id: 2}), (p2:Person {id: 3}) CREATE (p1)-[:KNOWS {since: 2021}]->(p2);',
    'MATCH (p1:Person {id: 3}), (p2:Person {id: 1}) CREATE (p1)-[:KNOWS {since: 2025}]->(p2);'
]


NEBULA_SCHEMA = [
    "DROP SPACE IF EXISTS graf_fuzz;",
    "CREATE SPACE IF NOT EXISTS graf_fuzz(vid_type=FIXED_STRING(32));",
    "USE graf_fuzz;",
    "CREATE TAG IF NOT EXISTS Person(name string, age int, score double);",
    "CREATE TAG IF NOT EXISTS Paper(title string, published bool);",
    "CREATE TAG IF NOT EXISTS Conference(name string, year int);",
    "CREATE EDGE IF NOT EXISTS WROTE(contribution double);",
    "CREATE EDGE IF NOT EXISTS PUBLISHED_IN(year int);",
    "CREATE EDGE IF NOT EXISTS KNOWS(since int);"
]


NEBULA_DATA = [
    'USE graf_fuzz;',
    'INSERT VERTEX Person(name, age, score) VALUES "p1":("Alice", 30, 99.9), "p2":("Bob", -2147483648, 0.0), "p3":("Charlie", 2147483647, -1e308);',
    'INSERT VERTEX Paper(title, published) VALUES "doc1":("Graph Fuzzing", true), "doc2":("\' OR 1=1", false), "doc3":("", true);',
    'INSERT VERTEX Conference(name, year) VALUES "c1":("SIGMOD", 2026), "c2":("S&P", 2027);',
    
    'INSERT EDGE WROTE(contribution) VALUES "p1"->"doc1":(0.9), "p2"->"doc1":(0.1), "p2"->"doc2":(1.0), "p3"->"doc3":(1.0);',
    'INSERT EDGE PUBLISHED_IN(year) VALUES "doc1"->"c1":(2026), "doc2"->"c1":(2026), "doc3"->"c2":(2027);',
    'INSERT EDGE KNOWS(since) VALUES "p1"->"p2":(2020), "p2"->"p3":(2021), "p3"->"p1":(2025);'
]