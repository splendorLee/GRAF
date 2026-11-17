.PHONY: install test audit-falkordb audit-kuzu benchmark-kuzu compile-check

install:
	python -m pip install -r requirements.txt

compile-check:
	python -m py_compile GRAF.py GraphAwareMutator.py FeedbackMonitor.py GraphContext.py Instantiator.py DB_Executor.py generate_cypher_skeletons.py graf/*.py tools/*.py tests/*.py

test: compile-check
	python -m unittest discover -s tests -v

audit-falkordb:
	python tools/audit_mutation_pipeline.py --target falkordb --sample-size 300 --seed 20261024 --output reports/mutation_audit_falkordb_300.json

audit-kuzu:
	python tools/audit_mutation_pipeline.py --target kuzu --sample-size 300 --seed 20261024 --output reports/mutation_audit_kuzu_300.json

benchmark-kuzu:
	python tools/benchmark_kuzu_runtime.py --iterations 50 --timeout 30 --assert-min-speedup 2.0 --output reports/kuzu_runtime_benchmark.json

