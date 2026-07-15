# compiler/

Intent → DAG compiler. Produces immutable execution graphs.

## Pipeline (§XII.2)
```
INTENT → Parse → Capability Resolution → Node Planning
      → DAG Generation → Optimization → Execution DAG
```

## Modules
- `parser/`    — Contract source parser (JSON/YAML MVP; .seme future)
- `planner/`   — Node planning and resource mapping
- `optimizer/` — DAG optimization (future)
- `graph/`     — DAG data structures (§XII.1)
- `validator/` — Semantic validation
