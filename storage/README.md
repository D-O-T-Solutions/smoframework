# storage/

Local persistent storage. All stores are per-node isolated.

## Invariant (§IX)
Never store mutable shared execution state globally.

## Stores
- `session_store/` — Active session state (capabilities, keys, expiration)
- `trust_store/`   — Trust score records
- `audit_store/`   — Execution audit log
- `dag_store/`     — Compiled execution DAG records
- `node_store/`    — Node identity, keys, configuration, route table
