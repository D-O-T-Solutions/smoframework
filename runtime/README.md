# runtime/

Actual heart of the system. Execution engine for contracts and DAGs.

## Modules
- `scheduler/`  — DAG-aware scheduler (NOT FIFO) (§IV Layer 4)
- `executor/`   — Actual opcode execution dispatch
- `sandbox/`    — Execution isolation (future: WASM, resource quotas)
- `workerpool/` — Concurrent worker management
- `fsm/`        — Finite state machines: node_fsm, mesh_fsm, consensus_fsm (§XIII)
- `audit/`      — Execution audit logging (§IX)
- `recovery/`   — State recovery and reconcile
