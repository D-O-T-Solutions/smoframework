# Sprint 5 — Distributed Operating Platform

**Status:** DRAFT — Proposed  
**Date:** 2026-07-17  
**Authors:** @dotlinux26, @D-O-T-Solutions

---

## Vision

Từ Sprint 5 trở đi, SMO không còn là "CLI quản lý node".

SMO là **Distributed Operating Platform**.

Mọi thứ xoay quanh một pipeline thống nhất:

```
Intent
    ↓
Service Layer
    ↓
Runtime
    ↓
Policy
    ↓
Scheduler
    ↓
Contract
    ↓
Event Bus
    ↓
Audit (Source of Truth)
    ├── Output
    ├── History
    ├── API Gateway
    ├── Dashboard
    ├── Metrics
    └── Notifications
```

---

## Architectural Rules (Phase 0 Freeze)

### Layer Rules

```
CLI / Dashboard / TUI / REST / gRPC / WebSocket / IPC
           │
           ▼
     Service Layer  ←── CLI không bao giờ include Runtime trực tiếp
     ├── MeshService
     ├── RuntimeService
     ├── AuditService
     ├── PolicyService
     └── VaultService
           │
           ▼
        Event Bus    ←── Mọi subsystem giao tiếp qua Event Bus
           │
     ┌─────┼─────┬─────┬─────┬─────┐
     │     │     │     │     │     │
  Scheduler Policy Audit Output History
     │                       │
     ▼                       ▼
ExecutionEngine         AggregateResult
     │
     ▼
  Contract Dispatcher
     │
     ▼
  Registry → NativeContract / Filesystem / Transfer / Vault / Workflow
```

### Critical Rules

| Rule | Mô tả |
|------|-------|
| **CLI × Runtime** | CLI không include Runtime. CLI → Service Layer → Runtime |
| **Runtime × Contract** | Runtime chỉ biết `ContractID`, `ABI`, `Input`, `Output`. Không biết Concrete Contract |
| **Event Bus trung tâm** | Không component nào gọi nhau trực tiếp. Tất cả qua Event Bus |
| **Audit là Source of Truth** | History là View của Audit. Output là View của Audit. Không lưu riêng |
| **Policy là plugin** | Policy là Event-driven plugin của Runtime, không phải layer riêng |
| **Vault độc lập** | Vault Service là Infrastructure, không nằm trong Runtime |
| **Service là facade** | Service Layer là facade duy nhất cho CLI/Dashboard/API |

### Naming Rules

| Pattern | Ví dụ | Ghi chú |
|---------|-------|---------|
| `*Service` | `MeshService`, `RuntimeService` | Service Layer |
| `*Engine` | `ExecutionEngine`, `PolicyEngine` | Internal engine |
| `*Dispatcher` | `ContractDispatcher` | Routing/dispatch |
| `*Store` | `ObjectStore`, `AuditStore` | Storage backend |
| `*Bus` | `EventBus` | Event/message bus |
| `Contract` | `FilesystemListContract` | Contract implementation |

### Event Naming

```
<DOMAIN>_<ACTION>[_<STATUS>]

Ví dụ:
CONTRACT_CREATED
CONTRACT_QUEUED
CONTRACT_RUNNING
NODE_ACCEPTED
NODE_DENIED
NODE_FINISHED
CONTRACT_COMPLETED
CONTRACT_FAILED
POLICY_DENIED
POLICY_QUORUM_NEEDED
AUDIT_FLUSHED
OUTPUT_AGGREGATED
VAULT_OBJECT_STAGED
VAULT_OBJECT_TRANSFERRED
```

---

## Sprint 5A — Runtime Foundation

**Ref:** DISCUSSION_0033 §8 (5-Engine Runtime), §10 (Event Bus)

### Architecture

```
Service Layer
    │
    ▼
Event Bus
    │
    ├── Scheduler
    │     ├── Queue (FIFO / Priority)
    │     ├── Batch (1000 nodes → chunked)
    │     ├── Concurrency (max parallel)
    │     └── Retry (exponential backoff)
    │
    ├── ExecutionEngine
    │     ├── Contract Dispatcher
    │     │     ├── Registry (ContractID → ContractFactory)
    │     │     └── SandboxAdapter (isolated execution)
    │     └── Result Collector
    │
    ├── AuditService
    │     ├── Event Subscriber
    │     ├── Audit Store (immutable, append-only)
    │     └── Retention Policy
    │
    ├── OutputManager
    │     ├── Streaming (tail -f 100 nodes)
    │     ├── Snapshot (per-node result)
    │     ├── Aggregate (summary)
    │     └── Export (JSON/YAML/CSV)
    │
    └── HistoryService
          └── Query Audit (read-only view)
```

### Task List

| # | Task | File |
|---|------|------|
| 1 | `EventBus` — typed event emitter, multiple subscribers, async dispatch | `core/events/event_bus.hpp/.cpp` |
| 2 | `Scheduler` — queue, batch, priority, concurrency, retry, timeout | `runtime/scheduler/scheduler.hpp/.cpp` |
| 3 | `ExecutionEngine` — dispatch Contract → Scheduler → collect results | `runtime/executor/execution_engine.hpp/.cpp` |
| 4 | `ContractDispatcher` — Registry lookup, instantiate, execute | `runtime/executor/contract_dispatcher.hpp/.cpp` |
| 5 | `AuditService` — subscribe EventBus, write immutable audit trail | `runtime/audit/audit_service.hpp/.cpp` |
| 6 | `OutputManager` — streaming, snapshot, aggregate, export | `runtime/output/output_manager.hpp/.cpp` |
| 7 | `HistoryService` — query Audit for timeline view | `runtime/history/history_service.hpp/.cpp` |
| 8 | `NativeContract` interface (execute, rollback, abort) | `runtime/contracts/contract.hpp` |
| 9 | `ContractRegistry` — map ContractID → Factory function | `runtime/contracts/registry.hpp/.cpp` |
| 10 | Service Layer skeleton: `MeshService`, `RuntimeService`, `AuditService` | `core/service/` |

---

## Sprint 5B — Mesh Lifecycle + Manifest

**Ref:** User feedback items #1–#8, DISCUSSION_0034 Phase 1-2, DISCUSSION_0033 §12

### Mesh States

```
     ┌──────────┐
     │  Draft    │  ← smo mesh create
     └────┬─────┘
          │ smo-admin create-mesh (keys generated)
          ▼
     ┌──────────┐
     │ Published│  ← smo mesh publish
     └────┬─────┘
          │ smo mesh serve
          ▼
     ┌──────────┐
     │  Online   │  ← Enroll server running
     └────┬─────┘
          │ smo mesh stop
          ▼
     ┌──────────┐
     │ Published│  ← Serve stopped, data intact
     └────┬─────┘
          │ smo mesh delete (confirm)
          ▼
     ┌──────────┐
     │ Archived  │  ← Backed up, removed from active
     └──────────┘
```

### Mesh Manifest v2

`mesh.json` trở thành manifest của cả mesh:

```json
{
  "manifest_version": 2,
  "schema_version": "2.0",
  "runtime_version": "3.0.0",
  "policy_version": 1,

  "mesh_id": "a1b2c3d4...",
  "display_name": "SOC-Production",
  "state": "Published",

  "cipher_suite_id": 3,
  "epoch": 1,
  "created_at": 1700000000000,

  "authority_pubkey": "...",
  "root_pubkey": "...",
  "hmac_secret": "...",

  "listen_address": "0.0.0.0:7777",
  "advertise_addresses": ["..."],
  "bootstrap_endpoints": ["..."],

  "objects": { "count": 0, "total_size": 0 },
  "workflow": { "enabled": false },
  "policy": { "default": "enterprise" },
  "audit": { "enabled": true, "retention_days": 90 }
}
```

### Task List

| # | Task | File |
|---|------|------|
| 1 | Mesh Manifest v2: thêm version, state, objects, workflow, policy, audit fields | `core/mesh/mesh_manifest.hpp` |
| 2 | Mesh state machine FSM + transition validation | `core/mesh/mesh_fsm.hpp/.cpp` |
| 3 | `smo mesh publish` merged flow: publish → "Start serve?" | `cmd/smo-cli/main.cpp` |
| 4 | `smo mesh current` rich display (Name, Suite, State, Members, Policy) | `cmd/smo-cli/main.cpp` |
| 5 | `smo mesh list` table format + state column | `cmd/smo-cli/main.cpp` |
| 6 | `smo mesh delete <name>` + confirm prompt | `cmd/smo-cli/main.cpp` |
| 7 | `smo mesh stop` (Online → Published) | `cmd/smo-cli/main.cpp` |
| 8 | `smo mesh backup` / `restore` | `cmd/smo-cli/main.cpp` |

---

## Sprint 5C — Policy Engine + Scheduler + Native Contracts

**Ref:** RFC 0029, DISCUSSION_0033 §9

### Policy Tiers (9 loại)

| Tier | Scope | Ví dụ |
|------|-------|-------|
| Filesystem | File/directory access | `/etc/shadow` deny, `/home` readwrite |
| Process | Process execution | `reboot` deny, `systemctl status` allow |
| Transfer | Data transfer (put/get) | `put` over 100MB deny, `get` config allow |
| Vault | Object store operations | `vault delete` requires Authority role |
| Workflow | Workflow orchestration | `deploy` requires quorum |
| Contract | Contract deployment | Custom contracts require admin approval |
| Shell | Emergency SSH access | Requires `--control emergency` |
| Mesh | Mesh administration | `mesh delete` requires Authority |
| Network | Network operations | Port binding, advertise, bootstrap |

### Architecture

```
Intent
    │
    ▼
PolicyEngine.check(intent, context)
    │
    ├── ALLOW          → EventBus: POLICY_ALLOWED  → Runtime tiếp tục
    ├── DENY           → EventBus: POLICY_DENIED   → Return error
    ├── QUORUM_NEEDED  → EventBus: QUORUM_REQUEST  → Chờ N/M approvals
    └── ESCALATE       → EventBus: ESCALATED       → Gửi lên Authority
```

### Task List

| # | Task | File |
|---|------|------|
| 1 | `PolicyEngine` — 9-tier evaluation pipeline | `core/acl/policy_engine.hpp/.cpp` |
| 2 | Policy schema per tier (filesystem, process, transfer, vault, workflow, contract, shell, mesh, network) | `core/acl/policy/` |
| 3 | Policy storage (TOML files + cache) | `core/acl/policy_store.hpp/.cpp` |
| 4 | Policy evaluation as EventBus subscriber | `core/acl/policy_engine.cpp` |
| 5 | `mesh policy` CLI: `list`, `show`, `apply`, `default` | `cmd/smo-cli/main.cpp` |
| 6 | Native Contracts: `ExecContract`, `FilesystemList`, `FilesystemCopy`, `FilesystemRemove` | `runtime/contracts/` |
| 7 | Policy-backed execution pipeline integration | `runtime/executor/execution_engine.cpp` |
| 8 | Decision events → Audit + Output + History | `runtime/` |

---

## Sprint 5D — Unified CLI + Offline Enrollment

**Ref:** DISCUSSION_0034 Phase 3-4, DISCUSSION_0033 §8

### Roadmap

| Sprint | `smo-admin` status | UX |
|--------|---------------------|-----|
| 5 | `smo mesh serve` gọi nội bộ `smo-admin serve`, in "Compatibility backend" | `smo` chính, `smo-admin` deprecated |
| 6 | `smo-admin` chỉ còn Internal Tool | Không ghi trong document |
| 7 | `smo-admin` + `smo-node` debug/recovery/boot only | User chỉ biết `smo` |

### Offline Enrollment Flow

```
# Authority
smo mesh create SOC-Production
smo mesh invite Worker --copy
# Token copied to clipboard

# Node (offline, no HTTP)
smo join
  → "Paste Join Token:"
  → User pastes
  → CSR generated
  → "Copy this CSR and send to Authority:"
  → <SMO-CSR-hex...>

# Authority
smo sign --paste
  → CSR from clipboard
  → Certificate signed
  → Copied to clipboard

# Node
  → "Paste Certificate:"
  → User pastes
  → Certificate imported
  → Identity: Enrolled
  → Done.
```

### Task List

| # | Task | File |
|---|------|------|
| 1 | `smo join` interactive mode: paste token, CSR output, paste cert | `cmd/smo-cli/main.cpp` |
| 2 | `smo sign <csr> -o <cert>` (merge `smo-admin sign`) | `cmd/smo-cli/main.cpp` |
| 3 | `smo sign --paste` — clipboard sign | `cmd/smo-cli/main.cpp` |
| 4 | `smo-admin` → deprecated alias (warning + proxy to `smo`) | `cmd/smo-admin/main.cpp` |
| 5 | `.smo/` detection in project directory (cwd → parent → ~) | `core/mesh/mesh_resolver.hpp` |
| 6 | `smo mesh serve` wrapper → `smo-admin serve` (compat backend) | `cmd/smo-cli/main.cpp` |

---

## Sprint 5E — Vault (Mailbox + Object Store + Transfer Engine)

**Ref:** DISCUSSION_0033 §4 (Mailbox), §6 (Staging)

### Architecture

```
VaultService
    │
    ├── Mailbox
    │     ├── inbox/       (incoming, not yet accepted)
    │     ├── outbox/      (outgoing, pending delivery)
    │     ├── processing/  (being extracted)
    │     ├── archive/     (processed/accepted)
    │     └── rejected/    (rejected deliveries)
    │
    ├── ObjectStore
    │     ├── Object Metadata (SQLite)
    │     │     ├── Hash → ID, Size, Created, RefCount
    │     │     ├── Dedup (same hash → single blob)
    │     │     └── Integrity (hash verification on read)
    │     ├── Object Blob (content-addressed storage)
    │     └── GC (unreferenced blobs → delete)
    │
    └── TransferEngine
          ├── Push (sender → receiver mailbox)
          ├── Pull (receiver fetches from sender)
          ├── Resume (interrupted transfer → continue)
          └── Verify (hash check after transfer)
```

### Staging Area (Git-like)

```
~/.smo/staging/
    metadata.db       — SQLite: filename → hash → path → size → object_id
    cache/
        OBJ-82ac13    — actual file content
        OBJ-91bd04
```

```
smo add backup.tar           # stage local file
  → OBJ-82ac13

smo put OBJ-82ac13 worker01  # transfer to node
  → Streaming to worker01... Done.

smo put backup.tar worker01  # lookup by filename
  → Found OBJ-82ac13 → Streaming...
```

### Task List

| # | Task | File |
|---|------|------|
| 1 | `ObjectStore` — content-addressed, dedup, refcount, integrity, GC | `core/vault/object_store.hpp/.cpp` |
| 2 | `Mailbox` — inbox/outbox/archive/rejected directory management | `core/vault/mailbox.hpp/.cpp` |
| 3 | `TransferEngine` — push, pull, resume, verify | `core/vault/transfer_engine.hpp/.cpp` |
| 4 | `VaultService` — facade cho CLI/API | `core/service/vault_service.hpp/.cpp` |
| 5 | Staging: `~/.smo/staging/`, `smo add <file>` | `core/staging/staging.hpp/.cpp` |
| 6 | `vault` CLI mode: `ls`, `info`, `receive`, `extract`, `delete`, `archive`, `reject` | `cmd/smo-cli/main.cpp` |
| 7 | Transfer Contract (Native) | `runtime/contracts/transfer_contract.cpp` |
| 8 | Vault policy tier integration | `core/acl/policy_engine.cpp` |

---

## Sprint 5F — Internal API + API Gateway

**Ref:** DISCUSSION_0033 §10, §11

### Architecture

```
Service Layer
    │
    ▼
API Gateway
    │
    ├── REST     (HTTP/JSON)    → CLI, Dashboard, External Integrations
    ├── gRPC     (HTTP/Protobuf) → SDK, Mobile, High-performance clients
    ├── WebSocket (real-time)   → Dashboard live updates, tail -f
    └── IPC      (Unix socket)  → Local CLI (fast path)
```

### API Endpoints (v1)

```
GET    /api/v1/health

GET    /api/v1/mesh
GET    /api/v1/mesh/:name
POST   /api/v1/mesh/:name/publish
POST   /api/v1/mesh/:name/serve
DELETE /api/v1/mesh/:name

GET    /api/v1/contracts
GET    /api/v1/contracts/:id
GET    /api/v1/contracts/:id/nodes
GET    /api/v1/contracts/:id/nodes/:node/trace

GET    /api/v1/audit?since=...&limit=...
GET    /api/v1/output/:contract_id

GET    /api/v1/metrics         (Prometheus compatible)

GET    /api/v1/events?since=... (Server-Sent Events)
```

### Task List

| # | Task | File |
|---|------|------|
| 1 | API Gateway skeleton — REST + WebSocket + IPC | `api/gateway.hpp/.cpp` |
| 2 | Mesh API endpoints | `api/v1/mesh_api.hpp/.cpp` |
| 3 | Runtime API endpoints | `api/v1/runtime_api.hpp/.cpp` |
| 4 | Audit/Output/History API endpoints | `api/v1/audit_api.hpp/.cpp` |
| 5 | Metrics endpoint (Prometheus) | `api/v1/metrics.hpp/.cpp` |
| 6 | Events endpoint (SSE / WebSocket) | `api/v1/events.hpp/.cpp` |
| 7 | CLI → API Gateway migration | `cmd/smo-cli/main.cpp` |

---

## Sprint 5G — Observability

**Ref:** Sprint 5 mới — Observability là yêu cầu enterprise cho 1000+ node

### Components

```
Observability
    │
    ├── Tracing
    │     ├── OpenTelemetry integration
    │     ├── Distributed trace: Intent → Execution → Node → Result
    │     └── Span context propagation
    │
    ├── Logging
    │     ├── Structured logging (JSON)
    │     ├── Log levels: DEBUG, INFO, WARN, ERROR, FATAL
    │     ├── Per-module log level
    │     └── Log shipping (syslog, file, stdout)
    │
    ├── Metrics
    │     ├── Prometheus endpoint (/api/v1/metrics)
    │     ├── Contracts/sec, latency P50/P95/P99
    │     ├── Active nodes, sessions, vault objects
    │     ├── Policy deny rate
    │     └── Audit write rate
    │
    ├── Health
    │     ├── /api/v1/health (liveness + readiness)
    │     ├── Component dependency health
    │     └── Mesh node health (aggregate from heartbeats)
    │
    └── Profiling
          ├── CPU / Memory / Goroutine-equivalent tracking
          ├── Slow contract detection (> threshold)
          └── Leak detection (stuck contracts, unclosed sessions)
```

### Task List

| # | Task | File |
|---|------|------|
| 1 | OpenTelemetry tracing integration | `observability/tracing/` |
| 2 | Structured logging (JSON) | `observability/logging/` |
| 3 | Prometheus metrics endpoint | `observability/metrics/` |
| 4 | Health check endpoint | `observability/health/` |
| 5 | Slow contract detection + profiling | `observability/profiling/` |

---

## Sprint 5 Summary

| Phase | Module | Priority | Dependency |
|-------|--------|----------|------------|
| **5.0** | Architecture Freeze | ⭐⭐⭐⭐⭐ | Không — rules & docs |
| **5A** | Runtime Foundation | ⭐⭐⭐⭐⭐ | 5.0 |
| **5B** | Mesh Lifecycle | ⭐⭐⭐⭐ | 5A (Event Bus) |
| **5C** | Policy + Scheduler + Contracts | ⭐⭐⭐⭐ | 5A (Runtime) |
| **5D** | Unified CLI + Offline Enrollment | ⭐⭐⭐⭐ | 5A, 5B (Mesh + Service) |
| **5E** | Vault | ⭐⭐⭐ | 5A (Event Bus + Service) |
| **5F** | Internal API | ⭐⭐⭐ | 5A (Service Layer) |
| **5G** | Observability | ⭐⭐⭐ | 5A (Event Bus + Metrics) |

### Module Dependency (Final)

```
CLI / Dashboard / TUI / REST / gRPC / WebSocket
           │
           ▼
     API Gateway (5F)
           │
           ▼
     Service Layer (5A)
     ├── MeshService      ← Mesh Lifecycle (5B)
     ├── RuntimeService   ← Runtime Foundation (5A)
     ├── AuditService     ← Runtime Foundation (5A)
     ├── PolicyService    ← Policy Engine (5C)
     └── VaultService     ← Vault (5E)
           │
           ▼
        Event Bus (5A)
           │
     ┌─────┼─────┬─────┬─────┬─────┐
     │     │     │     │     │     │
  Scheduler Policy Audit Output History
  (5C)     (5C)  (5A)  (5A)  (5A)
     │
     ▼
ExecutionEngine
     │
     ▼
  Contract Dispatcher → Registry → NativeContract (5C)
     │
     ├── FilesystemContract
     ├── TransferContract (5E)
     ├── VaultContract (5E)
     └── WorkflowContract (future)

Observability (5G) → gắn vào Event Bus + API Gateway
```

---

## References

- [DISCUSSION_0033 — 3-mode CLI, Mailbox, 5-Engine Runtime](discussions/DISCUSSION_0033_CLI_THREE_MODE_ARCHITECTURE.md)
- [DISCUSSION_0034 — UX Mesh Context, Offline Enrollment](discussions/DISCUSSION_0034_UX_MESH_CONTEXT.md)
- [RFC 0028 — Contract Runtime Architecture](../../RFC/0028-contract-runtime.md)
- [RFC 0029 — Policy Engine](../../RFC/0029-policy-engine.md)
- [RFC 0030 — Native Contracts](../../RFC/0030-native-contracts.md)
- [RFC 0032 — Context-Aware CLI](../../RFC/0032-context-cli.md)
- [SPEC.md](../SPEC.md)
- [ARCHITECTURE.md](../ARCHITECTURE.md)
- [PLAN.md](PLAN.md)

---

## Open Questions (cần chốt trước Sprint 5.0)

1. **Ngôn ngữ cho API Gateway** — C++ (native, zero-copy) hay Rust (memory safety) hay Go (ecosystem)?
2. **Vault Storage Backend** — SQLite + filesystem (như Git) hay embedded object store (SeaweedFS, MinIO)?
3. **OpenTelemetry** — C++ SDK đã ổn định chưa? Hay tự implement metrics core trước?
4. **`smo` binary duy nhất** — Có nên static link `smo-admin` + `smo-node` vào `smo` binary từ Sprint 5, hay giữ riêng đến Sprint 7?
5. **Policy storage format** — TOML (như config) hay YAML (dễ đọc) hay định dạng riêng?
