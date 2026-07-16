# RFC 0028 — Contract Runtime

**Status:** ACCEPTED  
**Date:** 2026-07-16  
**Authors:** dotlinux26, D-O-T-Solutions

---

## Summary

This RFC defines the **Contract Runtime** — the execution layer of SMO where Contracts are deployed, selected, scheduled, and executed across a distributed mesh.

---

## Motivation

Prior to this RFC, SMO had:
- Network layer (Bootstrap, Discovery, Gossip, Heartbeat)
- Contract definition and Registry
- Basic CLI with selection engine

Missing: **Execution layer** that connects intent to actual execution with full traceability.

---

## Design

### 1. Contract ID

```
ContractID = BLAKE3(publisher || name || version || abi_hash || semantic_hash)
```

- 64 hex chars
- Deterministic, content-addressed
- Version changes → new ID

### 2. Execution ID

```
ExecutionID = BLAKE3(
    ContractID || requester || selected_nodes || timestamp_ns || nonce
)
```

- Unique per execution
- Enables full traceability

### 3. Trace ID

```
TraceID = BLAKE3("TRACE" || timestamp_ns || random)
```

- Links multiple Executions in a Workflow
- Enables distributed tracing

---

## C++ Implementation

### ContractID API (`core/contract/contract_id.hpp`)

```cpp
class ContractID {
public:
    static constexpr size_t SIZE = 32;  // BLAKE3-256 → 32 bytes

    ContractID() = default;
    explicit ContractID(const std::array<uint8_t, SIZE>& bytes);

    // Compute ContractID = BLAKE3(canonical_form)
    static ContractID compute(HashProvider& hasher, const std::string& canonical_form);

    static Result<ContractID> from_hex(const std::string& hex);
    std::string to_hex() const;
    bool empty() const;
    static bool is_valid_hex(const std::string& hex) noexcept;
    auto operator<=>(const ContractID&) const = default;
    const std::array<uint8_t, SIZE>& bytes() const { return bytes_; }

private:
    std::array<uint8_t, SIZE> bytes_{};
};

template<>
struct std::hash<ContractID> {
    size_t operator()(const ContractID& id) const noexcept;
};
```

### ExecutionID & TraceID

Same pattern as ContractID: `operator<=>()`, `std::hash`, `to_hex()`/`from_hex()`/`empty()`, 32-byte BLAKE3.

### Error Category

```cpp
enum class ErrorCategory : uint8_t {
    Protocol = 7,     // was 6, bumped for Session conflict
    Contract = 14,    // Contract execution errors
};
```

---

## Event Sourcing Model

Every Execution generates a **Event Log**:

```
Created → Validated → Queued → Scheduled → Selected
    → Dispatched → Accepted → Started → Progress
    → Completed | Failed | Cancelled
```

Each Event:
- Immutable, append-only
- Chained via `prev_hash`
- Signed by actor
- Stored in `audit.db` (SQLite, CBOR)

---

## Core Components

### 1. Event Store (`core/runtime/event_store.hpp`)

```cpp
class EventStore {
    Result<uint64_t> append(const EventRecord&);
    Result<vector<EventRecord>> query_by_execution(execution_id);
    Result<vector<EventRecord>> query_by_trace(trace_id);
    Result<vector<EventRecord>> query_by_contract(contract_id);
}
```

- SQLite + CBOR storage
- Hash-chained events
- Indexed by execution_id, trace_id, contract_id, timestamp

### 2. Contract Registry

```cpp
class ContractRegistry {
    Result<void> register_contract(ContractDefinition, registered_by, HashImpl);
    Result<ContractEntry> get_contract(ContractID);
    Result<vector<ContractEntry>> list_contracts();
}
```

- SQLite-backed
- Immutable, append-only

### 3. Execution Engine

```cpp
class ExecutionEngine {
    Result<string> submit(ExecutionContext);
    Result<string> get_status(execution_id);
    Result<ExecutionResult> get_result(execution_id);
    Result<void> cancel(execution_id);
}
```

- Worker pool with priority queue
- Retry engine with exponential backoff
- Trace context propagation

### 4. Native Contracts

Pre-registered contracts executed directly by Runtime:

| Contract | Opcode | Purpose |
|----------|--------|---------|
| `fs.list` | 0x01 | List directory |
| `fs.mkdir` | 0x02 | Create directory |
| `fs.remove` | 0x03 | Remove file/dir |
| `fs.copy` | 0x04 | Copy file/dir |
| `fs.move` | 0x05 | Move/rename |
| `fs.stat` | 0x06 | File info |
| `fs.read` | 0x07 | Read file |
| `fs.write` | 0x08 | Write file |
| `fs.chmod` | 0x09 | Change permissions |
| `fs.chown` | 0x0A | Change owner |
| `fs.symlink` | 0x0B | Create symlink |
| `fs.readlink` | 0x0C | Read symlink |
| `fs.realpath` | 0x0D | Resolve path |
| `exec` | 0x10 | Execute command |
| `proc.kill` | 0x11 | Kill process |
| `proc.ps` | 0x12 | List processes |
| `proc.top` | 0x13 | System stats |
| `systemd.start` | 0x20 | Start service |
| `systemd.stop` | 0x21 | Stop service |
| `systemd.restart` | 0x22 | Restart service |
| `file.put` | 0x30 | Upload file |
| `file.get` | 0x31 | Download file |
| `file.sync` | 0x32 | Sync directories |
| `workflow.deploy` | 0x40 | Deploy workflow |
| `workflow.start` | 0x41 | Start workflow |
| `workflow.stop` | 0x42 | Stop workflow |

---

## Audit Database Schema

```sql
CREATE TABLE audit_records (
    sequence INTEGER PRIMARY KEY,
    type INTEGER NOT NULL,
    timestamp_ns INTEGER NOT NULL,
    actor_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    contract_id TEXT,
    execution_id TEXT,
    trace_id TEXT,
    details TEXT NOT NULL,      -- JSON
    prev_hash TEXT NOT NULL,
    record_hash TEXT NOT NULL,
    signature TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000000000)
);

CREATE INDEX idx_audit_actor ON audit_records(actor_id);
CREATE INDEX idx_audit_target ON audit_records(target_id);
CREATE INDEX idx_audit_contract ON audit_records(contract_id);
CREATE INDEX idx_audit_execution ON audit_records(execution_id);
CREATE INDEX idx_audit_type ON audit_records(type);
CREATE INDEX idx_audit_timestamp ON audit_records(timestamp_ns);
```

---

## Event Record Format (CBOR)

```json
{
  "sequence": 12345,
  "type": "ExecutionStarted",
  "timestamp_ns": 1700000000000000000,
  "contract_id": "abc123...",
  "execution_id": "exec_abc123",
  "trace_id": "trace_xyz",
  "node_id": "node-01",
  "actor_id": "admin@company.com",
  "payload": { "args": ["ls", "/"] },
  "prev_hash": "abc123...",
  "event_hash": "def456...",
  "signature": "ed25519_sig..."
}
```

---

## Execution Lifecycle

```
User Intent
     ↓
Intent Parser → Opcode + Params
     ↓
Contract Factory → ContractID
     ↓
Selector → NodeSet
     ↓
Policy Engine → Allow/Deny
     ↓
Scheduler → Queue
     ↓
Executor → Node
     ↓
Event Store ← Event
     ↓
Result → User
```

---

## Error Handling

| Error | Code | Retry | Recovery |
|-------|------|-------|----------|
| ContractNotFound | 404 | No | User fix |
| PolicyDenied | 403 | No | Check caps |
| NodeUnreachable | 503 | Yes | Retry other nodes |
| Timeout | 504 | Yes | Retry with backoff |
| ExecutionFailed | 500 | Config | Check logs |
| ContractRevoked | 410 | No | Re-deploy |

---

## Implementation Order

| Sprint | Deliverable |
|--------|-------------|
| 5.1 | Contract ID + Execution ID + Event Store |
| 5.2 | Contract Registry + Native Contracts (FS) |
| 5.3 | Execution Engine + Event Store integration |
| 5.4 | Audit DB + Trace ID + History API |
| 5.5 | Native Contracts (FS, Transfer, Process) |
| 5.6 | CLI Intent Parser + Native Contract wiring |

---

## Testing Strategy

| Test | Scope |
|------|-------|
| Contract ID generation | Unit |
| Execution ID uniqueness | Unit |
| Event Store append/query | Integration |
| Contract Registry CRUD | Integration |
| Execution Engine submit/query | Integration |
| Native Contract execution | Integration |
| Audit trail integrity | Security |
| Trace propagation | Integration |

---

## References

- [RFC 0025] Contract Runtime Architecture
- [RFC 0026] Contract ABI Specification
- [RFC 0027] Network Layer
- [RFC 0029] Policy Engine (next)
- [RFC 0030] Native Contracts (next)
- [RFC 0031] Mesh Manager (next)

---

**End of RFC 0028**