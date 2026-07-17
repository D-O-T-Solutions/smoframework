# Discussion 0033 — CLI Three-Mode Architecture, Intent Layer, Mailbox & Platform Vision

**Date:** 2026-07-17  
**Participants:** @dotlinux26, @D-O-T-Solutions  
**Status:** 🔴 DRAFT — For discussion, NOT for implementation  
**Canonical implementation reference:** [SPEC.md](../../SPEC.md), [RFC 0032](../../RFC/0032-context-cli.md)

---

## Table of Contents

1. [The Core Problem — Two Abstractions Confused](#1-the-core-problem--two-abstractions-confused)
2. [The Fix — Three Clear Modes](#2-the-fix--three-clear-modes)
3. [Control Mode — Intent Shell (not Remote Shell)](#3-control-mode--intent-shell-not-remote-shell)
4. [Mailbox Mode — Not Vault, Not Filesystem](#4-mailbox-mode--not-vault-not-filesystem)
5. [Linux Shell Mode — Emergency/Debug Only](#5-linux-shell-mode--emergencydebug-only)
6. [Staging Area — Git-like `add`](#6-staging-area--git-like-add)
7. [Output Manager — Large-Scale Results](#7-output-manager--large-scale-results)
8. [Five-Engine Runtime Architecture](#8-five-engine-runtime-architecture)
9. [Policy Tiers](#9-policy-tiers)
10. [Event Bus, Metrics & Dashboard API](#10-event-bus-metrics--dashboard-api)
11. [Repository Pattern — SQLite → Service → API → Client](#11-repository-pattern--sqlite--service--api--client)
12. [SMO Platform Diagram](#12-smo-platform-diagram)
13. [Open Questions](#13-open-questions)

---

## 1. The Core Problem — Two Abstractions Confused

The current SMO architecture confuses two fundamentally different layers:

### Layer 1: SMO Control Plane (Remote Management)

What we are building today. Commands like `smo exec`, `smo ls`, `smo cp`, `smo put`, `smo get`.

This is **Remote Management** — analogous to SSH, Ansible, pdsh, Salt. It operates directly on the node's shell.

### Layer 2: SMO Runtime (Contract Execution)

This is where Contracts run. Workflow, Storage, Audit, Event, History.

**The bug:** The current CLI treats `ls`, `cp`, `rm` as if they are thin wrappers over Linux commands (`system("ls")`). This is wrong. They should be **Intent → Contract → Policy → Sandbox → Audit** pipelines.

---

## 2. The Fix — Three Clear Modes

The CLI should be split into three distinct modes so that "mesh administration", "data transfer", and "OS control" never get confused.

### Mode 1: Control Mode (default)

Mesh management and contract dispatch.

```
mesh       — manage meshes
select     — select target nodes
policy     — manage policy context
history    — view contract history
exec       — execute contract
put        — send object to node (via staging)
get        — receive object from node
deploy     — deploy contract to mesh
workflow   — workflow orchestration
```

### Mode 2: Mailbox Mode

Object transfer management. Enter via `mailbox` or `vault` command.

```
vault> ls                  — list mailbox objects (not Linux files)
vault> info OBJ-123        — show object metadata
vault> receive             — accept to filesystem
vault> extract             — decompress/extract to filesystem
vault> delete              — remove from mailbox
vault> archive             — move to archive
vault> reject              — reject delivery
vault> pending             — show pending deliveries
vault> outbox              — show outgoing objects
```

### Mode 3: Linux Shell Mode

Emergency/debug access. Enter via `shell <node>`.

```
worker01:~$                 — real Linux shell prompt
pwd, ls, cat, vi, nano     — real Linux commands
systemctl, journalctl      — real system commands
exit                        — return to SMO Shell
```

---

## 3. Control Mode — Intent Shell (not Remote Shell)

**The single most important philosophical correction.**

When the user types `ls /etc`, the CLI MUST NOT run `system("ls /etc")` or SSH to the node.

Instead:

```
User: ls /etc

CLI:
  IntentParser
    │
    ▼
  Intent: FilesystemList
    path: /etc
    recursive: false
    │
    ▼
  Contract: fs.list
    signed
    metadata-only
    │
    ▼
  PolicyEngine
    │
    ├── Allowed? → continue
    ├── Denied?  → return error
    ├── Quorum?  → wait for quorum
    └── Authority? → escalate
    │
    ▼
  ExecutionEngine
    │
    ├── SandboxAdapter → Linux → Result
    ├── Stream to selected nodes (mesh scope)
    └── Collect results
    │
    ▼
  AuditEngine
    │
    ├── Event: CONTRACT_CREATED
    ├── Event: CONTRACT_QUEUED
    ├── Event: CONTRACT_RUNNING
    ├── Event: NODE_ACCEPTED / NODE_DENIED
    ├── Event: NODE_FINISHED
    └── Event: CONTRACT_COMPLETED
    │
    ▼
  OutputManager
    │
    ├── Summary (498 success, 2 denied, 0 failed)
    ├── Detail (per node)
    └── Trace (full output per node)
    │
    ▼
  CLI: render table/json/yaml/csv
```

**No `system("ls")` at any point.**

This is the **Remote Intent Layer**, not a Remote Shell.

### Why This Matters

- **Policy** can deny `/etc/shadow` access, `reboot`, `rm -rf /`
- **Scope** can target 500 nodes at once with the same contract
- **Audit** records every operation immutably
- **Replay** — contracts can be replayed for recovery
- **Retry** — failed contracts can be retried automatically
- **Rollback** — contracts that support undo can be rolled back
- **Workflow** — contracts compose into workflows
- **Quorum** — sensitive operations require N-of-M approvals

### Examples

```bash
# Control Mode (default)
rm /tmp/*

# Internally:
# Contract: fs.remove
#   path: /tmp/*
#   recursive: false
#   force: false

# Policy checks:
#   User has CAP_FS_DELETE on /tmp?
#   Is control level sufficient? (safe blocks rm)
#   Is scope honored? (mesh vs single)

# Sandbox executes:
#   unlink("/tmp/xxx") for each matched file

# Audit records:
#   contract_id, user, timestamp, path, result, node_outputs
```

```bash
cp a b

# Contract: fs.copy
#   source: a
#   destination: b
#   scope: mesh (all 100 storage nodes)

# All 100 nodes execute the same copy atomically.
# This is impossible with plain SSH.
```

---

## 4. Mailbox Mode — Not Vault, Not Filesystem

### Problem

"Vault" in security usually means Secret Store / Credential Store / PKI. Using it for file transfer is confusing and misleading.

### Solution: Mailbox Architecture

Data transfer between nodes should be **message-oriented**, not filesystem-oriented.

```
Node A                          Node B
    │                              │
    ├── smo add report.pdf         │
    │   └── hash → OBJ-123         │
    │       └── cache              │
    │                              │
    ├── put OBJ-123 nodeB ─────────┤
    │                              ├── Mailbox/Inbox/OBJ-123
    │                              │
    │                              ├── vault> receive
    │                              │   └── Accepted
    │                              │
    │                              ├── vault> extract
    │                              │   └── /data/reports/report.pdf
    │                              │
    │                              └── vault> archive
    │                                  └── Mailbox/Archive/OBJ-123
```

### Mailbox Directory Structure

```
vault/
    inbox/          — incoming objects (not yet accepted)
    outbox/         — outgoing objects (pending delivery)
    processing/     — objects being extracted
    archive/        — processed/accepted objects
    rejected/       — rejected deliveries
```

### Key Principle

**The recipient decides when to extract to filesystem — not the sender.**

This is like AirDrop, email attachments, or a message queue. The sender pushes into the mailbox; the receiver moves to the filesystem on their own terms.

### Vault Commands (Mailbox Mode)

| Command | Description |
|---------|-------------|
| `ls` | List objects (metadata, not Linux ls) |
| `info <id>` | Show object metadata (ID, Owner, Hash, Sender, Receiver, State, Created, Expires) |
| `receive` | Accept from inbox → filesystem |
| `extract` | Decompress/extract archive to filesystem |
| `delete` | Remove from mailbox |
| `archive` | Move to archive |
| `reject` | Reject delivery |
| `pending` | Show pending deliveries |
| `outbox` | Show outgoing objects |

### Display (not Linux ls)

```
vault> ls
ID          Owner       Hash          Sender  Receiver  State     Created             Expires
OBJ-82ac13  admin@corp  sha256:a3f... node-a  node-b    INBOX     2026-07-17 10:00    2026-07-24 10:00
OBJ-91bd04  admin@corp  sha256:e7c... node-a  node-b    ARCHIVE   2026-07-16 08:00    —
```

---

## 5. Linux Shell Mode — Emergency/Debug Only

Entered via `shell <node>`. This is a real SSH-like session.

```
smo shell worker01
worker01:/home/admin$
```

Here, commands are real Linux:

```
pwd, ls, cat, vi, nano, top, htop
systemctl, journalctl, ip addr, ss
```

**No audit, no policy, no contract** — this is raw access.

Exit returns to SMO Shell:

```
worker01:/home/admin$ exit
production(storage:12)>
```

This mode is for:
- Emergency incident response
- Low-level debugging
- Recovery operations
- Operations that have no SMO contract yet

---

## 6. Staging Area — Git-like `add`

### Current Problem

`smo put file.tar node` currently implies immediate upload. There is no staging step.

### Proposed Flow

```
~/.smo/
    staging/
        metadata.db       — SQLite: hash → path → timestamp → size → obect_id
        cache/
            OBJ-82ac13    — actual file content
            OBJ-91bd04
```

#### `smo add <file>`

```
$ smo add ./backup.tar
Added: OBJ-82ac13
  Path: /home/user/backup.tar
  Size: 1.2 GB
  Hash: sha256:a3f...
```

**Does not upload.** Only:
1. Hash the file
2. Record metadata in `metadata.db`
3. Cache the file locally
4. Return an Object ID

#### `smo put <file|obj> <node>`

```
$ smo put backup.tar worker01
```

CLI:
1. Lookup `backup.tar` in staging metadata (by filename or OBJ-xxxx)
2. Found → stream from cache → transfer to node's Mailbox
3. Not found → Error: File not staged. Hint: `smo add backup.tar`

#### `smo put OBJ-82ac13 worker01`

Direct ID reference — bypass filename lookup.

```
$ smo put OBJ-82ac13 worker01
Streaming OBJ-82ac13 to worker01... Done.
```

#### Error case

```
$ smo put unknown.tar worker01
Error: File not staged.
Hint: smo add unknown.tar
```

This mirrors `git add` / `git commit` — separate index step from transfer step.

### Why This Matters

- **Batch staging** — stage many files, then transfer in one session
- **Deduplication** — same hash → same OBJ-ID, no duplicate storage
- **Verification** — hash computed at add time, verified at transfer time
- **Partial transfer** — resume interrupted transfers by hash
- **Local-only** — works offline; only `put` needs network

---

## 7. Output Manager — Large-Scale Results

### Problem

Running `ls /etc` on 500 nodes cannot print all 500 outputs to terminal. It will flood, scroll, and lose information.

### Solution: Structured ContractResult

```cpp
class ContractResult {
    ContractID id;
    Summary summary;
    std::vector<NodeResult> nodes;
    std::vector<Event> events;
    Metrics metrics;
};

struct Summary {
    int total;
    int success;
    int denied;
    int failed;
    int timeout;
    Duration elapsed;
};

struct NodeResult {
    NodeID node;
    Status status;        // SUCCESS | DENIED | FAILED | TIMEOUT
    std::string output;   // full output (captured)
    std::string error;    // error message if failed
    Duration duration;
    std::string reason;   // e.g. "Policy denied: /etc/shadow"
};
```

### CLI Display Levels

#### Level 1: Summary (default)

```
Contract CON-3A92
Status: Completed
  Executed : 498
  Denied   : 2
  Failed   : 0
  Timeout  : 0
  Duration : 310 ms
```

#### Level 2: Detail

```
$ history CON-3A92 --detail

Node         Status    Duration  Reason
worker01     SUCCESS   2ms       —
worker02     SUCCESS   1ms       —
worker03     DENIED    0ms       Policy: /etc/shadow denied
...
worker500    SUCCESS   3ms       —
```

#### Level 3: Trace (full output per node)

```
$ trace CON-3A92 worker03

Node: worker03
Status: DENIED
Duration: 0ms
Reason: Policy denied: /etc/shadow is read-only
Output: (none)
```

### Output Formats

```
history CON-3A92               # table (terminal)
history CON-3A92 --json        # JSON
history CON-3A92 --yaml        # YAML
history CON-3A92 --csv         # CSV
```

This enables integration with SIEM, Grafana, ELK, Splunk.

### Result Storage

```
ContractResult
    → stored in SQLite (runtime DB)
    → served via REST API
    → CLI fetches and renders
    → Dashboard fetches and renders
```

---

## 8. Five-Engine Runtime Architecture

```
                    ┌──────────────────────────────┐
                    │       Intent Engine           │
                    │  Parse CLI → Build Intent     │
                    │  Resolve targets (selector)   │
                    └──────────┬───────────────────┘
                               │
                    ┌──────────▼───────────────────┐
                    │       Policy Engine           │
                    │  Load policies                │
                    │  Check allow/deny/readonly    │
                    │  Check control level          │
                    │  Check quorum requirements    │
                    └──────────┬───────────────────┘
                               │
                    ┌──────────▼───────────────────┐
                    │     Execution Engine          │
                    │  Build Contract               │
                    │  Dispatch to nodes            │
                    │  Stream results               │
                    │  Handle retry/timeout         │
                    └──────────┬───────────────────┘
                               │
                    ┌──────────▼───────────────────┐
                    │    Audit / Event Engine       │
                    │  Emit events (bus)            │
                    │  Write audit trail            │
                    │  Notifications (webhook/email)│
                    └──────────┬───────────────────┘
                               │
                    ┌──────────▼───────────────────┐
                    │   Query / History API         │
                    │  REST/gRPC endpoints          │
                    │  SQLite → Repository Layer    │
                    │  Serve CLI, Dashboard, SDK    │
                    └──────────────────────────────┘
```

### Engine Responsibilities

| Engine | Input | Output |
|--------|-------|--------|
| Intent | CLI tokens / parsed command | Intent struct (typed, validated) |
| Policy | Intent + node context | Decision (Allow/Deny/Quorum/Escalate) |
| Execution | Intent + policy decision | ContractResult (per-node results) |
| Audit/Event | Contract lifecycle | Events, Audit trail, Notifications |
| Query/History | API request (REST/gRPC) | Formatted results (JSON/table/csv) |

---

## 9. Policy Tiers

Current thinking is `allow = true/false`. Future policy is multi-tier.

### Filesystem Policy

```yaml
filesystem:
  deny:
    - /etc/shadow
    - /boot
    - /var/lib/smo
  readonly:
    - /etc
    - /usr
  readwrite:
    - /home
    - /opt/app
  allow_delete:
    - /tmp
```

### Process Policy

```yaml
process:
  allow:
    - systemctl status
    - journalctl
    - df
    - free
  deny:
    - systemctl stop sshd
    - reboot
    - poweroff
    - rm -rf /
```

### Mesh Policy

```yaml
mesh:
  roles:
    worker:
      deny: [deploy, workflow]
    storage:
      deny: [kill, reboot]
    authority:
      allow: [everything]
```

### Policy Evaluation

```
PolicyEngine.check(intent, node_role, control_level)
    → ALLOW | DENY | QUORUM_NEEDED | ESCALATE
```

---

## 10. Event Bus, Metrics & Dashboard API

### Event Bus

Every contract lifecycle stage emits events:

```
CONTRACT_CREATED
CONTRACT_QUEUED
CONTRACT_RUNNING
NODE_ACCEPTED
NODE_DENIED
NODE_FAILED
NODE_TIMEOUT
NODE_FINISHED
CONTRACT_COMPLETED
```

Subscribers:
- CLI (real-time status)
- Dashboard (realtime via WebSocket)
- Notification service (email/slack/discord/webhook)
- Audit service (persistent storage)
- Metrics service (Prometheus)

### Metrics API

```
GET /api/metrics

{
    "contracts_running": 12,
    "contracts_completed": 921,
    "contracts_failed": 3,
    "contracts_denied": 8,
    "mesh_nodes": 53,
    "avg_latency_ms": 18,
    "active_sessions": 7
}
```

Prometheus can scrape directly.

### Contracts API

```
GET /api/contracts
→ [{ id, status, success, failed, denied, duration, timestamp }]

GET /api/contracts/:id
→ { full ContractResult }

GET /api/contracts/:id/nodes
→ per-node status + output

GET /api/contracts/:id/nodes/:node/trace
→ full output for one node
```

### Dashboard

Vue/React app:
- Fetch from `/api/contracts`
- Subscribe to event bus for real-time
- No direct DB access

---

## 11. Repository Pattern — SQLite → Service → API → Client

**Critical rule:** CLI MUST NOT read SQLite directly.

```
SQLite (runtime DB)
    │
    ▼
Repository Layer (data access)
    │
    ▼
History Service (business logic)
    │
    ▼
REST API (HTTP/gRPC)
    │
    ├── CLI (render)
    ├── Dashboard (render)
    ├── Mobile App (render)
    ├── VSCode Extension (render)
    └── External SIEM (consume)
```

### Benefits

- CLI and Dashboard always show the same data
- Switch SQLite → PostgreSQL → cluster DB without touching clients
- API is the single source of truth
- Rate limiting, auth, caching at API layer
- Clients are interchangeable

---

## 12. SMO Platform Diagram

```
                         SMO Platform

              ┌────────────────────────────────────┐
              │          SMO CLI Shell              │
              │  (3-mode interactive shell)         │
              └─────────┬──────────┬───────────────┘
                        │          │
              ┌─────────┘          └─────────┐
              │                              │
     ┌────────▼────────┐          ┌──────────▼──────┐
     │   Control Mode   │          │   Linux Shell   │
     │   (Intent Shell) │          │   (Emergency)   │
     │                  │          │                  │
     │ mesh  select     │          │ pwd  ls  cat    │
     │ policy  history  │          │ vi  systemctl   │
     │ exec  put  get   │          │ journalctl  top │
     │ deploy  workflow │          │ exit → SMO      │
     └────────┬─────────┘          └─────────────────┘
              │
     ┌────────▼─────────┐
     │   Mailbox Mode    │
     │   (Object Transfer)│
     │                    │
     │ ls  info  receive  │
     │ extract  delete    │
     │ archive  reject    │
     └────────┬───────────┘
              │
     ┌────────▼──────────────────────────────────────┐
     │             5-Engine Runtime                   │
     │                                                  │
     │  Intent → Policy → Execution → Audit → Query    │
     └────────┬─────────────────────────────────────────┘
              │
     ┌────────▼──────────────────────────────────────┐
     │           REST API (single source of truth)    │
     └────────┬─────────────────────────────────────────┘
              │
     ┌────────▼────────┐  ┌──────────▼───────────┐
     │    Dashboard     │  │  External Integrations│
     │    (Vue/React)   │  │  Prometheus, Grafana  │
     │    Web UI        │  │  ELK, Splunk, Slack   │
     └─────────────────┘  └────────────────────────┘
```

---

## 13. Open Questions

1. **Contract ↔ Intent mapping** — Does every CLI command map 1:1 to a contract? Or are there composite commands?

2. **Mailbox protocol** — How does the sender know delivery status? ACK? NACK? Callback?

3. **Policy storage** — Where are policies stored? SQLite? TOML files? Distributed policy sync?

4. **Output size limits** — What happens when `cat /var/log/syslog` on 500 nodes returns 2GB of text? Stream to object store?

5. **Rollback support** — Which contracts support undo? How is rollback authorized?

6. **Shell mode security** — Should `shell` mode require `--control emergency` or Authority cert only?

7. **Staging garbage collection** — When are staged files removed from cache? After successful put? LRU eviction?

8. **Event bus delivery guarantee** — At-least-once? Exactly-once? Best-effort for real-time?

9. **API versioning** — `/api/v1/contracts`? How to handle breaking changes?

10. **Plugin system** — Can third parties add new contract types? New policy engines?

---

## References

- [RFC 0032 — Context-Aware CLI](../../RFC/0032-context-cli.md) — current CLI design
- [RFC 0029 — Policy Engine](../../RFC/0029-policy-engine.md) — policy architecture
- [RFC 0028 — Contract Runtime](../../RFC/0028-contract-runtime.md) — runtime layer
- [RFC 0030 — Native Contracts](../../RFC/0030-native-contracts.md) — contract types
- [SPEC.md](../../SPEC.md) — canonical specification
- [ARCHITECTURE.md](../../ARCHITECTURE.md) — architectural rationale
- [PLAN.md](../PLAN.md) — current sprint plan
