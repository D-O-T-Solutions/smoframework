# SECURE MESH OPERATION (SMO) — Engineering Specification

Version: 3.0
Codename Supersedes: SMF (ShellMap Framework) V3
Canonical Name: Secure Mesh Operation (SMO)

---

## PREFACE — How to Read This Document

This document is the single source of truth for the SMO system. Every module, interface, state machine, protocol decision, and engineering constraint is defined here. Nothing is inferred from conversation.

Sections are ordered by conceptual dependency, not by implementation order. Read §Implementation Order for the recommended build sequence.

---

## 0. TERMINOLOGY

| Term | Definition |
|---|---|
| SMO | Secure Mesh Operation — the complete distributed execution runtime |
| SMF | ShellMap Framework — the predecessor framework. Concepts absorbed into SMO |
| Node | A single machine running the SMO runtime, participating in the mesh |
| Mesh | The collection of all participating SMO nodes |
| Contract | A metadata-only document that describes execution intent and constraints. NEVER contains application data |
| Requester | The node that proposes a contract |
| Responder | The node that receives and executes (or rejects) a contract. Has final decision authority |
| Witness | An independent third node that attests to the contract's existence and integrity. Does not execute |
| Intent | What the requester wants to accomplish. Expressed as an opcode and parameters |
| Capability | A runtime-validated, session-scoped permission. NOT a static role |
| Opcode | The operation type (LS, GET, PUT, EXEC, MKDIR, RM, CP, QUARANTINE, etc.) |
| Session | A scoped execution context with associated capabilities and constraints |
| DAG | Directed Acyclic Graph — the immutable execution plan produced by the compiler |
| FSM | Finite State Machine — governs node-level and mesh-level execution transitions |
| Trust Score | A composite local metric used as one input (not the sole) to execution decisions |
| Citizen Score | A trust sub-component measuring online time, heartbeat stability, route reliability |
| Execution Score | A trust sub-component measuring successful contract completions |
| Witness Score | A trust sub-component measuring witness accuracy and participation |
| Consistency Score | A trust sub-component measuring result agreement with majority |
| Origin Node | The authority that signs and distributes initial capability grants |
| Policy | Node-local rules governing which contracts it will accept and how to execute them |

---

## I. SYSTEM POSITIONING

SMO IS:
- A capability-scoped distributed execution runtime operating on untrusted mesh environments
- A distributed constrained execution environment where contract is the unit of communication
- An incident response runtime for mass operations on Linux (and later, other OS) fleets
- A platform for intent-based orchestration: "describe intent, distribute trust, execute locally"

SMO IS NOT:
- An SSH replacement
- A Kubernetes clone
- A Dropbox-like sync tool
- An RPC framework
- A remote shell
- A distributed bash
- A blockchain or ledger
- A VPN tool

---

## II. CORE PHILOSOPHY

The following philosophical positions anchor every architectural decision in SMO. They are not optional.

1. **Contract ≠ Data.** A contract describes intent, execution constraints, participants, and metadata. It NEVER embeds application data. Data lives outside the contract and is handled by the runtime.

2. **Node sovereignty.** Every node retains the final decision over whether to execute a contract. No node can force another node to execute. Responder evaluates capability, policy, trust, signature, session, and witness attestation before executing.

3. **Trust is local, evidence is shared.** Trust scores are computed locally on each node. Evidence (contract records, heartbeat digests, attestations) is shared across the mesh via gossip and witness.

4. **No global state.** There is no single global execution state. Each node maintains its own session store, audit store, trust store, and DAG store. Mutable shared execution state is never stored globally.

5. **Execution graph immutable after compile.** Once the compiler produces an execution DAG, the DAG is never mutated. This guarantees that all nodes operate on the same execution plan.

6. **Capabilities, not roles.** The runtime does not know R/W/X as hardcoded levels. It only knows capabilities. Reader / Contributor / Authority are preset groupings of capabilities.

7. **Witness is not consensus.** A witness attests, not decides. Witness does not vote, does not execute, does not arbitrate. It provides independent evidence.

8. **Contract is the unit of communication.** Nodes do not exchange raw function calls. They exchange contracts. The receiving node evaluates and decides.

---

## III. DESIGN INVARIANTS

These invariants MUST hold at all times across the entire system. Violating an invariant is a specification violation.

### I-01: Contract Purity
A contract MUST NOT embed application data. It contains only execution intent, execution constraints, participant identities, capabilities required, and metadata required by the runtime.

### I-02: Node Final Authority
The Responder node ALWAYS retains the final decision to execute or reject a contract. No external node (Requester, Witness, or any other) can override this decision.

### I-03: Execution Graph Immutability
An execution DAG, once produced by the compiler, MUST NOT be mutated. No runtime component may modify a compiled graph.

### I-04: Deterministic State Transition
Every FSM state transition MUST be deterministic. Given the same input and the same prior state, the transition MUST produce the same output.

### I-05: Auditable Transition
Every FSM state transition MUST be recorded in the audit log. The audit log MUST be sufficient to reconstruct the full execution history of any contract.

### I-06: Replayable Transition
Every FSM state transition MUST be replayable from the audit log. Replay must produce identical state.

### I-07: Serializable Transition
Every FSM state MUST be serializable for storage, transmission, and verification.

### I-08: No Global Mutable State
No component may store mutable shared execution state that is visible to all nodes. All execution state is per-node isolated.

### I-09: Capability Ephemerality
All capabilities MUST be ephemeral and session-scoped. Capabilities are validated at runtime, never assumed from static configuration.

### I-10: Transport Independence
The runtime MUST NOT depend on any specific transport protocol. Transport is interchangeable (TCP, QUIC, relay, etc.).

### I-11: Opcode Replay Safety
Every opcode MUST be replay-safe or explicitly declared as non-idempotent. Replaying an idempotent opcode MUST produce the same side-effect as a single execution.

### I-12: No Silent Mutation
No component may silently mutate state. All state mutations MUST be recorded and auditable.

### I-13: Trust Is Eventually Consistent
Trust scores are NOT absolute truth. They are local estimates that converge over time. No execution decision may depend on trust alone.

---

## IV. SYSTEM LAYERS

The architecture is decomposed into exactly seven layers. No layer may bypass the layer below it.

```
┌──────────────────────────────────┐
│  1. CLI / SDK LAYER              │  User-facing entry points
├──────────────────────────────────┤
│  2. INTENT LANGUAGE LAYER         │  Contract source (JSON/YAML; later .seme DSL)
├──────────────────────────────────┤
│  3. EXECUTION COMPILER            │  Intent → DAG compilation pipeline
├──────────────────────────────────┤
│  4. DAG SCHEDULER                 │  DAG-aware execution scheduling
├──────────────────────────────────┤
│  5. NODE EXECUTION FSM            │  Per-node state machine
├──────────────────────────────────┤
│  6. CONSENSUS + TRUST ENGINE      │  Multi-node attestation, scoring, weighting
├──────────────────────────────────┤
│  7. TRANSPORT ABSTRACTION         │  Interchangeable network layer
└──────────────────────────────────┘
```

---

## V. PROJECT ARCHITECTURE (REPOSITORY STRUCTURE)

```
smo/
├── cmd/
│   ├── smo-cli/             User-facing execution tool
│   ├── smo-node/            Node daemon — FSM, session, capability enforcement
│   ├── smo-admin/           Mesh administration commands
│   └── smo-debug/           Internal tracing and debugging
│
├── core/                    Pure contracts/interfaces only. NO business logic.
│   ├── intent/              Intent type definitions
│   ├── opcode/              Opcode enumeration and registry
│   ├── capability/          Capability type definitions
│   ├── session/             Session type definitions
│   ├── state/               State type definitions
│   └── errors/              Error type definitions
│
├── compiler/                Intent → DAG compiler
│   ├── parser/              Contract source parser
│   ├── planner/             Node planning and resource mapping
│   ├── optimizer/           DAG optimization (future)
│   ├── graph/               DAG data structures
│   └── validator/           Semantic validation
│
├── runtime/                 Core execution engine
│   ├── scheduler/           DAG-aware scheduler (NOT a FIFO queue)
│   ├── executor/            Actual opcode execution dispatch
│   ├── sandbox/             Execution isolation (future WASM, resource quotas)
│   ├── workerpool/          Concurrent worker management
│   ├── fsm/                 Finite state machine implementations
│   │   ├── node_fsm/        Per-node execution FSM
│   │   ├── mesh_fsm/        Multi-node coordination FSM
│   │   ├── consensus_fsm/   Witness/consensus FSM
│   │   └── transitions/     State transition definitions
│   ├── audit/               Execution audit logging
│   └── recovery/            State recovery and reconcile
│
├── transport/               Abstract communication layer
│   ├── tcp/                 TCP transport implementation
│   ├── quic/                QUIC transport implementation (future)
│   ├── relay/               Relay/proxy transport (future)
│   ├── framing/             Message framing
│   └── serialization/       Wire serialization/deserialization
│
├── protocol/                Wire format definitions
│   ├── packet/              Packet structure and encoding
│   ├── schema/              Schema definitions
│   ├── signing/             Cryptographic signing and verification
│   ├── encryption/          Payload encryption
│   └── replay/              Replay protection (nonce, timestamp)
│
├── consensus/               Multi-node coordination
│   ├── witness/             Witness selection and protocol
│   ├── attestation/         Attestation collection and verification
│   └── weighting/           Trust-weighted decision support
│
├── trust/                   Trust engine
│   ├── scoring/             Trust score computation
│   ├── decay/               Score decay over time
│   ├── store/               Trust data persistence
│   └── exchange/            Trust digest gossip
│
├── acl/                     Access control
│   ├── policy/              Local policy engine (capability resolution)
│   ├── presets/             Predefined capability groupings (Reader, Contributor, Authority)
│   └── revocation/          Capability revocation
│
├── storage/                 Local persistent storage
│   ├── session_store/       Active session state
│   ├── trust_store/         Trust score records
│   ├── audit_store/         Audit log
│   ├── dag_store/           Execution DAG records
│   └── node_store/          Node identity and configuration
│
├── sdk/                     Client and plugin SDK
│   ├── client/              API client library
│   └── plugin/              Plugin authoring interfaces
│
├── tooling/                 Observability and developer tools
│   ├── tracing/             Distributed tracing
│   ├── metrics/             Performance metrics
│   ├── profiling/           CPU/memory profiling
│   └── audit-viewer/        Audit log viewer
│
├── plugins/                 External plugin directory (not built in)
│
├── docs/                    Documentation
├── tests/
│   ├── unit/                Unit tests
│   ├── integration/         Integration tests
│   ├── mesh/                Multi-node mesh tests
│   ├── chaos/               Chaos simulations (delay, split-brain, compromise)
│   ├── replay/              Deterministic replay tests
│   └── adversarial/         Security adversarial tests
│
├── examples/                Example contracts and configurations
└── deployments/             Deployment configurations and templates
```

---

## VI. PROTOCOL DESIGN

### 6.1 Packet Format

Every wire message uses the following packet structure:

```
+--------------------------------------------------+
| HEADER                                           |
+--------------------------------------------------+
| SESSION ID     (16 bytes)                        |
| INTENT ID      (16 bytes)                        |
| OPCODE ID      (4 bytes)                         |
| TIMESTAMP      (8 bytes)                         |
| NONCE          (8 bytes)                         |
+--------------------------------------------------+
| PAYLOAD        (variable length)                  |
+--------------------------------------------------+
| SIGNATURE      (64 bytes — Ed25519)              |
+--------------------------------------------------+
```

### 6.2 Wire Protocol Rules

1. Every packet MUST carry a nonce for replay protection.
2. Every packet MUST be signed by the sender.
3. Every packet MUST carry a timestamp. Receivers MAY reject packets outside a configurable time window.
4. Payload MAY be encrypted at the session level. Packet header fields are never encrypted (they are needed for routing).
5. Every session MUST derive a symmetric session key via the transport handshake.

---

## VII. CONTRACT MODEL

### 7.1 Contract Definition

A contract is a metadata-only document. It MUST NOT embed application data.

### 7.2 Contract Format (MVP)

Contracts use structured JSON/YAML in the MVP phase. A DSL (.seme) MAY be introduced later.

```json
{
  "contract_id": "c-91ad",
  "requester": "node-a",
  "responder": "node-b",
  "witness": "node-c",
  "opcode": "PUT",
  "parameters": {
    "source": "/tmp/log.txt",
    "target": "/myshared/log.txt"
  },
  "constraints": {
    "capabilities": ["CAP_FS_WRITE"],
    "trust_min": 0.7
  },
  "policy": {
    "overwrite": false
  },
  "created_at": "2026-01-01T00:00:00Z",
  "signature_requester": "...",
  "signature_responder": "..."  // filled after acceptance
}
```

### 7.3 Contract Record (Post-Execution)

After execution, each participant stores a contract record:

| Field | Description |
|---|---|
| ContractID | Unique identifier |
| RequesterID | Originating node |
| ResponderID | Executing node |
| WitnessID | Attesting node |
| IntentHash | Hash of the raw intent |
| PolicyHash | Hash of the effective policy |
| StartTime | Execution start |
| FinishTime | Execution end |
| Status | SUCCESS / FAILURE / REJECTED / TIMEOUT |
| ResultHash | Hash of the execution result (not the data) |
| AuditHash | Hash of the full audit trail |
| RequesterSignature | Signed by requester |
| ResponderSignature | Signed by responder |
| WitnessSignature | Signed by witness |

### 7.4 Contract Lifecycle

```
[Requester] ──Proposal──> [Responder]
                              │
                    ┌─────────┼─────────┐
                    │         │         │
                    ▼         ▼         ▼
              Check     Check      Ask
              Policy   Capability  Witness
                    │         │         │
                    └─────────┼─────────┘
                              │
                              ▼
                         Decision
                        /        \
                   EXECUTE      REJECT
                       │
                       ▼
                 Record + Notify
                  Witness + Requester
```

### 7.5 Contract Storage Rule

All three participants (Requester, Responder, Witness) MUST store an identical contract record after execution completes. This record serves as the non-repudiation evidence for the contract.

### 7.6 Large Data Handling

If an opcode operates on large data (e.g., PUT of a 2 GB file), the data is transferred through a separate channel. The contract references the data only by hash. The contract record stores ResultHash, never the data itself.

---

## VIII. WITNESS PROTOCOL

### 8.1 Witness Role

A witness is an independent third node that:
- Does NOT execute the contract
- Does NOT own the target resource
- Does NOT vote or arbitrate
- Attests that it knows both Requester and Responder
- Confirms it has no knowledge of anomalous behavior
- Stores a copy of the contract record for future non-repudiation

### 8.2 Witness Selection

1. The Responder selects the witness.
2. Selection priority:
   a. Most trusted node known to the Responder (highest local Trust Score)
   b. Random selection from known nodes (if no high-trust candidate)
3. The Requester MAY propose a witness candidate, but the Responder has final choice.

### 8.3 Witness Redundancy

If the primary witness is unreachable or times out:

```
Primary Witness
     ↓ timeout
Secondary Witness
     ↓ timeout
Fallback: Responder proceeds with local decision only (no witness)
```

### 8.4 Witness Confirmation Payload

A witness confirmation contains:
```
witness_id
contract_id
requester_id
responder_id
trust_digest     // witness's local trust assessment of both nodes
attestation      // "I confirm these nodes exist and I have no adverse evidence"
timestamp
witness_signature
```

---

## IX. HEARTBEAT AND MESH MEMBERSHIP

### 9.1 Heartbeat Purpose

Heartbeat packets maintain mesh membership and propagate lightweight state. Each heartbeat carries:

- Node online/offline status
- Latency estimates
- Public key fingerprint
- Trust digest (composite Trust Score, not full history)
- Capability digest (list of capability hashes, not full capabilities)
- Protocol version

### 9.2 Gossip Propagation

Heartbeat information propagates via gossip protocol:
```
A → B → D → F → H
```
Each node forwards digest information to a subset of its neighbors. There is no central server or broadcast to all nodes.

### 9.3 Node Offline Handling

1. When A, C, D all fail to ping B, each independently updates its route table marking B as offline.
2. Each node applies a trust score penalty for B's unavailability (one penalty per detection event, not per failed ping).
3. When B reconnects, B MUST proactively re-discover and re-connect to the mesh. The mesh does not actively search for lost nodes.

### 9.4 Reconnection Sequence

```
OFFLINE
    ↓
RECONNECT
    ↓
BOOTSTRAP  (re-establish identity, key exchange)
    ↓
DISCOVER   (gossip with known nodes to learn current mesh state)
    ↓
HEARTBEAT  (normal heartbeat cycle resumes)
    ↓
REJOIN     (full mesh membership restored)
```

---

## X. CAPABILITY SYSTEM

### 10.1 Capability Format

Capabilities are expressed as uppercase identifiers:

```
CAP_FS_READ
CAP_FS_WRITE
CAP_PROC_EXEC
CAP_NET_BIND
CAP_SESSION_CREATE
CAP_NODE_QUARANTINE
```

### 10.2 Capability Properties

- **Ephemeral**: Capabilities are not permanent. They are granted within a session.
- **Session-scoped**: A capability is valid only within the context of a specific session.
- **Runtime validated**: Capabilities are checked at execution time, never assumed from configuration.

### 10.3 Capability Presets (ROLE Profiles)

The runtime does NOT hardcode R/W/X. These are predefined capability groupings:

**ROLE_READER** =
```
CAP_HEARTBEAT
CAP_VERIFY
CAP_FS_READ
CAP_SESSION_CREATE   // limited to read-only sessions
```

**ROLE_CONTRIBUTOR** =
```
ROLE_READER
+
CAP_FS_WRITE
CAP_MKDIR
CAP_RM
CAP_CP
CAP_CUSTOM_CONTRACT   // if explicitly granted
```

**ROLE_AUTHORITY** =
```
ROLE_CONTRIBUTOR
+
CAP_PROC_EXEC
CAP_GRANT
CAP_REVOKE
CAP_DISTRIBUTE        // broadcast contract to whole mesh
CAP_POLICY_CHANGE
CAP_NODE_BOOTSTRAP
```

### 10.4 Capability Origin

Capabilities originate from the Origin Node (Authority). The Origin Node signs capability grants. All nodes in the mesh can verify the signature chain back to the Origin Node.

### 10.5 Capability Revocation

Capabilities can be explicitly revoked by the granting Authority. Revocation is propagated via gossip. Nodes MUST check for revocation before accepting a contract.

---

## XI. TRUST AND REPUTATION SYSTEM

### 11.1 Trust Components

Trust is decomposed into four independent components. Each component is computed locally on every node.

| Component | Measures | Input Signals |
|---|---|---|
| Citizen Score | Online time, heartbeat stability, route reliability | Heartbeat response rate, uptime, route consistency |
| Execution Score | Successful contract execution, no rollbacks, no witness objections | Contract completion ratio, witness attestations |
| Witness Score | Witness participation, accuracy of attestations | Number of witness assignments, confirmation accuracy |
| Consistency Score | Agreement with majority in multi-node operations | Result comparison across nodes |

### 11.2 Composite Trust Score

```
Trust = Citizen × 0.2 + Execution × 0.5 + Witness × 0.2 + Consistency × 0.1
```

These weights are default values. Individual nodes MAY configure different weights in their local policy.

### 11.3 Score Decay

All trust scores MUST use sliding window decay. Scores reflect recent behavior, not cumulative history. Scores that grow without bound are forbidden.

### 11.4 Trust in Execution Decisions

Trust is ONE input to the Responder's decision, not the sole factor. The decision matrix is:

```
Execute = CapabilityValid AND
          PolicyMatches AND
          SignatureValid AND
          SessionValid AND
          (Trust >= LocalThreshold OR OverrideByAuthority)
```

If any precondition fails, the contract is REJECTED regardless of trust score.

### 11.5 Penalties

- Contract rejected due to insufficient trust: small score penalty to Requester.
- Contract rejected due to insufficient capability: larger score penalty to Requester (because Requester should have known).
- Spam detection: nodes that repeatedly submit rejectable contracts accumulate score penalties.

---

## XII. EXECUTION DAG

### 12.1 DAG Format (Internal)

After compilation, the intent becomes an immutable execution DAG:

```json
{
  "graph_id": "dag-777",
  "nodes": [
    {
      "task_id": "t1",
      "opcode": "LOG_SCAN",
      "depends_on": [],
      "parameters": { ... }
    },
    {
      "task_id": "t2",
      "opcode": "FILE_SCAN",
      "depends_on": ["t1"],
      "parameters": { ... }
    }
  ]
}
```

### 12.2 Compiler Pipeline

```
INTENT SOURCE
    ↓
PARSE                  →  structured AST
    ↓
CAPABILITY RESOLUTION  →  capability requirement binding
    ↓
NODE PLANNING          →  target node(s) assignment
    ↓
DAG GENERATION         →  dependency graph construction
    ↓
OPTIMIZATION           →  (future) graph-level optimizations
    ↓
EXECUTION DAG          →  immutable output
```

### 12.3 DAG Immutability Rule

Once the DAG is produced, it MUST NOT be modified. All nodes involved in execution operate on the same DAG. If a DAG must change (e.g., due to node failure), a new DAG is compiled from the original intent.

---

## XIII. NODE EXECUTION FSM

### 13.1 FSM Implementation Rules

Every state transition MUST be:
1. **Auditable** — recorded in the audit log
2. **Deterministic** — same input + same prior state = same output
3. **Replayable** — the audit log is sufficient to reconstruct the exact execution
4. **Serializable** — the state can be stored, transmitted, and verified

### 13.2 Node-Level States

```
BOOTSTRAP
    ↓
KEY_GENERATION
    ↓
DOMAIN_JOIN
    ↓
CAPABILITY_NEGOTIATION
    ↓
ACTIVE
    ↓
CONTRACT_PENDING     →   CONTRACT_VALIDATING
                             ↓
                        CONTRACT_ACCEPTED  or  CONTRACT_REJECTED
                             ↓
                        (if accepted) EXECUTING
                             ↓
                        COMPLETED  or  FAILED
                             ↓
                        AUDITING
                             ↓
                        RECORDING
                             ↓
                        ACTIVE  (back to idle)
    ↓
DEGRADED  or  QUARANTINED  or  OFFLINE
```

### 13.3 Contract Execution Sub-FSM

```
PENDING
    ↓
VALIDATE_POLICY       →  REJECTED (if policy fails)
    ↓
VALIDATE_CAPABILITY   →  REJECTED (if capability insufficient)
    ↓
VALIDATE_SIGNATURE    →  REJECTED (if signature invalid)
    ↓
VERIFY_SESSION        →  REJECTED (if session expired/invalid)
    ↓
CONSULT_WITNESS       →  REJECTED (if witness negative or timeout with no fallback)
    ↓
LOCAL_DECISION
    ↓
EXECUTE  or  REJECT
    ↓
RECORD_RESULT
    ↓
NOTIFY_PARTICIPANTS
    ↓
FINALIZED
```

---

## XIV. STORAGE MODEL

### 14.1 Storage Types

| Store | Content | Scope |
|---|---|---|
| session_store | Active session state (capabilities, keys, expiration) | Per-node |
| trust_store | Trust scores, score history, decay parameters | Per-node |
| audit_store | Execution audit log (all state transitions) | Per-node |
| dag_store | Compiled execution DAGs | Per-node |
| node_store | Node identity, keys, configuration, route table | Per-node |

### 14.2 Storage Invariant

Never store mutable shared execution state globally. All stored state is per-node isolated. No store is shared across nodes.

---

## XV. SECURITY IMPLEMENTATION

### 15.1 Phase 1 Cryptography

| Algorithm | Purpose |
|---|---|
| Ed25519 | Signing and identity |
| XChaCha20-Poly1305 | Symmetric encryption |
| Blake3 | Hashing |

Rationale: Fast, modern, and implementable across multiple programming environments.

### 15.2 Phase 2 Cryptography (Future)

Post-quantum cryptographic primitives MAY be added in a future phase. The transport and protocol layers MUST be designed to allow algorithm agility.

### 15.3 Key Management

- Each node generates its own Ed25519 key pair during the KEY_GENERATION lifecycle step.
- The public key IS the node's identity in the mesh.
- Session keys are derived via transport-level key exchange (e.g., X25519 + symmetric ratchet).
- Long-term keys are stored in node_store.

---

## XVI. FILESYSTEM EVOLUTION MODEL

SMO's filesystem interaction evolves in three phases:

### Phase 1 — Shared Root (MVP)

- Single shared workspace: `/myshared`
- All file operations are sandboxed within this directory.
- SAFE for initial implementation and demonstration.

### Phase 2 — Multi-Root Capability

- Multiple roots exposed: `/shared`, `/var/log`, `/opt/runtime`
- Each root is capability-scoped. A node must have the specific capability (e.g., CAP_FS_WRITE on `/var/log`).
- Roots are defined in the node's local policy.

### Phase 3 — System Execution Domain

- Full controlled execution: process execution, service orchestration, runtime isolation, incident containment.
- SMO is no longer a file-access tool. It becomes a distributed constrained execution environment.
- Opcodes like EXEC, QUARANTINE operate on the system level, not just files.

---

## XVII. NODE LIFECYCLE

```
BOOTSTRAP              Initial node setup, configuration loading
    ↓
KEY_GENERATION         Ed25519 key pair generation
    ↓
DOMAIN_JOIN            Connect to mesh, exchange identity with at least one existing node
    ↓
CAPABILITY_NEGOTIATION Receive initial capability grants from Authority
    ↓
ACTIVE                 Full participation: heartbeat, contract execution, witness
   /    \    \
  ↓      ↓    ↓
DEGRADED  QUARANTINED  OFFLINE
  (trust    (capability  (network
   below      revoked)    disconnected)
   threshold)
```

---

## XVIII. OPCODES (MVP)

### 18.1 MVP Opcodes

Exactly five opcodes for the MVP:

| Opcode | Description | Requires | Idempotent |
|---|---|---|---|
| LS | List directory contents | CAP_FS_READ | Yes |
| PUT | Write file | CAP_FS_WRITE | Yes (same content) |
| GET | Read file | CAP_FS_READ | Yes |
| EXEC | Execute a command | CAP_PROC_EXEC | No (explicitly non-idempotent) |
| QUARANTINE | Isolate a node from mesh operations | CAP_NODE_QUARANTINE | No (explicitly non-idempotent) |

### 18.2 Opcode Categories

Additional opcodes (MKDIR, RM, CP, CUSTOM) are recognized but considered post-MVP. Their behavior is:

| Opcode | Description | Requires |
|---|---|---|
| MKDIR | Create directory | CAP_FS_WRITE |
| RM | Remove file or directory | CAP_FS_WRITE |
| CP | Copy file | CAP_FS_WRITE |
| CUSTOM | User-defined operation (plugin) | CAP_CUSTOM_CONTRACT |

### 18.3 Opcode Replay Rule (Engineering Rule)

Every opcode MUST be either:
- **replay-safe**: executing it N times produces the same effect as executing it once, OR
- **explicitly declared non-idempotent**: the system documents that replay has side effects.

---

## XIX. CLI DESIGN

### 19.1 Entry Points

| Binary | Purpose |
|---|---|
| `smo-cli` | User-facing execution tool |
| `smo-node` | Node daemon |
| `smo-admin` | Mesh administration |
| `smo-debug` | Internal tracing and debugging |

### 19.2 CLI Commands (MVP)

```
smo mesh discover
smo exec --target node-a --opcode ls --path /var/log
smo trust inspect node-a
smo quarantine node-c
smo admin grant-cap --node node-b --cap CAP_FS_WRITE
smo admin revoke-cap --node node-b --cap CAP_FS_WRITE
```

---

## XX. OBSERVABILITY

Observability is mandatory, not optional.

```
tooling/
├── tracing/             Distributed tracing (trace IDs propagated through contracts)
├── metrics/             Performance and health metrics
├── profiling/           CPU and memory profiling
└── audit-viewer/        Audit log browser
```

Without observability, distributed systems become unmanageable.

---

## XXI. TESTING MODEL

```
tests/
├── unit/                Per-module unit tests
├── integration/         Cross-module integration tests
├── mesh/                Multi-node mesh topology tests
├── chaos/               CRITICAL — simulate network delay, node compromise, split-brain, divergence
├── replay/              Deterministic replay from audit logs
└── adversarial/         Security-focused adversarial scenarios
```

### 21.1 Chaos Testing Requirements

The chaos test suite MUST simulate:
- Delayed packets
- Compromised nodes
- Split-brain conditions
- State divergence between nodes

---

## XXII. MVP SCOPE

### 22.1 Deliverables

1. **5 opcodes**: LS, PUT, GET, EXEC, QUARANTINE
2. **1 killer workflow**: Incident Containment
   ```
   Detect suspicious node
       ↓
   Reduce trust score
       ↓
   Revoke capabilities
       ↓
   Quarantine node
       ↓
   Reroute workloads (future)
   ```
3. Transport + Session + Signatures operational
4. Single-node FSM operational
5. Contract proposal/acceptance/rejection flow operational
6. Witness protocol (basic, single-witness, no fallback required for MVP)

### 22.2 Out of MVP Scope

- Full DAG scheduler
- Trust engine with all four components
- Consensus weighting
- Fancy DAG optimizer
- .seme DSL (JSON/YAML only)
- WASM sandbox
- Multi-root filesystem (Phase 1 only: /myshared)
- Windows/macOS adapters

---

## XXIII. IMPLEMENTATION ORDER

DO NOT start with trust AI, fancy consensus, or complex DAG optimization.

### Stage 1 — Foundation

```
transport + session + signature
```

### Stage 2 — Single Node

```
single-node FSM (contract lifecycle without witness)
```

### Stage 3 — Multi-Node

```
multi-node propagation (basic witness)
```

### Stage 4 — DAG

```
DAG execution (compiler + scheduler)
```

### Stage 5 — Trust

```
trust engine (basic scoring)
```

### Stage 6 — Full Consensus

```
consensus weighting (multi-witness, trust-weighted)
```

---

## XXIV. GOLDEN ENGINEERING RULES

### Rule 1: Invariant First
Invariants MUST be defined and enforced before features are added. Never add a feature that violates an invariant.

### Rule 2: Opcode Replay Safety
Every opcode must be replay-safe or explicitly declared non-idempotent. This is not a guideline; it is a requirement.

### Rule 3: No Silent Mutation
No component may silently mutate state. ALL mutations must be recorded and auditable. EVER. This rule has no exceptions.

### Rule 4: Trust Is Eventually Consistent
Trust is NOT absolute truth. It is a local, eventually-consistent estimate. No execution decision may depend on trust alone. Trust informs; policy and capability decide.

### Rule 5: Execution Graph Immutability
The execution graph is immutable after compilation. No runtime component may modify a compiled graph. If changes are needed, recompile from the original intent.

---

## XXV. FINAL ARCHITECTURE VIEW

```
INTENT  (contract source)
   ↓
COMPILER  (parse → resolve → plan → generate → optimize)
   ↓
EXECUTION DAG  (immutable)
   ↓
SCHEDULER  (DAG-aware, not FIFO)
   ↓
NODE FSM  (per-node execution lifecycle)
   ↓
MESH FSM  (multi-node coordination)
   ↓
CONSENSUS / WITNESS  (attestation, trust weighting)
   ↓
AUDIT  (record all transitions)
   ↓
FINALIZED STATE
```

---

## XXVI. APPENDIX A — BUSINESS AND LICENSING

This section documents project context, not architecture. It is non-normative.

### A.1 License

Apache License 2.0.

### A.2 Copyright

```
Copyright (c) 2026 Nguyen Duc Canh
Copyright (c) 2026 Distributed Offensive Technology Solutions Co., Ltd.
SPDX-License-Identifier: Apache-2.0
```

### A.3 Open Core Model

- **Community Edition**: Apache 2.0. Includes CLI, runtime, compiler, transport, SDK, documentation, basic examples.
- **Commercial**: Incident Response Packs, SOC Automation Packs, Enterprise playbooks (`.seme`), consulting, training, support.

### A.4 Project Identity

- **Founder / Lead Architect**: Nguyen Duc Canh
- **Organization**: Distributed Offensive Technology Solutions Co., Ltd.
- **Repository**: https://github.com/dotlinux26/smoframework

---

## XXVII. APPENDIX B — REFERENCE LEGACY

This section is non-normative.

The directory `reference/OLD_SHELLMAP` contains the implementation of the predecessor ShellMap Framework (SMF). This code is:

- **NOT** to be reused as architecture
- **NOT** to be copied as code structure
- Available for reference of:
  - Post-quantum cryptographic wrapper implementations
  - Networking helper patterns
  - Serialization approaches
  - Implementation history and lessons learned

All new implementation MUST follow the SMO specification defined in this document. Legacy code does not override this specification.
