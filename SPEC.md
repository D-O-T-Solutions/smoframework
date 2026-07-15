# SECURE MESH OPERATION (SMO) — Engineering Specification

Version: 3.0
Canonical Name: Secure Mesh Operation (SMO)
Supersedes: SMF (ShellMap Framework) V3

---

## PREFACE — How to Read This Document

This document is the single source of truth for the SMO system. Every module, interface, state machine, protocol decision, and engineering constraint is defined here. Nothing is inferred from conversation.

Sections are ordered by conceptual dependency, not by implementation order. Read §Implementation Order for the recommended build sequence.

---

## 0. TERMINOLOGY

| Term | Definition |
|---|---|
| SMO | Secure Mesh Operation — the complete distributed execution runtime |
| SMF | ShellMap Framework — the predecessor. Concepts absorbed into SMO |
| Node | A single machine running the SMO runtime, participating in one or more meshes |
| Mesh | A logical domain of participating SMO nodes, identified by a unique MeshID |
| MeshID | Deterministic hash derived at mesh creation: Blake3(RootPublicKey \|\| CreatedAt \|\| Random) |
| Contract | A metadata-only document that describes execution intent and constraints. NEVER contains application data |
| Requester | The node that proposes a contract |
| Responder | The node that receives and executes (or rejects) a contract. Has final decision authority |
| Witness | An independent third node that attests to the contract's existence and integrity. Does not execute |
| Intent | What the requester wants to accomplish. Expressed as an opcode and parameters |
| Capability | A runtime-validated, session-scoped permission. NOT a static role |
| Opcode | The operation type. Hierarchical namespace: DISCOVERY, CONTROL, EXECUTION, DATA |
| Session | A scoped execution context with associated capabilities and constraints |
| DAG | Directed Acyclic Graph — the immutable execution plan produced by the compiler |
| FSM | Finite State Machine — governs node-level and mesh-level execution transitions |
| Identity | A node's Ed25519 keypair. Immutable for the lifetime of the node |
| Membership Certificate | A signed document linking a node's PublicKey to a MeshID, Role, and CapabilitySet |
| Mesh Root Key | The offline key generated at mesh creation. Used only for bootstrap, recovery, and Authority signing |
| Authority Key | An online key used for daily operations: signing certificates, granting capabilities, revocation |
| Enrollment | The process of delivering a node's PublicKey to an Authority and receiving a Membership Certificate |
| .smor | Enrollment Request file — contains PublicKey, mesh_id, nonce, timestamp, signed by node |
| .smoc | Node Certificate file — contains MeshID, Role, Capabilities, Epoch, signed by Authority |
| Epoch | Mesh-wide counter incremented on major capability changes. Certificates with old Epoch are rejected |
| Join Token | A single-use, time-limited token that authorizes a node to enroll. Distributed out-of-band |
| Recovery Authority | A holder of a Shamir secret share of the Root Key. M-of-N threshold can reconstruct the Root |
| Crypto Suite ID | An identifier that maps to a concrete set of cryptographic algorithms. Protocol references Suite ID, not algorithm names |
| Connectivity Layer | The layer responsible for NAT traversal, STUN, ICE, hole punching, relay. Produces a connected socket |
| Trust Score | A composite local metric used as one input (not the sole) to execution decisions |
| Citizen Score | A trust sub-component measuring online time, heartbeat stability, route reliability |
| Execution Score | A trust sub-component measuring successful contract completions |
| Witness Score | A trust sub-component measuring witness accuracy and participation |
| Consistency Score | A trust sub-component measuring result agreement with majority |
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

3. **Trust is local, evidence is shared.** Trust scores are computed locally on each node. Evidence (contract records, heartbeat digests, attestations) is shared across the mesh via gossip and witness. Trust digests are hints, not authoritative values.

4. **No global state.** There is no single global execution state. Each node maintains its own session store, audit store, trust store, and DAG store. Mutable shared execution state is never stored globally.

5. **Execution graph immutable after compile.** Once the compiler produces an execution DAG, the DAG is never mutated. This guarantees that all nodes operate on the same execution plan.

6. **Capabilities, not roles.** The runtime does not know R/W/X as hardcoded levels. It only knows capabilities. Reader / Contributor / Authority are preset groupings of capabilities.

7. **Witness is not consensus.** A witness attests, not decides. Witness does not vote, does not execute, does not arbitrate. It provides independent evidence.

8. **Contract is the unit of communication.** Nodes do not exchange raw function calls. They exchange contracts. The receiving node evaluates and decides.

9. **Identity ≠ Membership ≠ Capability.** A node's keypair (identity) is distinct from its certificate (membership), which is distinct from its currently active capabilities (session-scoped). These layers never mix.

10. **Root Key NEVER circulates.** Only certificates circulate. Private keys never leave their host node.

11. **Protocol describes meaning. Transport describes bytes.** The protocol layer defines what a contract is and how it flows. The transport layer decides whether to send those bytes over TCP, UDP, or a Unix socket. These are independent decisions.

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
The runtime MUST NOT depend on any specific transport protocol. Transport is interchangeable (TCP, UDP, QUIC, relay, Unix socket).

### I-11: Opcode Replay Safety
Every opcode MUST be replay-safe or explicitly declared as non-idempotent. Replaying an idempotent opcode MUST produce the same side-effect as a single execution.

### I-12: No Silent Mutation
No component may silently mutate state. All state mutations MUST be recorded and auditable.

### I-13: Trust Is Eventually Consistent
Trust scores are NOT absolute truth. They are local estimates that converge over time. No execution decision may depend on trust alone.

### I-14: Private Key Confinement
A node's private key MUST NEVER leave the node on which it was generated. All identity proof is via signed challenges (CSR, signed nonce), never via key transport.

### I-15: Certificate Chain Verification
Every Membership Certificate MUST be verifiable up to the Mesh Root Public Key. A node with only the Root public key can verify any certificate in the chain.

### I-16: Protocol Layer Isolation
No protocol layer (Discovery, Control, Execution, Data) may assume anything about the layers above it. Discovery does not know what a contract is. Control does not know how execution chunks data.

### I-17: Carrier Independence
The Enrollment Protocol defines the format of enrollment requests and responses. It does not specify how they are transported. QR, USB, clipboard, REST API, and file are all valid carriers.

---

## IV. SYSTEM LAYERS

The architecture is decomposed into eleven layers. No layer may bypass the layer below it.

```
┌──────────────────────────────────────────────┐
│  1. CLI / SDK LAYER                           │  User-facing entry points
├──────────────────────────────────────────────┤
│  2. INTENT LANGUAGE LAYER                     │  Contract source (JSON/YAML; later .seme DSL)
├──────────────────────────────────────────────┤
│  3. EXECUTION COMPILER                        │  Intent → DAG compilation pipeline
├──────────────────────────────────────────────┤
│  4. DAG SCHEDULER                             │  DAG-aware execution scheduling
├──────────────────────────────────────────────┤
│  5. NODE EXECUTION FSM                        │  Per-node state machine
├──────────────────────────────────────────────┤
│  6. CONSENSUS + TRUST ENGINE                  │  Multi-node attestation, scoring, weighting
├──────────────────────────────────────────────┤
│  7. PROTOCOL LAYER                            │
│   ├── Discovery Protocol                      │  UDP — HELLO, PING, DISCOVER, HEARTBEAT
│   ├── Control Protocol                        │  TCP — CONTRACT, SESSION, WITNESS, CSR
│   ├── Execution Protocol                      │  TCP — EXEC_START, PROGRESS, RESULT
│   └── Data Protocol                           │  TCP — CHANNEL_OPEN, CHUNK, ACK, FIN
├──────────────────────────────────────────────┤
│  8. SESSION LAYER                             │  Keys, identity, capability negotiation
├──────────────────────────────────────────────┤
│  9. CONNECTIVITY LAYER                        │  STUN, ICE, NAT traversal, hole punch, relay
├──────────────────────────────────────────────┤
│ 10. TRANSPORT ABSTRACTION                     │  Interchangeable network layer (TCP, UDP, ...)
├──────────────────────────────────────────────┤
│ 11. IDENTITY + MEMBERSHIP LAYER               │  Keypairs, certificates, chain verification
└──────────────────────────────────────────────┘
```

---

## V. PROJECT ARCHITECTURE (REPOSITORY STRUCTURE)

```
smo/
├── cmd/
│   ├── smo-cli/             User-facing execution tool (§XIX)
│   ├── smo-node/            Node daemon — FSM, session, capability enforcement
│   ├── smo-admin/           Mesh administration (§XIX)
│   └── smo-debug/           Internal tracing and debugging
│
├── core/                    Pure contracts/interfaces only. NO business logic.
│   ├── intent/              Intent type definitions
│   ├── opcode/              Hierarchical opcode enumeration (§XVIII)
│   ├── capability/          Capability type definitions (§VIII)
│   ├── session/             Session type definitions
│   ├── state/               State type definitions (§XIV)
│   ├── identity/            NodeIdentity, Ed25519 keypair generation, nonce signing
│   ├── mesh/                MeshID, MeshGenesis, Epoch, MembershipCertificate
│   ├── enroll/              EnrollRequest, EnrollResponse, ExportFormat
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
│   │   ├── node_fsm/        Per-node execution FSM (§XIV)
│   │   ├── mesh_fsm/        Multi-node coordination FSM
│   │   ├── consensus_fsm/   Witness/consensus FSM
│   │   └── transitions/     State transition definitions
│   ├── audit/               Execution audit logging
│   └── recovery/            State recovery and reconcile
│
├── protocol/
│   ├── discovery/           Discovery protocol — HELLO, PING, DISCOVER, HEARTBEAT
│   ├── control/             Control protocol — CONTRACT, SESSION, CSR, WITNESS, REVOKE
│   ├── execution/           Execution protocol — EXEC_START, PROGRESS, RESULT, CANCEL
│   ├── data/                Data protocol — CHANNEL_OPEN, CHUNK, ACK, FIN
│   ├── packet/              Packet structure and zero-copy parsing
│   ├── schema/              Schema definitions
│   ├── signing/             Cryptographic signing and verification (§XVI)
│   ├── encryption/          Payload encryption (§XVI)
│   └── replay/              Replay protection (nonce, timestamp)
│
├── transport/
│   ├── tcp/                 TCP transport implementation
│   ├── udp/                 UDP transport implementation (discovery, heartbeat)
│   ├── stun/                STUN client (RFC 8489)
│   ├── ice/                 ICE candidate gathering (RFC 8445)
│   ├── nat/                 UDP hole punch
│   ├── relay/               TURN relay (RFC 8656)
│   ├── enrollment/          QR generation, format export/import
│   ├── certificate/         Unified ImportCertificate() with format auto-detection
│   ├── framing/             Message framing
│   └── serialization/       Wire serialization/deserialization
│
├── consensus/               Multi-node coordination
│   ├── witness/             Witness selection and protocol
│   ├── attestation/         Attestation collection and verification
│   └── weighting/           Trust-weighted decision support
│
├── trust/                   Trust engine (§XII)
│   ├── scoring/             Trust score computation
│   ├── decay/               Score decay over time
│   ├── store/               Trust data persistence
│   └── exchange/            Trust digest gossip
│
├── acl/                     Access control (§VIII)
│   ├── policy/              Local policy engine (capability resolution)
│   ├── presets/             Predefined capability groupings
│   └── revocation/          Capability revocation
│
├── storage/                 Local persistent storage (§XV)
│   ├── session_store/       Active session state
│   ├── trust_store/         Trust score records
│   ├── audit_store/         Audit log
│   ├── dag_store/           Execution DAG records
│   ├── node_store/          Node identity, keys, configuration, route table
│   └── mesh_store/          Mesh memberships, certificates, epoch
│
├── sdk/                     Client and plugin SDK
│   ├── client/              API client library
│   └── plugin/              Plugin authoring interfaces
│
├── tooling/                 Observability and developer tools (§XXI)
│   ├── tracing/             Distributed tracing
│   ├── metrics/             Performance metrics
│   ├── profiling/           CPU/memory profiling
│   └── audit-viewer/        Audit log browser
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

## VI. NETWORKING ARCHITECTURE

### 6.1 Four Protocol Layers

The SMO networking stack defines exactly four protocol layers, each with a distinct responsibility:

```
┌─────────────────────────────────────────────┐
│ DISCOVERY PROTOCOL  (UDP)                    │
│ HELLO · DISCOVER · NODE_INFO                │
│ HEARTBEAT · PING · OFFLINE                  │
├─────────────────────────────────────────────┤
│ CONTROL PROTOCOL     (TCP)                   │
│ CONTRACT · SESSION · CSR · WITNESS          │
│ REVOKE_CERT · EPOCH_INCREMENT               │
│ TRUST_DIGEST · CAP_GRANT · CAP_REVOKE       │
├─────────────────────────────────────────────┤
│ EXECUTION PROTOCOL   (TCP)                   │
│ EXEC_START · EXEC_PROGRESS · EXEC_EVENT     │
│ EXEC_RESULT · EXEC_CANCEL · EXEC_TIMEOUT    │
├─────────────────────────────────────────────┤
│ DATA PROTOCOL        (TCP)                   │
│ CHANNEL_OPEN · CHUNK · ACK · NACK · FIN     │
└─────────────────────────────────────────────┘
```

**Layer isolation rule:** A layer MUST NOT assume anything about the layers above it. Discovery does not know what a contract is. Control does not know how execution chunks data.

### 6.2 Transport Assignment

| Layer | Transport | Rationale |
|---|---|---|
| Discovery | UDP | Connectionless, broadcast, NAT traversal, low overhead. No state needed. |
| Control | TCP | Reliable, ordered, stream-oriented. Contracts must not be lost or reordered. |
| Execution | TCP | Stateful, long-lived, progress reports must be in order. |
| Data | TCP | Bulk transfer, flow control, independent stream. |

### 6.3 Connectivity vs Transport

SMO distinguishes between Connectivity and Transport:

**Transport layer**: Raw byte movement (TCP, UDP, Unix socket). Stateless. Pluggable.

**Connectivity layer**: NAT traversal, address discovery, hole punching, relay. Produces a connected socket.

```
CONNECTIVITY LAYER
  STUN (RFC 8489)        — discover public address
  ICE  (RFC 8445)        — gather and exchange candidates
  NAT hole punch          — open UDP mappings for direct P2P
  TURN (RFC 8656)        — relay fallback when direct connection fails
       │
       ▼  (produces a connected socket)
TRANSPORT LAYER
  TCP  — reliable streams
  UDP  — connectionless datagrams
```

**Key rule:** The Runtime and Protocol layers never touch Connectivity code. They receive a connected socket from the layer below.

### 6.4 Crypto Suite ID

SMO uses a **Crypto Suite ID** to achieve algorithm agility. The protocol NEVER references specific algorithms. It references Suite IDs. The mapping from Suite ID to concrete algorithms is a local configuration.

| Suite ID | Name | Identity/Signing | Key Exchange | Symmetric | Hash |
|---|---|---|---|---|---|
| 1 | Classical | Ed25519 | X25519 | XChaCha20-Poly1305 | Blake3 |
| 2 | Hybrid PQC | Ed25519 + ML-DSA | X25519 + ML-KEM | XChaCha20-Poly1305 | Blake3 |
| 3 | Pure PQC | ML-DSA | ML-KEM | XChaCha20-Poly1305 | Blake3 |

**Rules:**
- Every node MUST implement Suite 1 (minimum baseline).
- A node MAY implement additional suites.
- During session establishment, nodes negotiate the highest mutually supported suite.
- The suite ID is part of the connection handshake, NOT part of every packet.

### 6.5 Hierarchical Opcode Namespace

All protocol messages use a two-level namespace:

```
Namespace      Byte   Messages
──────────     ────   ────────
DISCOVERY      0x01   HELLO(0x01), DISCOVER(0x02), NODE_INFO(0x03),
                      PING(0x04), OFFLINE(0x05)

CONTROL        0x02   CONTRACT_PROPOSAL(0x01), CONTRACT_ACCEPT(0x02),
                      CONTRACT_REJECT(0x03), CONTRACT_RESULT(0x04),
                      SESSION_OPEN(0x10), SESSION_CLOSE(0x11),
                      SESSION_RENEW(0x12),
                      CSR(0x20), CERTIFICATE(0x21),
                      WITNESS_REQUEST(0x30), WITNESS_RESPONSE(0x31),
                      CAP_GRANT(0x40), CAP_REVOKE(0x41),
                      REVOKE_CERT(0x50), EPOCH_INCREMENT(0x51),
                      TRUST_DIGEST(0x60)

EXECUTION      0x03   EXEC_START(0x01), EXEC_PROGRESS(0x02),
                      EXEC_EVENT(0x03), EXEC_RESULT(0x04),
                      EXEC_CANCEL(0x05), EXEC_TIMEOUT(0x06),
                      EXEC_ERROR(0x07)

DATA           0x04   CHANNEL_OPEN(0x01), CHUNK(0x02),
                      ACK(0x03), NACK(0x04), FIN(0x05), CANCEL(0x06)
```

### 6.6 Packet Format

Every wire message uses the following packet structure:

```
+--------------------------------------------------+
| HEADER                                           |
+--------------------------------------------------+
| PROTOCOL VERSION (1 byte)                        |
| SUITE ID      (1 byte)                           |
| NAMESPACE     (1 byte)  — DISCOVERY/CONTROL/...  |
| MESSAGE ID    (2 bytes) — opcode within namespace |
| SESSION ID    (16 bytes)                         |
| TIMESTAMP     (8 bytes)                          |
| NONCE         (8 bytes)                          |
+--------------------------------------------------+
| PAYLOAD        (variable length)                  |
+--------------------------------------------------+
| SIGNATURE      (64 bytes — Suite 1: Ed25519)     |
+--------------------------------------------------+
```

### 6.7 Wire Protocol Rules

1. Every packet MUST carry a nonce for replay protection.
2. Every packet MUST be signed by the sender using the negotiated Suite's signing algorithm.
3. Every packet MUST carry a timestamp. Receivers MAY reject packets outside a configurable time window.
4. Payload MAY be encrypted at the session level. Header fields are never encrypted.
5. Every session MUST negotiate a Crypto Suite during establishment.

---

## VII. MESH IDENTITY & TRUST INFRASTRUCTURE (MITI)

### 7.1 Three Distinct Concepts

```
┌──────────────────────────────────────────────────┐
│ IDENTITY                                          │
│ "Tôi là node X."                                  │
│ NodeID = Blake3(NodePublicKey)                    │
│ Immutable for the lifetime of the node.           │
├──────────────────────────────────────────────────┤
│ MEMBERSHIP                                        │
│ "Tôi thuộc Mesh Y với vai trò Z."                │
│ MembershipCertificate, signed by Authority.       │
│ Per-mesh. One node can hold multiple memberships. │
├──────────────────────────────────────────────────┤
│ CAPABILITY                                        │
│ "Trong Mesh Y, tôi được phép làm gì."            │
│ CapabilitySet derived from Role in certificate.   │
│ Validated at runtime per session.                 │
└──────────────────────────────────────────────────┘
```

### 7.2 Mesh Genesis

A mesh is defined by its **Mesh Genesis** — a deterministic ID derived at creation.

```
MeshID = Blake3(
    MeshRootPublicKey ||
    CreatedAtUnixMs ||
    32 random bytes
)
```

**Mesh creation flow:**

```
smo mesh create --name "SOC-Production"

1. Generate Mesh Root Keypair (Suite 1: Ed25519)
2. Compute MeshID = Blake3(RootPK || time || random)
3. Generate first Authority Keypair
4. Root signs Authority Certificate:
     AuthorityID, MeshID, Role: AUTHORITY,
     Capabilities: [CAP_GRANT, CAP_REVOKE, ...],
     IssuedBy: RootID, Signature: RootPrivateKey
5. Export Recovery Package (AES-256-GCM encrypted, password-protected)
6. Delete Root Private Key from runtime filesystem
7. Authority certificate stored on node. Root stored OFFLINE.
```

### 7.3 Key Hierarchy

| Key | Purpose | Storage | Usage |
|---|---|---|---|
| Mesh Root Key | Bootstrap, recovery, rotate Authorities | OFFLINE (USB, YubiKey, cold storage, paper) | Once per mesh lifetime ideally never |
| Authority Key | Daily operations: sign certs, grant capabilities, revoke | Online (node runtime) | Every contract, every join |
| Node Key | Node identity, sign contracts, sign enrollment requests | Online (node runtime) | Every operation |

**The Root Key NEVER circulates.** It is:
1. Generated during mesh creation
2. Used immediately to sign the first Authority certificate
3. Exported as an encrypted Recovery Package
4. Deleted from the runtime filesystem

### 7.4 Certificate Chain

```
ROOT (offline)
  │  signs Authority.PublicKey
  ▼
AUTHORITY CERTIFICATE
  │  signs Contributor.PublicKey
  ▼
CONTRIBUTOR CERTIFICATE
  │  signs Reader.PublicKey (if policy allows)
  ▼
READER CERTIFICATE
```

Every certificate contains:

```json
{
  "mesh_id": "SOC-Production",
  "node_public_key": "base64...",
  "role": "AUTHORITY",
  "capabilities": ["CAP_GRANT", "CAP_REVOKE", "CAP_QUARANTINE"],
  "epoch": 1,
  "issued_by": "ROOT",
  "issued_at": "2026-07-15T00:00:00Z",
  "expires_at": "2032-07-15T00:00:00Z",
  "signature": "base64..."
}
```

**Verification:** Any node with the Mesh Root Public Key can verify the full chain:
```
Reader.cert → signed by → Authority.cert → signed by → Root.pub
```

### 7.5 Membership Certificate Format (.smoc)

The `.smoc` file is the serialized form of a Membership Certificate. It MAY be encoded as JSON, CBOR, or ASCII Armor.

**ASCII Armor:**
```
-----BEGIN SMO CERTIFICATE-----
SMOC1:
eyJtZXNoX2lkIjoiU09DLVZOIiw...
-----END SMO CERTIFICATE-----
```

### 7.6 Authority Privilege Boundaries

| Action | Authority A | Authority B | Root |
|---|---|---|---|
| Sign Contributor certs | YES (its own) | YES (its own) | YES |
| Revoke its own certs | YES | YES | YES |
| Revoke another Authority's certs | NO | NO | YES |
| Create new Root | NO | NO | N/A (via recovery) |
| Increment Epoch | NO | NO | YES |
| Read other nodes' keys | NO | NO | NO |

An Authority can only revoke certificates it personally issued (enforced by `issued_by` field).

### 7.7 Capability Epoch

The mesh maintains a monotonically increasing **Epoch** counter. Each Membership Certificate carries the Epoch at which it was issued. When the Epoch increments, all certificates with an older Epoch become invalid.

```
if cert.epoch < mesh.current_epoch → REJECT
(node must request a new certificate)
```

**Epoch increment IS a contract (Control protocol):**
```
Namespace: CONTROL
Message:   EPOCH_INCREMENT (0x02 0x51)
Signers:   Root (or M-of-N Recovery Authorities)
Propagation: gossip
```

This mechanism replaces CRL (Certificate Revocation Lists). No blacklist needed. Old certificates self-invalidate.

### 7.8 Recovery Authorities (Threshold)

At mesh creation, the Root Private Key is split into N shares using Shamir Secret Sharing with threshold M.

```
smo mesh create --recovery-group 5 --threshold 3

Root Private Key
  → divided into 5 shares
  → each share exported as separate file
  → each share stored on a different device/person
  → Root Private Key deleted from runtime
```

**Recovery flow (Root lost):**

```
3 of 5 share holders cooperate:
  smo mesh recover --shares 3-of-5
  → shares combined → reconstruct Root Private Key
  → smo mesh authority rotate --new-root
  → new Root generated
  → new Authority certificates issued
  → old certificates revoked via Epoch increment
```

### 7.9 Mesh Context Switching

A single node may hold Membership Certificates for multiple meshes. The runtime maintains an "active mesh context."

```
Node
├── Identity (Ed25519 keypair, immutable)
├── Membership: Mesh A (certificate, epoch, capabilities)
├── Membership: Mesh B (certificate, epoch, capabilities)
└── Membership: Mesh C (certificate, epoch, capabilities)
```

**Switching:**
```
smo ctx use SOC-Production        ← CLI context switch
smo exec --mesh SOC-Production    ← per-command mesh selection
smo node join --mesh Research     ← join new mesh
smo node leave --mesh SOC         ← leave mesh
```

Each mesh context has its own route table, trust store, capability set, and contract history. The node's Identity is shared across all meshes.

---

## VIII. CAPABILITY SYSTEM

### 8.1 Capability Format

Capabilities are expressed as uppercase identifiers:

```
CAP_HEARTBEAT
CAP_VERIFY
CAP_FS_READ
CAP_FS_WRITE
CAP_PROC_EXEC
CAP_EXEC_BASIC
CAP_NET_BIND
CAP_SESSION_CREATE
CAP_NODE_QUARANTINE
CAP_GRANT
CAP_REVOKE
CAP_DISTRIBUTE
CAP_POLICY_CHANGE
CAP_NODE_BOOTSTRAP
CAP_SIGN_NODE
CAP_EPOCH_INCREMENT
CAP_CUSTOM_CONTRACT
```

### 8.2 Capability Properties

- **Ephemeral**: Capabilities are not permanent. They are granted within a session.
- **Session-scoped**: A capability is valid only within the context of a specific session.
- **Runtime validated**: Capabilities are checked at execution time, never assumed from configuration.
- **Epoch-gated**: The certificate's epoch must match the mesh's current epoch for capabilities to be valid.

### 8.3 Capability Presets (Role Profiles)

The runtime does NOT hardcode roles. These are predefined groupings:

**ROLE_READER** =
```
CAP_HEARTBEAT
CAP_VERIFY
CAP_FS_READ
CAP_SESSION_CREATE
```

**ROLE_CONTRIBUTOR** =
```
ROLE_READER
+
CAP_FS_WRITE
CAP_EXEC_BASIC
CAP_CUSTOM_CONTRACT
```

**ROLE_AUTHORITY** =
```
ROLE_CONTRIBUTOR
+
CAP_PROC_EXEC
CAP_GRANT
CAP_REVOKE
CAP_DISTRIBUTE
CAP_POLICY_CHANGE
CAP_NODE_BOOTSTRAP
CAP_SIGN_NODE
CAP_EPOCH_INCREMENT
CAP_NODE_QUARANTINE
```

Custom roles are defined in configuration, never in the runtime:

```
PRESET: ROLE_SOC_ANALYST
  CAP_FS_READ
  CAP_EXEC_BASIC
  CAP_NODE_QUARANTINE
  (but NOT CAP_GRANT, NOT CAP_REVOKE)
```

### 8.4 Capability Origin

Capabilities originate from the Authority that signs the Membership Certificate. All nodes can verify the signature chain back to the Root.

### 8.5 Capability Revocation

Capabilities are revoked by:
1. **Capability Epoch increment** — all old certificates invalidated at once
2. **REVOKE_CERT contract** — revokes a specific certificate
3. **Session expiry** — capabilities expire with the session

Revocation via REVOKE_CERT is itself a contract (Control protocol), propagated via gossip.

---

## IX. ENROLLMENT PROTOCOL

### 9.1 Enrollment Architecture

Enrollment is the process of delivering a node's Public Key to an Authority and receiving a Membership Certificate. SMO defines the Enrollment Protocol but NOT the transport carrier.

```
┌─────────────────────────────────────────────┐
│ IDENTITY LAYER                               │
│ smo-node init → generates Ed25519 keypair    │
│                node.key (private, NEVER leaves)│
│                node.pub (public, 32 bytes)   │
├─────────────────────────────────────────────┤
│ ENROLLMENT LAYER                             │
│ How does node.pub reach the Authority?       │
│                                              │
│ Carriers (all valid):                        │
│   File (scp, USB)                            │
│   Clipboard (copy-paste)                     │
│   QR (air-gap, demo)                         │
│   REST API (POST /api/v1/enroll)             │
│   Bluetooth / NFC                            │
├─────────────────────────────────────────────┤
│ CERTIFICATION LAYER                          │
│ Authority validates → signs → returns        │
│ MembershipCertificate (.smoc)                │
└─────────────────────────────────────────────┘
```

### 9.2 Enrollment Request (.smor)

```json
{
  "version": 1,
  "mesh_id": "SOC-Production",
  "node_name": "server-01",
  "os": "Linux 6.8.0-amd64",
  "smo_version": "3.0.0",
  "public_key": "MCowBQYDK2VwAyEA...",
  "fingerprint": "A3F9...",
  "requested_role": "CONTRIBUTOR",
  "requested_capabilities": ["CAP_FS_READ", "CAP_FS_WRITE", "CAP_EXEC_BASIC"],
  "nonce": "7b8a9c1d2e3f4a5b",
  "timestamp": "2026-07-15T12:00:00Z",
  "signature": "base64..."    // signed by node's private key
}
```

### 9.3 Node Certificate (.smoc)

```json
{
  "version": 1,
  "mesh_id": "SOC-Production",
  "node_public_key": "MCowBQYDK2VwAyEA...",
  "node_fingerprint": "A3F9...",
  "role": "CONTRIBUTOR",
  "capabilities": ["CAP_FS_READ", "CAP_FS_WRITE", "CAP_EXEC_BASIC"],
  "epoch": 1,
  "issued_by": "Authority-A",
  "issued_at": "2026-07-15T12:01:00Z",
  "expires_at": "2030-07-15T12:01:00Z",
  "signature": "base64..."    // signed by Authority's private key
}
```

### 9.4 CLI Workflow (SSH-like)

```
# On the new node:
smo-node init
  → generates node.key, node.pub
  → outputs enrollment request

smo export --format text > join_request.smor
  (or --format qr, --format json, --format binary)

# Transfer to Authority (any carrier):
scp join_request.smor admin@authority:/tmp/

# On the Authority machine:
smo-admin sign join_request.smor
  → validates request
  → signs certificate
  → outputs node.smoc

# Transfer certificate back to node:
scp node.smoc admin@node:/tmp/

# On the node:
smo-node import node.smoc
  → installs certificate
  → node is now a mesh member
```

**This mirrors SSH:** `ssh-keygen` → `ssh-copy-id` → login.

### 9.5 Enrollment Modes

| Mode | Medium | Use Case |
|---|---|---|
| Interactive (CLI↔CLI) ⭐ | File transfer (scp, rsync, curl) | DevOps, server-to-server |
| Clipboard | Copy-paste (text, email, chat) | Remote teams, Discord, Signal |
| QR | Phone camera, KVM camera | Air-gap, on-prem, demos |
| USB | Removable media | Isolated networks, compliance |
| API | REST endpoint | Enterprise, CI/CD, cloud |

Every mode is optional. A deployment may implement only the modes it needs. The .smor/.smoc format is mandatory; the carrier is not.

### 9.6 Join Token

QR codes carry a **Join Token**, not a certificate:

```
SMO://JOIN
  ?mesh=soc-vn
  &token=abcefg123
  &bootstrap=node.company.com:5555
```

**Token properties:**
- Generated by Authority
- Single-use (consumed after first successful join)
- Time-limited (default: 10 minutes)
- No private key in token — token is purely an authorization secret

**Node join via token:**
```
1. Node scans QR
2. Connects to bootstrap node
3. Generates ephemeral keypair for join
4. Sends CSR: { mesh_id, join_token, public_key, signed_nonce }
5. Authority validates token → signs Membership Certificate
6. Node receives and imports certificate
```

### 9.7 Export/Import Abstraction

```cpp
// Export an enrollment request in any format
std::error_code ExportEnrollmentRequest(
    const EnrollRequest& request,
    ExportFormat format,       // TEXT | JSON | QR | BINARY
    std::vector<uint8_t>& out
);

// Import from any format (auto-detect encoding)
std::error_code ImportCertificate(
    std::span<const uint8_t> data,
    NodeCertificate& cert
);
```

```bash
smo export --format text     # ASCII Armor (.smor)
smo export --format json     # JSON (.smor.json)
smo export --format qr       # QR on terminal
smo export --format binary   # Raw CBOR (.smor.cbor)
```

Export changes only the presentation. The underlying EnrollRequest is identical.

---

## X. CONTRACT MODEL

### 10.1 Contract Definition

A contract is a metadata-only document. It MUST NOT embed application data.

### 10.2 Contract Format (MVP)

Contracts use structured JSON/YAML in the MVP phase. A DSL (.seme) MAY be introduced later.

```json
{
  "contract_id": "c-91ad",
  "requester": "node-a",
  "responder": "node-b",
  "witness": "node-c",
  "opcode": {
    "namespace": "CONTROL",
    "id": "CONTRACT_PROPOSAL"
  },
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
  "signature_responder": "..."
}
```

### 10.3 Contract Record (Post-Execution)

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

### 10.4 Contract Lifecycle

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

### 10.5 Contract Storage Rule

All three participants (Requester, Responder, Witness) MUST store an identical contract record after execution completes.

### 10.6 Large Data Handling

If an opcode operates on large data, the data is transferred through a separate **Data Protocol** channel (CHANNEL_OPEN, CHUNK, ACK, FIN). The contract references the data only by hash.

---

## XI. WITNESS PROTOCOL

### 11.1 Witness Role

A witness is an independent third node that:
- Does NOT execute the contract
- Does NOT own the target resource
- Does NOT vote or arbitrate
- Attests that it knows both Requester and Responder
- Confirms it has no knowledge of anomalous behavior
- Stores a copy of the contract record for future non-repudiation

### 11.2 Witness Selection

1. The Responder selects the witness.
2. Selection priority: (a) Most trusted node known to the Responder (highest local Trust Score). (b) Random selection from known nodes.
3. The Requester MAY propose a witness candidate, but the Responder has final choice.

### 11.3 Witness Redundancy

```
Primary Witness
     ↓ timeout
Secondary Witness
     ↓ timeout
Fallback: Responder proceeds with local decision only (no witness)
```

### 11.4 Witness Confirmation Payload

```
witness_id
contract_id
requester_id
responder_id
trust_digest
attestation
timestamp
witness_signature
```

---

## XII. TRUST AND REPUTATION SYSTEM

### 12.1 Trust Components

| Component | Measures | Input Signals |
|---|---|---|
| Citizen Score | Online time, heartbeat stability, route reliability | Heartbeat response rate, uptime, route consistency |
| Execution Score | Successful contract execution, no rollbacks, no witness objections | Contract completion ratio, witness attestations |
| Witness Score | Witness participation, accuracy of attestations | Number of witness assignments, confirmation accuracy |
| Consistency Score | Agreement with majority in multi-node operations | Result comparison across nodes |

### 12.2 Composite Trust Score

```
Trust = Citizen × 0.2 + Execution × 0.5 + Witness × 0.2 + Consistency × 0.1
```

Weights are defaults. Individual nodes MAY configure different weights in their local policy.

### 12.3 Score Decay

All trust scores MUST use sliding window decay. Scores reflect recent behavior, not cumulative history.

### 12.4 Trust in Execution Decisions

Trust is ONE input to the Responder's decision, not the sole factor:

```
Execute = CapabilityValid AND
          PolicyMatches AND
          CertificateValid AND
          EpochValid AND
          SignatureValid AND
          SessionValid AND
          (Trust >= LocalThreshold OR OverrideByAuthority)
```

### 12.5 Trust Digests Are Hints

Trust digests transmitted over the wire (via TRUST_DIGEST message in Control protocol) are **hints only**. The receiving node:
1. Receives the trust digest from the wire
2. Compares it against its locally computed score for that node
3. Blends the two (weighted by the sender's own trust score)
4. Uses the blended value as ONE input

The local trust computation is always authoritative.

### 12.6 Penalties

- Contract rejected due to insufficient trust: small score penalty to Requester
- Contract rejected due to insufficient capability: larger score penalty to Requester
- Spam detection: nodes that repeatedly submit rejectable contracts accumulate score penalties

---

## XIII. EXECUTION DAG

### 13.1 DAG Format (Internal)

```json
{
  "graph_id": "dag-777",
  "nodes": [
    {
      "task_id": "t1",
      "opcode": { "namespace": "EXECUTION", "id": "EXEC_START" },
      "depends_on": [],
      "parameters": { ... }
    },
    {
      "task_id": "t2",
      "opcode": { "namespace": "EXECUTION", "id": "EXEC_EVENT" },
      "depends_on": ["t1"],
      "parameters": { ... }
    }
  ]
}
```

### 13.2 Compiler Pipeline

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

### 13.3 DAG Immutability Rule

Once the DAG is produced, it MUST NOT be modified. All nodes involved in execution operate on the same DAG. If a DAG must change, a new DAG is compiled from the original intent.

---

## XIV. NODE EXECUTION FSM

### 14.1 FSM Implementation Rules

Every state transition MUST be:
1. **Auditable** — recorded in the audit log
2. **Deterministic** — same input + same prior state = same output
3. **Replayable** — the audit log is sufficient to reconstruct the exact execution
4. **Serializable** — the state can be stored, transmitted, and verified

### 14.2 Node-Level States

```
UNINITIALIZED           No keypair yet
    ↓
KEY_GENERATION          Generate Ed25519 keypair (smo-node init)
    ↓
ENROLLING               Send CSR, await Membership Certificate
    ↓
DOMAIN_JOIN             Certificate received, begin discovery
    ↓
CAPABILITY_NEGOTIATION  Verify certificate chain, establish session
    ↓
ACTIVE                  Full participation
    ↓
CONTRACT_PENDING    →   CONTRACT_VALIDATING
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
                       ACTIVE
    ↓
DEGRADED  or  QUARANTINED  or  OFFLINE
```

### 14.3 Contract Execution Sub-FSM

```
PENDING
    ↓
VALIDATE_POLICY         →  REJECTED
    ↓
VALIDATE_CERTIFICATE    →  REJECTED (cert expired, wrong epoch, bad chain)
    ↓
VALIDATE_CAPABILITY     →  REJECTED
    ↓
VALIDATE_SIGNATURE      →  REJECTED
    ↓
VERIFY_SESSION          →  REJECTED
    ↓
CONSULT_WITNESS         →  REJECTED or fallback
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

## XV. STORAGE MODEL

### 15.1 Storage Types

| Store | Content | Scope |
|---|---|---|
| session_store | Active session state (capabilities, keys, expiration) | Per-node |
| trust_store | Trust scores, score history, decay parameters | Per-node |
| audit_store | Execution audit log (all state transitions) | Per-node |
| dag_store | Compiled execution DAGs | Per-node |
| node_store | Node identity keypair, configuration, route table | Per-node |
| mesh_store | Mesh memberships, certificates, epoch, root public key | Per-node |

### 15.2 Storage Invariant

Never store mutable shared execution state globally. All stored state is per-node isolated.

---

## XVI. SECURITY IMPLEMENTATION

### 16.1 Crypto Suite 1 (Phase 1 — Classical)

| Algorithm | Purpose |
|---|---|
| Ed25519 | Signing and identity |
| X25519 | Key exchange |
| XChaCha20-Poly1305 | Symmetric encryption |
| Blake3 | Hashing |

### 16.2 Crypto Suite 2 (Phase 2 — Hybrid PQC)

| Algorithm | Purpose |
|---|---|
| Ed25519 + ML-DSA (Dilithium) | Signing and identity |
| X25519 + ML-KEM (Kyber) | Key exchange |
| XChaCha20-Poly1305 | Symmetric encryption |
| Blake3 | Hashing |

### 16.3 Crypto Suite 3 (Phase 3 — Pure PQC)

| Algorithm | Purpose |
|---|---|
| ML-DSA (Dilithium) | Signing and identity |
| ML-KEM (Kyber) | Key exchange |
| XChaCha20-Poly1305 | Symmetric encryption |
| Blake3 | Hashing |

### 16.4 Key Management

- Each node generates its own keypair during `smo-node init`.
- NodeID = Blake3(NodePublicKey).
- Root Key generated at mesh creation, exported as encrypted Recovery Package, deleted from runtime.
- Authority Keys are signed by the Root and stored on the Authority node.
- Session keys are derived via the negotiated Crypto Suite's key exchange mechanism.
- Long-term keys are stored in node_store (encrypted at rest).

### 16.5 Session Binding (Certificate → Session)

After the certificate is established, session-level authentication uses a **signed nonce** challenge:

```
1. Node A connects to Node B
2. Node B sends a random nonce (32 bytes)
3. Node A signs the nonce with its Ed25519 private key
4. Node B verifies:
   a. Signature matches Node A's PublicKey
   b. Node A's PublicKey matches the Membership Certificate
   c. Membership Certificate chain verifies up to Root
   d. Certificate Epoch >= mesh CurrentEpoch
   e. Certificate has not expired
5. → Session established
```

Two independent security layers are required: both the certificate (membership) and the signed nonce (key possession) must be valid.

---

## XVII. FILESYSTEM EVOLUTION MODEL

### Phase 1 — Shared Root (MVP)

- Single shared workspace: `/myshared`
- All file operations are sandboxed within this directory.

### Phase 2 — Multi-Root Capability

- Multiple roots: `/shared`, `/var/log`, `/opt/runtime`
- Each root is capability-scoped.

### Phase 3 — System Execution Domain

- Full controlled execution: process execution, service orchestration, runtime isolation, incident containment.

---

## XVIII. NODE LIFECYCLE

```
UNINITIALIZED               No keypair, no config
    ↓
KEY_GENERATION              smo-node init → Ed25519 keypair generated
    ↓
ENROLLMENT                  smo-node import → Membership Certificate received
    ↓
DOMAIN_JOIN                 Connect to bootstrap node, verify certificate chain
    ↓
CAPABILITY_NEGOTIATION      Session established, capabilities active
    ↓
ACTIVE                      Heartbeat, contracts, witness, execution
   /    \    \
  ↓      ↓    ↓
DEGRADED  QUARANTINED  OFFLINE
```

---

## XIX. OPCODES

### 19.1 Hierarchical Namespace

All opcodes use a two-level namespace. The first byte is the namespace, the second byte is the message within that namespace.

### 19.2 Discovery Protocol Opcodes

| ID | Message | Description | Transport |
|---|---|---|---|
| 0x01 0x01 | HELLO | Session initiation over UDP | UDP |
| 0x01 0x02 | DISCOVER | Find nodes on the mesh | UDP |
| 0x01 0x03 | NODE_INFO | Node metadata exchange | UDP |
| 0x01 0x04 | PING | Liveness check | UDP |
| 0x01 0x05 | OFFLINE | Graceful departure announcement | UDP |

### 19.3 Control Protocol Opcodes

| ID | Message | Description | Transport |
|---|---|---|---|
| 0x02 0x01 | CONTRACT_PROPOSAL | Propose a contract | TCP |
| 0x02 0x02 | CONTRACT_ACCEPT | Accept proposed contract | TCP |
| 0x02 0x03 | CONTRACT_REJECT | Reject proposed contract | TCP |
| 0x02 0x04 | CONTRACT_RESULT | Report execution result | TCP |
| 0x02 0x10 | SESSION_OPEN | Open a new session | TCP |
| 0x02 0x11 | SESSION_CLOSE | Close an existing session | TCP |
| 0x02 0x12 | SESSION_RENEW | Renew a session | TCP |
| 0x02 0x20 | CSR | Certificate Signing Request | TCP |
| 0x02 0x21 | CERTIFICATE | Certificate delivery | TCP |
| 0x02 0x30 | WITNESS_REQUEST | Request witness attestation | TCP |
| 0x02 0x31 | WITNESS_RESPONSE | Witness attestation response | TCP |
| 0x02 0x40 | CAP_GRANT | Grant capabilities to a node | TCP |
| 0x02 0x41 | CAP_REVOKE | Revoke capabilities from a node | TCP |
| 0x02 0x50 | REVOKE_CERT | Revoke a specific certificate | TCP |
| 0x02 0x51 | EPOCH_INCREMENT | Increment mesh epoch | TCP |
| 0x02 0x60 | TRUST_DIGEST | Gossip trust digest | TCP |

### 19.4 Execution Protocol Opcodes

| ID | Message | Description | Transport |
|---|---|---|---|
| 0x03 0x01 | EXEC_START | Begin execution | TCP |
| 0x03 0x02 | EXEC_PROGRESS | Execution progress update | TCP |
| 0x03 0x03 | EXEC_EVENT | Execution event (stdout, status) | TCP |
| 0x03 0x04 | EXEC_RESULT | Final execution result | TCP |
| 0x03 0x05 | EXEC_CANCEL | Cancel execution | TCP |
| 0x03 0x06 | EXEC_TIMEOUT | Execution timed out | TCP |
| 0x03 0x07 | EXEC_ERROR | Execution error | TCP |

### 19.5 Data Protocol Opcodes

| ID | Message | Description | Transport |
|---|---|---|---|
| 0x04 0x01 | CHANNEL_OPEN | Open a data transfer channel | TCP |
| 0x04 0x02 | CHUNK | Data chunk | TCP |
| 0x04 0x03 | ACK | Acknowledge chunk receipt | TCP |
| 0x04 0x04 | NACK | Negative acknowledgment | TCP |
| 0x04 0x05 | FIN | End of data stream | TCP |
| 0x04 0x06 | CANCEL | Cancel data transfer | TCP |

### 19.6 Opcode Categories (Application-Level)

These map to the original SM opcodes but are expressed as contract parameters, not wire-level opcodes:

| Opcode | Description | Requires | Idempotent |
|---|---|---|---|
| LS | List directory contents | CAP_FS_READ | Yes |
| PUT | Write file | CAP_FS_WRITE | Yes (same content) |
| GET | Read file | CAP_FS_READ | Yes |
| EXEC | Execute a command | CAP_PROC_EXEC | No (explicitly non-idempotent) |
| QUARANTINE | Isolate a node | CAP_NODE_QUARANTINE | No |
| MKDIR | Create directory | CAP_FS_WRITE | Yes |
| RM | Remove file or directory | CAP_FS_WRITE | No |
| CP | Copy file | CAP_FS_WRITE | Yes |
| CUSTOM | User-defined operation (plugin) | CAP_CUSTOM_CONTRACT | (declared by plugin) |

### 19.7 Opcode Replay Rule

Every opcode MUST be either:
- **replay-safe**: executing it N times produces the same effect as executing it once, OR
- **explicitly declared non-idempotent**: the system documents that replay has side effects.

---

## XX. CLI DESIGN

### 20.1 Entry Points

| Binary | Purpose |
|---|---|
| `smo-cli` | User-facing execution tool |
| `smo-node` | Node daemon |
| `smo-admin` | Mesh administration |
| `smo-debug` | Internal tracing and debugging |

### 20.2 CLI Commands

```
# Mesh lifecycle
smo mesh create --name "SOC-Production" --recovery-group 5 --threshold 3
smo mesh discover
smo node join --mesh SOC --token abc123
smo node leave --mesh SOC

# Context switching
smo ctx use SOC-Production
smo ctx list

# Enrollment
smo-node init
smo export --format text > join_request.smor
smo-admin sign join_request.smor
smo-node import node.smoc

# Execution
smo exec --mesh SOC --target node-a --opcode LS --path /var/log
smo exec --file contract.json

# Administration
smo admin authority issue --pubkey candidate.pub
smo admin authority revoke --node node-x
smo admin grant-cap --node node-b --cap CAP_FS_WRITE
smo admin revoke-cap --node node-x --cap CAP_PROC_EXEC
smo admin epoch increment
smo admin recover --shares 3-of-5

# Trust
smo trust inspect node-a
smo trust peers

# Mesh operations
smo quarantine node-c
```

---

## XXI. OBSERVABILITY

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

## XXII. TESTING MODEL

```
tests/
├── unit/                Per-module unit tests
├── integration/         Cross-module integration tests
├── mesh/                Multi-node mesh topology tests
├── chaos/               CRITICAL — simulate network delay, node compromise, split-brain, divergence
├── replay/              Deterministic replay from audit logs
└── adversarial/         Security-focused adversarial scenarios
```

### 22.1 Chaos Testing Requirements

The chaos test suite MUST simulate:
- Delayed packets
- Compromised nodes
- Split-brain conditions
- State divergence between nodes
- Authority failure and recovery
- Root key loss and M-of-N recovery

---

## XXIII. MVP SCOPE

### 23.1 Deliverables

1. **5 application opcodes**: LS, PUT, GET, EXEC, QUARANTINE
2. **1 killer workflow**: Incident Containment
   ```
   Detect suspicious node
       ↓
   Reduce trust score
       ↓
   Revoke capabilities
       ↓
   Quarantine node
   ```
3. Transport + Session + Signatures operational (TCP, UDP discovery)
4. Single-node FSM operational (including enrollment flow)
5. Contract proposal/acceptance/rejection flow operational
6. Witness protocol (basic, single-witness, no fallback required for MVP)
7. Identity system: node init, keypair generation, enrollment (.smor/.smoc)
8. Single mesh with single Authority

### 23.2 Out of MVP Scope

- Full DAG scheduler
- Trust engine with all four components
- Consensus weighting
- DAG optimizer
- .seme DSL (JSON/YAML only)
- WASM sandbox
- Multi-root filesystem (Phase 1 only: /myshared)
- Windows/macOS adapters
- Multiple Authority support
- Recovery Authorities (threshold recovery)
- Capability Epoch (manual revocation only)
- STUN/ICE/NAT connectivity (direct TCP only)
- Mesh context switching (single mesh per node)
- REVOKE_CERT and EPOCH_INCREMENT (manual revocation only)

---

## XXIV. IMPLEMENTATION ORDER

DO NOT start with trust AI, fancy consensus, or complex DAG optimization.

### Stage 1 — Foundation

```
identity + transport + session + signature
```
- Ed25519 keypair generation
- TCP transport
- Session establishment (signed nonce)
- Discovery protocol (basic UDP HELLO/PING)

### Stage 2 — Node Core

```
enrollment + single-node FSM
```
- .smor/.smoc enrollment flow
- Contract proposal/accept/reject
- Single-node execution FSM

### Stage 3 — Multi-Node

```
multi-node propagation + witness
```
- Multi-node contract flow
- Basic witness protocol
- Control protocol over TCP

### Stage 4 — DAG

```
compiler + DAG scheduler
```
- Intent → DAG compiler
- DAG-aware scheduler
- Execution protocol

### Stage 5 — Trust

```
trust engine + membership protocol
```
- Trust scoring (all four components)
- SWIM-inspired membership (gossip, suspicion, indirect ping)
- Heartbeat protocol over UDP

### Stage 6 — Full Networking

```
connectivity + data protocol
```
- STUN client (RFC 8489)
- ICE candidate gathering (RFC 8445)
- UDP hole punch
- TURN relay (RFC 8656)
- Data protocol (chunked transfer)

### Stage 7 — Governance

```
multiple authorities + epoch + recovery
```
- Multiple Authority support
- Capability Epoch
- Recovery Authorities (Shamir threshold)
- REVOKE_CERT and EPOCH_INCREMENT

---

## XXV. GOLDEN ENGINEERING RULES

### Rule 1: Invariant First
Invariants MUST be defined and enforced before features are added. Never add a feature that violates an invariant.

### Rule 2: Opcode Replay Safety
Every opcode must be replay-safe or explicitly declared non-idempotent. This is not a guideline; it is a requirement.

### Rule 3: No Silent Mutation
No component may silently mutate state. ALL mutations must be recorded and auditable. EVER.

### Rule 4: Trust Is Eventually Consistent
Trust is NOT absolute truth. It is a local, eventually-consistent estimate. No execution decision may depend on trust alone.

### Rule 5: Execution Graph Immutability
The execution graph is immutable after compilation. No runtime component may modify a compiled graph.

### Rule 6: Private Key Never Travels
No private key ever leaves the node on which it was generated. All identity proof is via signed challenges.

### Rule 7: Certificate Chain Verifiable by All
Every Membership Certificate must be verifiable up to the Root Public Key by any node in the mesh.

---

## XXVI. FINAL ARCHITECTURE VIEW

```
                      ┌──────────────────────────────────────┐
                      │           APPLICATION                 │
                      │  (incident response, fleet ops, ...) │
                      └──────────────┬───────────────────────┘
                                     │
                      ┌──────────────▼───────────────────────┐
                      │   CLI / SDK                           │
                      │   smo-cli · smo-admin · smo-node     │
                      └──────────────┬───────────────────────┘
                                     │
                      ┌──────────────▼───────────────────────┐
                      │   INTENT LANGUAGE                     │
                      │   JSON/YAML · (.seme future)          │
                      └──────────────┬───────────────────────┘
                                     │
                      ┌──────────────▼───────────────────────┐
                      │   COMPILER                            │
                      │   Parse → Resolve → Plan → DAG       │
                      └──────────────┬───────────────────────┘
                                     │
                      ┌──────────────▼───────────────────────┐
                      │   SCHEDULER + FSM                     │
                      │   DAG-aware · Node FSM · Mesh FSM   │
                      └──────────────┬───────────────────────┘
                                     │
                      ┌──────────────▼───────────────────────┐
                      │   CONTROL PROTOCOL  (TCP)             │
                      │   Contract · Session · Witness       │
                      │   CSR · Certificate · Revoke         │
                      └──────────────┬───────────────────────┘
                                     │
                      ┌──────────────▼───────────────────────┐
                      │   EXECUTION PROTOCOL  (TCP)           │
                      │   Start · Progress · Event · Result  │
                      └──────────────┬───────────────────────┘
                                     │
              ┌──────────────────────┼──────────────────────┐
              │                      │                      │
   ┌──────────▼──────────┐ ┌─────────▼─────────┐ ┌─────────▼─────────┐
   │  DISCOVERY (UDP)    │ │ DATA PROTOCOL(TCP)│ │  WITNESS          │
   │  HELLO · PING       │ │ CHUNK · ACK · FIN │ │  Attest           │
   │  HEARTBEAT · GOSSIP │ │                   │ │  Verify           │
   └──────────┬──────────┘ └─────────┬─────────┘ └─────────┬─────────┘
              │                      │                      │
   ┌──────────▼──────────────────────▼──────────────────────▼──────────┐
   │                    SESSION LAYER                                  │
   │   Keys · Identity · Capability negotiation · Signed nonce        │
   └──────────────────────────────┬───────────────────────────────────┘
                                  │
   ┌──────────────────────────────▼───────────────────────────────────┐
   │                    CONNECTIVITY LAYER                             │
   │   STUN (RFC 8489) · ICE (RFC 8445) · NAT hole punch             │
   │   TURN relay (RFC 8656)                                          │
   └──────────────────────────────┬───────────────────────────────────┘
                                  │
   ┌──────────────────────────────▼───────────────────────────────────┐
   │                    TRANSPORT LAYER                               │
   │   TCP · UDP · (future: QUIC, Unix socket)                       │
   └──────────────────────────────┬───────────────────────────────────┘
                                  │
   ┌──────────────────────────────▼───────────────────────────────────┐
   │                    IDENTITY + MEMBERSHIP LAYER                    │
   │   Ed25519 keypairs · Membership Certificates · Chain verification│
   │   Mesh Root · Authority · Epoch · Recovery                       │
   └──────────────────────────────────────────────────────────────────┘
```

---

## XXVII. APPENDIX A — BUSINESS AND LICENSING

This section is non-normative.

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

## XXVIII. APPENDIX B — REFERENCE LEGACY

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
