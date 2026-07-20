# Discussion 0040 — Release 0.0.1: Architecture Review, Gaps & Ship Plan

**Date:** 2026-07-20  
**Status:** 🟡 PLANNING — all Phase 1–8 implemented, protocol pre-freeze review in progress  
**Goal:** Freeze SMO Protocol v1.0, ship 0.0.1, then build compliance tests on top  
**Scope:** References SPEC.md (2744 lines), 10 RFCs, 8 discussion docs, core + cmd source

---

## 0. Executive Review (From Architecture Review)

**Rating: ~9.7/10**

The system has evolved from a collection of RFCs and isolated modules into a complete distributed system. The key strengths:

| Dimension | Score | Reason |
|-----------|-------|--------|
| Layered architecture | 10/10 | Clean 7-layer separation (CLI→Service→Runtime→Core→Network→Storage→Crypto) |
| Join protocol | 10/10 | No HTTP, pure TCP/CBOR, replay protection via nonce+timestamp+signature |
| Bootstrap | 10/10 | Seed-only (not full dump), epoch-based delta sync, transport decoupled from discovery |
| Gossip separation | 10/10 | Bootstrap ≠ Discovery ≠ Gossip — three distinct concerns, three different transports (TCP bootstrap, UDP discovery, TCP gossip) |
| Delta sync | 10/10 | Epoch-based, 6 typed delta channels (membership/crl/policy/manifest/routing/contracts) |
| PKI | 9.5/10 | Three-tier key hierarchy, Root offline, Authority online, Capability Epoch instead of CRL |
| State machine | 9.5/10 | 12 states, FULLY resumable (persisted to join_state.bin), 6 transition paths to FAILED |
| Versioning | 8.5/10 | Missing protocol_version in JOIN_REQUEST/BOOTSTRAP_SYNC, ambiguous epoch vs version semantics |
| Capability negotiation | 8.5/10 | Mentioned in SPEC.md §7.4 but not implemented: no required/optional flag, no protocol-level capability exchange |

### What must be fixed before freeze

1. **Versioning**: ambiguous `manifest_epoch` vs `policy_version` — docs need to clarify: are policies inside manifest or independent? (`SPEC.md:1112-1119`, `join_protocol.hpp:39-53`)

2. **Capability negotiation**: SPEC.md:709 says "Session: Capability negotiation" but no mechanism exists. Need `required`/`optional` flags (`gossip.hpp:41-56` DeltaType enum is fixed, not negotiable)

3. **JOIN_REQUEST protocol_version**: currently has `version = 1` hardcoded (join_protocol.hpp:47). Needs `protocol_version` + `client_version` + `supported_capabilities` for future-proofing

4. **ABORTED vs FAILED**: Join state machine only has `FAILED = -1` (join_protocol.hpp:146). Token expiry, protocol mismatch, unreachable endpoint should all be `ABORTED` (non-retryable, distinct from FAILED)

5. **server_time in JOIN_RESPONSE/BOOTSTRAP_RESPONSE**: Neither response has a server timestamp (join_protocol.hpp:67-78, bootstrap_snapshot.hpp:32-69). Without it, clients depend entirely on local clock for expiry/epoch drift checks

6. **Seed priority/region**: BootstrapResponse has seed lists but no `region/latency_hint/priority` fields (join_protocol.hpp:74). Large meshes need geographic-aware seed selection

**Critical meta-recommendation**: After fixing these 6 items, FREEZE the protocol. Do NOT add features. Write a **Protocol Compliance Test** suite. Distributed systems die from protocol drift, not missing features.

---

## 1. Current State (What Exists)

All 8 phases of the mesh lifecycle are implemented at the code level:

| Phase | Feature | Status | Key Files | Source Refs |
|-------|---------|--------|-----------|-------------|
| 1 | PKI & Governance (Root-as-Node, 2-tier gov, slots, recovery) | ✅ | `core/genesis/`, `core/mesh/`, `core/governance/`, `core/recovery/`, `core/authority/`, `core/certificate/` | RFC 0033, RFC 0035, DISCUSSION_0035 |
| 2 | Bootstrap Protocol (namespace 0x05, CBOR, snapshot) | ✅ | `core/bootstrap/`, `core/network/bootstrap/` | RFC 0034, SPEC.md §V.3 |
| 3 | Signature Join Token v2 (CBOR+HMAC) + Root Redesign | ✅ | `core/enroll/join_token.hpp/.cpp` | DISCUSSION_0036, SPEC.md §7.5.6 |
| 4 | Runtime Skeleton (kernel, dispatcher, pipeline) | ✅ | `core/runtime/` (41 files) | RFC 0035, SPEC.md §IX |
| 5 | 6 Native Contracts (echo, bootstrap, join, governance, recovery, file) | ✅ | `core/runtime/contracts/` | SPEC.md §IX.3 |
| 6 | Mesh catalog CLI (`smo mesh list/use/create`) | ✅ | `cmd/smo-cli/main.cpp` | RFC 0032, DISCUSSION_0034 |
| 7 | Mesh catalog sync via gossip (MembershipSync, GossipEngine, TCP GOSP) | ✅ | `core/discovery/gossip.*`, `core/network/sync/` | DISCUSSION_0039 §7 |
| 8a | SyncService delta handlers (CRL/manifest/policy/routing/contracts) | ✅ | `core/network/sync/sync_service.*`, `core/discovery/gossip.*` | DISCUSSION_0039 §8a |
| 8b | GOSSIP_SYNC join FSM (WAIT_SYNC→READY) | ✅ | `core/enroll/auto_enroll.cpp:718-726` | DISCUSSION_0039 §8b |
| 8c | `smo mesh create` inline keygen | ✅ | `cmd/smo-cli/main.cpp:585-655` | DISCUSSION_0039 §8c |
| — | DiscoveryEngine UDP (§5.20 HELLO/WELCOME/PING/PONG) | ✅ | `core/discovery/discovery.*`, `core/network/udp/` | DISCUSSION_0039 §5.20 |

### Binaries building successfully (all targets clean)

| Binary | Purpose | Lines | Entry Point |
|--------|---------|-------|-------------|
| `smo` | Top-level alias | ~10 | `cmd/smo/main.cpp` |
| `smo-cli` | Interactive CLI shell | 1267 | `cmd/smo-cli/main.cpp` |
| `smo-node` | Node daemon (FSM, gossip, sync, runtime) | 1814 | `cmd/smo-node/main.cpp` |
| `smo-admin` | Mesh administration (sign, create-mesh, invite, serve) | 1071 | `cmd/smo-admin/main.cpp` |
| `smo-debug` | Low-level debug tool | ~200 | `cmd/smo-debug/main.cpp` |

### Test results (current baseline)

- 72% passed (13/18)
- 3 pre-existing failures: `governance_model` ×2 (`core/governance/test_governance.cpp:91,221`), `contract_model` ×1 (`core/contract/test_contract.cpp:120`)
- 3 Not Run: `core`, `protocol`, `compiler` (missing executables at `tests/unit/core_test.cpp`, `protocol_test.cpp`, `compiler_test.cpp`)

---

## 2. Full Architecture Overview

### 2.1 Layer Stack (7 Layers)

```
┌──────────────────────────────────────────────────────────┐
│                    CLI LAYER                              │
│  smo-cli (intent parser, readline)                      │
│  smo-admin (sign, create-mesh, invite, serve)           │
│  smo-node (daemon FSM, runtime bridge)                  │
│  smo-debug (low-level debug)                            │
│  Reference: cmd/smo-cli/main.cpp, cmd/smo-admin/main.cpp │
│  cmd/smo-node/main.cpp, cmd/smo-debug/main.cpp          │
├──────────────────────────────────────────────────────────┤
│                   SERVICE LAYER                           │
│  MeshManager     — mesh lifecycle (create/join/leave)    │
│  SyncService     — delta sync scheduler (6 intervals)    │
│  GossipEngine    — typed delta fanout (5 deltas + memb)  │
│  DiscoveryEngine — UDP HELLO/WELCOME/PING/PONG           │
│  JoinService     — join protocol orchestration           │
│  BootstrapSvc    — bootstrap session management          │
│  RuntimeBridge   — bridges CLI intents → Runtime kernel  │
│  NodeLifecycleFSM — top-level node state machine         │
│  Reference: core/mesh/mesh_manager.hpp:24-64             │
│  core/network/sync/sync_service.hpp:24-56               │
│  core/discovery/gossip.hpp:39-105, discovery.hpp         │
├──────────────────────────────────────────────────────────┤
│                   RUNTIME KERNEL                          │
│  Dispatcher → MiddlewarePipeline → ActionExecutor        │
│  → Scheduler → ExecutionEngine → Contract::execute()     │
│  EventBus (side-channel)  ServiceRegistry  Telemetry     │
│  Reference: core/runtime/runtime_kernel.hpp              │
│  core/runtime/middleware_pipeline.hpp, dispatcher.hpp     │
│  SPEC.md §IX — Runtime Execution Model                   │
├──────────────────────────────────────────────────────────┤
│                  CORE DOMAIN                              │
│  Genesis — mesh genesis block, bootstrap slots           │
│  Governance — policy evaluation, action dispatch         │
│  Recovery — recovery engine, CRL management              │
│  Authority — key management, certificate issuance        │
│  Certificate — PEM, chain verification                   │
│  Identity — NodeID = Blake3(PubKey)                      │
│  Trust — 4-component composite scoring                   │
│  Capability — bitmask-based (R/W/X presets)              │
│  PolicyEngine — access control evaluation               │
│  Selector — node selection query engine                  │
│  Reference: core/genesis/, core/governance/              │
│  core/recovery/, core/authority/, core/certificate/      │
│  SPEC.md §VII — Mesh Identity & Trust                    │
├──────────────────────────────────────────────────────────┤
│                  NETWORK / TRANSPORT                      │
│  TCP Transport — connector, listener, session            │
│  UDP Transport — datagram read/write, heartbeat          │
│  Framing — SMO frame header (9B magic + length)          │
│  SecureSession — key exchange + AEAD encryption          │
│  PacketDispatcher — opcode routing to handlers           │
│  AddressResolver — DNS, SRV record resolution            │
│  Reference: core/transport/tcp_transport.hpp             │
│  core/network/udp/udp_transport.hpp                      │
│  core/transport/framing.hpp, secure_session.hpp          │
│  core/network/packet_dispatcher.hpp                      │
├──────────────────────────────────────────────────────────┤
│                  STORAGE                                  │
│  SQLiteStore — generic KV store with CRUD                │
│  ManifestStore — epoch-based manifest storage            │
│  AuditStore — append-only contract audit log             │
│  PeerStore — peer record persistence                     │
│  SeedStore — seed endpoint persistence                   │
│  NodeRegistry — node/certificate/alias registry          │
│  ContractRegistry — Blake3-addressed contract store      │
│  Reference: core/storage/sqlite_store.hpp                │
│  core/storage/manifest_store.hpp, audit_store.hpp         │
│  SPEC.md §XV — Storage                                   │
├──────────────────────────────────────────────────────────┤
│                  CRYPTO                                   │
│  Suite1 (Classical: Ed25519+X25519+XChaCha20+Blake3)     │
│  Suite3 (PurePQC: ML-DSA+ML-KEM)                         │
│  CryptoRegistry — suite lookup by CryptoSuiteID          │
│  HashProvider — Blake3, SHA256 adapters                  │
│  Signer — Ed25519/ML-DSA sign/verify                     │
│  KEM — X25519/ML-KEM key encapsulation                  │
│  AEAD — XChaCha20-Poly1305 encrypt/decrypt               │
│  Reference: core/crypto/suite.hpp, registry.hpp          │
│  providers/suite1_classical/, suite3_purepqc/            │
│  RFC 0009, SPEC.md §XVI                                  │
└──────────────────────────────────────────────────────────┘
```

### 2.2 Four Protocol Namespaces (per RFC 0020)

| Namespace | ID | Transport | Messages | Source Ref | Phase |
|-----------|----|-----------|----------|------------|-------|
| **DISCOVERY** | `0x01` | UDP | HELLO(`0x0101`), WELCOME(`0x0102`), PING(`0x0103`), PONG(`0x0104`), DISCOVER(`0x0105`), NODE_INFO(`0x0106`), OFFLINE(`0x0107`) | RFC 0020:33-55, SPEC.md §XII.3 | ✅ |
| **BOOTSTRAP** | `0x05` | TCP | BOOTSTRAP_REQUEST(`0x0501`), BOOTSTRAP_RESPONSE(`0x0502`) | RFC 0034:41-58, SPEC.md §V.3 | ✅ |
| **JOIN** | `0x06` | TCP | JOIN_REQUEST(`0x0601`), JOIN_RESPONSE(`0x0602`), BOOTSTRAP_SYNC_REQ(`0x0603`), BOOTSTRAP_SYNC_RESP(`0x0604`) | join_protocol.hpp:27-34, DISCUSSION_0039 §5 | ✅ |
| **GOSSIP** | `0x01` sub | TCP | GOSP magic `0x474F5350` (4B) + typed delta segments `[type:1][len:4 LE][payload]` | gossip.hpp:45-51, DISCUSSION_0039 §8a | ✅ |

### 2.3 Transport Assignment (per §5.20)

```
Layer         Transport    Pattern
────────────────────────────────────────────────
Discovery     UDP          HELLO/WELCOME/PING/PONG (sendto/recvfrom)
Bootstrap     TCP          Connect → send/receive → close (single request-response)
Gossip        TCP          Connect → send frames → close (fanout to 3 random peers, per tick)
                           Reference: core/discovery/discovery.cpp (UDP)
                           core/bootstrap/bootstrap_protocol.cpp (TCP)
                           core/discovery/gossip.cpp:send_gossip_to_peer() (TCP fanout)
```

### 2.4 Opcode Namespace Allocation (per RFC 0020)

```
0x01 ─ DISCOVERY    HELLO, WELCOME, PING, PONG (UDP)
0x02 ─ CONTROL      Session lifecycle, capability (not yet used on wire)
0x03 ─ EXECUTION    Contract execution (not yet used on wire)
0x04 ─ DATA         File transfer (not yet used on wire)
0x05 ─ BOOTSTRAP    Bootstrap request/response (TCP)
0x06 ─ JOIN         Join request/response, bootstrap sync (TCP)
0x07-0xFD ─ RESERVED for future namespaces
0xFE ─ INTERNAL     Runtime-internal opcodes
0xFF ─ CUSTOM       Plugin-defined opcodes
```

### 2.5 Key Data Flow: smo mesh join → smo-node --daemon

```
User runs: smo mesh join --token SMO-JOIN-xxxxx
  │
  ├─ 1. auto_enroll::run_join_command()          [auto_enroll.cpp:280-500]
  │     ├─ Decode token → CBOR payload + HMAC verify [join_token.hpp:42-59]
  │     ├─ Initialize identity (generate keypair)    [identity.hpp]
  │     ├─ Build CSR                                 [certificate.hpp]
  │     ├─ TCP connect to bootstrap_endpoints[0]     [auto_enroll.cpp:301-320]
  │     ├─ Send JOIN_REQUEST (0x0601):               [join_protocol.hpp:46-57]
  │     │     CBOR keys: {1:token, 2:csr, 3:timestamp, 4:nonce, 5:csr_hash, 6:signature}
  │     ├─ Receive JOIN_RESPONSE (0x0602):            [join_protocol.hpp:67-78]
  │     │     CBOR keys: {1:cert, 2:mesh_id, 3:mf_digest, 4:mf_epoch, 5:seeds, 6:nonce}
  │     ├─ Verify certificate chain                  [auto_enroll.cpp:410-440]
  │     ├─ Send BOOTSTRAP_SYNC_REQUEST (0x0603):     [join_protocol.hpp:89-103]
  │     │     CBOR keys: {1:mesh_id, 2:node_id, 3:mf_epoch, 4:crl_epoch, 5:member_epoch, 6:policy_ver}
  │     ├─ Receive BOOTSTRAP_SYNC_RESPONSE (0x0604): [join_protocol.hpp:113-132]
  │     │     CBOR keys: {1:mf_delta, 2:member_delta, 3:policy_delta, 4:crl_delta,
  │     │                  5:mf_epoch, 6:member_epoch, 7:crl_epoch, 8:policy_ver}
  │     ├─ Persist join_state.bin                    [auto_enroll.cpp:486-495]
  │     └─ Return JoinResult
  │
  └─ 2. Start smo-node --daemon                    [cmd/smo-node/main.cpp]
        ├─ Initialize all services                  [smo-node:500-700]
        │     Crypto(register_suite1+suite3) → Identity → MeshManager →
        │     DiscoveryEngine → GossipEngine → MembershipSync → SyncService →
        │     CRL → ManifestStore → PacketDispatcher → RuntimeBridge
        ├─ Bootstrap: TCP HELLO → WELCOME → DISCOVER → NODE_INFO
        │     [discovery.cpp, bootstrap_protocol.cpp]
        ├─ Resume join FSM from persisted state       [auto_enroll.cpp:700-750]
        │     FSM transitions:
        │       WAIT_SYNC(8)  + GOSSIP_STARTED(108)  → GOSSIP_SYNC(9)
        │       GOSSIP_SYNC(9) + GOSSIP_COMPLETE(109) → WAIT_GOSSIP(10)
        │       WAIT_GOSSIP(10) + GOSSIP_COMPLETE(109) → READY(11)
        │     [join_protocol.cpp:340-370 transition table]
        ├─ SyncService::tick() fires delta callbacks: [sync_service.cpp]
        │     routing(15s) → policy(60s) → crl(300s) → manifest(on change)
        │     → contracts(on change) → membership(30s) → gossip.tick()
        │     [sync_service.hpp:25-38 SyncSchedule]
        └─ Main loop: poll UDP + TCP + tick timers    [smo-node:1600-1750]
```

---

## 3. Complete CLI Command Reference

### 3.1 `smo-cli` — Interactive Shell (`cmd/smo-cli/main.cpp:1267`)

| Command | Description | Source Ref |
|---------|-------------|------------|
| `smo mesh create <name>` | Create mesh with inline keygen (authority+root+PQC) | `main.cpp:583-655` |
| `smo mesh list` | List all local meshes from catalog | `main.cpp:532-560` |
| `smo mesh use <name>` | Switch active mesh context | `main.cpp:570-577` |
| `smo mesh publish [--listen] [--ep]` | Configure bootstrap endpoints | Delegates to smo-admin |
| `smo mesh invite --role --expire --ep` | Generate SMO-JOIN-xxx token | Delegates to smo-admin |
| `smo mesh join --token <token>` | Zero-touch join (TCP/CBOR full lifecycle) | `main.cpp:651-680` → `auto_enroll.cpp` |
| `ls [path]` | List directory contents | Intent parser → exec |
| `cd <path>` | Change directory | Context state |
| `pwd` | Print working directory | Context state |
| `info [node]` | Node/mesh info | `main.cpp:intent->info` |
| `ping <node>` | Ping mesh node | Session → HEARTBEAT |
| `exec <cmd> [args]` | Execute command on target | Runtime → Contract |
| `get <remote> [local]` | Download file | FS contract |
| `put <local> <remote>` | Upload file | FS contract |
| `cat <remote>` | Display remote file | FS contract |
| `deploy <contract> [args]` | Deploy a contract | Registry → runtime |
| `undeploy <contract>` | Remove a contract | Registry |
| `genesis [payload]` | Run mesh genesis | `main.cpp:handle_genesis` |
| `governance <action>` | Governance operations | Governance engine |
| `recovery [options]` | Recovery operations | Recovery engine |
| `policy <action> [args]` | Policy management | Policy engine |
| `help` / `exit` / `quit` | System | Shell |

### 3.2 `smo-admin` — Administration (`cmd/smo-admin/main.cpp:1071`)

| Command | Description | Source Ref |
|---------|-------------|------------|
| `smo-admin --mesh <name> create-mesh <name>` | Create mesh (offline keygen) | `main.cpp:295-370` |
| `smo-admin --mesh <name> mesh publish` | Configure bootstrap endpoints | `main.cpp:390-480` |
| `smo-admin --mesh <name> sign <csr> -o <out>` | Sign CSR → issue certificate | `main.cpp:190-260` |
| `smo-admin --mesh <name> generate-invite <role>` | Generate Join Token | `main.cpp:500-590` |
| `smo-admin --mesh <name> serve [--port]` | Start enroll HTTP server | `main.cpp:600-700` (legacy) |

### 3.3 `smo-node` — Daemon (`cmd/smo-node/main.cpp:1814`)

| Command | Description | Source Ref |
|---------|-------------|------------|
| `smo-node --init --name <n> --data <dir>` | Initialize node identity | `main.cpp:100-180` |
| `smo-node --import [file\|clip\|stdin]` | Import certificate | `main.cpp:200-260` |
| `smo-node --daemon --data <dir>` | Start daemon (no bootstrap) | `main.cpp:1500-1750` |
| `smo-node --daemon --seed <host:port>` | Start daemon with seed | `main.cpp:1520` |
| `smo-node --join --token SMO-JOIN-...` | Headless join + daemon | `main.cpp:280-400` |
| `smo-node --pubkey` | Show public key | `main.cpp:90` |
| `smo-node --fingerprint` | Show key fingerprint | `main.cpp:95` |

### 3.4 `smo-debug` — Debug (`cmd/smo-debug/main.cpp:~200`)

| Command | Description |
|---------|-------------|
| `smo-debug [options]` | Low-level debug ops (raw CBOR dump, connection test, etc.) |

---

## 4. Complete Data Models

### 4.1 Mesh Configuration — `mesh.json`

```json
{
  "mesh_id": "a1b2c3d4e5f6...",
  "display_name": "production",
  "authority_pubkey": "hex-encoded",
  "root_pubkey": "hex-encoded",
  "hmac_secret": "hex-encoded-32-bytes",
  "cipher_suite_id": 3,
  "epoch": 1,
  "created_at": 1721452800,
  "listen_address": "0.0.0.0:7777",
  "advertise_addresses": ["authority.example.com:7777"],
  "bootstrap_endpoints": ["authority.example.com:7777"],
  "bootstrap_configured": true
}
```
**Source:** `core/mesh/mesh_manager.hpp:24-40` (MeshConfig struct). Written by `smo mesh create` at `cmd/smo-cli/main.cpp:630-650`. Loaded by `MeshManager::load_mesh_config()`.

### 4.2 Node Identity — `identity.json`

```
NodeID = Blake3(NodePublicKey)
```
```
~/.smo/meshes/<name>/
├── identity.json     { node_id, public_key, created_at, display_name }
├── identity.key      (raw private key, chmod 600)
├── mesh.json         (mesh config)
├── authority.pub     (authority public key)
├── authority.key     (authority private key)
├── root.pub          (root public key)
├── node_registry.db   (SQLite: nodes, certificates, aliases, pending_enrollments)
├── peers.db          (SQLite: peer records)
├── audit.db          (SQLite: audit log)
├── contract.db       (SQLite: contract registry)
└── join_state.bin    (FSM state for resume)
```
**Source:** `core/mesh/mesh_manager.hpp:42-57` (MeshPaths struct), `core/identity/identity.hpp`.

### 4.3 Join Token v2 — Wire Format (SPEC.md §7.5.6)

```
SMO-JOIN-<base64url(CBOR_payload || HMAC_SHA256(CBOR_payload))>

CBOR Payload (integer-keyed map):
{
  1: version            uint        — currently 1
  2: mesh_id            bstr(16)    — Blake3 hash
  3: mesh_epoch         uint        — mesh epoch at creation
  4: cipher_suite_id    uint        — 0=Classical, 2=PurePQC
  5: bootstrap_endpoints [tstr]     — at least 1 endpoint
  6: role               tstr        — "Authority"/"Member"/"Contributor"/"Observer"
  7: expiry             uint        — Unix timestamp
  8: nonce              bstr(8-16)  — 128-bit random, alias for token_id
}
```
**Source:** `core/enroll/join_token.hpp:42-59` (JoinToken struct). SPEC.md §7.5.6:1108-1120.
**HMAC keyed with:** `hmac_secret` from mesh.json (32 random bytes generated at mesh creation).
**Contains:** Authorization proof only. NO certificate, NO private key.

### 4.4 Membership Certificate — `.smoc` (SPEC.md §VII.4)

```
MembershipCertificate {
    NodeID:           Blake3(NodePublicKey)           [32 bytes]
    NodePublicKey:    Ed25519 or ML-DSA public key    [varies by suite]
    MeshID:           Blake3(RootPK || time || random) [32 bytes]
    Role:             "AUTHORITY" | "CONTRIBUTOR" | "READER"
    Capabilities:     [CAP_FS_READ, CAP_HEARTBEAT, ...]  // expanded from Role
    Epoch:            uint64                          // Capability Epoch (§7.10)
    IssuedBy:         AuthorityID
    IssuedAt:         unix ms
    ExpiresAt:        unix ms (0 = never)
    Signature:        Authority's signature over all above fields
}
```
**Source:** SPEC.md §VII.4:808-821. Created by `authority::MeshAuthority::issue_certificate()` (`core/authority/authority.cpp`). Verified by `certificate::verify_chain()` (`core/certificate/certificate.cpp`).

### 4.5 Three-Tier Key Hierarchy (SPEC.md §7.8)

| Key | Purpose | Storage | Status |
|-----|---------|---------|--------|
| **Root Key** | Bootstrap, recovery, rotate Authorities | OFFLINE (encrypted recovery package, then deleted from filesystem) | ✅ Implemented in `cmd/smo-cli/main.cpp:600-620` |
| **Authority Key** | Daily ops: sign certs, grant capabilities, revoke | Online (`mesh_dir/authority.key`) | ✅ Created at `smo mesh create` |
| **Node Key** | Per-node identity, signing contracts | Online (`data_dir/identity.key`) | ✅ Created at `smo-node --init` |

**Capability Epoch** (SPEC.md §7.10): Incremented on Authority revocation or major capability change.
Old certificates (epoch < current) are rejected. **No CRL needed for basic revocation.**

### 4.6 Gossip Wire Format (GOSP)

```
[SMO Frame Header: 9B]
  magic:    0x534D4F (3B "SMO")
  flags:    0x01 (1B)  — GOSSIP type
  length:   4B LE
[GOSP Segment Header: 5B per delta type]
  magic:    0x474F5350 (4B "GOSP")
  segments: variable number of:
    delta_type:  uint8     — 0=Membership, 1=CRL, 2=Policy, 3=Manifest, 4=Routing, 5=Contracts
    payload_len: uint32 LE
    payload:     bytes[payload_len]
```
**Source:** `core/discovery/gossip.hpp:41-56` (DeltaType enum), `gossip.cpp:assemble_gossip_payload()`, `gossip.cpp:apply_gossip()`. DISCUSSION_0039 §8a.

### 4.7 Join FSM — Complete State Table (12 states, 13 events)

```
State Table (join_protocol.cpp:340-370):

Current State        Event               Next State
─────────────────────────────────────────────────────
NEW(0)               TOKEN_PARSED(100)   TOKEN_RECEIVED(1)
TOKEN_RECEIVED(1)    CSR_BUILT(101)      CSR_CREATED(2)
CSR_CREATED(2)       MSG_SENT(102)       JOIN_SENT(3)
JOIN_SENT(3)         RESPONSE_RCVD(103)  CERT_RECEIVED(5)
CERT_RECEIVED(5)     CERT_VERIFIED(104)  BOOTSTRAP_SYNC(7)
CERT_RECEIVED(5)     CERT_INVALID(105)   FAILED(-1)
CERT_VERIFY(6)       CERT_VERIFIED(104)  CERT_RECEIVED(5)
CERT_VERIFY(6)       FAIL(112)           FAILED(-1)
BOOTSTRAP_SYNC(7)    SYNC_REQUESTED(106) WAIT_SYNC(8)
WAIT_SYNC(8)         SYNC_COMPLETE(107)  GOSSIP_SYNC(9)
WAIT_SYNC(8)         FAIL(112)           FAILED(-1)
GOSSIP_SYNC(9)       GOSSIP_STARTED(108) WAIT_GOSSIP(10)
GOSSIP_SYNC(9)       FAIL(112)           FAILED(-1)
WAIT_GOSSIP(10)      GOSSIP_COMPLETE(109) READY(11)
WAIT_GOSSIP(10)      FAIL(112)           FAILED(-1)
WAIT_RESPONSE(4)     TIMEOUT(110)        FAILED(-1)    [30s timeout]
WAIT_SYNC(8)         TIMEOUT(110)        FAILED(-1)    [30s timeout]
WAIT_GOSSIP(10)      TIMEOUT(110)        FAILED(-1)    [60s timeout]
```
**Source:** `core/join/join_protocol.hpp:134-166` (enum definitions), `join_protocol.cpp:340-370` (transition table), `auto_enroll.cpp:700-750` (runtime FSM execution).

### 4.8 Core Data Structures

| Model | Header | Key Fields | Used By |
|-------|--------|------------|---------|
| `PeerRecord` | `core/discovery/discovery.hpp` | node_id, display_name, hostname, role, tags, endpoint, state (ONLINE/OFFLINE/SUSPECT), last_seen_ns, ping_misses, rtt_ms | MembershipTable, HealthMonitor, Selector |
| `MeshConfig` | `core/mesh/mesh_manager.hpp:24-40` | mesh_id, display_name, authority_pubkey, root_pubkey, hmac_secret, cipher_suite_id, epoch, listen/advertise/bootstrap | MeshManager, Genesis, CLI |
| `MeshContext` | `core/mesh/mesh_manager.hpp:42-57` | config, display_name, paths (mesh_dir, cert_path, identity_json, 9 DB paths) | All services |
| `JoinRequest` | `core/join/join_protocol.hpp:46-57` | version(1), token, csr_pem, timestamp, nonce[8], csr_hash, request_signature | Join protocol |
| `JoinResponse` | `core/join/join_protocol.hpp:67-78` | version(1), nonce[8], certificate_pem, mesh_id, manifest_digest, manifest_epoch, bootstrap_nodes[] | Join protocol |
| `BootstrapSyncRequest` | `core/join/join_protocol.hpp:89-103` | version(1), nonce[8], mesh_id, node_id, 4 epoch/version fields | Delta sync |
| `BootstrapSyncResponse` | `core/join/join_protocol.hpp:113-132` | version(1), nonce[8], 4 delta blobs, 4 epoch/version fields | Delta sync |
| `BootstrapSnapshot` | `core/bootstrap/bootstrap_snapshot.hpp:32-69` | schema_version, mesh_id, mesh_state, epoch, genesis_manifest_cbor, authorities[], seeds[], policy_version, governance_version, crl_digest, crl_count, health, cipher_suite, opcodes[], active_proposals | Bootstrap protocol |
| `JoinToken` | `core/enroll/join_token.hpp:42-59` | version, mesh_id, mesh_epoch, cipher_suite_id, bootstrap_endpoints[], admission (role+profile+slot), expiry, nonce, issuer, signature | Enrollment |
| `ContractDefinition` | `core/contract/contract_definition.hpp` | contract_version, category, opcode, name, semver, input_schema, output_schema, capability_mask, opcode_dependencies[], min/max_runtime_version | Contract registry |
| `Capability` | `core/capability/capability.h` | Bitmask: CAP_FS_READ(0x01), CAP_FS_WRITE(0x02), CAP_EXEC(0x04), CAP_GRANT(0x08), CAP_REVOKE(0x10), CAP_EPOCH_INCR(0x20), CAP_SIGN_NODE(0x40), CAP_QUARANTINE(0x80), etc. | Policy engine, certificate |

---

## 5. Lifecycle Flows (Complete)

### 5.1 Mesh Creation (Phase 8c — Fully Inline)

```
smo mesh create mymesh
  │
  ├─ Create ~/.smo/meshes/mymesh/                 [cmd/smo-cli/main.cpp:583]
  ├─ Generate HMAC secret (32 random bytes → hex)  [main.cpp:590-597]
  ├─ Derive mesh_id = Blake3(name + timestamp)      [main.cpp:582-588]
  ├─ Init MeshAuthority (register root + authority) [main.cpp:599-610]
  │     via authority.init(*crypto, rng)
  │     via authority.create_mesh_keys(cfg, *crypto, rng, root_pubkey)
  │     Source: core/authority/authority.hpp:create_mesh_keys()
  ├─ Write root.pub, authority.pub, authority.key, root.key
  ├─ Write mesh.json:                               [main.cpp:627-648]
  │     mesh_id, display_name, authority_pubkey, root_pubkey,
  │     hmac_secret, cipher_suite_id(3=PurePQC), epoch(1), created_at
  ├─ Set current mesh context
  └─ Print: "Created and switched to mesh: mymesh"
```

### 5.2 Publish (Bootstrap Configuration)

```
smo mesh publish --listen 0.0.0.0:7777 --ep node.example.com:7777
  │
  ├─ Check port availability (SO_REUSEADDR bind probe)  [core/network/port_check.hpp]
  ├─ Detect public IP (STUN/UDP echo)                    [core/network/public_ip.hpp]
  ├─ Detect NAT (compare private vs public)              [core/network/nat_detect.hpp]
  ├─ Resolve DNS if provided                             [core/network/dns.hpp]
  ├─ Enumerate local interfaces                          [core/network/interface.hpp]
  ├─ Update mesh.json: listen_address, advertise_addresses[], bootstrap_endpoints[]
  │     Source: MeshManager::publish_mesh() in core/mesh/mesh_manager.cpp
  └─ Mesh is now ONLINE
  NOTE: "Mesh is not ONLINE until bootstrap is configured." — SPEC.md §7.7
```

### 5.3 Invite (Token Generation)

```
smo mesh invite --role Worker --expire 1h --ep node.example.com:7777
  │
  ├─ Load mesh.json (MUST have bootstrap_endpoints, else error 214)
  ├─ Build CBOR payload:                                [join_token.hpp:42-59]
  │     {version:1, mesh_id, mesh_epoch, cipher_suite_id,
  │      bootstrap_endpoints, role, expiry, nonce(random)}
  ├─ Compute HMAC-SHA256 with hmac_secret from mesh.json
  ├─ Encode: "SMO-JOIN-" + base64url(payload + hmac)    [join_token.cpp]
  └─ Print token
```

### 5.4 Join (Zero-Touch Onboarding) — Full TCP/CBOR

```
smo mesh join --token SMO-JOIN-xxxxx
  │
  ├─ 1. Token decode + verification                      [auto_enroll.cpp:300-340]
  │     ├─ base64url decode → split payload|hmac
  │     ├─ Verify HMAC with mesh's hmac_secret
  │     │   (NB: requires mesh.json locally; for remote join,
  │     │    bootstrap endpoint validates)
  │     └─ Check expiry
  │
  ├─ 2. Identity initialization                          [auto_enroll.cpp:200-250]
  │     ├─ Generate NodeKey (Ed25519 or ML-DSA per suite)
  │     ├─ identity.json written to data_dir
  │     └─ NodeID = Blake3(pubkey)
  │
  ├─ 3. CSR construction                                 [auto_enroll.cpp:260-280]
  │     └─ Fields per SPEC.md §VII: NodeID, PubKey, MeshID, DisplayName,
  │        Platform, Version, Role → signed with NodePrivateKey
  │
  ├─ 4. JOIN_REQUEST (0x0601)                            [auto_enroll.cpp:340-360]
  │     ├─ TCP connect to bootstrap_endpoints[0]
  │     ├─ CBOR: {1:token, 2:csr, 3:timestamp(nonce), 4:nonce[8],
  │     │          5:csr_hash, 6:request_signature}
  │     │  Reference: join_protocol.cpp:58-72 (CBOR keys 1-6)
  │     └─ Signature: sign(1:token || 3:timestamp || 4:nonce || 5:csr_hash)
  │
  ├─ 5. Server processes JOIN_REQUEST                   [join_protocol.cpp:75-116]
  │     ├─ Verify timestamp within ±30s window
  │     ├─ Verify nonce not replayed (requires tracking — ⚠️ NOT IMPLEMENTED)
  │     ├─ Verify request_signature against token's nonce
  │     ├─ Validate token HMAC + expiry
  │     ├── Verify CSR signature (proves key possession)
  │     ├── Issue certificate signed by Authority key
  │     └── Return JOIN_RESPONSE (0x0602):              [join_protocol.cpp:119-170]
  │           {1:cert, 2:mesh_id, 3:mf_digest, 4:mf_epoch, 5:seeds, 6:nonce}
  │
  ├─ 6. Client receives JOIN_RESPONSE                   [auto_enroll.cpp:400-440]
  │     ├─ Verify certificate chain (Node→Authority→Root)
  │     ├─ Store certificate at data_dir/cert.smoc
  │     └─ Save bootstrap_nodes for later gossip
  │
  ├─ 7. BOOTSTRAP_SYNC (0x0603→0x0604)                 [auto_enroll.cpp:560-620]
  │     ├─ Send: {1:mesh_id, 2:node_id, 3:mf_epoch(0), 4:crl_epoch(0),
  │     │         5:member_epoch(0), 6:policy_ver(0)}
  │     ├─ Receive: {1-4:deltas, 5-8:current_epochs}
  │     └─ Apply deltas to local state
  │
  ├─ 8. Persist join_state.bin                          [auto_enroll.cpp:700-750]
  │     └─ Saves: current_state, node_id, mesh_id, token_data, bootstrap_nodes
  │
  └─ 9. Post-import summary
        NodeID: 7A9F... (64 hex)
        Certificate: C9D3... (fingerprint)
        Mesh: mymesh
        Role: Worker
        → Ready to start daemon
```

### 5.5 Daemon Start + Gossip Sync (Full Node READY)

```
smo-node --daemon --data /tmp/node1 --port 9121 --seed 127.0.0.1:5454
  │
  ├─ 1. Initialize all services                       [smo-node:1500-1650]
  │     ├─ register_suite1_classical() + register_suite3_purepqc()
  │     ├─ Identity::load_or_create()
  │     ├─ MeshManager::initialize()
  │     ├─ DiscoveryEngine (MembershipTable, HealthMonitor)
  │     ├─ GossipEngine (TCP fanout, typed deltas)
  │     ├─ MembershipSync (event bus → serialized events)
  │     ├─ SyncService (6-interval delta scheduler)
  │     ├─ CRL (certificate revocation list)
  │     ├─ ManifestStore (epoch-based manifest storage)
  │     ├─ PacketDispatcher (opcode routing: 0x0501→BootstrapContract,
  │     │    0x0601→JoinContract, GOSP→GossipEngine)
  │     ├─ RuntimeBridge (intent → kernel → execute)
  │     └─ ServiceRegistry + Telemetry
  │
  ├─ 2. Bootstrap (TCP)                                [smo-node:1650-1680]
  │     ├─ Connect to seed: send HELLO (NodeID, protocol_version, pubkey_fp)
  │     ├─ Receive WELCOME (seed's PeerRecord)
  │     ├─ Send DISCOVER → Receive NODE_INFO (full peer table)
  │     └─ Populate MembershipTable
  │
  ├─ 3. Resume join FSM                                [auto_enroll.cpp:700-750]
  │     ├─ Load join_state.bin (current_state=WAIT_SYNC(8) or later)
  │     ├─ FSM tick loop:
  │     │   WAIT_SYNC(8) → fire SYNC_COMPLETE → GOSSIP_SYNC(9)
  │     │   GOSSIP_SYNC(9) → fire GOSSIP_STARTED → WAIT_GOSSIP(10)
  │     │   [GossipEngine sends first fanout]
  │     │   WAIT_GOSSIP(10) → fire GOSSIP_COMPLETE → READY(11)
  │     └─ Node is READY
  │
  ├─ 4. Main loop (<1ms per iteration)                 [smo-node:1700-1750]
  │     ├─ poll(UDP_fd, TCP_fds, timer_fd, timeout=50ms)
  │     ├─ UDP: datagram → dispatch_discovery_datagram()
  │     │     magic(0x44) + type → HELLO/WELCOME/PING/PONG handler
  │     ├─ TCP: incoming → PacketDispatcher::dispatch_session()
  │     │     opcode → BootstrapContract / JoinContract / GossipEngine
  │     ├─ SyncService::tick(now):
  │     │     routing_delta(15s) → policy_delta(60s) → crl_delta(300s) →
  │     │     manifest_delta(on change) → contracts_delta(on change) →
  │     │     membership_delta(30s) → gossip.tick()
  │     └─ HealthMonitor::tick(): PING timeout → SUSPECT → CONFIRMED DEAD
  │
  └─ 5. Node is READY(11)
        Accepting intents, gossiping deltas, syncing state
```

---

## 6. Pre-Freeze Protocol Fixes (6 Items)

These MUST be resolved before the protocol is frozen for v1.0.

### F1: manifest_epoch vs policy_version — Clarify Object Model

**Problem:** The wire format has both `manifest_epoch` and `policy_version` as separate fields (`BootstrapSyncRequest` keys 3 & 6, `join_protocol.cpp:41-44`), but SPEC.md doesn't clarify whether policy is inside or outside the manifest.

**Ambiguity:** If policy *is* inside the manifest, then `policy_version` is redundant — `manifest_epoch` suffices. If policy is independent, then `policy_version` should be renamed `policy_epoch` for consistency.

**Source references:**
- `core/join/join_protocol.cpp:41-44` — `K_SYNC_REQ_MF_EPOCH=3, K_SYNC_REQ_POLICY_VER=6` — mixed naming
- `core/join/join_protocol.cpp:47-54` — `K_SYNC_RESP_MF_EPOCH=5, K_SYNC_RESP_POLICY_VER=8` — mixed naming
- `BootstrapSnapshot` (`bootstrap_snapshot.hpp:46-47`) — has both `policy_version` and `governance_version`
- SPEC.md §VII.3 — Manifest contains: mesh_id, genesis info, CRL anchor, governance rules, bootstrap slots
- SPEC.md §X (Capability System) — Policy is evaluated independently of manifest

**❓ Question:** Is policy a first-class object (like CRL) or a section within the manifest? If within manifest, remove `policy_version`. If independent, rename to `policy_epoch`.

### F2: JOIN_REQUEST Needs protocol_version + capabilities

**Problem:** `JoinRequest` currently has only `version = 1` (hardcoded) and no protocol version fields (`join_protocol.hpp:46-57`). This makes future protocol evolution impossible — a v2 node can't tell if the other end speaks v1 or v3.

**Current fields:** token, csr_pem, timestamp, nonce, csr_hash, request_signature

**Proposed addition:**
```cpp
uint8_t  protocol_version = 1;    // JOIN protocol version
uint8_t  client_version_major = 0; // smo-node major version
uint8_t  client_version_minor = 1; // smo-node minor version
uint32_t capabilities_mask = 0;    // supported features bitmask
```

**CBOR key assignments (extending current keys 1-6):**
```
K_REQ_PROTOCOL_VERSION = 7    // uint — protocol version
K_REQ_CLIENT_VERSION   = 8    // string — "0.1.0"
K_REQ_CAPABILITIES     = 9    // uint — bitmask
```

**Source references:**
- SPEC.md:709 — "Session: Capability negotiation" — mentioned but not implemented
- HELLO message (SPEC.md:2121) — has `protocol_version` but JOIN_REQUEST doesn't
- DISCUSSION_0039 §5.17 — JOIN_REQUEST replay protection, no mention of versioning

### F3: Capability Negotiation Needs required/optional

**Problem:** SPEC.md:709 references capability negotiation, and the `DeltaType` enum (`gossip.hpp:41-56`) defines 6 fixed types, but there's no mechanism to negotiate which capabilities a peer supports.

**Proposed protocol extension:**
Add to JOIN_RESPONSE and BOOTSTRAP_SYNC_RESPONSE:
```cpp
uint32_t supported_features = 0;   // bitmask of supported features
// Bit assignments:
// 0x01 = delta_sync (all 6 types)
// 0x02 = compression (zstd payload)
// 0x04 = crt (contract runtime)
// 0x08 = contract_sync
```

Add `required`/`optional` semantic:
```
Joining node sends capabilities_mask (bits 0-31)
Responding node echoes back its capabilities_mask
If required bit not echoed → protocol mismatch → ABORT
If optional bit not echoed → degrade gracefully
```

**❓ Question:** What is the minimum supported features set for 0.0.1? All bits 0 (delta_sync only)?

### F4: Add ABORTED State to Join FSM

**Problem:** Join FSM has only `FAILED = -1` (`join_protocol.hpp:146`). Several error conditions are non-retryable and semantically different:

| Condition | Current | Should Be |
|-----------|---------|-----------|
| Token expired | → FAILED | → ABORTED (no retry possible) |
| Protocol mismatch | → FAILED | → ABORTED (can't negotiate) |
| Invalid HMAC | → FAILED | → ABORTED (token wrong) |
| Unreachable endpoint | → FAILED | → ABORTED (wrong address) |
| CSR verification fail | → FAILED | → FAILED (could retry with new CSR) |
| Network timeout (30s) | → FAILED | → FAILED (could retry) |
| CERT_INVALID | → FAILED | → FAILED (could re-join) |

**Proposed addition to `join_protocol.hpp:134-166`:**
```cpp
ABORTED = -2,  // Non-retryable terminal state
```

**Source references:**
- `auto_enroll.cpp:718-726` — current transition logic
- `join_protocol.cpp:340-370` — transition table (all → FAILED)
- `join_protocol.hpp:146` — `FAILED = -1` is the only terminal state

### F5: Add server_time to JOIN_RESPONSE + BOOTSTRAP_RESPONSE

**Problem:** Neither `JoinResponse` nor `BootstrapSyncResponse`/`BootstrapResponse`/`BootstrapSnapshot` carries a server timestamp. The client has no reference clock and must rely entirely on its local clock for:

- Certificate expiry validation (needs server's "now")
- Epoch drift detection (is the server ahead/behind?)
- Token expiry alignment (5-minute grace period?)

**Current fields:** `JoinResponse` has `nonce`, `certificate_pem`, `mesh_id`, `manifest_digest`, `manifest_epoch`, `bootstrap_nodes` — NO timestamp (`join_protocol.hpp:67-78`)
`BootstrapSnapshot` has `schema_version`, `mesh_id`, `mesh_state`, `epoch` — NO timestamp (`bootstrap_snapshot.hpp:32-69`)

**Proposed addition:**
```cpp
int64_t server_time = 0;  // UNIX ms — server's current clock
```
CBOR key:
```
K_RESP_SERVER_TIME = 7    // extend JoinResponse to 7 keys
K_SNAP_SERVER_TIME = 9    // extend BootstrapSnapshot
```

**❓ Question:** Should certificate `IssuedAt`/`ExpiresAt` already provide enough clock reference? The server_time is needed for the *drift check*, not for certificate validity per se.

### F6: Add Region/Hint to Seed Endpoints

**Problem:** `JoinResponse::bootstrap_nodes` is `std::vector<std::string>` — just host:port strings (`join_protocol.hpp:74`). `BootstrapSnapshot::seeds` is also `std::vector<std::string>`. Large meshes spanning multiple regions need geographic-aware seed selection.

**Current format:** `["seed1.example.com:7777", "seed2.example.com:7777"]`

**Proposed extension to `join_protocol.hpp` and `bootstrap_snapshot.hpp`:**
```cpp
struct SeedInfo {
    std::string endpoint;        // "host:port"
    std::string region;          // "us-east-1", "ap-southeast-1"
    uint32_t    priority = 0;    // 0=highest
    uint32_t    latency_hint_ms = 0;  // expected RTT (from Authority's perspective)
};
```
Replace `std::vector<std::string> bootstrap_nodes` with `std::vector<SeedInfo> bootstrap_nodes`.

**Source references:**
- DISCUSSION_0039 §5.11 — Seed priority fallback: "seed1 → fail → seed2 → fail → seed3 → fail → error"
- SPEC.md §XII.5 — Bootstrap seed priority: "Seed priority fallback: seed1 → fail → seed2"
- No region/latency fields exist in any struct today

---

## 7. Open Questions (Need Discussion)

These are areas where the spec or implementation is ambiguous:

### Q1: Is Policy Inside Manifest or Independent?

**Evidence for "inside":** `SPEC.md §VII.3` describes manifest as containing: mesh_id, genesis info, CRL anchor, governance rules, bootstrap slots. Policies could be part of governance rules.

**Evidence for "independent":** `BootstrapSyncRequest` has separate `policy_version` (key 6) and `manifest_epoch` (key 3) (`join_protocol.cpp:41-44`). The SyncSchedule also treats policy_delta as a separate channel (`sync_service.hpp:28`).

**Impact on F1:** If inside → remove `policy_version` from wire. If independent → rename to `policy_epoch`.

### Q2: What Is the Minimum Capability Set for 0.0.1?

The `DeltaType` enum defines 6 types + `GossipEngine::set_delta_handler()`. For 0.0.1:
- CRL delta: ✅ working (`recovery/crl.hpp`)
- Manifest delta: ✅ working (`storage/manifest_store.hpp`)
- Membership delta: ✅ working (`sync/membership_sync.hpp`)
- Policy delta: ⚠️ stub (policy_store not built)
- Routing delta: ⚠️ stub
- Contracts delta: ⚠️ stub

**Question:** Ship 0.0.1 with 3/6 working deltas and 3 stubs, or hold until all 6 are implemented?

### Q3: How Does Token Work Without Local mesh.json?

`smo mesh join --token` currently requires the user to have previously run `smo mesh create` (which creates mesh.json with hmac_secret). But the intended UX for a brand-new node is:
```
# New node, never seen this mesh:
smo mesh join --token SMO-JOIN-xxxxx
```

The token itself carries: mesh_id, mesh_epoch, cipher_suite_id, bootstrap_endpoints. But HMAC verification requires `hmac_secret` from mesh.json.

**Options:**
1. Bootstrap endpoint verifies the token (current approach — token is a "proof of authorization")
2. Token carries its own verification material (breaks the "no private key in token" invariant)
3. Two-phase join: Phase 1 = get mesh.json from bootstrap, Phase 2 = verify token locally

**Current reality:** `auto_enroll.cpp:300-340` tries to verify the token locally but falls back to server-side verification if mesh.json isn't found.

**❓ Need to clarify:** Is token verification done by the Authority (server-side) or by the joining node (client-side)? The answer affects whether we need `hmac_secret` in the JOIN_REQUEST or rely entirely on the server.

### Q4: Should BootstrapSyncRequest Include a Nonce?

`BootstrapSyncRequest` has `nonce` in the struct (`join_protocol.hpp:91`) but the CBOR keys (1-6) don't include nonce (`join_protocol.cpp:38-44`). Compare:
- JoinRequest: nonce = key 4, used in request_signature
- BootstrapSyncRequest: nonce declared but NOT serialized!

**Fix:** Either remove nonce from BootstrapSyncRequest, or add key 7 for nonce in the CBOR encoding.

### Q5: What Happens to HTTP enroll_server in smo-admin?

`smo-admin serve --port` starts an HTTP server (`core/authority/enroll_server.hpp`). But the entire control plane has moved to TCP/CBOR. Is this HTTP server:
- (a) Legacy backward compat — remove for 0.0.1?
- (b) Alternative enrollment for cloud/enterprise (SPEC.md §7.5.1 — future)?
- (c) Internal admin UI?

### Q6: JoinState Enum Values Are Scattered

`JoinState` enum (`join_protocol.hpp:134-147`) has non-contiguous values:
```
NEW=0, TOKEN_RECEIVED=1, CSR_CREATED=2, JOIN_SENT=3,
WAIT_RESPONSE=4, CERT_RECEIVED=5, CERT_VERIFY=6,
BOOTSTRAP_SYNC=7, WAIT_SYNC=8, GOSSIP_SYNC=9,
WAIT_GOSSIP=10, READY=11, FAILED=-1
```

Note `CERT_VERIFY=6` comes AFTER `CERT_RECEIVED=5` in the value assignment but BEFORE it in the actual FSM flow. The actual flow is:
```
JOIN_SENT(3)→WAIT_RESPONSE(4)→CERT_RECEIVED(5)→CERT_VERIFY(6)→
BOOTSTRAP_SYNC(7)...
```

So `CERT_RECEIVED(5) → CERT_VERIFY(6) → CERT_RECEIVED(5?)` — the transition table shows:
```
CERT_RECEIVED(5) + CERT_VERIFIED → BOOTSTRAP_SYNC(7)
CERT_VERIFY(6)   + CERT_VERIFIED → CERT_RECEIVED(5)
```

This means `CERT_VERIFY` is actually a *sub-state* looped back to `CERT_RECEIVED`. This is confusing. The values don't match the flow order.

**❓ Question:** Should the enum be reordered to match the actual flow? Or is the loop intentional (CERT_VERIFY → re-verify → CERT_RECEIVED as retry)?

### Q7: SyncService tick Order — Why Routing First?

`SyncService::tick()` fires in order: `routing → policy → crl → manifest → contracts → membership → gossip.tick()`. Why is `routing(15s)` first and `membership(30s)` last? Shouldn't membership (which determines who you know) come before routing (which determines how to reach them)?

---

## 8. Release 0.0.1 Checklist

### 8.1 Critical (Must-Fix Before 0.0.1)

| # | Item | Area | Effort | Source Ref |
|---|------|------|--------|------------|
| **R1** | E2E smoke test: create → publish → invite → join → daemon | Integration | 2d | `cmd/smo-cli/main.cpp:583-655`, `auto_enroll.cpp:280-750` |
| **R2** | Fix `governance_model` test: `to_string(PolicyChange)` returns wrong string | Governance | 0.5d | `test_governance.cpp:91` |
| **R3** | Fix `governance_model` test: invalid level assertion | Governance | 0.5d | `test_governance.cpp:221` |
| **R4** | Fix `contract_model` test: `contract_version != "1.0"` (minimal version parse) | Contract | 0.5d | `test_contract.cpp:120` |
| **R5** | Fix `core` / `protocol` / `compiler` test executables (Not Run) | Build/Test | 1d | `tests/unit/core_test.cpp`, `protocol_test.cpp`, `compiler_test.cpp` |
| **R6** | Daemon-side gossip readiness: GOSSIP_SYNC wait for actual networked send/receive | Enroll | 1d | `auto_enroll.cpp:718-726`, DISCUSSION_0039 §8b gap 3 |
| **R7** | Fix `SqliteStore` API mismatch → uncomment `add_subdirectory(policy_store)` | Storage/Policy | 1d | `storage/CMakeLists.txt`, DISCUSSION_0039 |

### 8.2 Protocol Fixes (F1-F6 — Must Freeze Before Release)

| # | Item | Area | Effort | Source Ref |
|---|------|------|--------|------------|
| **F1** | Clarify manifest_epoch vs policy_version (epoch vs version semantics) | Protocol Design | 0.5d | `join_protocol.cpp:41-44`, `bootstrap_snapshot.hpp:46-47`, SPEC.md §VII.3 |
| **F2** | Add protocol_version + capabilities to JOIN_REQUEST | Protocol | 0.5d | `join_protocol.hpp:46-57`, SPEC.md:709 |
| **F3** | Add required/optional capability negotiation | Protocol | 0.5d | `gossip.hpp:41-56`, SPEC.md:709, HELLO message |
| **F4** | Add ABORTED state to Join FSM (non-retryable terminal) | FSM | 0.5d | `join_protocol.hpp:146`, `auto_enroll.cpp:718-726` |
| **F5** | Add server_time to JOIN_RESPONSE + BOOTSTRAP_RESPONSE | Protocol | 0.5d | `join_protocol.hpp:67-78`, `bootstrap_snapshot.hpp:32-69` |
| **F6** | Add region/priority/latency_hint to seed endpoints | Protocol | 1d | `join_protocol.hpp:74`, `bootstrap_snapshot.hpp:43` |

### 8.3 Important (Quality-of-Release)

| # | Item | Area | Effort |
|---|------|------|--------|
| **R8** | Add `--version` flag to all 4 binaries | CLI | 0.5d |
| **R9** | Add `--help` consistency across all binaries | CLI | 0.5d |
| **R10** | Add TCP connect timeout to GossipEngine (currently blocking) | Gossip | 0.5d |
| **R11** | Add retry logic in `send_gossip_to_peer()` | Gossip | 0.5d |
| **R12** | Persist manifest_epoch after BOOTSTRAP_SYNC | Join | 0.5d |
| **R13** | Add nonce uniqueness tracking for JOIN_REQUEST (anti-replay) | Join | 0.5d |
| **R14** | Makefile/man pages for all binaries | Docs | 1d |

### 8.4 Effort Summary

| Category | Items | Est. Effort |
|----------|-------|-------------|
| Critical (R1-R7) | 7 | 6.5d |
| Protocol Fixes (F1-F6) | 6 | 3.5d |
| Important (R8-R14) | 7 | 4d |
| **Total for 0.0.1** | **20** | **~14d (3 weeks)** |

---

## 9. Protocol Compliance Test (Recommendation)

**This is the single most important recommendation.**

After fixing F1-F6, do NOT add features. Write a **Protocol Compliance Test** suite:

### Mandatory Tests (Protocol Conformance)

```
PCT-001: JOIN_REQUEST encode/decode roundtrip
PCT-002: JOIN_RESPONSE encode/decode roundtrip (with all optional fields)
PCT-003: BOOTSTRAP_SYNC_REQUEST encode/decode roundtrip
PCT-004: BOOTSTRAP_SYNC_RESPONSE encode/decode roundtrip
PCT-005: Join FSM — full flow NEW → READY
PCT-006: Join FSM — every FAIL transition (6 paths)
PCT-007: Join FSM — every TIMEOUT transition (3 paths)
PCT-008: Join FSM — persist + resume (WAIT_SYNC → daemon restart → READY)
PCT-009: Bootstrap handshake (HELLO → WELCOME → DISCOVER → NODE_INFO)
PCT-010: Gossip payload assemble + send + receive + dispatch (all 6 delta types)
PCT-011: Token HMAC verification (valid + tampered + expired)
PCT-012: Certificate chain verification (Node → Authority → Root)
PCT-013: Nonce replay detection (same nonce rejected within TTL)
PCT-014: Timestamp ±30s window (past/future rejection)
PCT-015: Epoch-based delta sync (request changes → receive only new data)
PCT-016: CRL delta — entries_since() roundtrip
PCT-017: CBOR map key forward compat (unknown keys ignored, not error)
```

### Recommended Structure

```
tests/protocol/
├── compliance/
│   ├── test_pct_001_join_request_roundtrip.cpp
│   ├── test_pct_002_join_response_roundtrip.cpp
│   ├── ...
│   └── test_pct_017_cbor_forward_compat.cpp
├── fixtures/
│   ├── valid_token.txt
│   ├── expired_token.txt
│   ├── tampered_token.txt
│   ├── valid_csr.pem
│   └── valid_cert.smoc
└── CMakeLists.txt
```

### Why This Matters

Distributed systems die from protocol drift:
```
Node A (v0.1.0)  →  sends JOIN_REQUEST with 6 fields
Node B (v0.2.0)  →  expects 9 fields (added protocol_version, capabilities, nonce_version)
                   →  decode failure → ABORTED
                   →  mesh split
```

A Protocol Compliance Test run at CI prevents this. Every commit runs all 17 PCTs. If a PCT fails, the commit is rejected.

---

## 10. Sprint Plan — 37.5 Stabilization

| Week | Day | Focus | Items |
|------|-----|-------|-------|
| **1** | Mon | Protocol freeze design | F1 (epoch vs version), F3 (cap negotiation) — spec decisions |
| | Tue | Protocol freeze code | F2 (JOIN_REQUEST version), F5 (server_time), F6 (seed region) |
| | Wed | FSM fix | F4 (ABORTED state), Q4 (BootstrapSync nonce), Q6 (state enum order) |
| | Thu | Test fixes | R2 (governance to_string), R3 (governance level), R4 (contract version), R5 (missing bins) |
| | Fri | Network hardening | R10 (TCP timeout), R11 (retry), R12 (manifest_epoch persist), R13 (nonce dedup) |
| **2** | Mon | Build fix | R7 (policy_store cmake), R8 (--version), R9 (--help) |
| | Tue | E2E infrastructure | R1 (smoke test script) — write full lifecycle bash test |
| | Wed | E2E run + debug | Run full lifecycle, fix failures |
| | Thu | Gossip readiness | R6 (daemon-side FSM waits for actual network I/O) |
| | Fri | PCT suite | Write PCT-001 through PCT-008 (first 8 compliance tests) |
| **3** | Mon | PCT suite | Write PCT-009 through PCT-017 |
| | Tue | PCT CI integration | Add PCT target to CMake, run in CI |
| | Wed | Final review | Architecture review sign-off, protocol freeze declaration |
| | Thu | Docs + tagging | Write CHANGELOG, tag v0.0.1, create GitHub release |
| | Fri | Buffer | Fix anything that broke during the week |

---

## 11. Known Limitations in 0.0.1

| Limitation | Impact | Workaround |
|------------|--------|------------|
| Single Authority only | No HA for enrollment | Manual failover (restart with backup key) |
| No WASM | Only native contracts | Write contracts in C++ (6 exist: echo, bootstrap, join, governance, recovery, file) |
| No Compiler pipeline | No custom contract definitions | Use native contracts only |
| No Audit history queries | No forensics | Direct SQLite access to audit.db |
| Gossip readiness stubbed | FSM may report READY before actual gossip (auto_enroll.cpp:718) | Acceptable for single-node/LAN; production fix in R6 |
| No NAT punch for discovery | Only works on same subnet/LAN | Use bootstrap TCP for cross-network (works across NAT) |
| `policy_store` not built | Policy delta stub only (sync_service.cpp) | CRL + manifest deltas work; policy is optional for MVP |
| HTTP enroll server in smo-admin | Mixed transport | Use Join Token TCP path instead of HTTP (SPEC.md §7.5.6) |
| No nonce dedup in production | JOIN_REQUEST replay possible within TTL | Acceptable for MVP; fix in R13 |
| No protocol_version on wire | v0.2.0 won't be backward compatible | Fix in F2 before it's too late |

---

## 12. Directory Map (Complete Source Tree)

```
smoframework/
├── SPEC.md                          # Master specification (2744 lines)
├── ARCHITECTURE_SUMMARY.md          # Vietnamese architecture summary
├── ARCHITECTURE.md                  # Architecture diagrams
├── IMPLEMENT.md                     # Implementation notes
├── CMakeLists.txt                   # Root build file
│
├── core/                            # Core library (all domain logic)
│   ├── acl/                         # Policy engine (core/acl/policy_engine.hpp)
│   ├── authority/                   # Mesh authority, enroll server, registry
│   ├── bootstrap/                   # Bootstrap protocol, CBOR, snapshot
│   ├── capability/                  # Capability definitions (capability.h)
│   ├── certificate/                 # Certificate PEM, verification
│   ├── contract/                    # Contract ABI, definitions, registry, native/
│   ├── crypto/                      # Crypto suites, providers, hash, KEM, AEAD
│   ├── discovery/                   # Discovery engine, gossip engine, peer store
│   ├── enroll/                      # Auto-enrollment (811 lines), join token
│   ├── errors/                      # Error model, codes (error.hpp, error_codes.md)
│   ├── fsm/                         # FSM framework, node lifecycle FSM
│   ├── genesis/                     # Genesis block, manifest, bootstrap slots, recovery
│   ├── governance/                  # Governance engine
│   ├── identity/                    # Node identity (NodeID = Blake3(PubKey))
│   ├── intent/                      # Intent data structures
│   ├── join/                        # Join protocol (0x0601-0x0604), join service
│   ├── mesh/                        # Mesh manager, mesh FSM, resolver
│   ├── network/                     # Network interfaces, DNS, NAT, packet dispatcher
│   │   ├── sync/                    # SyncService, MembershipSync
│   │   ├── tcp/                     # TCP connector, listener, session
│   │   ├── udp/                     # UDP transport, heartbeat, discovery, gossip
│   │   ├── transport/               # Address resolver, dispatcher, selector
│   │   └── bootstrap/              # Peer cache, seed resolver
│   ├── opcode/                      # Opcode definitions, registry
│   ├── recovery/                    # Recovery engine, CRL
│   ├── runtime/                     # Runtime kernel (41 files)
│   │   ├── contracts/               # 6 native contracts
│   │   └── services/               # Service registry
│   ├── select/                      # Selector, query parser
│   ├── session/                     # Session management
│   ├── state/                       # State data structures
│   ├── storage/                     # SQLite store, manifest store, audit store
│   ├── transport/                   # Transport layer, TCP, framing, secure session
│   └── trust/                       # Trust evaluation engine (4-component)
│
├── cmd/                             # CLI binaries
│   ├── smo/                         # Top-level alias (delegates to smo-cli)
│   ├── smo-cli/                     # Interactive CLI shell (1267 lines)
│   ├── smo-admin/                   # Administration CLI (1071 lines)
│   ├── smo-node/                    # Node daemon (1814 lines)
│   └── smo-debug/                   # Debug tool (~200 lines)
│
├── providers/                       # Crypto provider implementations
│   ├── suite1_classical/            # Ed25519+X25519+XChaCha20+Blake3
│   └── suite3_purepqc/             # ML-DSA+ML-KEM
│
├── tests/                           # Tests
│   ├── unit/                        # Unit tests (core, protocol, compiler + subdirs)
│   ├── integration/                 # Integration tests (empty)
│   ├── mesh/                        # Mesh tests (empty)
│   ├── chaos/                       # Chaos tests (empty)
│   ├── adversarial/                 # Adversarial tests (empty)
│   └── replay/                      # Replay tests (empty)
│
├── RFC/                             # 35 RFC documents
├── docs/discussions/                # 40 discussion documents
├── third_party/                     # Third-party dependencies
├── tooling/                         # Clipboard provider, etc.
├── cmake/                           # CMake modules
├── deployments/                     # Deployment scripts
├── examples/                        # Examples
└── build/                           # Build output
```

---

## 13. Error Codes Reference (Defined in `core/errors/error_codes.md`)

| Code | Name | Category | Description | Source |
|------|------|----------|-------------|--------|
| 212 | INVALID_TOKEN | Protocol | Join Token HMAC mismatch | SPEC.md §7.5.6 |
| 213 | TOKEN_EXPIRED | Protocol | Join Token past expiry | SPEC.md §7.5.6 |
| 214 | BOOTSTRAP_NOT_CONFIGURED | Protocol | No bootstrap endpoints published | SPEC.md §7.7 |
| 215 | TOKEN_REJECTED | Protocol | Authority explicitly rejected token | SPEC.md §7.8 |
| 216 | VERIFY_FAILED | Certificate | Certificate chain verification failed | SPEC.md §7.8 |
| 217 | MESH_NOT_FOUND | Mesh | Mesh ID not found in registry | SPEC.md §7.8 |
| 223 | BOOTSTRAP_NOT_CONFIGURED | Bootstrap | Daemon start without mesh publish | SPEC.md §7.7 |
| 224 | PORT_UNAVAILABLE | Network | Port bind probe failed in publish wizard | SPEC.md §7.7 |
| 225 | NO_PUBLIC_IP | Network | Cannot detect public IP for advertise | SPEC.md §7.7 |
| 450 | EMPTY_SELECTION | Discovery | Select query has no filters | SPEC.md §XI.2 |
| 451 | NO_NODES | Discovery | No nodes match selection criteria | SPEC.md §XI.2 |

---

## 14. Crypto Suite IDs

| ID | Name | Algorithms | Source |
|----|------|------------|--------|
| `0x0000` | Suite1 Classical | Ed25519 + X25519 + XChaCha20-Poly1305 + Blake3 + HKDF | `providers/suite1_classical/`, RFC 0009 |
| `0x0001` | Suite2 Reserved | Reserved | — |
| `0x0002` | Suite3 PurePQC | ML-DSA (FIPS 204) + ML-KEM (FIPS 203) + XChaCha20-Poly1305 + Blake3 + HKDF | `providers/suite3_purepqc/`, RFC 0009 |
| `0x0003` | Suite4 Hybrid | Classical + PQC combined | Future |

**Default for new meshes:** Suite3 PurePQC (`0x0002`), set in `cmd/smo-cli/main.cpp:606`.

---

## Appendix: Cross-Reference Index

| Topic | SPEC.md | RFC | Discussion Doc | Source File |
|-------|---------|-----|----------------|-------------|
| Join Token | §7.5.6:1108-1120 | RFC 0007 §3 | DISCUSSION_0036 | `core/enroll/join_token.hpp:42-59` |
| JOIN_REQUEST | §7.8:1356-1384 | RFC 0007 §4 | DISCUSSION_0039 §5.17 | `core/join/join_protocol.hpp:46-57` |
| JOIN_RESPONSE | §7.8:1357 | RFC 0007 §4 | DISCUSSION_0039 §5.1 | `core/join/join_protocol.hpp:67-78` |
| Bootstrap | §V.3:509-606 | RFC 0034 | DISCUSSION_0039 §5.2-5.4 | `core/bootstrap/bootstrap_protocol.hpp` |
| BootstrapSync | §7.8:1367 | — | DISCUSSION_0039 §5.4 | `core/join/join_protocol.hpp:89-132` |
| Discovery | §XII:2072 | RFC 0015 | DISCUSSION_0039 §5.20 | `core/discovery/discovery.hpp` |
| Gossip | — | — | DISCUSSION_0039 §7, §8a | `core/discovery/gossip.hpp:39-105` |
| SyncService | — | — | DISCUSSION_0039 §5.19 | `core/network/sync/sync_service.hpp:24-56` |
| Mesh Manager | §VII:715 | RFC 0031 | — | `core/mesh/mesh_manager.hpp` |
| Join FSM | §5.21 | — | DISCUSSION_0039 §5.21 | `core/join/join_protocol.hpp:134-166` |
| Capability Epoch | §7.10:1486 | — | — | `core/capability/capability.h` |
| Three-tier PKI | §7.8:1387-1418 | RFC 0006 | DISCUSSION_0035 | `core/authority/authority.hpp` |
| Runtime Kernel | §IX:1812 | RFC 0035 | — | `core/runtime/runtime_kernel.hpp` |
| Contract System | §VIII:1645 | RFC 0025 | — | `core/contract/contract_definition.hpp` |
| Opcode Registry | §V.4:608-648 | RFC 0020 | — | `core/opcode/opcode_registry.hpp` |
| Error Model | §V:400 | RFC 0008 | — | `core/errors/error.hpp` |
| Crypto Provider | §XVI | RFC 0009 | — | `core/crypto/suite.hpp`, `registry.hpp` |
| Storage | §XV | RFC 0010 | — | `core/storage/sqlite_store.hpp` |
| CLI Context | — | RFC 0032 | DISCUSSION_0034 | `cmd/smo-cli/main.cpp`, `cli_context.hpp` |
| Enrollment Transport | §7.5:1003-1230 | RFC 0007 | — | `core/enroll/auto_enroll.cpp` |
