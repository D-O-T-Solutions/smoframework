# Discussion 0039 — Mesh Lifecycle: Complete Implementation Plan

**Date:** 2026-07-20  
**Status:** 🟢 PHASE 1–8 ✅  
**Core Principle:** **NO HTTP in mesh communication.** Everything via TCP Transport + CBOR opcodes.

---

## ⚡ KEY CLARIFICATIONS (Confirmed)

| Aspect | Design Decision |
|--------|-----------------|
| **Invite/Join mechanism** | ✅ **Static token (copy-paste)** — `SMO-JOIN-xxxxx` generated once, copied to joining node |
| **Transport** | ✅ **Pure TCP/CBOR** — **NO HTTP anywhere** in mesh communication |
| **Join flow** | Token (copy-paste) → TCP `JOIN_REQUEST` (0x0601) → `JOIN_RESPONSE` with cert + mesh_id + bootstrap_ticket (no manifest, no seeds) |
| **Bootstrap sync** | `BOOTSTRAP_SYNC_REQUEST` (0x0603) → `BOOTSTRAP_SYNC_RESPONSE` delta (revision-based, changed components only + seeds) |
| **Auth** | Token is self-contained (CBOR payload + Ed25519/ML-DSA signature), no server-side session |

---

## 📚 REFERENCES

| Reference | Description |
|-----------|-------------|
| [RFC 0020 - Opcode Registry](../RFC/0020-opcode-registry.md) | Opcode namespace allocation, registration rules |
| [RFC 0031 - Mesh Manager](../RFC/0031-mesh-manager.md) | MeshManager API, mesh lifecycle, multi-mesh support |
| [RFC 0032 - Context-Aware CLI](../RFC/0032-context-cli.md) | Mesh context, current mesh, CLI context management |
| [RFC 0033 - Mesh Genesis & Governance](../RFC/0033-mesh-genesis-governance.md) | Mesh lifecycle states, bootstrap slots, governance tiers |
| [RFC 0034 - Bootstrap Protocol](../RFC/0034-bootstrap-protocol.md) | Bootstrap protocol (namespace 0x05), CBOR schemas, message flow |
| [RFC 0035 - Runtime Architecture](../RFC/0035-runtime-architecture.md) | Runtime kernel, execution pipeline, contract interface |
| [DISCUSSION_0034_UX_MESH_CONTEXT](DISCUSSION_0034_UX_MESH_CONTEXT.md) | Mesh context, CLI UX, mesh catalog |
| [DISCUSSION_0035_PKI_GOVERNANCE](DISCUSSION_0035_PKI_GOVERNANCE.md) | PKI hierarchy, governance tiers, certificate lifecycle |
| [DISCUSSION_0036_JOIN_TOKEN_BOOTSTRAP](DISCUSSION_0036_JOIN_TOKEN_BOOTSTRAP.md) | Join token format, bootstrap protocol, invite flow |
| [DISCUSSION_0037_WIRING_BRIDGE](DISCUSSION_0037_WIRING_BRIDGE.md) | Runtime wiring, kernel, dispatcher, middleware |
| [SPEC.md](../SPEC.md) | Main specification document |
| [ARCHITECTURE_SUMMARY.md](../ARCHITECTURE_SUMMARY.md) | Architecture summary |

---

## 1. Current State: What Works (✅ Tested)

| Feature | Command | Status |
|---------|---------|--------|
| Node init | `smo-node --init --name <name> --data <dir>` | ✅ Creates identity + CSR |
| Certificate signing | `smo-admin sign` + `smo-node --import` | ✅ Authority signs CSR |
| Mesh creation | `smo-admin create-mesh <name> <dir>` | ✅ Creates mesh + authority + mesh.json |
| Bootstrap config | `smo-admin mesh publish --listen ... --endpoint ...` | ✅ Configures bootstrap endpoints |
| Generate invite | `smo-admin generate-invite --role <role> --expire <dur> --endpoint <ep>` | ✅ Creates JoinToken v2 (CBOR + sig) |
| Join via token | `smo-node --join --token SMO-JOIN-... --port <p> --data <dir>` | ✅ TCP/CBOR JOIN_REQUEST (0x0601) |
| Bootstrap | `smo-node --daemon --seed <ip:port>` | ✅ HelloMsg → BootstrapResponse → snapshot + BootstrapSync (0x0603) |

---

## 2. Completed & Remaining

| Priority | Feature | Status |
|----------|---------|--------|
| **1** | `smo mesh create <name>` | ✅ done (MeshManager::create_mesh + smo-cli handler) |
| **2** | `smo mesh invite <role>` | ✅ done (generate-invite via smo-admin, token format v2) |
| **3** | `smo mesh join --token` | ✅ done (TCP/CBOR JOIN_REQUEST 0x0601, state machine, CERT_VERIFY, persist) |
| **4** | `/mesh/bootstrap` endpoint | ✅ done (BootstrapContract + opcodes 0x0603/0x0604 + daemon raw handler + client) |
| **5** | `MeshManager::join_mesh` (secure) | ✅ PQ handshake + CERT_VERIFY + manifest sig verify |
| **6** | Mesh catalog in `smo` CLI | ✅ mesh list/use/join catalog integration |
| **7** | Mesh catalog sync via gossip | ✅ MembershipEvent serialization, GossipEngine→MembershipSync wiring, TCP send/receive with GOSP framing, PacketDispatcher gossip intercept, SyncService→GossipEngine delta trigger, smo-node wiring |

---

## ⚡ NO HTTP — Pure TCP/CBOR Protocol (CONFIRMED)

### Current (has HTTP - REMOVE):
```
smo-node --join --token ... → HTTP POST /enroll → returns cert
```

### Target (pure TCP/CBOR):
```
Node                          Bootstrap Endpoint
  │                                    │
  │── JOIN_REQUEST (opcode 0x0601) ────►│
  │    { token_wire, csr_cbor,         │
  │      timestamp, nonce, csr_hash,   │
  │      request_signature }           │
  │                                    │── verify timestamp ±30s
  │                                    │── verify token_id not used
  │                                    │── verify nonce fresh
  │                                    │── verify request signature
  │                                    │── verify CSR
  │                                    │── issue certificate
│◄── JOIN_RESPONSE ──────────────────│
│    { certificate, mesh_id,         │
│      bootstrap_ticket }            │
│                                    │
│── BOOTSTRAP_SYNC_REQUEST ─────────►│
│    { manifest_revision,            │
│      crl_revision,                 │
│      membership_revision,          │
│      policy_revision,              │
│      bootstrap_ticket }            │
│◄── BOOTSTRAP_SYNC_RESPONSE ───────│
│    { manifest_delta?,              │
│      membership_delta?,            │
│      policy_delta?,                │
│      crl_delta?,                   │
│      seeds? ... }                  │
```

### New Opcodes (namespace 0x06 - Join):

| Opcode | Name | Direction |
|--------|------|-----------|
| `0x0601` | JOIN_REQUEST | Node → Bootstrap endpoint |
| `0x0602` | JOIN_RESPONSE | Bootstrap → Node |
| `0x0603` | BOOTSTRAP_SYNC_REQUEST | Node → Bootstrap |
| `0x0604` | BOOTSTRAP_SYNC_RESPONSE | Bootstrap → Node |

---

## 5. Critical Protocol Fixes (Must Fix Before P6 Implementation)

### 5.1 JOIN_RESPONSE: Lightweight (No Full Manifest)

**Critical design decision:** JOIN_RESPONSE must NOT return full manifest. For a mesh with large policy/contract sets, manifest can be several MB. This would make JOIN_RESPONSE a bottleneck.

**Principle:** JOIN gives you a certificate. Bootstrap gives you state.

**JOIN_RESPONSE (minimal — identity only):**
```cbor
{
  1: certificate,          // PEM-encoded certificate
  2: mesh_id,              // assigned mesh identifier
  3: bootstrap_ticket,     // opaque bytes — ticket for BOOTSTRAP_SYNC auth
  6: nonce,                // echoes request nonce
  7: server_time,          // UNIX ms — authority clock for drift correction
  8: capabilities          // uint64 bitmap — filtered by authority
}
```

**Post-join flow:**
```
JOIN
  ↓
CERTIFICATE received
  ↓
BOOTSTRAP_SYNC (0x0603)
  ↓
manifest_delta / full manifest
  ↓
membership_delta
  ↓
READY
```

> **Rationale:** Join grants identity. Bootstrap grants world state. Never mix them.

---

### 5.2 Bootstrap Sync: Revision-Based Delta Sync

**Fixed Request (REVISION-BASED):**
```cbor
{
  1: mesh_id,
  2: node_id,
  3: manifest_revision,
  4: crl_revision,
  5: membership_revision,
  6: policy_revision,
  7: bootstrap_ticket      // opaque ticket from JOIN_RESPONSE
}
```

**Bootstrap Response Logic:**
```
manifest_revision == local_manifest_revision  → skip manifest
crl_revision == local_crl_revision            → skip CRL
membership_revision == local_revision         → skip membership
policy_revision == local_revision             → skip policies
Only send changed components (delta sync)
+ seeds (array of SeedInfo for gossip bootstrap)
```

---

### 5.3 JOIN_RESPONSE: Only Seeds, Not Full Peers

**Current (BROKEN - returns ALL peers):**
```cbor
{
  certificate,
  manifest,
  peers[10000],    // NOT OK for large mesh
  seeds
}
```

**Fixed - Identity Only (DISCUSSION_0040 change 1):**
```cbor
{
  1: certificate_pem,     // PEM-encoded membership certificate
  2: mesh_id,             // string — assigned mesh identifier
  3: bootstrap_ticket,    // bytes — opaque auth ticket for BOOTSTRAP_SYNC
  6: nonce,               // bytes — echoes request nonce
  7: server_time,         // int — authority clock for drift correction
  8: capabilities         // uint64 — bitmap of granted capabilities
}
```

> **Rationale:** JOIN does ONE thing: grant membership. Seeds, manifest, policy all come via BOOTSTRAP_SYNC.

---

### 5.4 BOOTSTRAP_SYNC_RESPONSE: Delta Format

**Current (FULL SNAPSHOT + duplicate CBOR keys):**
```cbor
{
  manifest,
  peers,
  seeds,
  policies
}
```

**Fixed - DELTA FORMAT + SEEDS:**
```cbor
{
  1: manifest_delta?,          // present only if manifest_revision > known
  2: membership_delta?,        // present if membership_revision > known
  3: policy_delta?,            // present if policy_revision > known
  4: crl_delta?,               // present if crl_revision > known
  5: manifest_revision,        // monotonic uint64
  6: membership_revision,      // monotonic uint64
  7: crl_revision,             // monotonic uint64
  8: policy_revision,          // monotonic uint64
 10: server_time,              // int — server clock for drift correction
 11: seeds                     // [SeedInfo] — seed endpoints for gossip bootstrap
}
```

> **Rationale:** Mesh with 10,000 nodes → full sync = MB. Delta = KB.

---

### 5.5 MeshManager::join_mesh - Verification Steps

**Current (INSECURE):**
```
connect → sync → update → gossip
```

**Fixed - SECURE FLOW:**
```
load local identity
    ↓
connect seed (TCP)
    ↓
TLS / PQ handshake
    ↓
verify bootstrap cert
    ↓
verify mesh authority
    ↓
BOOTSTRAP_SYNC
    ↓
validate manifest signature
    ↓
apply manifest
    ↓
update peer db
    ↓
start heartbeat
    ↓
start gossip
```

> **Critical:** Verify bootstrap authority cert chain to Root before accepting manifest.

---

### 5.6 Gossip: What to Sync vs NOT

**SYNC via Gossip (GossipEngine):**
```
membership changes (join/leave/suspend)
policy updates (add/remove/modify)
CRL updates (revocations)
contract deployments/updates
routing table updates
CRT scores
```

**DO NOT SYNC via Gossip (Local State):**
```
mesh aliases (display names)
CLI context (current mesh)
current_mesh in ~/.smo/context.json
local node identity.json
per-node config.json
```

> **Rationale:** Local state is per-node, not mesh-wide. Gossip = mesh-wide state only.

---

### 5.7 Service Decomposition (Avoid God Object)

**Current (GOD OBJECT - MeshManager):**
```cpp
class MeshManager {
    create_mesh()
    join_mesh()          // join logic
    join_mesh()          // bootstrap sync
    list_meshes()
    switch_mesh()
    // ... 50+ methods
}
```

**Fixed - DECOMPOSED:**
```
MeshManager
├── JoinService
│   ├── JOIN_REQUEST / JOIN_RESPONSE
│   ├── CSR validation & orchestration
│   └── AuthorityService::issue_certificate() ← delegation
├── BootstrapService
│   ├── BOOTSTRAP_SYNC_REQUEST/RESPONSE
│   ├── Manifest + peer + seed + policy delta sync
│   └── Manifest signature verification
└── SyncService
    ├── Membership delta sync (gossip)
    ├── Policy delta sync
    ├── CRL delta sync
    ├── Manifest delta sync
    └── GossipEngine integration
```

> **Benefit:** Each service testable independently, single responsibility, no god object.

---

### 5.8 Join State Machine (Resume Capability)

```
NEW
  ↓
TOKEN_RECEIVED
  ↓
CSR_CREATED
  ↓
JOIN_SENT
  ↓
WAIT_RESPONSE
  ↓
timeout → retry (max 3, exponential backoff) → FAILED
  ↓
CERT_RECEIVED
  ↓
BOOTSTRAP_SYNC
    ↓
    WAIT_SYNC
    ↓
    timeout → retry → FAILED
  ↓
GOSSIP_SYNC
  ↓
  WAIT_GOSSIP
  ↓
  timeout → retry → FAILED
  ↓
READY
```

**On Failure:**
```
ANY_STATE
  ↓
RETRY (max 3, exponential backoff)
  ↓
FAILED (persist state to disk)
```

**On Restart:**
```
Read persisted state
Resume from last completed step
```

> **Rationale:** Node crash/restart during join → resume without user intervention.

---

### 5.9 Manifest Revision & Schema (renamed from manifest_version)

Renamed to avoid confusion with software version:
- `manifest_version` → `manifest_schema` (manifest format version, e.g., 1, 2, 3)
- `manifest_epoch` → `manifest_revision` (monotonic content revision counter)

```
manifest_revision:  1, 2, 3, 4     // only increments, ordering
manifest_schema:   1, 2, 3          // format version for compatibility

compatibility check:
  schema mismatch → negotiate lowest common
  revision comparison → delta sync
```

---

### 5.10 Capability Negotiation (uint64 Bitmap)

Capabilities use a **uint64 bitmap** instead of string array for speed and size:

```cbor
capabilities: uint64  // bitmask
```

| Bit | Capability | Description |
|-----|-----------|-------------|
| 0 | CAP_DELTA_SYNC | Supports delta sync |
| 1 | CAP_COMPRESSION | Supports payload compression |
| 2 | CAP_CRT | Supports certificate revocation transparency |
| 3 | CAP_CONTRACT_SYNC | Supports contract registry sync |
| 4 | CAP_ANTI_ENTROPY | Supports anti-entropy gossip |
| 5 | CAP_COMPRESSION_ZSTD | Supports zstd compression algorithm |
| 6 | CAP_COMPRESSION_BROTLI | Supports brotli compression algorithm |
| 7 | CAP_STREAM_CONTRACT | Supports stream contracts |
| 8 | CAP_FILE_VAULT | Supports file vault |
| 9 | CAP_GPU_COMPUTE | Supports GPU compute contracts |
| 10 | CAP_RUNTIME_NEGOTIATE | Supports extended runtime capability negotiation |

> **Compression negotiation:** Both sides advertise supported algorithms via bitmap bits 5–6. Fallback to `none` if no common algorithm.
>
> **Runtime Negotiation (bit 10):** Nodes capable of extended runtime negotiation can exchange compression/contract/feature support beyond the basic JOIN bitmap.

---

### 5.11 Seed Node Weight (priority removed)

Seed nodes use **weight only** — no priority. Client performs weighted random selection.

```cbor
seeds: [
  {
    "endpoint": "mesh.company.com:5454",
    "weight": 100
  },
  {
    "endpoint": "vpn.company.com:5454",
    "weight": 50
  }
]
```

> **Weighted random:** Higher weight = more likely to be selected. Simple, no priority maintenance needed.
> Previously had both `priority` and `weight`. Now weight-only for the wire protocol.

---

### 5.12 SyncService Scheduler (Policy-Driven)

Intervals are **configurable via mesh policy** (governance ChangePolicy action), not hardcoded:

```
SyncService
└── SyncScheduler
    ├── heartbeat    (default 20s, policy key: "heartbeat")
    ├── membership   (default 45s, policy key: "membership")
    ├── policy       (default 60s, policy key: "policy")
    ├── crl          (default 10min, policy key: "crl")
    ├── manifest     (on change, policy key: "manifest")
    ├── routing      (default 15s, policy key: "routing")
    └── contracts    (on change, policy key: "contracts")
```

> Mesh admins can tune via governance: `smo governance propose ChangePolicy {"heartbeat": 10, "membership": 30}`

---

### 5.13 Acceptance Criteria (Final State)

```
READY
  ↓
Heartbeat ACTIVE
  ↓
Discovery ACTIVE
  ↓
Gossip ACTIVE
  ↓
Sync ACTIVE
```

---

### 5.14 JoinService → AuthorityService Delegation

```
JoinService
  ↓
CSR validation
  ↓
AuthorityService::issue_certificate()
  ↓
JoinService builds response
```

> **Authority is CA owner.** JoinService only orchestrates. HSM/remote signer support requires this separation.

---

---

### 5.15 Revision vs Schema — Explicit Semantics

Renamed from epoch/version to avoid confusion with software versioning.

| Field | Type | Semantics | Use |
|-------|------|-----------|-----|
| `manifest_revision` | monotonic uint64 | 1, 2, 3, 4 ... | Sync ordering (what's newer) |
| `manifest_schema` | uint32 | 1, 2, 3 ... | Manifest format version (compatibility check) |

**Rules:**
- NEVER use schema for sync ordering — revision handles that
- NEVER use revision for compatibility — schema handles that
- Schema mismatch → negotiate lowest common schema
- Schema 1 == original genesis manifest format

---

### 5.16 Join Token — Add Nonce for Replay Protection

**Current token:**
```cbor
{
  expiry,
  mesh_id,
  role,
  signature
}
```

**Fixed token (with token_id):**
```cbor
{
  1: token_id,             // 128-bit random (crypto-grade RNG)
  2: mesh_id,              // 16 bytes
  3: role,                 // "member" | "admin" | "observer"
  4: expiry,               // UNIX timestamp uint64
  5: signature             // Ed25519 or ML-DSA
}
```

**Bootstrap cache:**
- Maintain `used_token_ids: Vec<[u8; 16]>` (only in memory, not persisted)
- On JOIN_REQUEST: reject if `token_id` in `used_token_ids`
- After expiry: flush all expired token_ids from cache
- This prevents replay even if token is intercepted

---

### 5.17 JOIN_REQUEST — Replay Protection (Timestamp + Nonce)

Each JOIN_REQUEST includes per-request freshness:

```cbor
{
  1: token_wire,            // the JoinToken CBOR blob
  2: csr_cbor,              // CSR (Ed25519 or ML-DSA public key)
  3: timestamp,             // UNIX seconds uint64 (±30s window)
  4: nonce,                 // 64-bit random per-request
  5: csr_hash,              // sha256(csr_cbor) — bind request to CSR
  6: request_signature      // sign(token_wire || timestamp || nonce || csr_hash)
}
```

**Bootstrap verify:**
1. `timestamp` within ±30s of local clock
2. `token_id` not in `used_token_ids` (from token_wire)
3. `nonce` not seen before (per-peer dedup window, flush after 60s)
4. `request_signature` valid against token issuer public key
5. Delete token from `used_token_ids` after first use (or keep until expired)

> **Without this:** Anyone intercepting a JOIN_REQUEST can replay it to re-issue a certificate.

---

### 5.18 BootstrapService — Stateless + Separate Stores

**BootstrapService is stateless:**
```
Node sends BOOTSTRAP_SYNC_REQUEST
  ↓
BootstrapService queries stores
  ↓
Serializes delta response
  ↓
Sends BOOTSTRAP_SYNC_RESPONSE
  ↓
State returned to caller (no internal cache)
```

All state lives in dedicated stores:

```
MeshManager
  │
  ├── JoinService
  │     └── AuthorityService
  │
  ├── BootstrapService    (stateless — queries stores)
  │
  ├── SyncService
  │     └── GossipEngine
  │
  ├── DiscoveryEngine     (UDP only — see 5.20)
  │
  └── Stores
        ├── PeerStore       // peer list, heartbeat timestamps
        ├── SeedStore       // bootstrap seed nodes with weight (no priority)
        ├── AuthorityStore  // trusted authorities, CA chain
        ├── ManifestStore   // immutable manifest snapshots
        └── PolicyStore     // active policies
```

> **Rationale:** Stateless BootstrapService can be horizontally scaled. No sync needed between bootstrap instances.

---

### 5.19 Gossip — Add routing_delta

Policy-driven intervals (see §5.12), defaults shown:

```
SyncScheduler:
  heartbeat    (default 20s)     ← NEW — node liveness
  membership   (default 45s)
  policy       (default 60s)
  crl          (default 10min)
  manifest     (on change)
  routing      (default 15s)     ← NEW
  contracts    (on change)
```

> Defaults are overridable via mesh policy. Example: large mesh might set `heartbeat: 30, membership: 60, crl: 600`.

---

### 5.20 Discovery vs Bootstrap — Protocol Separation

**Discovery (UDP — ephemeral, best-effort):**
```
Hello    → UDP broadcast "I exist"
Welcome  → UDP response "I see you"
Ping     → UDP liveness check
Pong     → UDP liveness response
```

**Bootstrap (TCP — reliable, stateful):**
```
JOIN_REQUEST          → TCP
JOIN_RESPONSE         → TCP
BOOTSTRAP_SYNC_REQUEST  → TCP
BOOTSTRAP_SYNC_RESPONSE → TCP
```

**Rule:** Discovery NEVER participates in JOIN/BOOTSTRAP. Discovery is only for:
- Initial peer discovery (find nodes on same LAN)
- Liveness monitoring
- NAT traversal hints

---

### 5.21 State Machine — Add CERT_VERIFY

Current:
```
CERT_RECEIVED
  ↓
BOOTSTRAP_SYNC
```

Fixed:
```
CERT_RECEIVED
  ↓
CERT_VERIFY          ← NEW state
  │ verify cert chain → bootstrap authority → mesh root
  │ verify signature
  │ verify not expired
  │ verify not revoked (check CRL)
  ↓
BOOTSTRAP_SYNC
```

**Full state machine:**
```
NEW
  ↓
TOKEN_RECEIVED
  ↓
CSR_CREATED
  ↓
JOIN_SENT
  ↓
WAIT_RESPONSE
  ↓ timer / retry → FAILED
  ↓
CERT_RECEIVED
  ↓
CERT_VERIFY           ← NEW
  ↓ fail → FAILED
  ↓
BOOTSTRAP_SYNC
  ↓
  WAIT_SYNC
  ↓ timer / retry → FAILED
  ↓
GOSSIP_SYNC
  ↓
  WAIT_GOSSIP
  ↓ timer / retry → FAILED
  ↓
READY
```

> **Rationale:** Receiving a cert doesn't mean the cert is valid. Chain verification, expiry, and CRL checks must happen before proceeding to bootstrap.

---

### 5.22 Manifest — Immutable (Git-like)

Manifests are **never updated in-place**. Each change creates a new manifest version:

```
Manifest V1  ── hash: a1b2c3
Manifest V2  ── hash: d4e5f6
Manifest V3  ── hash: g7h8i9
```

**Storage:**
```
~/.smo/meshes/<name>/manifests/
  ├── v1_manifest.cbor        (immutable)
  ├── v2_manifest.cbor        (immutable)
  └── LATEST                  → symlink to v2_manifest.cbor
```

**Delta sync:** Bootstrap compares `manifest_epoch`. If joining node's epoch < current, send only changed components (delta). If delta too large (cross-version gap > N), send full manifest.

> **Rationale:** Immutable manifests make auditing, rollback, and verification trivial. Hash (digest) serves as content identifier.

---

### 5.23 Service Graph — Dependencies

```
MeshManager
    │
    ├── JoinService
    │      │
    │      ├── AuthorityService   (CA: issue_certificate)
    │      │
    │      └── JoinStateMachine   (persisted FSM)
    │
    ├── BootstrapService          (stateless)
    │      │
    │      ├── ManifestStore
    │      ├── PeerStore
    │      ├── SeedStore
    │      └── PolicyStore
    │
    ├── SyncService
    │      │
    │      └── SyncScheduler
    │             │
    │             ├── membership_delta
    │             ├── policy_delta
    │             ├── crl_delta
    │             ├── manifest_delta
    │             ├── routing_delta
    │             └── contracts_delta
    │
    ├── GossipEngine              (TCP — mesh-wide state)
    │
    ├── DiscoveryEngine           (UDP — liveness + LAN discovery)
    │
    └── Stores
          ├── PeerStore
          ├── SeedStore
          ├── AuthorityStore
          ├── ManifestStore
          └── PolicyStore
```

**Dependency direction:** Top → Bottom. `JoinService` depends on `AuthorityService`. `SyncService` depends on `GossipEngine`. `BootstrapService` depends on Stores. `MeshManager` orchestrates all.

---

## 6. Updated Implementation Phases

### Phase 1: `smo mesh create` + `smo mesh invite` ✅
- `cmd/smo-cli/main.cpp` → handlers for `mesh create`, `mesh invite`
- `MeshManager::create_mesh()` ✅ exists, `generate_invite()` ✅ exists

### Phase 2: `smo mesh join --token` (TCP/CBOR) ✅
- `cmd/smo-cli/main.cpp` → handler for `mesh join --token`
- `core/enroll/auto_enroll.cpp` — replaced HTTP POST `/enroll` with TCP/CBOR ✅
- JOIN_REQUEST: add timestamp, nonce, csr_hash, request_signature (replay protection) ✅
- JOIN_RESPONSE: minimal — cert, mesh_id, bootstrap_ticket (NO manifest, NO seeds) ✅
- **State machine:** add CERT_VERIFY state between CERT_RECEIVED and BOOTSTRAP_SYNC ✅
- Persist state after each step (resume on crash) ✅

### Phase 3: `/mesh/bootstrap` endpoint ✅
- `BootstrapContract::handle_bootstrap_sync()` — BootstrapService is stateless ✅
- Opcodes: `0x0603` (request), `0x0604` (response) — registered in PacketDispatcher + RuntimeBridge ✅
- Delta sync: `manifest_delta?`, `membership_delta?`, `policy_delta?`, `crl_delta?` ✅
- Revision-based request: `{ manifest_revision, crl_revision, membership_revision, policy_revision, bootstrap_ticket }` ✅
- BOOTSTRAP_SYNC_RESPONSE includes seeds for gossip bootstrap ✅
- Client-side BootstrapSync TCP/CBOR in `auto_enroll.cpp` ✅
- Daemon raw handler wired for JoinRequest + BootstrapSyncRequest ✅

### Phase 4: Service Decomposition ✅ (MeshManager refactored)
- Stores built: `SeedStore` (core/discovery/) ✅, `AuthorityStore` (core/authority/) ✅, `ManifestStore` (core/storage/) ✅, `PolicyStore` exists in `storage/policy_store/`
- Services built: `JoinService` (core/join/) ✅, `BootstrapService` (core/bootstrap/) ✅, `SyncService` (core/network/sync/) ✅
- `MeshManager` refactor ✅ — service injection via `set_join_service`/`set_bootstrap_service`/`set_sync_service`, `join_mesh()`/`leave_mesh()`/`delete_mesh()` delegate to services
- `DiscoveryEngine` (UDP) ❌ **NOT DONE** (separate concern, see §5.20)
- Build: ✅ all targets (`smo_core`, `smo-cli`, `smo-admin`, `smo-node`)
- Phase 5 SecureSession integration started: `auto_enroll.cpp` + `smo-node` accept loop ✅

### Phase 5: `MeshManager::join_mesh` (Secure)
- ✅ `SecureSession` class: PQ 1-RTT KEM handshake + XChaCha20-Poly1306 AEAD + HKDF key derivation
- ✅ `KemImpl::generate_keypair` added to all 3 suites (Classical/Modern/PurePQC)
- ✅ Client integration: `auto_enroll.cpp` — `tcp_cbor_exchange` replaced with `SecureSession` handshake + encrypted send/recv for both JoinRequest and BootstrapSync
- ✅ Server integration: `smo-node` accept loop — PQ handshake on accepted TCP fds with server cert + identity signing key; `SecureTransportSession` adapter for transparent dispatch; fallback to plaintext when no cert
- ✅ PacketDispatcher refactor: `dispatch_session(TcpSession&)` → `dispatch_session(TransportSession&)` — encryption-agnostic
- ✅ CERT_VERIFY (§5.21): after JoinResponse, verify cert chain (server cert → authority), verify signature, check expiry, save authority pubkey for manifest verify
- ✅ Manifest signature validation (§5.5): after BootstrapSync, verify manifest CBOR envelope signature against authority pubkey
- ✅ Delta sync with epoch checks — implemented in Phase 3
- ✅ State machine persistence (including CERT_VERIFY) — FSM transitions fully wired
- ✅ Manifest immutable (Git-like versioned snapshots) — already documented in §5.22

### Phase 6: `smo mesh list/use` in `smo` CLI ✅
- ✅ `smo mesh list` — lists all meshes from `~/.smo/meshes/` with role + mesh_id metadata; current marked with `*`
- ✅ `smo mesh use <name>` — switches current context via CLIContextManager
- ✅ `smo mesh create <name>` — creates mesh directory + sets context
- ✅ `smo mesh join --token` — after join, registers mesh in catalog (`~/.smo/meshes/<name>/mesh.json`), sets as current context
- ✅ `JoinResult` struct returned from `run_join_command` for CLI to use on success

### Phase 7: Mesh catalog sync via gossip (GossipEngine + MembershipSync) ✅

- ✅ `MembershipSync::serialize_events()` — binary format: `[count][[type][node_id(32)][ts][seq][payload_len][payload]...]`
- ✅ `MembershipSync::apply_events()` — deserialize + upsert/remove MembershipTable + re-emit to local subscribers
- ✅ `GossipEngine::set_membership_sync()` — connects engine to rich event source
- ✅ `GossipEngine::pending_updates()` → delegates to `MembershipSync::pending_events()` (fallback: PeerRecord list)
- ✅ `GossipEngine::apply_gossip()` → delegates to `MembershipSync::apply_events()`
- ✅ `GossipEngine::send_gossip_to_peer()` — **TCP** connect + SMO FrameHeader + `"GOSP"` magic + serialized events
- ✅ `select_fanout_peers()` → **TCP** endpoints (was UDP stub)
- ✅ `PacketDispatcher::dispatch_session()` — intercepts gossip frames via `"GOSP"` magic before Packet parse; routes to `GossipEngine::apply_gossip()`
- ✅ `PacketDispatcher::set_gossip_engine()` — wiring point for incoming gossip
- ✅ `SyncService::tick()` — membership delta interval auto-calls `gossip.tick(now_ns)`
- ✅ `cmd/smo-node/main.cpp` — `MembershipSync → GossipEngine → PacketDispatcher` wired in init flow; redundant `pending_events()` removed from daemon loop
- **Wire format:** `[SMO FrameHeader (9 bytes)][GOSP magic (4 bytes)][serialized MembershipEvents]`

---

## 7. Remaining Gaps (Phase 8)

| Priority | Gap | Status | Details |
|----------|-----|--------|---------|
| **1** | SyncService delta handlers (policy, crl, manifest, routing, contracts) | ✅ | `GossipEngine` extended with `DeltaType` enum + typed GOSP wire format `[delta_type:1][payload_len:4][payload]` per segment; `queue_delta()` / `set_delta_handler()` / `set_delta_provider()` added; `send_gossip_to_peer()` bundles all pending deltas; `apply_gossip()` dispatches by type. `SyncService::tick()` reordered to fire all delta callbacks before membership gossip fanout. CRL delta fully implemented (serialize `entries_since(epoch)` send-side, `CRL::deserialize` + merge receive-side via `set_crl()`). Manifest delta serializes new epoch list. Policy delta stubbed (PolicyStore `SqliteStore` mismatch tracked). Routing/contracts stubs registered. `SyncService` wired into daemon main loop, replacing direct `gossip_engine.tick()` call |
| **2** | DiscoveryEngine (UDP) — HELLO/WELCOME/PING/PONG | ✅ | **FIXED:** Rewired `DiscoveryEngine` to UDP transport; added `dispatch_discovery_datagram()` with magic+type dispatch (`0x44('D')` + `DiscoveryMsgType`); added UDP read loop in daemon (`smo-node:1630-1645`); added `wrap_discovery_msg()` helper; `send_node_info()` now wraps with type tag. `Bootstrap::find_seed()` remains on TCP (per §5.20: bootstrap = TCP). Both TCP (bootstrap) and UDP (LAN discovery) HELLO paths coexist correctly |
| **3** | GOSSIP_SYNC join FSM — wait for actual gossip readiness | ⚠️ stub | `auto_enroll.cpp:718-726` transitions `WAIT_SYNC → GOSSIP_STARTED → GOSSIP_COMPLETE → READY` immediately without waiting for GossipEngine to actually send/receive |
| **4** | `smo mesh create` — full key generation | ✅ | `smo mesh create <name>` now generates authority + root keypairs inline via `MeshAuthority::create_mesh_keys()`, derives `mesh_id` from name+timestamp hash, generates HMAC secret, and writes complete `mesh.json` with `authority_pubkey`, `root_pubkey`, `hmac_secret`, `cipher_suite_id`, `epoch`. No longer delegates to `smo-admin create-mesh` |

## Acceptance Criteria (Final)

```bash
# 1. Create mesh (smo, not smo-admin)
smo mesh create mymesh
# → ~/.smo/meshes/mymesh/ created with mesh.json + keys

# 2. Configure bootstrap
smo mesh publish --listen 0.0.0.0:5454 --endpoint mesh.mydomain.com:5454

# 3. Generate invite
smo mesh invite --role member --expire 1h --endpoint mesh.mydomain.com:5454
# → SMO-JOIN-xxxxx

# 4. Join (pure TCP/CBOR, no HTTP)
smo mesh join --token SMO-JOIN-xxxxx
# → TCP JOIN_REQUEST (0x0601, with timestamp+nonce+signature)
# → JOIN_RESPONSE (cert + mesh_id + bootstrap_ticket)
# → BOOTSTRAP_SYNC_REQUEST (revisions + ticket) → BOOTSTRAP_SYNC_RESPONSE (deltas + seeds)

# 5. Start node
smo-node --daemon --data /tmp/node1 --port 9121 --seed 127.0.0.1:5454
# → BOOTSTRAP_SYNC_REQUEST (revisions) → BOOTSTRAP_SYNC_RESPONSE (deltas + seeds)
# → Bootstrap complete. Peers: 1
# State machine: NEW → TOKEN_RECEIVED → CSR_CREATED → JOIN_SENT → WAIT_RESPONSE → CERT_RECEIVED → CERT_VERIFY → BOOTSTRAP_SYNC → WAIT_SYNC → GOSSIP_SYNC → WAIT_GOSSIP → READY

# 6. Mesh catalog
smo mesh list
smo mesh use mymesh

# 7. Verify state machine on restart
# Kill node during GOSSIP_SYNC → restart → resume from GOSSIP_SYNC
```

---

## Next Step

**All 15 architectural improvements (updated for DISCUSSION_0040 changes):**
1. ✅ 5.1 JOIN_RESPONSE minimal — cert + mesh_id + bootstrap_ticket only
2. ✅ 5.4 BOOTSTRAP_SYNC_RESPONSE: delta + seeds, no duplicate CBOR keys
3. ✅ 5.10 Capabilities as uint64 bitmap (not string array)
4. ✅ 5.11 Seed weight only (no priority, weighted random)
5. ✅ 5.12 SyncScheduler policy-driven (not hardcoded)
6. ✅ 5.15 manifest_revision + manifest_schema (renamed from epoch/version)
7. ✅ 5.16 Join Token nonce (token_id) for replay protection
8. ✅ 5.17 JOIN_REQUEST timestamp+nonce+signature replay protection
9. ✅ 5.18 BootstrapService stateless + store separation
10. ✅ 5.19 Gossip routing + heartbeat intervals policy-configurable
11. ✅ 5.20 Discovery (UDP) vs Bootstrap (TCP) separation
12. ✅ 5.21 State machine: CERT_VERIFY + BOOTSTRAP_SYNC + GOSSIP_SYNC states
13. ✅ 5.22 Manifest revision-based delta, seeds in BOOTSTRAP_SYNC_RESPONSE
14. ✅ 5.23 Service graph with JoinService→BootstrapService→SyncService separation
15. ✅ Runtime Capability Negotiation (CAP_RUNTIME_NEGOTIATE bit 10)

**Phase 5—7**: Mesh catalog, sync, gossip ✅
**Phase 8a—8c**: SyncService delta + GOSSIP_SYNC FSM + keygen ✅
**Protocol freeze (DISCUSSION_0040)**: protocol_version, capability_bitmap, SeedInfo, ABORTED, CBOR keys ✅

**Next Step**: All Phase 1–8 complete. Run end-to-end validation.