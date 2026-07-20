# Discussion 0040 — Release 0.0.1: Complete Ecosystem & Ship Plan

**Date:** 2026-07-20  
**Status:** 🟡 PLANNING — all Phase 1–8 implemented, gaps identified  
**Goal:** Define what 0.0.1 means, document the full architecture, and produce an actionable checklist for release.

---

## 1. Current State (What Exists)

All 8 phases of the mesh lifecycle are implemented at the code level:

| Phase | Feature | Status | Key Files |
|-------|---------|--------|-----------|
| 1 | PKI & Governance (Root-as-Node, 2-tier gov, slots, recovery) | ✅ | `core/genesis/`, `core/mesh/`, `core/governance/`, `core/recovery/`, `core/authority/`, `core/certificate/` |
| 2 | Bootstrap Protocol (namespace 0x05, CBOR, snapshot) | ✅ | `core/bootstrap/`, `core/network/bootstrap/` |
| 3 | Signature Join Token v2 (CBOR+HMAC) + Root Redesign | ✅ | `core/enroll/join_token.hpp/.cpp` |
| 4 | Runtime Skeleton (kernel, dispatcher, pipeline) | ✅ | `core/runtime/` (41 files) |
| 5 | 6 Native Contracts (echo, bootstrap, join, governance, recovery, file) | ✅ | `core/runtime/contracts/` |
| 6 | Mesh catalog CLI (`smo mesh list/use/create`) | ✅ | `cmd/smo-cli/main.cpp` |
| 7 | Mesh catalog sync via gossip (MembershipSync, GossipEngine, TCP GOSP) | ✅ | `core/discovery/gossip.*`, `core/network/sync/` |
| 8a | SyncService delta handlers (CRL/manifest/policy/routing/contracts) | ✅ | `core/network/sync/sync_service.*`, `core/discovery/gossip.*` |
| 8b | GOSSIP_SYNC join FSM (WAIT_SYNC→READY) | ✅ | `core/enroll/auto_enroll.cpp` |
| 8c | `smo mesh create` inline keygen | ✅ | `cmd/smo-cli/main.cpp` |
| — | DiscoveryEngine UDP (§5.20 HELLO/WELCOME/PING/PONG) | ✅ | `core/discovery/discovery.*`, `core/network/udp/` |

### Binaries building successfully

| Binary | Purpose | Lines |
|--------|---------|-------|
| `smo` | Top-level alias | ~10 |
| `smo-cli` | Interactive CLI shell | 1267 |
| `smo-node` | Node daemon | 1814 |
| `smo-admin` | Mesh administration | 1071 |
| `smo-debug` | Low-level debug tool | ~200 |

### Test results (current)

- 72% passed (13/18)
- 3 pre-existing failures: `governance_model` ×2, `contract_model` ×1
- 3 Not Run: `core`, `protocol`, `compiler` (missing executables)

---

## 2. Full Architecture Overview

### 2.1 Layer Stack

```
┌──────────────────────────────────────────────────────────┐
│                    CLI LAYER                              │
│  smo-cli     smo-admin    smo-node    smo-debug          │
│  (intent     (admin       (daemon     (low-level         │
│   parser)     ops)         FSM)        debug)            │
├──────────────────────────────────────────────────────────┤
│                   SERVICE LAYER                           │
│  MeshManager  SyncService  GossipEngine  DiscoveryEngine │
│  JoinService  BootstrapSvc  RuntimeBridge  NodeLifecycle │
├──────────────────────────────────────────────────────────┤
│                   RUNTIME KERNEL                          │
│  Dispatcher → MiddlewarePipeline → ActionExecutor        │
│  → Scheduler → ExecutionEngine → Contract::execute()     │
│  EventBus (side-channel)  ServiceRegistry  Telemetry     │
├──────────────────────────────────────────────────────────┤
│                  CORE DOMAIN                              │
│  Genesis  Governance  Recovery  Authority  Certificate   │
│  Identity  Trust  Capability  PolicyEngine  Selector     │
├──────────────────────────────────────────────────────────┤
│                  NETWORK / TRANSPORT                      │
│  TCP Transport  UDP Transport  Framing  SecureSession    │
│  PacketDispatcher  AddressResolver  DNS  NAT Detection   │
├──────────────────────────────────────────────────────────┤
│                  STORAGE                                  │
│  SQLiteStore  ManifestStore  AuditStore  PeerStore       │
│  SeedStore  NodeRegistry  ContractRegistry               │
├──────────────────────────────────────────────────────────┤
│                  CRYPTO                                   │
│  Suite1 (Classical: Ed25519+X25519+XChaCha20+Blake3)    │
│  Suite3 (PurePQC: ML-DSA+ML-KEM)                        │
│  CryptoRegistry  HashProvider  Signer  KEM  AEAD  KDF   │
└──────────────────────────────────────────────────────────┘
```

### 2.2 Four Protocol Namespaces (per RFC 0020)

| Namespace | ID | Transport | Messages | Phase |
|-----------|----|-----------|----------|-------|
| **DISCOVERY** | `0x01` | UDP | HELLO, WELCOME, PING, PONG, DISCOVER, NODE_INFO, OFFLINE | ✅ |
| **BOOTSTRAP** | `0x05` | TCP | BOOTSTRAP_REQUEST/`0x0501`, BOOTSTRAP_RESPONSE/`0x0502` | ✅ |
| **JOIN** | `0x06` | TCP | JOIN_REQUEST/`0x0601`, JOIN_RESPONSE/`0x0602`, BOOTSTRAP_SYNC_REQ/`0x0603`, BOOTSTRAP_SYNC_RESP/`0x0604` | ✅ |
| **GOSSIP** | `0x01` sub | TCP | GOSP magic `0x474F5350` + typed delta segments | ✅ |

### 2.3 Transport Assignment (per §5.20)

```
Discovery  →  UDP (HELLO/WELCOME/PING/PONG on port)
Bootstrap  →  TCP (JOIN/BOOTSTRAP_SYNC)
Gossip     →  TCP (membership sync + typed deltas, connect→send→close fanout)
```

### 2.4 Key Data Flow: smo mesh join → smo-node --daemon

```
User runs: smo mesh join --token SMO-JOIN-xxxxx
  │
  ├─ 1. auto_enroll::run_join_command()
  │     ├─ Decode token (CBOR + HMAC verify)
  │     ├─ Initialize identity (generate keypair)
  │     ├─ Build CSR
  │     ├─ Connect to bootstrap endpoint (TCP)
  │     ├─ Send JOIN_REQUEST (0x0601): {token, csr, timestamp, nonce, signature}
  │     ├─ Receive JOIN_RESPONSE (0x0602): {cert, mesh_id, manifest_digest, seeds}
  │     ├─ Verify certificate chain
  │     ├─ Send BOOTSTRAP_SYNC_REQUEST (0x0603): {epochs}
  │     ├─ Receive BOOTSTRAP_SYNC_RESPONSE (0x0604): {deltas}
  │     ├─ Persist join_state.bin
  │     └─ Return JoinResult
  │
  └─ 2. Start smo-node --daemon
        ├─ Initialize services (MeshManager, DiscoveryEngine, GossipEngine, etc.)
        ├─ Bootstrap: TCP HELLO → WELCOME → DISCOVER → NODE_INFO
        ├─ Resume join FSM from persisted state
        ├─ FSM: WAIT_SYNC → GOSSIP_STARTED → GOSSIP_COMPLETE → READY
        │         [2x GOSSIP_COMPLETE to reach READY(11)]
        ├─ SyncService::tick() fires delta callbacks:
        │     routing(15s) → policy(60s) → crl(300s) → manifest(on change)
        │     → contracts(on change) → membership(30s) → gossip.tick()
        └─ Main loop: poll UDP + TCP + tick timers
```

---

## 3. Complete CLI Command Reference

### 3.1 `smo-cli` (Interactive Shell)

```
# Mesh Management
smo mesh create <name>              Create mesh with inline keygen (Phase 8c)
smo mesh list                        List all local meshes
smo mesh use <name>                  Switch active mesh context
smo mesh publish [--listen p] [--ep addr]  Configure bootstrap endpoints
smo mesh invite --role r --expire d --ep addr   Generate Join Token
smo mesh join --token SMO-JOIN-...   Join a mesh (zero-touch)

# Navigation & Info
ls [path]                            List directory
cd <path>                            Change directory
pwd                                  Print working directory
info [node]                          Show node/mesh info
ping <node>                          Ping a mesh node

# Execution
exec <command> [args]                Execute command on node(s)
ps                                  List running processes
top                                 Resource monitor

# File Operations
get <remote> [local]                 Download file from node
put <local> <remote>                 Upload file to node
cat <remote>                         Display remote file

# Deployment
deploy <contract> [args]             Deploy a contract
undeploy <contract>                  Remove a contract
status [contract]                    Show contract status

# Governance
genesis [options]                    Run mesh genesis
governance <action> [args]           Governance operations
recovery [options]                   Recovery operations
policy <action> [args]               Policy management
control <action> [args]              Control operations

# Context
ctx use <mesh>                       Switch mesh context
context                              Show current context

# System
help                                 Show help
exit / quit                          Exit CLI
```

### 3.2 `smo-admin` (Administration)

```
smo-admin --mesh <name> create-mesh           Create mesh (offline keygen)
smo-admin --mesh <name> mesh publish          Configure bootstrap endpoints
smo-admin --mesh <name> sign <csr> -o <out>   Sign CSR → certificate
smo-admin --mesh <name> generate-invite <role>  Generate Join Token
smo-admin --mesh <name> serve [--port p]       Start enroll server
```

### 3.3 `smo-node` (Daemon)

```
smo-node --init --name <name> --data <dir>    Initialize node identity
smo-node --import [file]                      Import certificate
smo-node --daemon --data <dir>                Start daemon
smo-node --daemon --seed <host:port>           Start daemon with seed
smo-node --join --token SMO-JOIN-...           Join via token (headless)
smo-node --pubkey                              Show public key
smo-node --fingerprint                         Show key fingerprint
```

### 3.4 `smo-debug`

```
smo-debug [options]                           Low-level debug ops
```

---

## 4. Data Models

### 4.1 `mesh.json` (Mesh Config)

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

### 4.2 Identity (`identity.json`)

```
NodeID = Blake3(NodePublicKey)
```
Stored in `<data_dir>/identity.json`:
```json
{
  "node_id": "hex-64-chars",
  "public_key": "hex",
  "created_at": 1721452800,
  "display_name": "node-1"
}
```
Private key stored separately in `<data_dir>/identity.key` (restricted permissions).

### 4.3 Membership Certificate (`.smoc`)

Three-tier key hierarchy:
```
Root Key (offline) → Authority Key (online) → Node Key (daily)
```
Certificate binds: `PublicKey ↔ MeshID + Role + CapabilitySet + Epoch`
Format: PEM with CBOR payload.

### 4.4 Join Token (v2, CBOR+HMAC)

```
SMO-JOIN-<base64url(CBOR_payload || HMAC_SHA256(CBOR_payload))>

CBOR Payload:
{
  "version": 1,
  "mesh_id": bstr(16),
  "mesh_epoch": uint,
  "cipher_suite_id": uint,
  "bootstrap_endpoints": [tstr],
  "role": tstr,
  "expiry": uint(unix_timestamp),
  "nonce": bstr(8-16)
}
```
Token proves authorization to enroll — contains NO certificate, NO private key.
HMAC keyed with `hmac_secret` from `mesh.json`.

### 4.5 Gossip Wire Format (GOSP)

```
[SMO Frame Header 9B]
[GOSP Magic: 0x474F5350 (4B)]
[delta_type:1][payload_len:4 LE][payload:varies]
[delta_type:1][payload_len:4 LE][payload:varies]
...

Delta Types:
  0 = Membership
  1 = CRL
  2 = Policy
  3 = Manifest
  4 = Routing
  5 = Contracts
```

### 4.6 Join FSM States

```
NEW(0) → TOKEN_RECEIVED(1) → CSR_CREATED(2) → JOIN_SENT(3) →
WAIT_RESPONSE(4) → CERT_RECEIVED(5) → CERT_VERIFY(6) →
BOOTSTRAP_SYNC(7) → WAIT_SYNC(8) → GOSSIP_SYNC(9) →
WAIT_GOSSIP(10) → READY(11)

Events:
  TOKEN_PARSED(100)  CSR_BUILT(101)  MSG_SENT(102)
  RESPONSE_RCVD(103) CERT_VERIFIED(104)  CERT_INVALID(105)
  SYNC_REQUESTED(106) SYNC_COMPLETE(107) GOSSIP_STARTED(108)
  GOSSIP_COMPLETE(109) TIMEOUT(110) RETRY(111) FAIL(112)
```

### 4.7 Core Domain Models

| Model | File | Key Fields |
|-------|------|------------|
| `PeerRecord` | `core/discovery/discovery.hpp` | node_id, display_name, hostname, role, tags, endpoint, state, last_seen_ns, ping_misses, rtt_ms |
| `MeshConfig` | `core/mesh/mesh_manager.hpp` | mesh_id, display_name, authority_pubkey, root_pubkey, hmac_secret, cipher_suite_id, epoch, listen/advertise/bootstrap |
| `MeshContext` | `core/mesh/mesh_manager.hpp` | config, display_name, paths (mesh_dir, cert_path, identity_json, peers_db, audit_db, contract_db, etc.) |
| `JoinRequest` | `core/join/join_protocol.hpp` | version, token, csr_pem, timestamp, nonce[8], csr_hash, request_signature |
| `JoinResponse` | `core/join/join_protocol.hpp` | version, nonce[8], certificate_pem, mesh_id, manifest_digest, manifest_epoch, bootstrap_nodes |
| `BootstrapSyncRequest` | `core/join/join_protocol.hpp` | version, nonce[8], mesh_id, node_id, manifest_epoch, crl_epoch, membership_epoch, policy_version |
| `BootstrapSyncResponse` | `core/join/join_protocol.hpp` | version, nonce[8], manifest_delta, membership_delta, policy_delta, crl_delta, epochs |
| `ContractDefinition` | `core/contract/contract_definition.hpp` | contract_version, category, opcode, name, semver, input_schema, output_schema, capability_mask, opcode_dependencies |
| `Capability` | `core/capability/capability.h` | Bitmask-based: CAP_FS_READ, CAP_FS_WRITE, CAP_EXEC, CAP_GRANT, CAP_REVOKE, etc. |

---

## 5. Lifecycle Flows

### 5.1 Mesh Creation (Complete)

```
smo mesh create mymesh
  │
  ├─ Create ~/.smo/meshes/mymesh/
  ├─ Generate HMAC secret (32 random bytes → hex)
  ├─ Derive mesh_id = Blake3(name + timestamp)
  ├─ Init MeshAuthority (register root + authority keypairs)
  ├─ Write root.pub, authority.pub, authority.key, root.key
  ├─ Write mesh.json:
  │     mesh_id, display_name, authority_pubkey, root_pubkey,
  │     hmac_secret, cipher_suite_id(3), epoch(1), created_at
  ├─ Set current mesh context
  └─ Print success + keys generated
```

### 5.2 Publish (Bootstrap Configuration)

```
smo mesh publish --listen 0.0.0.0:7777 --ep node.example.com:7777
  │
  ├─ Check port availability (bind probe)
  ├─ Detect public IP (STUN/UDP echo)
  ├─ Resolve DNS if provided
  ├─ Update mesh.json:
  │     listen_address, advertise_addresses, bootstrap_endpoints
  └─ Mesh is now ONLINE
```

### 5.3 Invite (Token Generation)

```
smo mesh invite --role Worker --expire 1h --ep node.example.com:7777
  │
  ├─ Load mesh.json (must have bootstrap_endpoints)
  ├─ Build CBOR payload: {version, mesh_id, epoch, cipher_suite_id,
  │     bootstrap_endpoints, role, expiry, nonce}
  ├─ Compute HMAC-SHA256 with hmac_secret
  ├─ Encode as SMO-JOIN-<base64url(payload + hmac)>
  └─ Print token
```

### 5.4 Join (Zero-Touch Onboarding)

```
smo mesh join --token SMO-JOIN-xxxxx
  │
  ├─ Decode token → CBOR payload + HMAC
  ├─ Verify HMAC with mesh's hmac_secret (requires mesh.json locally
  │   or token must carry enough info for network join)
  ├─ Generate node identity keypair
  ├─ Build CSR
  ├─ TCP connect to bootstrap_endpoints[0]
  ├─ Send JOIN_REQUEST (0x0601):
  │     token_wire, csr_cbor, timestamp, nonce, csr_hash, signature
  │
  ├─ Authority receives:
  │     │─ Validate token HMAC + expiry
  │     │─ Verify CSR signature
  │     │─ Issue certificate (signed with Authority key)
  │     └─ Return JOIN_RESPONSE (0x0602):
  │           certificate, mesh_id, manifest_digest, manifest_epoch, seeds
  │
  ├─ Verify certificate chain to Root
  ├─ Send BOOTSTRAP_SYNC_REQUEST (0x0603):
  │     mesh_id, node_id, epochs (might be all 0)
  ├─ Receive BOOTSTRAP_SYNC_RESPONSE (0x0604):
  │     manifest/membership/policy/crl deltas + current epochs
  ├─ Persist join state (join_state.bin)
  ├─ Print post-import summary
  └─ Ready to start daemon
```

### 5.5 Daemon Start + Gossip Sync

```
smo-node --daemon --data /tmp/node1 --port 9121 --seed 127.0.0.1:5454
  │
  ├─ Initialize:
  │     Crypto (register suites), Identity, MeshManager, DiscoveryEngine,
  │     GossipEngine, MembershipSync, SyncService, CRL, ManifestStore,
  │     PacketDispatcher, RuntimeBridge, ServiceRegistry
  │
  ├─ Bootstrap:
  │     │─ TCP connect to seed
  │     │─ Send HELLO → Receive WELCOME (seed's PeerRecord)
  │     │─ Send DISCOVER → Receive NODE_INFO (full peer table)
  │     └─ Populate local MembershipTable
  │
  ├─ Resume join FSM:
  │     │─ Load join_state.bin
  │     │─ FSM executes: WAIT_SYNC → GOSSIP_STARTED
  │     │─ [GossipEngine starts ticking]
  │     │─ FSM: GOSSIP_COMPLETE → WAIT_GOSSIP
  │     │─ [GossipEngine sends first fanout + receives responses]
  │     │─ FSM: GOSSIP_COMPLETE → READY(11)
  │     └─ Node fully operational
  │
  ├─ Main loop (every tick):
  │     │─ UDP: read discovery datagrams (HELLO, PING, PONG)
  │     │─ TCP: accept/read session data
  │     │─ SyncService::tick() → fires delta callbacks:
  │     │     routing(15s) → policy(60s) → crl(300s) →
  │     │     manifest(on change) → contracts(on change) →
  │     │     membership(30s) → gossip.tick()
  │     └─ HealthMonitor::tick() (PING timeout detection)
  │
  └─ Node is READY: accepting intents, gossiping, syncing
```

---

## 6. Release 0.0.1 Checklist

### 6.1 Critical (Must-Fix Before Release)

| # | Item | Area | Effort | Status |
|---|------|------|--------|--------|
| **R1** | E2E smoke test: create → publish → invite → join → daemon | Integration | 1-2d | ❌ Not done |
| **R2** | Fix `governance_model` test failure: `to_string(PolicyChange)` returns wrong string | Governance | 0.5d | ❌ Pre-existing |
| **R3** | Fix `governance_model` test failure: invalid level assertion at line 221 | Governance | 0.5d | ❌ Pre-existing |
| **R4** | Fix `contract_model` test failure: `contract_version != "1.0"` (minimal version parse) | Contract | 0.5d | ❌ Pre-existing |
| **R5** | Fix `core` / `protocol` / `compiler` test executables (Not Run — path/config) | Build/Test | 1d | ❌ |
| **R6** | Daemon-side gossip readiness: GOSSIP_SYNC should wait for actual networked send/receive | Enroll | 1d | ⚠️ Stubbed |
| **R7** | Error: `SqliteStore::remove()` / `::list_by_prefix()` API mismatch → uncomment `add_subdirectory(policy_store)` | Storage/Policy | 1d | ⚠️ Commented out |

### 6.2 Important (Should-Fix For Quality)

| # | Item | Area | Effort | Status |
|---|------|------|--------|--------|
| **R8** | Add `--version` flag to all 4 binaries | CLI | 0.5d | ❌ |
| **R9** | Add `--help` flag consistency across all binaries | CLI | 0.5d | ❌ |
| **R10** | Write man pages or `help` subcommand for smo-cli | Docs | 1d | ❌ |
| **R11** | Validate all CBOR encoding/decoding roundtrips with fuzz tests | Network | 2d | ❌ |
| **R12** | Add timeout to TCP connect in GossipEngine (currently blocking) | Gossip | 0.5d | ❌ |
| **R13** | Add retry logic in `send_gossip_to_peer()` (connections fail silently) | Gossip | 0.5d | ❌ |
| **R14** | Persist `manifest_epoch` after BOOTSTRAP_SYNC to avoid redundant sync | Join | 0.5d | ❌ |
| **R15** | Add nonce uniqueness check on JOIN_REQUEST (prevent replay) | Join | 0.5d | ❌ |

### 6.3 Nice-To-Have (Post-0.0.1)

| # | Item | Area | Effort |
|---|------|------|--------|
| **R16** | WASM contract execution | Runtime | 4-6w |
| **R17** | Compiler pipeline (Parser → SMIR → DAG) | Compiler | 4w |
| **R18** | Multi-Authority support (add/revoke) | Authority | 2w |
| **R19** | Recovery Package export/import | Genesis | 1w |
| **R20** | Cross-mesh trust | Mesh | 3w |
| **R21** | Full SWIM gossip (indirect checks, suspicion) | Discovery | 2w |
| **R22** | History/Audit queries | Storage | 1w |
| **R23** | Scheduler (DAG-aware) | Runtime | 2w |

### 6.4 Effort Summary

| Category | Items | Est. Effort |
|----------|-------|-------------|
| Critical (R1–R7) | 7 | 5-7d |
| Important (R8–R15) | 8 | 6d |
| **Total for 0.0.1** | **15** | **~2-3 weeks** |
| Post-0.0.1 (R16–R23) | 8 | 15-20w |

---

## 7. Test Strategy for 0.0.1

### 7.1 Current Test Structure

```
tests/
├── unit/
│   ├── core_test.cpp        (Not Run — no binary?)
│   ├── compiler_test.cpp    (Not Run — no binary?)
│   ├── protocol_test.cpp    (Not Run — no binary?)
│   ├── core/                (discovery, fsm, governance, contract, crypto, error, session, transport, storage, cert, identity, etc.)
│   ├── protocol/
│   └── storage/
├── integration/    (.gitkeep only)
├── mesh/           (.gitkeep only)
├── chaos/          (.gitkeep only)
├── adversarial/    (.gitkeep only)
└── replay/         (.gitkeep only)
```

### 7.2 What Tests Cover

| Test File | What It Tests | Status |
|-----------|--------------|--------|
| `test_discovery` | DiscoveryEngine, MembershipTable, HealthMonitor | ✅ Pass |
| `test_fsm` | FSM framework, transitions, timeouts | ✅ Pass |
| `test_crypto` | All 3 suites, sign/verify, encrypt/decrypt | ✅ Pass |
| `test_session` | Session open/close, state management | ✅ Pass |
| `test_governance` | Governance actions, engine | ❌ 2 fails |
| `test_contract` | Contract definition, ABI, registry | ❌ 1 fail |
| `test_identity` | Identity creation, storage | ✅ Pass |
| `test_certificate` | Certificate signing, verification | ✅ Pass |
| `test_transport` | TCP transport, framing | ✅ Pass |
| `test_storage` | SQLiteStore, CRUD operations | ✅ Pass |
| `test_error` | Error model, error codes | ✅ Pass |

### 7.3 Required Tests For 0.0.1

| Test | Type | Priority | Description |
|------|------|----------|-------------|
| E2E smoke (create→join→sync) | Integration | R1 | Full lifecycle script |
| GossipEngine TCP fanout | Unit | R12-R13 | Connect→send→close with timeout |
| SyncService delta callbacks | Unit | R6 | All 6 delta types fire correctly |
| CRL delta serialization | Unit | R7 | `entries_since(epoch)` → serialize → deserialize → merge |
| ManifestStore delta | Unit | R14 | Epoch-based query |
| Join FSM state recovery | Unit | R6 | Load persisted state, resume correctly |
| Enroll server token validation | Unit | R2-R4 | HMAC verify, expiry check, nonce dedup |

---

## 8. Known Limitations In 0.0.1

| Limitation | Impact | Workaround |
|------------|--------|------------|
| Single Authority only | No HA for enrollment | Manual failover |
| No WASM | Only native contracts | Write contracts in C++ |
| No Compiler | No custom contract definitions | Use native contracts only |
| No Audit history queries | No forensics | Direct SQLite access |
| Gossip readiness stubbed | FSM may report READY before actual gossip | Acceptable for single-node/LAN |
| No NAT punch for discovery | Only works on same subnet/LAN | Use bootstrap TCP for cross-network |
| `policy_store` not built | Policy delta stub only | CRL + manifest deltas work |
| HTTP enroll server still in `smo-admin` | Mixed transport | Use Join Token path instead |

---

## 9. Directory Map (Complete Source Tree)

```
smoframework/
├── SPEC.md                          # Master specification (2744 lines)
├── ARCHITECTURE_SUMMARY.md          # Vietnamese architecture summary
├── ARCHITECTURE.md                  # Architecture diagrams
├── IMPLEMENT.md                     # Implementation notes
├── CMakeLists.txt                   # Root build
│
├── core/                            # Core library (all domain logic)
│   ├── acl/                         # Policy engine
│   ├── authority/                   # Mesh authority, enrollment server, registry
│   ├── bootstrap/                   # Bootstrap protocol, CBOR, snapshot
│   ├── capability/                  # Capability definitions
│   ├── certificate/                 # Certificate PEM, verification
│   ├── contract/                    # Contract ABI, definitions, registry, native/
│   ├── crypto/                      # Crypto suites, providers, hash, KEM, AEAD, KDF
│   ├── discovery/                   # Discovery engine, gossip engine, peer/seed store
│   ├── enroll/                      # Auto-enrollment, join token
│   ├── errors/                      # Error model, error codes
│   ├── fsm/                         # FSM framework, node lifecycle FSM
│   ├── genesis/                     # Genesis block, manifest, bootstrap slots, recovery
│   ├── governance/                  # Governance engine
│   ├── identity/                    # Node identity
│   ├── intent/                      # Intent data structures
│   ├── join/                        # Join protocol, join service
│   ├── mesh/                        # Mesh manager, mesh FSM, resolver
│   ├── network/                     # Network interfaces, DNS, NAT, packet dispatcher
│   │   ├── sync/                    # SyncService, MembershipSync
│   │   ├── tcp/                     # TCP connector, listener, session
│   │   ├── udp/                     # UDP transport, heartbeat, discovery, gossip
│   │   ├── transport/               # Address resolver, dispatcher, selector
│   │   └── bootstrap/              # Peer cache, seed resolver
│   ├── opcode/                      # Opcode definitions, registry
│   ├── recovery/                    # Recovery engine, CRL
│   ├── runtime/                     # Runtime kernel, dispatcher, executors, middleware
│   │   ├── contracts/               # Native contracts (echo, bootstrap, join, governance, recovery, file)
│   │   └── services/               # Service registry
│   ├── select/                      # Selector, query parser
│   ├── session/                     # Session management
│   ├── state/                       # State structures
│   ├── storage/                     # SQLite store, manifest store, audit store
│   ├── transport/                   # Transport layer, TCP, framing, secure session
│   └── trust/                       # Trust evaluation engine
│
├── cmd/                             # CLI binaries
│   ├── smo/                         # Top-level alias (delegates to smo-cli)
│   ├── smo-cli/                     # Interactive CLI shell (1267 lines)
│   ├── smo-admin/                   # Administration CLI (1071 lines)
│   ├── smo-node/                    # Node daemon (1814 lines)
│   └── smo-debug/                   # Debug tool
│
├── providers/                       # Crypto provider implementations
│   ├── suite1_classical/            # Ed25519+X25519+XChaCha20+Blake3
│   └── suite3_purepqc/             # ML-DSA+ML-KEM
│
├── tests/                           # Tests
│   ├── unit/                        # Unit tests
│   ├── integration/                 # Integration tests (empty)
│   ├── mesh/                        # Mesh tests (empty)
│   ├── chaos/                       # Chaos tests (empty)
│   ├── adversarial/                 # Adversarial tests (empty)
│   └── replay/                      # Replay tests (empty)
│
├── RFC/                             # RFC documents (35 files)
├── docs/                            # Documentation
│   └── discussions/                 # Discussion documents (0040 files)
│
├── third_party/                     # Third-party dependencies
├── tooling/                         # Tooling (clipboard)
├── cmake/                           # CMake modules
├── compiler/                        # Compiler (future)
├── contract/                        # Contract tools (future)
├── transport/                       # Transport helpers (future)
├── trust/                           # Trust helpers (future)
├── storage/                         # Storage helpers (future)
├── protocol/                        # Protocol definitions (future)
├── runtime/                         # Runtime plugins (future)
├── sdk/                             # SDK (future)
├── plugins/                         # Plugins (future)
├── deployments/                     # Deployment scripts
├── examples/                        # Examples
├── reference/                       # Reference implementations
├── acl/                             # ACL templates (future)
└── build/                           # Build output
```

---

## 10. Next Steps / Sprint Plan

### Sprint 37.5 — Release Stabilization (1 week)

| Day | Focus | Items |
|-----|-------|-------|
| 1 | Fix build + tests | R2 (governance to_string), R3 (governance level), R4 (contract version) |
| 2 | Fix build + tests | R5 (missing test bins), R7 (policy_store cmake) |
| 3 | Network hardening | R12 (TCP timeout), R13 (retry), R15 (nonce dedup) |
| 4 | E2E infrastructure | R1 (smoke test script), R14 (manifest_epoch persist) |
| 5 | E2E run + fix bugs | Run full lifecycle, fix what breaks |
| 6 | Gossip readiness | R6 (daemon-side wait) |
| 7 | Polish + release | R8 (--version), R9 (--help), tag 0.0.1 |

### Acceptance Criteria for 0.0.1

```bash
# Must all pass:
smo mesh create mymesh                              # Creates ~/.smo/meshes/mymesh/ with keys
smo mesh publish --listen 0.0.0.0:7777 --ep ...     # Configures bootstrap
smo mesh invite --role member --expire 1h --ep ...  # Prints SMO-JOIN-xxx
smo mesh join --token SMO-JOIN-...                  # Full lifecycle: TCP JOIN → cert → sync → READY

# Start first node:
smo-node --daemon --data /tmp/node1 --port 7777 --seed ...  # Becomes bootstrap

# Start second node:
smo-node --daemon --data /tmp/node2 --port 7778 --seed ...  # Joins via bootstrap

# Both nodes show:
smo mesh list                    # Shows mymesh
smo mesh use mymesh              # Context switches
smo-cli: ls                      # Lists mesh nodes
smo-cli: info                    # Shows mesh state → READY
```

---

## Appendix A: Error Codes (Defined)

| Code | Name | Description |
|------|------|-------------|
| 212 | INVALID_TOKEN | Join Token HMAC mismatch |
| 213 | TOKEN_EXPIRED | Join Token past expiry |
| 214 | BOOTSTRAP_NOT_CONFIGURED | No bootstrap endpoints |
| 215 | TOKEN_REJECTED | Authority rejected token |
| 216 | VERIFY_FAILED | Certificate chain verify failed |
| 217 | MESH_NOT_FOUND | Mesh ID not found |
| 223 | BOOTSTRAP_NOT_CONFIGURED | Daemon start without publish |
| 224 | PORT_UNAVAILABLE | Port bind probe failed |
| 225 | NO_PUBLIC_IP | No public IP detected |
| 450 | EMPTY_SELECTION | Select query has no filters |
| 451 | NO_NODES | No nodes match selection |

## Appendix B: Crypto Suite IDs

| ID | Name | Algorithms |
|----|------|------------|
| `0x0000` | Suite1 Classical | Ed25519 + X25519 + XChaCha20-Poly1305 + Blake3 + HKDF |
| `0x0001` | Suite2 Reserved | Reserved |
| `0x0002` | Suite3 PurePQC | ML-DSA (FIPS 204) + ML-KEM (FIPS 203) + XChaCha20-Poly1305 + Blake3 + HKDF |
| `0x0003` | Suite4 Hybrid | Classical + PQC combined |

Default for new meshes: Suite3 PurePQC (`0x0002`).
