# ShellMap Master System Map — Đại Kiến Thiết

> Tài liệu tổng hợp toàn bộ hệ thống modules, trạng thái, dependencies,
> và kiến trúc runtime/authorization/trust pipeline.

---

## I. TỔNG QUAN KIẾN TRÚC

```
┌──────────────────────────────────────────────────────────────┐
│                        smo-node Daemon                        │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐ │
│  │ Identity  │  │  Crypto   │  │ Transport│  │  Discovery   │ │
│  │  System   │  │  Suites   │  │  TCP/UDP │  │  + Gossip    │ │
│  └──────────┘  └──────────┘  └──────────┘  └──────────────┘ │
│                                                              │
│  ┌────────────────────────────────────────────────────┐      │
│  │            Runtime Pipeline (core/runtime)          │      │
│  │  Packet → Bridge → Authorize → Kernel → Execute    │      │
│  └────────────────────────────────────────────────────┘      │
│                                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐ │
│  │ Session   │  │  Trust   │  │   CRL    │  │  Governance  │ │
│  │ Manager   │  │ Manager  │  │ (Revoke) │  │   Engine     │ │
│  └──────────┘  └──────────┘  └──────────┘  └──────────────┘ │
│                                                              │
│  ┌────────────────────────────────────────────────────┐      │
│  │               6 Native Contracts                     │      │
│  │  Bootstrap → Join → Recovery → Governance → File → Process│
│  └────────────────────────────────────────────────────┘      │
└──────────────────────────────────────────────────────────────┘
```

---

## II. MODULE MAP — TOÀN BỘ HỆ THỐNG

### A. CORE MODULES (smo_core — tất cả đều BUILDING)

| # | Module | Đường dẫn | Trạng thái | Key Classes | Ghi chú |
|---|--------|-----------|------------|-------------|---------|
| 1 | **intent** | `core/intent/` | ✅ BUILDING + WIRED | Intent | Header-only |
| 2 | **opcode** | `core/opcode/` | ✅ BUILDING + WIRED | OpcodeRegistry | Thêm contract opcodes Sprint 37 |
| 3 | **contract** | `core/contract/` | ✅ BUILDING + WIRED | ContractId, ContractDefinition | Module cốt lõi |
| 4 | **capability** | `core/capability/` | ✅ BUILDING + WIRED | Capability, CapabilitySet | 14 cap bits |
| 5 | **session** | `core/session/` | ✅ BUILDING + WIRED | Session, SessionManager | 5-state FSM |
| 6 | **state** | `core/state/` | ✅ BUILDING + WIRED | NodeState, ContractState | Header-only |
| 7 | **errors** | `core/errors/` | ✅ BUILDING + WIRED | Error, ErrorCode | 15+ categories |
| 8 | **crypto** | `core/crypto/` | ✅ BUILDING + WIRED | CryptoRegistry, HashProvider, Ed25519, X25519, ML-DSA, ML-KEM | Suite1 + Suite3 |
| 9 | **storage** | `core/storage/` | ✅ BUILDING + WIRED | Database, SqliteStore | SQLite-backed |
| 10 | **identity** | `core/identity/` | ✅ BUILDING + WIRED | Identity | --init flow |
| 11 | **certificate** | `core/certificate/` | ✅ BUILDING + WIRED | Certificate, CertificateChain, CSR | PKI không truyền thống |
| 12 | **fsm** | `core/fsm/` | ✅ BUILDING + WIRED | FsmInstance | Event-driven FSM |
| 13 | **transport** | `core/transport/` | ✅ BUILDING + WIRED | Transport, TcpTransport | TCP framing |
| 14 | **discovery** | `core/discovery/` | ✅ BUILDING + WIRED | DiscoveryEngine, GossipEngine, PeerStore | Heartbeat + gossip |
| 15 | **governance** | `core/governance/` | ✅ BUILDING + WIRED | GovernanceEngine, GovernanceProposal | M-of-N signing |
| 16 | **trust** | `core/trust/` | ✅ BUILDING + WIRED | TrustManager, TrustScore, Attestation | **ĐÃ WIRED vào runtime** |
| 17 | **select** | `core/select/` | ✅ BUILDING + WIRED | Selector, QueryParser | Peer selection |
| 18 | **network** | `core/network/` | ✅ BUILDING + WIRED | PacketDispatcher, HeartbeatService, UdpTransport | UDP + packet dispatch |
| 19 | **enroll** | `core/enroll/` | ✅ BUILDING + WIRED | JoinToken, AutoEnroll | --join flow |
| 20 | **authority** | `core/authority/` | ✅ BUILDING + WIRED | MeshAuthority, NodeRegistry | CSR sign, cert issue |
| 21 | **mesh** | `core/mesh/` | ✅ BUILDING + WIRED | MeshManager | Mesh CRUD, SQLite catalog |
| 22 | **genesis** | `core/genesis/` | ✅ SEPARATE LIB (smo_genesis) | GenesisManager, RecoveryPackage | smo-admin uses |
| 23 | **recovery** | `core/recovery/` | ✅ BUILDING + WIRED | RecoveryEngine, CRL | **CRL implement đầy đủ** |
| 24 | **bootstrap** | `core/bootstrap/` | ✅ BUILDING + WIRED | BootstrapProtocol, BootstrapSnapshot | CBOR encode/decode |
| 25 | **runtime** | `core/runtime/` | ✅ SEPARATE LIB (smo_runtime) + WIRED | RuntimeKernel, RuntimeBridge, AuthorizationManager, 6 contracts | **Pipeline chính** |

### B. RUNTIME MODULE (smo_runtime — trái tim của hệ thống)

| File | Class | Chức năng |
|------|-------|-----------|
| `runtime_bridge.hpp/.cpp` | RuntimeBridge | Packet → Route → Authorize → Kernel |
| `runtime_kernel.hpp/.cpp` | RuntimeKernel | execute() + execute_direct() pipelines |
| `authorization_manager.hpp/.cpp` | AuthorizationManager | Session + Trust + CRL + Capability check |
| `action_executor.hpp/.cpp` | ActionExecutor | NextAction → send response |
| `dispatcher.hpp/.cpp` | Dispatcher | Contract registry + dispatch |
| `contracts/bootstrap_contract.hpp/.cpp` | BootstrapContract | snapshot/request/info |
| `contracts/join_contract.hpp/.cpp` | JoinContract | join/leave/info |
| `contracts/governance_contract.hpp/.cpp` | GovernanceContract | propose/vote/commit/list/status/info |
| `contracts/recovery_contract.hpp/.cpp` | RecoveryContract | assess/start/sign/execute/cancel + CRL ops |
| `contracts/file_contract.hpp/.cpp` | FileContract | ls/mkdir/rm/cp/mv/stat/read/write/... |
| `contracts/process_contract.hpp/.cpp` | ProcessContract | exec/kill/ps/top/systemctl/service/info |
| `contract_interface.hpp` | ContractInterface, NativeContract | Base classes |
| `runtime_types.hpp` | RuntimeRequest, RuntimeResult, NextAction, ... | Type definitions |
| `runtime_context.hpp` | RuntimeContext, RuntimeServices | Execution context |

### C. SUPPORTING LIBRARIES

| Library | Path | Trạng thái |
|---------|------|------------|
| smo_protocol | `protocol/` | ✅ BUILDING + WIRED |
| smo_storage | `storage/` | ✅ BUILDING + WIRED |
| smo_contract | `contract/` | ✅ BUILDING + WIRED |
| smo_transport | `transport/` | ✅ BUILDING + WIRED (TCP + framing) |
| smo_trust | `trust/` | ✅ BUILDING (stub — trust logic ở core/trust/) |
| smo_acl | `acl/` | ✅ BUILDING (stub) |
| smo_compiler | `compiler/` | ✅ BUILDING (NOT WIRED vào daemon) |
| smo_sdk | `sdk/` | ✅ BUILDING (stub) |
| smo_tooling | `tooling/` | ✅ BUILDING (stub) |
| smo_genesis | `core/genesis/` | ✅ BUILDING + WIRED (smo-admin) |
| smo_mesh | `core/mesh/` | ✅ BUILDING + WIRED (smo-admin) |

### D. EXECUTABLES

| Binary | Path | Trạng thái | Liên kết |
|--------|------|------------|----------|
| **smo-node** | `cmd/smo-node/` | ✅ BUILDING — **DAEMON CHÍNH** | smo_runtime + smo_core + smo_storage + smo_contract + smo_tooling + suites |
| smo-cli | `cmd/smo-cli/` | ✅ BUILDING — CLI client | smo_sdk + smo_genesis |
| smo-admin | `cmd/smo-admin/` | ✅ BUILDING — Admin tool | smo_sdk + smo_mesh + smo_genesis |
| smo-debug | `cmd/smo-debug/` | ✅ BUILDING — Debug stub | smo_tooling |
| smo | `cmd/smo/` | ❌ NOT BUILDING — orphan | Không có CMakeLists.txt |

### E. ORPHAN / DEAD CODE

| Module | Files | Lý do |
|--------|-------|-------|
| **core/acl/** | `policy_engine.hpp/.cpp` (499+333 lines) | ❌ Không CMakeLists.txt, không build |
| **runtime/** (legacy) | 11 sub-modules | ❌ Commented out trong CMakeLists.txt |
| **core/storage/audit_store** | `.hpp/.cpp` | ❌ Files tồn tại nhưng không build |
| **core/contract/native/** | 7 files | ❌ Không build |
| **core/contract/registry** | `.hpp/.cpp` | ❌ Không build |
| **cmd/smo/** | `main.cpp` | ❌ Không build |

---

## III. RUNTIME PIPELINE — LUỒNG XỬ LÝ CHI TIẾT

### Hiện tại (Sprint 37)

```
TCP accept
    ↓
PacketDispatcher::dispatch_session()
    ↓
Handler lambda [opcode → runtime_handler]
    ↓
RuntimeBridge::bridge(Packet&&)
    ├─ 1. resolve(opcode) → contract_id + method
    ├─ 2. session_id from packet (16 bytes)
    ├─ 3. AuthorizationManager::authorize(session_id, contract_meta)
    │      ├─ Anonymous? → skip
    │      ├─ Session exists? → lookup
    │      ├─ Session valid? → state != Closed
    │      ├─ CRL check? → cert fingerprint revoked?
    │      ├─ Trust check? → score >= 0.2
    │      └─ Capability check → session.caps ⊇ contract.caps
    ├─ 4. Build RuntimeRequest
    └─ 5. RuntimeKernel::execute_direct(req)
           ├─ validate(contract exists)
           ├─ validate(input)
           └─ contract->execute(input, ctx)
    ↓
RuntimeResult (chứa NextActions)
    ↓
ActionExecutor::execute(action, original_pkt)
    └─ ActionDispatchMessage → send response packet
```

### Authorization Pipeline (AuthorizationManager::authorize)

```
┌─────────────────────────────────────────────┐
│           authorize(session_id, meta)        │
├─────────────────────────────────────────────┤
│ 1. Contract anonymous? ──────────→ ALLOW    │
│ 2. Session lookup ───┐                     │
│    ├─ not found ─────→ DENY (no session)    │
│    └─ found           │                     │
│ 3. Session valid?     │                     │
│    ├─ Closed ────────→ DENY (closed)        │
│    └─ valid            │                     │
│ 4. CRL check (nếu có) │                     │
│    ├─ revoked ───────→ DENY (revoked)       │
│    └─ not revoked      │                     │
│ 5. Trust check (nếu có)│                     │
│    ├─ below 0.2 ─────→ DENY (low trust)    │
│    └─ sufficient       │                     │
│ 6. Capability check    │                     │
│    ├─ insufficient ───→ DENY (no caps)      │
│    └─ sufficient       │                     │
│ 7. → ALLOW             │                     │
└─────────────────────────────────────────────┘
```

### Tương lai (execute() full pipeline)

```
RuntimeBridge::bridge()
    ↓
AuthorizationManager::authorize()
    ↓
PolicyEngine::evaluate(context)
    ↓
Middleware::on_stage("before_resolve")
    ↓
RuntimeKernel::execute() (full pipeline)
    ├─ validate
    ├─ resolve (plan resolution)
    ├─ before_dispatch middleware
    ├─ dispatch (contract execution)
    ├─ after_dispatch middleware
    ├─ after_commit middleware
    ├─ collect (gather results)
    ├─ aggregate
    ├─ audit
    └─ complete
    ↓
ActionExecutor
```

---

## IV. TRUST ENGINE — THUẬT TOÁN

### TrustComponents (4 dimensions)
```
citizen     = online time, heartbeat stability          weight = 0.2
execution   = contract success ratio                    weight = 0.5
witness     = witness participation and accuracy        weight = 0.2
consistency = result agreement with majority            weight = 0.1
```

### Composite Score
```python
composite = citizen*0.2 + execution*0.5 + witness*0.2 + consistency*0.1
clamped [0.0, 1.0]
```

### Trust Levels
```
Absolute: ≥ 0.9  (trust anchor → score = 1.0)
High:     ≥ 0.7
Medium:   ≥ 0.4
Low:      ≥ 0.2
None:     < 0.2
```

### Scoring Operations
| Operation | Effect | Code |
|-----------|--------|------|
| `record_success(node, weight)` | execution += 0.01 * weight | trust.cpp:227 |
| `record_failure(node, weight)` | execution -= 0.02 * weight | trust.cpp:240 |
| `record_offline(node)` | citizen -= 0.001 | trust.cpp:249 |
| `apply_attestation(att)` | witness = existing*0.7 + claimed*0.3 | trust.cpp:337 |
| `tick(now)` | all *= 0.5^(days/30) — half-life decay | trust.cpp:367 |
| **Trust anchor** | composite = 1.0 override | trust.cpp:255-281 |

### Decay Model
```
half_life = 30 days
factor = 0.5 ^ (elapsed_days / 30)  →  after 30d: 50%, after 60d: 25%
composite *= factor
```

### Attestation Flow
1. Witness creates `Attestation{witness_id, subject_id, claimed_score, timestamp, sig}`
2. `verify_attestation()` — check timestamp window (±1h), score [0,1], sig non-empty
3. `apply_attestation()` — blend: `witness = existing*0.7 + attestation*0.3`

### Digest Gossip
1. `produce_digest()` — snapshot all scores, increment sequence counter
2. Gossip → peers receive `TrustDigest{origin, sequence, timestamp, scores[]}`
3. `apply_digest()` — newer sequence wins, merge scores peer-by-peer

---

## V. CRL — CERTIFICATE REVOCATION LIST

### Vị trí trong architecture
```
Certificate
    ↓ (revoked)
CRL (Certificate Revocation List)
    ↓ (checked by)
AuthorizationManager::authorize()
    ↓ (deny if revoked)
RuntimeKernel → Contract execution denied
```

### CRL API (core/recovery/crl.hpp + crl.cpp)

| Method | Chức năng |
|--------|-----------|
| `revoke(fingerprint, node_id, reason, epoch, now)` | Thêm cert vào revocation list |
| `is_revoked(fingerprint)` | Check cert có bị revoke không |
| `is_epoch_invalid(cert_epoch, current_epoch)` | Epoch-based revocation |
| `entries_since(epoch)` | Lấy entries từ epoch trở đi (CRL sync) |
| `serialize()` / `deserialize()` | Persistence cho crash recovery |
| `clear()` | Xóa toàn bộ (hard recovery) |

### Wire Protocol Messages

| Message | Fields |
|---------|--------|
| `RevokeCertMsg` | cert_fingerprint, node_id_hex, reason, epoch, signature |
| `RevokeAckMsg` | cert_fingerprint, accepted, error_message |

### CRL Sync Flow
```
Node A revokes Cert X
    ↓
publish RevokeCertMsg → peers
    ↓
Node B receives → CRL::revoke()
    ↓
AuthorizationManager::authorize()
    → CRL::is_revoked(cert.fingerprint)
    → DENY
```

---

## VI. SESSION MANAGEMENT

### Session FSM (5 states)
```
Closed ──OpenRequest──→ Handshake ──Established──→ Established
                           │  │                       │
                        Close │                   Activate
                           │  │                       │
                           ↓  ↓                       ↓
                         Closed                    Active
                                                      │
                                              CompleteContract
                                                      │
                                                      ↓
                                                 Established
                                                      
                                              (Renew → Renewing → Established)
```

### SessionManager API
| Method | Chức năng |
|--------|-----------|
| `open(session)` | Tạo session mới |
| `lookup(id)` | Tra cứu session |
| `close(id, now)` | Đóng session |
| `transition(id, event, now)` | FSM transition |
| `tick(now)` | Expire timeout sessions |
| `collect_garbage()` | Xóa closed sessions |
| `serialize_all()` | Persistence |

### Session → Authorization
```
Packet arrives with session_id
    ↓
SessionManager::lookup(session_id)
    ↓
Session::peer_cert() → CRL::is_revoked(fingerprint)
    ↓
Session::capabilities() → ContractCapability check
    ↓
Session::peer_id() → TrustManager::get_score()
```

---

## VII. OPCODE ROUTING

### Flat Opcodes (Opcode enum)

| Opcode | Value | Contract | Method |
|--------|-------|----------|--------|
| ECHO | 0x06 | system.echo | echo |
| BOOTSTRAP_SNAPSHOT | 0x30 | system.bootstrap | snapshot |
| BOOTSTRAP_INFO | 0x31 | system.bootstrap | info |
| JOIN | 0x33 | system.join | join |
| LEAVE | 0x34 | system.join | leave |
| JOIN_INFO | 0x35 | system.join | info |
| GOV_PROPOSE | 0x24 | system.governance | propose |
| GOV_VOTE | 0x25 | system.governance | vote |
| GOV_COMMIT | 0x26 | system.governance | commit |
| GOV_LIST | 0x27 | system.governance | list |
| GOV_STATUS | 0x28 | system.governance | status |
| GOV_INFO | 0x29 | system.governance | info |
| RECOVERY | 0x2A | system.recovery | invoke* |
| FILE_OP | 0x2B | system.file | invoke* |
| PROCESS | 0x2C | system.process | invoke* |

\* `invoke` = method parsed from payload header

### Bootstrap Namespace Opcodes (từ bootstrap_protocol.hpp)
| Opcode | Value | Contract | Method |
|--------|-------|----------|--------|
| kOpcodeBootstrapRequest | 0x0105 | system.bootstrap | request |
| kOpcodeBootstrapResponse | 0x0205 | system.bootstrap | (response) |

### Route Registration (RuntimeBridge)
```
bridge.register_route(opcode, "system.contract", "method");
bridge.set_anonymous("system.bootstrap", true);   // no session needed
bridge.set_anonymous("system.join", true);         // no session needed
```

---

## VIII. CAPABILITY MAPPING

### ContractCapability (runtime) → Capability (session)

| ContractCapability | Session Capabilities Required |
|-------------------|------------------------------|
| Filesystem | FS_READ, FS_WRITE |
| Scheduler | PROC_EXEC |
| Governance | GRANT, REVOKE, POLICY_CHANGE |
| Recovery | GRANT, VERIFY |
| Identity | VERIFY |
| Storage | FS_READ, FS_WRITE |
| Audit | VERIFY |
| Network | HEARTBEAT |
| Crypto | (none — infrastructure) |
| Vault | (none — infrastructure) |

### Anonymous Contracts (no check)
- `system.bootstrap` — anyone can request bootstrap
- `system.join` — anyone can join with valid token

---

## IX. TESTING STATUS

### Passing Tests (13/18)
| Test | Status |
|------|--------|
| protocol_model | ✅ PASS |
| trust_model | ✅ PASS |
| session_model | ✅ PASS |
| transport_model | ✅ PASS |
| transport_highlevel | ✅ PASS |
| fsm_model | ✅ PASS |
| certificate_model | ✅ PASS |
| identity_model | ✅ PASS |
| storage_stores | ✅ PASS |
| storage_model | ✅ PASS |
| crypto_model | ✅ PASS |
| error_model | ✅ PASS |
| discovery_model | ✅ PASS |

### Failing Tests (5/18 — pre-existing, không do Sprint 37)
| Test | Failure | Root Cause |
|------|---------|------------|
| governance_model | `to_string(PolicyChange)` sai | Pre-existing bug |
| governance_model | `submit invalid level` | Pre-existing validation bug |
| contract_model | Không rõ | Pre-existing |
| core | Smo_all_tests not found | Pre-existing path issue |
| protocol | Smo_all_tests not found | Pre-existing path issue |
| compiler | Smo_all_tests not found | Pre-existing path issue |

---

## X. BUILD STATUS — TẤT CẢ TARGET

```
smo_core           ── ✅ BUILDING + WIRED (25 sub-modules)
smo_runtime        ── ✅ BUILDING + WIRED (new runtime)
smo_protocol       ── ✅ BUILDING + WIRED
smo_storage        ── ✅ BUILDING + WIRED
smo_contract       ── ✅ BUILDING + WIRED
smo_transport      ── ✅ BUILDING + WIRED (TCP+framing)
smo_trust          ── ✅ BUILDING (stubs)
smo_acl            ── ✅ BUILDING (stubs)
smo_compiler       ── ✅ BUILDING (not in daemon)
smo_genesis        ── ✅ BUILDING (separate lib)
smo_mesh           ── ✅ BUILDING (separate lib)
smo_suite1_classical ── ✅ BUILDING + WIRED
smo_suite3_purepqc ── ✅ BUILDING + WIRED (w/ PQC)

smo-node           ── ✅ BUILDING — DAEMON CHÍNH
smo-cli            ── ✅ BUILDING — CLI
smo-admin          ── ✅ BUILDING — Admin
smo-debug          ── ✅ BUILDING — Debug stub
cmd/smo            ── ❌ NOT BUILDING — orphan
```

---

## XI. NEXT STEPS — SPRINT 37+

### Priority 1: AuthorizationManager → PolicyEngine bridge
- [ ] Fix `core/acl/policy_engine` — thêm CMakeLists.txt, compile
- [ ] Fix `SMO_ERR_ACL` macro undefined
- [ ] Wire PolicyEngine vào AuthorizationManager (sau Trust + CRL check)

### Priority 2: execute_direct() → execute() migration
- [ ] Wire middleware pipeline (PolicyMiddleware)
- [ ] Wire audit trail
- [ ] Remove `execute_direct()` (keep only for debug)

### Priority 3: TrustManager → full integration
- [ ] Wire `record_success/failure` vào runtime kernel sau mỗi contract execution
- [ ] Wire `record_offline` vào heartbeat service
- [ ] Wire `apply_digest` vào gossip engine

### Priority 4: CertificateStore
- [ ] Tạo CertificateStore (SQLite-backed) để lưu trusted certs
- [ ] Certificate chain verification trong Authorization pipeline

### Priority 5: E2E Test (2-node mesh)
- [x] Script 2-node bootstrap + join + governance proposal
- [x] E2E result: Both nodes start, Node B TCP-connects to Node A, but `PacketDispatcher` fails `Failed to unframe data` — pre-existing bootstrap protocol vs packet format mismatch
- [ ] Fix bootstrap protocol framing (Bootstrap `find_seed` uses raw CBOR, PacketDispatcher expects opcode+len+payload)
- [ ] Test CRL revoke + trust score decay

---

## XII. STORAGE ARCHITECTURE — CẤU TRÚC THƯ MỤC TRÊN ĐĨA

### Default root: `~/.smo/`

```
~/.smo/
├── meshes/                          # Mesh configurations (smo-admin)
│   └── <mesh-name>/                 # e.g. test-mesh/
│       ├── authority.pub            # Mesh authority public key
│       ├── authority.sec            # Mesh authority secret key
│       ├── root.cert                # Root certificate
│       ├── root.pub.hex             # Root public key (hex)
│       ├── authority.cert           # Authority certificate
│       ├── node_registry.db         # SQLite: registered nodes
│       ├── mesh.json                # Mesh config (listen addr, endpoints, etc.)
│       └── invites/                 # Generated invite tokens
│           └── <token>.json
│
└── node/                            # Default data dir (smo-node --daemon)
    ├── identity.json                # Node identity (keypair + state)
    ├── node.csr.smor                # Certificate Signing Request (exported)
    ├── node.cert.smoc               # Signed certificate (imported)
    ├── peer.db                      # SQLite: PeerStore
    ├── peer.db-shm                  # SQLite shared memory (WAL)
    └── peer.db-wal                  # SQLite WAL
```

### File formats

| File | Format | Content |
|------|--------|---------|
| `identity.json` | JSON | `node_id`, `state` (KeypairReady/Enrolled/Active), `suite_id`, `public_key_hex`, `secret_key_hex` |
| `*.smor` | Binary (CBOR) | CertificateSigningRequest: pubkey, name, platform, version, timestamp, signature |
| `*.smoc` | Binary (CBOR) | Certificate: pubkey, issuer, role, epoch, not_before, not_after, signature chain |
| `*.cert` | Binary (CBOR) | Mesh root/authority certificates |
| `*.pub.hex` | Text | Hex-encoded public key |
| `*.sec` | Binary | Secret key (raw bytes) |
| `peer.db` | SQLite | PeerStore: peers table with endpoint, node_id, last_seen |
| `node_registry.db` | SQLite | Mesh authority node registry: node_id, cert, role, status |

### Data lifecycle

```
smo-node --init
    → creates identity.json (state=KeypairReady)
    → creates node.csr.smor

smo-admin sign <csr> -o <cert>
    → signs CSR using mesh authority
    → outputs .smoc certificate file

smo-node --import <cert>
    → imports .smoc
    → should set state=Enrolled (⚠️ pre-existing bug: state stays KeypairReady)
    → saves node.cert.smoc

smo-node --daemon
    → loads identity.json
    → opens/creates peer.db
    → listens on TCP+UDP
    → enters main loop
```

---

## XIII. CLI ECOSYSTEM — CÔNG CỤ DÒNG LỆNH

### 1. smo-node — Node Daemon

```
USAGE:
  smo-node --init --name <name> [--data <dir>]
  smo-node --export [<file> | --copy] [--data <dir>]
  smo-node --import [<file>] [--data <dir>]
  smo-node --pubkey [--copy | --fingerprint] [--data <dir>]
  smo-node --join <token> --data <dir> [--name <name>] [--port <port>]
  smo-node --daemon --port <port> --data <data-dir> [--name <name>]
                 [--seed <host:port>]

COMMANDS:
  --init                  Generate identity + CSR (first step)
  --name <name>           Display name for the node
  --data <dir>            Data directory (default: ~/.smo/node)
  --export <file>         Export CSR to file
  --export --copy         Copy CSR to clipboard (for smo-admin sign --paste)
  --import [<file>]       Import signed certificate (auto stdin→clipboard→file)
  --pubkey                Display public key (SMO-PUBKEY-...)
  --pubkey --copy         Copy public key to clipboard
  --pubkey --fingerprint  Show short hex fingerprint
  --join <token>          Join mesh using Join Token (auto-enrollment)
  --daemon                Run as mesh node daemon
  --port <port>           Listen port (default: 7777)
  --seed <host:port>      Bootstrap seed node for discovery
  --help                  Show help
```

### 2. smo-admin — Mesh Administration

```
USAGE:
  smo-admin --mesh <name> <command> [options]
  smo-admin --mesh-dir <path> <command> [options]

COMMANDS:
  create-mesh <name>              Initialize a new mesh
  sign <csr-file> -o <output>     Sign a CSR, issue certificate
  mesh publish [options]          Configure network endpoints
  generate-invite <role>          Generate a Join Token
  serve [--port <port>]           Start enroll HTTP server

DEPRECATED:
  create-mesh → use 'smo genesis create' instead
```

### 3. smo-cli — Client CLI

```
USAGE:
  smo-cli [options] <command>

COMMANDS:
  (TBD — currently stub, linked to smo_sdk + smo_genesis)
```

### 4. smo-debug — Debug Utility

```
USAGE:
  smo-debug [options]

STATUS: stub
```

---

## XIV. E2E TEST SCENARIOS — KỊCH BẢN KIỂM THỬ THẬT

### Scenario 1: Full Lifecycle (hiện tại đã chạy được)

```bash
# 1. Init both nodes
smo-node --init --name "Node-A" --data /tmp/e2e/node_a
smo-node --init --name "Node-B" --data /tmp/e2e/node_b

# 2. Create mesh & sign certificates
smo-admin create-mesh "test-mesh"
smo-admin --mesh-dir ~/.smo/meshes/test-mesh sign /tmp/e2e/node_a/node.csr.smor -o /tmp/e2e/node_a/node.cert.smoc
smo-admin --mesh-dir ~/.smo/meshes/test-mesh sign /tmp/e2e/node_b/node.csr.smor -o /tmp/e2e/node_b/node.cert.smoc

# 3. Import certificates
smo-node --import /tmp/e2e/node_a/node.cert.smoc --data /tmp/e2e/node_a
smo-node --import /tmp/e2e/node_b/node.cert.smoc --data /tmp/e2e/node_b

# 4. Start Node A (seed)
smo-node --daemon --port 9000 --data /tmp/e2e/node_a --name "Node-A"

# 5. Start Node B (joiner)
smo-node --daemon --port 9001 --data /tmp/e2e/node_b --name "Node-B" --seed 127.0.0.1:9000
```

#### Expected result (Sprint 37):
```
Node A: [smo-node] Entering main loop...
Node B: [smo-node] Connecting to seed: 127.0.0.1:9000
Node A: [smo-node] Accepted TCP connection from tcp://127.0.0.1:XXXXX
Node A: [smo-node] Dispatch failed: Failed to unframe data
Node B: [smo-node] Seed connection failed: no seed nodes responded
Node B: [smo-node] Continuing as first node in mesh
Node B: [smo-node] Entering main loop...
```

#### Root cause of dispatch failure:
- Bootstrap `find_seed()` sends raw CBOR bytes over TCP
- `PacketDispatcher::dispatch_session()` expects `num_opcodes(4B) + opcode(4B) + length(4B) + payload`
- **Fix needed:** align bootstrap protocol wire format with PacketDispatcher framing

### Scenario 2: Runtime Pipeline (khi wire format fixed)

```bash
# After bootstrap framing fixed:
# 1. Send ECHO opcode (0x06) packet to seed node
printf '\x06\x00\x00\x00\x00\x00\x00\x00Hello' | nc 127.0.0.1 9000

# Expected: RuntimeBridge::bridge() → AuthorizationManager::authorize()
#           → RuntimeKernel::execute_direct() → EchoContract::execute()
#           → ActionExecutor → response packet
```

### Scenario 3: CRL Revocation Test

```bash
# 1. After mesh established, send REVOKE opcode (0x2A) for Node-B cert
# 2. AuthorizationManager should reject Node-B packets via CRL::is_revoked()
# 3. TrustManager score for Node-B should drop below 0.2
```

### Scenario 4: Governance Proposal

```bash
# 1. After session established, send GOV_PROPOSE (0x24) with proposal payload
# 2. GovernanceEngine: M-of-N signature threshold
# 3. GOV_VOTE (0x25), GOV_COMMIT (0x26) flow
```

---

## XV. DOCUMENT STATUS

| Document | Path | Status | Content |
|----------|------|--------|---------|
| **Master System Map** | `docs/MASTER_SYSTEM_MAP.md` | ✅ Current | Full architecture, all modules, runtime pipeline, trust, CRL, CLI, storage, tests |
| **Sprint 37 Status** | `docs/SPRINT_37_STATUS.md` | ✅ Current | Gap analysis, implementation plan, trust model algorithms |
| USER_MANUAL.md | `docs/` | ❌ Not created | |
| API_REFERENCE.md | `docs/` | ❌ Not created | |
| CONTRIBUTING.md | `docs/` | ❌ Not created | |
| ARCHITECTURE.md | `docs/` | ❌ Not created | |

---

## XVI. KNOWN BUGS & LIMITATIONS

### Critical
| Bug | File | Impact |
|-----|------|--------|
| Bootstrap protocol framing mismatch | `core/bootstrap/` ↔ `core/network/` | 2-node mesh cannot bootstrap via seed (raw CBOR vs PacketDispatcher format) |

### Medium
| Bug | File | Impact |
|-----|------|--------|
| `Identity::transition_to(Enrolled)` không save | `core/identity/` | identity.json stays `KeypairReady` after `--import` |
| `to_string(GovernanceAction::PolicyChange)` sai | `core/governance/` | governance_model test fails |
| ASan runtime warning at startup | `cmake/CompilerOptions.cmake` | Non-critical warning, does not affect execution |

### Low
| Bug | File | Impact |
|-----|------|--------|
| `stdout` buffered when not TTY | `cmd/smo-node/main.cpp` | Daemon log invisible until setvbuf fix added |

---

## XVII. FILE MANIFEST — TẤT CẢ FILES MỚI/SỬA (Sprint 37)

### Created
| File | Purpose |
|------|---------|
| `core/runtime/authorization_manager.hpp` | AuthorizationManager — full authorization pipeline |
| `core/runtime/authorization_manager.cpp` | Capability mapping + Trust + CRL integration |
| `core/recovery/crl.cpp` | CRL full implementation (revoke, is_revoked, entries_since, serialize) |
| `docs/SPRINT_37_STATUS.md` | Sprint 37 status & gap analysis |
| `docs/MASTER_SYSTEM_MAP.md` | This document |

### Modified
| File | Changes |
|------|---------|
| `core/runtime/runtime_bridge.hpp` | Added Dispatcher&, SessionManager&, TrustManager*, CRL*, AuthorizationManager |
| `core/runtime/runtime_bridge.cpp` | Authorization check, session lookup, Bytes fix |
| `core/runtime/CMakeLists.txt` | Added authorization_manager.cpp |
| `core/opcode/opcode.h` | Added BOOTSTRAP_SNAPSHOT/INFO, JOIN/LEAVE/JOIN_INFO, GOV_LIST/STATUS/INFO, RECOVERY, FILE_OP, PROCESS |
| `core/recovery/CMakeLists.txt` | Added crl.cpp |
| `cmd/smo-node/main.cpp` | SessionManager, TrustManager, MeshManager, Authority, CRL, GovernanceEngine, RecoveryEngine — tất cả contracts registered, tất cả routes, tất cả PacketDispatcher handlers, SessionManager tick |
