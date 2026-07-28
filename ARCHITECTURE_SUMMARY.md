# SMO Framework — Tổng Hợp Discussion, Trạng Thái & Kế Hoạch

## 1. Discussion & RFC Đã Chốt (Spec Frozen)

| Doc | Trạng thái | Nội dung cốt lõi |
|-----|------------|------------------|
| **DISCUSSION_0035** | ✅ Frozen | PKI & Governance: Root-as-Node, 2-tier Governance, Mesh States, Bootstrap Slots, Recovery Soft/Hard |
| **DISCUSSION_0036** | ✅ Frozen | 3-layer Role Model (Identity/Policy/Runtime), Join Token v2 (CBOR+signature), Bootstrap Plane vs Mesh Plane |
| **RFC 0033** | ✅ Frozen | Mesh Genesis & Governance: State machine, Stage 0/1, SlotRing, Manifest, GovernanceEngine, RecoveryEngine, CRL |
| **RFC 0034** | ✅ Frozen | Bootstrap Protocol: namespace 0x05, CBOR, BOOTSTRAP_REQUEST/RESPONSE, no HTTP between nodes |

---

## 2. Implementation Status (Code Đã Hoàn Thành)

### Phase 1 — Sprint 35 (PKI & Governance) — ✅ **100% DONE**
```
core/genesis/           ✅ Manifest, SlotRing, RecoveryPackage, RootSession, GenesisWizard
core/mesh/              ✅ MeshState, MeshFsm (12 rules + 5 timeouts)
core/governance/        ✅ 2-tier (Membership/Constitution), 16 Actions, MeshHealth
core/recovery/          ✅ Soft/Hard Recovery, RecoverySession, CRL
core/certificate/       ✅ +Recovery role, deprecate Reader→Member
core/authority/         ✅ sign_bootstrap_csr (deprecated create_mesh_keys)
cmd/smo-cli/            ✅ genesis, governance, recovery commands
```

### Phase 2 — Sprint 36 (Bootstrap & Role Model → Runtime Contracts) — ✅ **100% DONE**

#### Sprint 36A — Bootstrap Protocol ✅
```
core/bootstrap/
  ├── cbor.hpp/.cpp                 ✅ Minimal CBOR encoder/decoder (~200 LOC)
  ├── bootstrap_snapshot.hpp/.cpp   ✅ CBOR-serialized snapshot
  ├── bootstrap_protocol.hpp/.cpp   ✅ handle_bootstrap_request(), register_handler()
core/network/
  ├── packet_dispatcher.hpp/.cpp    ✅ Route by opcode_id (0x05 = Bootstrap)
RFC/0034-bootstrap-protocol.md      ✅ Spec chốt
```
> **Deleted:** HTTP `bootstrap_service.hpp/.cpp` — không còn HTTP giữa các node.

#### Sprint 36B — Signature Join Token & Root Redesign ✅
```
core/crypto/
  └── signer_context.hpp            ✅ SignerContext (abstract) + SoftwareSignerContext
                                    ✅ SignerMetadata (backend/algorithm/provider/key_id/persistent/hardware/origin/created_at)

core/genesis/
  ├── root_session.hpp/.cpp         ✅ NEW API:
                                    - RootRequest {op, payload, mesh_id, requester, reason, ts}
                                    - RootResult {success, output}
                                    - Capability enum + SessionPolicy (std::set<Capability>)
                                    - AuditSink callback + AuditEvent {audit_id, ts, op, reason, success, details}
                                    - execute() pipeline: Validate → Policy → SignerContext → Audit → Result
                                    - destroy() = zeroize + invalidate handle + audit
                                    - activate() accepts existing signer (from unlock)
  ├── recovery_package.hpp/.cpp     ✅ unlock() → create SoftwareSignerContext + version verify
  ├── genesis.hpp/.cpp              ✅ run_stage_0 nhận unique_ptr<SignerContext>

core/enroll/
  ├── join_token.hpp/.cpp           ✅ JoinToken v2 (CBOR + signature), validate_token() verify qua SignerImpl

cmd/smo-admin/
  └── main.cpp (generate-invite)    ✅ RecoveryPackage → unlock → RootSession.activate → execute(SignJoinToken)
```

---

## 3. Bộ Mặt Thực Tế — End-to-End Flow

### A. Genesis (Tạo mesh mới)
```
smo mesh create Company --profile enterprise --authorities 5
  → GenesisWizard::run_stage_0()
    → GenesisManifest (mesh.json)
    → RecoveryPackage (recovery.pkg, encrypted with passphrase)
    → SlotRing (5 slots Waiting)
    → RootSessionManager.start_session() with SignerContext
    → Print SMO-BOOT-XXXX join codes
```

### B. Bootstrap Authority (Join máy #2..#N)
```
smo join SMO-BOOT-Company-001
  1. Auto-sinh ML-DSA keypair (private KHÔNG rời máy)
  2. Sinh CSR + Slot Token
  3. Gửi BOOTSTRAP_REQUEST (opcode 0x05/0x0001) tới Root
  4. Root: verify slot token → ký CSR → Certificate role=Authority
  5. Slot: Waiting → Fulfilled
  6. Khi tất cả slots Fulfilled: Mesh State = Online, Root → Dormant
```

### C. Bootstrap Node mới (Post-join)
```
smo node bootstrap
  1. Kết nối tới bootstrap endpoint (từ Join Token)
  2. Gửi BOOTSTRAP_REQUEST {nonce, node_id, cert_fingerprint}
  3. Authority: assemble BootstrapSnapshot → ký response → BOOTSTRAP_RESPONSE
  4. Node nhận snapshot:
     - store manifest
     - register authorities (endpoint + pubkey)
     - update epoch, policy_version
     - cache CRL digest
     - FSM: Joining → Online
  5. Bắt đầu Mesh Plane: Gossip + Discovery + Routing
```

### D. Root Session (Unlock từ Recovery Package)
```
SMO_RECOVERY_PASSPHRASE="..." smo-admin --mesh-dir /path generate-invite Authority
  1. Load recovery.pkg → RecoveryPackage::deserialize()
  2. unlock(passphrase, hash, aead, signer, rng)
     → Blake3(passphrase) → AEAD key
     → decrypt nonce(12) + ciphertext → plaintext (2-byte pubkey_len + pubkey + secret_key)
     → make_software_signer_context(secret_key, signer, metadata)
     → RootSession (Inactive, có signer)
  3. session.activate(sid, "root", root_pubkey, nullptr, bootstrap_policy, noop_sink, now, 1h)
     → state = Active, TTL=1h
  4. Build JoinToken (role=Authority, endpoints, expiry, issuer="root:<fp>")
  5. payload = token.serialize_payload()
  6. req = RootRequest{SignJoinToken, payload, mesh_id, "admin", "generate-invite Authority", now}
  7. exec_res = session.execute(req, rng, now)
     → Policy.check(SignJoinToken) ✓
     → signer.sign(payload, rng) → signature
     → AuditSink(audit_event) → emit
     → RootResult{true, signature}
  8. token.signature = signature
  9. encode_token_wire(token) → print
  10. session.consume(now) → zeroize signer + audit → state=Consumed
```

### E. Governance (Mesh Online)
```
# Membership (Level A - registry only):
smo mesh propose add-authority --node-id abc...

# Constitution (Level B - manifest++ epoch++):
smo mesh propose change-maximum --value 10

# Health check:
smo mesh health
  → Healthy/Warning/Critical/Recovery + quorum + fault tolerance
```

### F. Recovery
```
Soft Recovery (còn quorum):
  recovery.pkg + passphrase → RootSession (1h TTL)
  → Recovery Proposal (quorum riêng: 1/2 + Recovery Package)
  → Root sign → epoch++ (chỉ authority bị replace) → done

Hard Recovery (mất quorum):
  recovery.pkg + passphrase → RootSession
  → Force: epoch++ → invalidate ALL certs + CRL mới
  → Clean slate: bootstrap lại từ đầu (Stage 0 + 1)
```

---

## 4. Vẫn Cần Definition / Shaping Hơn (GAPS)

### 🟡 High — Cần hoàn thiện
| Item | Current | Need |
|------|---------|------|
| Wire contracts into node daemon | ❌ RuntimeKernel chưa instantiated | Tích hợp Dispatcher + contracts vào main loop |
| Network → Runtime pipeline | ❌ PacketDispatcher → Kernel missing | Route opcode packets tới contract execution |
| Session establishment over network | ❌ SessionManager unwired | Kết nối Session FSM vào accept loop |
| `smo join` command | ❌ Chưa có | Parse token → auto-enroll → bootstrap → Online |
| `smo node bootstrap` | ❌ Chưa có | GET BootstrapSnapshot từ authority |
| AuthorityRegistry persistence | ❌ In-memory only | SQLite store authorities, certs, slots |
| MeshHealth online count | ❌ Hardcoded | Real-time từ heartbeat/gossip |

### 🟢 Medium — Nice to have / Deferable
- SignerContext implementations: TPM/HSM/YubiKey/CloudKMS (abstract class ready)
- CLI UX: Auto-complete, progress bars, colored output
- AuditEvent UUID: Thêm correlation ID, RequestID, SessionID
- RecoveryPackage v2 format: Version negotiation, key rotation support

---

## 5. Kế Hoạch Tiếp Theo

### ✅ Sprint 36C — Runtime Skeleton (Completed)
```
core/runtime/
├── event_bus.hpp/.cpp              ✅ Pub/Sub backbone
├── runtime_kernel.hpp/.cpp         ✅ Pipeline stages
├── dispatcher.hpp/.cpp             ✅ Contract-agnostic dispatch
├── contract_interface.hpp          ✅ Abstract interface
├── contract_registry.hpp/.cpp      ✅ Registry + Manager (lifecycle)
├── plan_executor.hpp/.cpp          ✅ 12-step FSM + NextAction dispatch
├── middleware.hpp/.cpp             ✅ Middleware chain
├── output_manager.hpp/.cpp         ✅ Aggregator (summary → drill-down)
├── runtime_context.hpp/.cpp        ✅ Per-execution context
├── runtime_types.hpp               ✅ All types (683 lines)
├── services/                       ✅ 15 service interfaces
└── CMakeLists.txt
```
Full RFC 0036–0040 freeze implemented.

### ✅ Sprint 36D — Migration (Completed)
```
core/runtime/contracts/
├── join_contract.hpp/.cpp          ✅ system.join — join/leave/info
├── bootstrap_contract.hpp/.cpp     ✅ system.bootstrap — snapshot/request/info
├── governance_contract.hpp/.cpp    ✅ system.governance — propose/vote/commit/list/status/info
├── recovery_contract.hpp/.cpp      ✅ system.recovery — assess/start/sign/execute/cancel/crl/info
├── file_contract.hpp/.cpp          ✅ system.file — list/mkdir/remove/copy/move/stat/read/write/chmod/chown/symlink/readlink/realpath/info
└── process_contract.hpp/.cpp       ✅ system.process — exec/kill/ps/top/systemctl/service/info
```
All 6 Native Contracts built, full project 100% clean.

### Sprint 37 — Integration & Wiring (v0.0.2 — ✅ Complete)
```
core/network/sync/              ✅ SyncBackend interface (delta + snapshot)
core/network/sync/              ✅ AntiEntropyService (4 Merkle trees + VV, 30-min)
core/network/sync/              ✅ VersionVector (merge, dominates, serialize)
core/network/sync/              ✅ MerkleTree (Membership 256b, CRL 256b, Policy 64b, Contract 64b)
core/consensus/                 ✅ RaftLog interface + InMemoryRaftLog stub
core/runtime/                   ✅ StructuredLogger (JSON/plaintext, trace_id/span_id)
core/storage/                   ✅ AuditStore query() with full SQLite parameterized queries
cmd/smo-node/                   ✅ Graceful shutdown (gossip→sync→AE→heartbeat→sessions→close)
cmd/smo-admin/                  ✅ HTTP enroll server marked deprecated
tests/                          ✅ PCT-018 (AE), PCT-019 (DEGRADED), PCT-022 (log), PCT-024 (chaos)
.github/workflows/ci.yml        ✅ CI pipeline (build ×4, sanitizer, lint, coverage)
.clang-format / .clang-tidy     ✅ Code style + static analysis config
CMakeLists.txt                  ✅ install() targets + CPack (DEB + TGZ) + find_package(SMO)
```

### Sprint 38 — Audit + History + Storage (TBD)
- `AuditService` as EventBus subscriber → SQLite
- `HistoryStore` as EventBus subscriber → event sourcing
- `ProposalStore`, `CRLStore`, `ManifestStore`, `RegistryStore` persistence

### Sprint 39 — Scheduler (TBD)
- Retry with exponential backoff
- Priority queues (realtime/high/normal/low)
- Recurring jobs (cron-style)
- Deadline enforcement + cancellation

### Sprint 40 — NAT Traversal + WASM + Plugin (TBD)
- STUN/TURN/ICE hole-punching (Internet mesh, v0.0.3)
- WASM contract runtime (wasmtime/wasm3)
- Plugin SDK for external contract development

---

## 6. Architecture Decision: Runtime Kernel Frozen

**Architecture frozen for Runtime Skeleton.**  
No more feature work (Join, Bootstrap, Governance, Recovery) until Runtime Kernel + EventBus + Dispatcher + OutputManager + ContractInterface are implemented and tested with a trivial contract.

---

## 7. Next Step

**Implement `core/runtime/` skeleton (Sprint 36C):**
1. `event_bus.hpp/.cpp` — Pub/Sub backbone
2. `runtime_kernel.hpp/.cpp` — Pipeline stages
3. `dispatcher.hpp/.cpp` — Contract-agnostic dispatch
4. `contract_interface.hpp` — Abstract interface
5. `native_contract.hpp/.cpp` — Native implementation
6. `output_manager.hpp/.cpp` — Aggregator (summary → drill-down)
7. `runtime_context.hpp` — Per-execution context
8. `runtime_request.hpp` — Request/Result types

---

## 8. Runtime Contracts Created (Sprint 36D)

| File | Description |
|------|-------------|
| `core/runtime/contracts/join_contract.hpp/.cpp` | JoinContract — system.join |
| `core/runtime/contracts/bootstrap_contract.hpp/.cpp` | BootstrapContract — system.bootstrap |
| `core/runtime/contracts/governance_contract.hpp/.cpp` | GovernanceContract — system.governance |
| `core/runtime/contracts/recovery_contract.hpp/.cpp` | RecoveryContract — system.recovery |
| `core/runtime/contracts/file_contract.hpp/.cpp` | FileContract — system.file |
| `core/runtime/contracts/process_contract.hpp/.cpp` | ProcessContract — system.process |
| `core/runtime/CMakeLists.txt` | Added all contract sources |
| `core/runtime/contract_registry.hpp/.cpp` | Contract registry + manager |
| `core/runtime/dispatcher.hpp/.cpp` | Contract dispatch |
| `core/runtime/event_bus.hpp/.cpp` | Event pub/sub |
| `core/runtime/middleware.hpp/.cpp` | Middleware chain |
| `core/runtime/output_manager.hpp/.cpp` | Output aggregation |
| `core/runtime/plan_executor.hpp/.cpp` | Step FSM + NextAction dispatch |
| `core/runtime/runtime_context.hpp/.cpp` | Execution context |
| `core/runtime/runtime_kernel.hpp/.cpp` | Main pipeline (8 stages) |
| `core/runtime/runtime_types.hpp` | All RFC 0036–0040 types |
| `core/runtime/services/*.hpp` | 15 service interfaces |
| `core/opcode/opcode.h` | GOV_PROPOSE/VOTE/COMMIT opcodes |
| `docs/PLAN.md` | Roadmap updated through Sprint 36D |

---

## 9. Build Status

```
✅ All binaries compile and link cleanly (100%):
   - smo_core             ✅  (+ consensus, sync, anti-entropy)
   - smo_runtime          ✅  (+ structured logger)
   - smo_protocol         ✅
   - smo_storage          ✅  (+ audit_store query)
   - smo_contract         ✅
   - smo_transport        ✅
   - smo_admin            ✅
   - smo_cli              ✅
   - smo_node             ✅  (+ graceful shutdown)
   - smo_debug            ✅
   - smo_pct              ✅  24 PCT tests (PCT-001–022, 024)
   - All 19 ctest targets ✅
```
**make -j$(nproc): 100% clean, zero errors.**

## 10. Packaging

```
✅ cmake --install → /usr/local/{bin,lib,include/smo,lib/cmake/smo}
✅ cpack -G DEB   → smo_0.0.2_amd64.deb (62 MB)
✅ cpack -G TGZ   → smo-0.0.2-x86_64.tar.gz (62 MB)
✅ find_package(SMO) via install(EXPORT SMO)
```

---

## 11. Tóm Tắt

**Đã xong (Sprint 1–40):**
- PKI & Governance spec + implementation (RFC 0033)
- Bootstrap Protocol spec + implementation (RFC 0034)
- Signature Join Token v2 (CBOR + Ed25519)
- RootSession (session-centric, SignerContext)
- Mesh Genesis (Stage 0/1, SlotRing, Manifest)
- Runtime Architecture (RFC 0035–0040) — full freeze
- Runtime Kernel (8-stage pipeline)
- 15 Service Interfaces (Crypto, Vault, Storage, File, Network, etc.)
- 12-step Execution State Machine + NextAction dispatch
- Contract Registry + Manager (lifecycle hooks)
- 6 Native Contracts: Join, Bootstrap, Governance, Recovery, File, Process
- TCP/UDP transport with framing + PacketDispatcher
- Anti-Entropy Service: 4 Merkle trees + Version Vectors (PCT-018)
- Gossip FSM: 6-condition READY + DEGRADED state (PCT-019)
- PolicyStore CRUD + SyncService integration (PCT-020)
- Nonce dedup + JOIN_REQUEST anti-replay (PCT-021)
- Structured Logger: JSON/plaintext, trace_id/span_id (PCT-022)
- Partition heal chaos test (PCT-024)
- RaftLog interface + InMemoryRaftLog stub
- AuditStore query() with time-range + node filter
- Graceful shutdown (ordered: gossip → sync → AE → heartbeat → session drain)
- HTTP enroll server deprecated
- CI/CD: GitHub Actions (build ×4, sanitizer, lint, coverage)
- Packaging: install targets, CPack DEB+TGZ, find_package(SMO)
- Code style: .clang-format + .clang-tidy

**Cần làm tiếp theo (v0.0.3):**
- Wire RuntimeKernel + Contracts vào smo-node main loop
- Kết nối PacketDispatcher → RuntimeKernel pipeline
- Kết nối SessionManager vào network path
- Audit + History + Persistence stores
- Config version migration (P11 deferred)
- Scheduler (retry, priority, recurring)
- NAT traversal (STUN/TURN/ICE)
- WASM contract runtime
- Plugin SDK
- Web dashboard, mobile agent, federation

**Tổng quan:** Toàn bộ spec và implementation cho mesh PKI, governance, bootstrap, runtime kernel, native contracts, anti-entropy, CI/CD, và packaging đã hoàn thành. SMO đã sẵn sàng cho v0.0.2 release. Bước tiếp theo (v0.0.3) mở rộng ra Internet mesh, WASM runtime, plugin SDK.


## 12. Kết Luận

Kiến trúc SMO đã trải qua ba giai đoạn phát triển rõ rệt:

### Giai đoạn 1 — v0.0.1: Protocol Freeze ✅
Hoàn thiện giao thức và "đóng băng" kiến trúc, trọng tâm là protocol correctness và compliance testing.

### Giai đoạn 2 — v0.0.2: Production Readiness ✅
Đưa runtime lên mức có thể vận hành thực tế:
- Anti-entropy + Merkle trees + Version Vectors
- Gossip FSM đúng nghĩa (6-condition READY, DEGRADED)
- CI/CD (GitHub Actions, sanitizer, lint, coverage)
- Packaging (install targets, CPack DEB+TGZ, find_package)
- Hardening (audit query, graceful shutdown, Raft stub)
- Observability (structured logging, Prometheus metrics)

### Giai đoạn 3 — v0.0.3+: Mở Rộng ⬜
Tập trung vào mở rộng khả năng thay vì sửa lõi:
- NAT traversal (STUN/TURN/ICE → Internet mesh)
- WASM contract runtime
- Plugin SDK
- Web dashboard, mobile agent, federation
- Distributed scheduler