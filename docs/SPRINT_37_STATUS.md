# Sprint 37 — Implementation Status & Gap Analysis

## Mục tiêu
Wire BootstrapContract + JoinContract + SessionManager + AuthorizationManager + GovernanceContract qua RuntimeBridge → RuntimeKernel → ActionExecutor pipeline, đạt 2-node ShellMap mesh thật (không echo server).

---

## I. KIẾN TRÚC TỔNG THỂ SAU KHI ĐỌC TOÀN BỘ CODE

```
TCP accept
    ↓
PacketDispatcher::dispatch_session()              [network/packet_dispatcher.hpp]
    ↓
Handler lambda (smo-node/main.cpp)
    ↓
RuntimeBridge::bridge(Packet)                     [runtime/runtime_bridge.hpp]
    ├─ resolve(opcode) → contract_id + method
    ├─ authorize(session_id, contract_metadata)    ← AuthorizationManager (MỚI)
    └─ RuntimeKernel::execute_direct(req)          [runtime/runtime_kernel.hpp]
         ├─ validate(contract tồn tại)
         ├─ validate(input)
         ├─ *** authorization check ***            ← HIỆN TẠI THIẾU
         └─ contract->execute(input, ctx)
    ↓
RuntimeResult (chứa NextActions)
    ↓
ActionExecutor::execute(action, original_pkt)     [runtime/action_executor.hpp]
    └─ ActionDispatchMessage → send response packet
```

---

## II. NHỮNG GÌ ĐÃ ĐỌC & PHÂN TÍCH

### A. Runtime Pipeline (ĐÃ HOẠT ĐỘNG)
| Component | File | Trạng thái |
|-----------|------|------------|
| RuntimeBridge | `core/runtime/runtime_bridge.hpp/.cpp` | ✅ Hoạt động, bridge Packet → RuntimeRequest → Kernel |
| RuntimeKernel | `core/runtime/runtime_kernel.hpp/.cpp` | ✅ `execute_direct()` hoạt động, nhưng THIẾU authorization |
| ActionExecutor | `core/runtime/action_executor.hpp/.cpp` | ✅ DispatchMessage → send response |
| Dispatcher | `core/runtime/dispatcher.hpp/.cpp` | ✅ register/get/has/execute contract |
| PlanResolver | `core/runtime/runtime_types.hpp` (inline) | ✅ Default fallback plan |

### B. Contracts (ĐÃ IMPLEMENT ĐỦ LOGIC)
| Contract | File | Methods |
|----------|------|---------|
| BootstrapContract | `contracts/bootstrap_contract.hpp/.cpp` | snapshot, request, info |
| JoinContract | `contracts/join_contract.hpp/.cpp` | join, leave, info |
| GovernanceContract | `contracts/governance_contract.hpp/.cpp` | propose, vote, commit, list, status, info |
| RecoveryContract | `contracts/recovery_contract.hpp/.cpp` | assess, start, sign, execute, cancel, crl_revoke, crl_check, crl_sync, info |
| FileContract | `contracts/file_contract.hpp/.cpp` | list, mkdir, remove, copy, move, stat, read, write, chmod, chown, symlink, readlink, realpath, info |
| ProcessContract | `contracts/process_contract.hpp/.cpp` | exec, kill, ps, top, systemctl, service, info |

**Tất cả đều được compile trong `core/runtime/CMakeLists.txt`** nhưng CHƯA được register vào Dispatcher trong `smo-node/main.cpp`.

### C. Session System (ĐÃ IMPLEMENT)
| Component | File | Trạng thái |
|-----------|------|------------|
| SessionId (128-bit) | `session.hpp:38-49` | ✅ derive(), to_bytes(), from_bytes() |
| Session FSM (5 states) | `session.hpp:54-134` | ✅ Closed→Handshake→Established→Active→Renewing |
| Session::create() | `session.cpp:159-178` | ✅ Khởi tạo với CapabilitySet |
| Session::on_event() | `session.cpp:180-194` | ✅ FSM transition |
| Session::has_capability() | `session.hpp:117-119` | ✅ Kiểm tra Capability |
| SessionManager | `session.hpp:139-171` | ✅ open/lookup/close/transition/tick/GC/serialize_all |
| SessionOpenMsg | `session.hpp:178-185` | ✅ Wire format cho handshake |
| SessionCloseMsg | `session.hpp:189-194` | ✅ Wire format cho close |

**Vấn đề:** SessionManager CHƯA được khởi tạo trong daemon loop, CHƯA có session nào được tạo khi TCP accept.

### D. Capability System (HAI HỆ THỐNG SONG SONG)

#### Hệ thống 1: `Capability` (capability.h) — Session-level permissions
```cpp
enum class Capability : uint8_t {
    FS_READ=0, FS_WRITE, PROC_EXEC, NET_BIND, SESSION_CREATE,
    NODE_QUARANTINE, GRANT, REVOKE, DISTRIBUTE, POLICY_CHANGE,
    NODE_BOOTSTRAP, VERIFY, CUSTOM_CONTRACT, HEARTBEAT
};
using CapabilitySet = std::bitset<14>;  // COUNT_ = 14
```
Dùng trong: `Session::capabilities_`, preset roles (reader/contributor/authority).

#### Hệ thống 2: `ContractCapability` (runtime_types.hpp) — Runtime resource requirements
```cpp
enum class ContractCapability : size_t {
    Crypto=0, Vault=1, Network=2, Filesystem=3, Scheduler=4,
    Governance=5, Recovery=6, Identity=7, Storage=8, Audit=9, Metrics=10
};
using ContractCapabilities = std::bitset<64>;
```
Dùng trong: `ContractMetadata::required_capabilities`, `RuntimeServices::granted_caps`.

**Vấn đề:** Hai hệ thống cap này KHÔNG CÓ mapping với nhau. Authorization check (`session.capabilities ⊇ contract.required_capabilities`) không thể thực hiện trực tiếp vì khác enum.

### E. Authorization (THIẾU HOÀN TOÀN)

| Thành phần | Trạng thái |
|-----------|-----------|
| AuthorizationManager class | ❌ Không tồn tại |
| Capability check trong RuntimeKernel::execute_direct() | ❌ Không có |
| Anonymous contract list (bootstrap/join) | ❌ Không có |
| Session → Contract capability mapping | ❌ Không có |

### F. Policy Engine (TỒN TẠI NHƯNG DEAD CODE)

| File | Trạng thái |
|------|-----------|
| `core/acl/policy_engine.hpp` (499 lines) | ✅ Code đầy đủ (7 presets, YAML parsing, trust score conditions) |
| `core/acl/policy_engine.cpp` (333 lines) | ✅ Implementation đầy đủ |
| `core/acl/CMakeLists.txt` | ❌ KHÔNG TỒN TẠI — không được build |
| `core/CMakeLists.txt` | ❌ Không có `add_subdirectory(acl)` |
| `SMO_ERR_ACL` macro | ❌ Không được định nghĩa trong error.hpp |
| PolicyMiddleware (runtime/middleware.cpp) | ❌ `// TODO: Integrate with PolicyEngine` — no-op |

**Kết luận:** PolicyEngine là dead code — không compile được, không link vào bất kỳ thư viện nào.

### G. Trust Engine (ĐÃ IMPLEMENT NHƯNG CHƯA WIRED)

| File | Dòng | Chức năng |
|------|------|-----------|
| `core/trust/trust.hpp` | 215 | TrustManager class: score, anchor, attestation, digest |
| `core/trust/trust.cpp` | 464 | Implementation đầy đủ |

**Thuật toán Trust:**
1. **4 dimensions** (trust.hpp:55-60): citizen (0.2), execution (0.5), witness (0.2), consistency (0.1)
2. **Composite score** (trust.cpp:86-101): `Σ(dimension × weight)`, clamped [0, 1]
3. **Trust levels** (trust.cpp:219-225): None(<0.2), Low(0.2-0.4), Medium(0.4-0.7), High(0.7-0.9), Absolute(≥0.9)
4. **Decay** (trust.cpp:367-387): Half-life model — `factor = 0.5^(days/half_life)`, mặc định half-life = 30 ngày
5. **Attestation blend** (trust.cpp:333-341): 70% existing + 30% attestation score
6. **Penalties**: offline (-0.001), rejected (-0.01), no_authority (-0.05)
7. **Success reward**: +0.01, **Failure penalty**: -0.02
8. **Trust anchor** (trust.cpp:255-281): Nếu là trust anchor → score = 1.0 (override)

**Vấn đề:** TrustManager không được gọi từ bất kỳ production code nào ngoài test. Runtime không biết đến TrustManager. Selector hardcode trust score = 0.5.

### H. Opcode Routing (CẦN THIẾT KẾ LẠI)

**Hiện tại:**
- Opcode enum (opcode.h): flat values 0x01-0x06, 0x10-0x26, 0xFF
- Bootstrap protocol (bootstrap_protocol.hpp): namespace scheme — `kOpcodeBootstrapRequest = 0x05 | (0x0001 << 8) = 0x0105`
- RuntimeBridge: dùng `uint32_t` opcode_id để route

**Vấn đề:** Cần thống nhất opcode scheme. Bootstrap dùng namespace scheme (0x0105), Opcode enum dùng flat scheme (0x06, 0x24...). Cả 2 đều là uint32_t nên có thể coexist, nhưng cần định nghĩa rõ.

---

## III. IMPLEMENTATION PLAN

### Phase 1: AuthorizationManager (capability check)
**Files:** `core/runtime/authorization_manager.hpp`, `.cpp`
- Mapping từ `ContractCapability` → `Capability` (session cap)
- Check session capabilities ⊇ contract requirements
- Anonymous access cho bootstrap + join
- **CMakeLists.txt** thêm `authorization_manager.cpp`

### Phase 2: RuntimeBridge mở rộng
**Files:** `core/runtime/runtime_bridge.hpp`, `.cpp`
- Thêm `SessionManager&` reference
- Thêm `AuthorizationManager` member
- Thêm authorization step trong `bridge()`:
  1. Resolve route
  2. Lấy contract metadata từ Dispatcher
  3. Lấy session từ SessionManager (nếu có)
  4. Authorize
  5. Execute

### Phase 3: Opcode constants
**File:** `core/opcode/opcode.h` (sửa đổi)
- Thêm opcode constants cho bootstrap, join, governance methods

### Phase 4: smo-node main.cpp wiring
**File:** `cmd/smo-node/main.cpp`
- Khởi tạo SessionManager
- Khởi tạo AuthorizationManager
- Register tất cả contracts vào runtime Dispatcher
- Register tất cả opcode routes vào RuntimeBridge
- Register PacketDispatcher handlers
- Tick SessionManager trong main loop

### Phase 5: Build & fix
- Fix lỗi compile
- Fix `SMO_ERR_ACL` nếu cần
- Build smo-node thành công

### Phase 6: E2E Test
- 2-node mesh: bootstrap → join → governance proposal

---

## IV. CÁC VẤN ĐỀ PHÁT HIỆN KHI ĐỌC CODE

### Critical (block Sprint 37 nếu không fix)

1. **❌ AuthorizationManager không tồn tại** — Không có lớp nào kiểm tra capability trước khi execute contract
2. **❌ Session không được wire vào packet flow** — Không tạo/lookup session khi TCP packet đến
3. **❌ Hai hệ thống capability không có mapping** — `Capability` (session.hpp) vs `ContractCapability` (runtime_types.hpp)
4. **❌ RuntimeBridge::bridge() truyền payload sai type** — Dùng `ContextValue(string)` nhưng contract mong đợi `ContextValue(Bytes)`

### Important (ảnh hưởng architecture)

5. **⚠️ PolicyEngine (core/acl/) không build được** — Thiếu CMakeLists.txt, macro `SMO_ERR_ACL` undefined
6. **⚠️ Hai PolicyEngine classes** — `smo::acl::PolicyEngine` (core/acl/) vs `smo::PolicyEngine` (acl/acl.h)
7. **⚠️ PolicyMiddleware no-op** — `middleware.cpp` todo, không được install vào kernel
8. **⚠️ TrustManager không wired** — Không production code gọi `record_success/failure/get_score`
9. **⚠️ Selector hardcode trust = 0.5** — Không query TrustManager

### Cosmetic (có thể deferred)

10. 📝 Opcode scheme chưa thống nhất (flat vs namespace)
11. 📝 `smo` (cmd/smo) không build — thiếu main.hpp
12. 📝 `smo-debug` (cmd/smo-debug) stub — return 0;

---

## V. QUYẾT ĐỊNH CHO SPRINT 37

### Sẽ làm:
- ✅ AuthorizationManager — mapping ContractCapability → Capability
- ✅ RuntimeBridge mở rộng — SessionManager + AuthorizationManager
- ✅ Wire SessionManager vào daemon loop
- ✅ Register BootstrapContract, JoinContract, GovernanceContract
- ✅ Opcode constants cho bootstrap/join/governance methods
- ✅ Build & 2-node E2E test

### Sẽ KHÔNG làm (Sprint 37+):
- ❌ RecoveryContract, FileContract, ProcessContract network wiring (để sprint sau)
- ❌ PolicyEngine integration (dead code, cần refactor)
- ❌ TrustManager integration (cần architecture decision)
- ❌ Scheduler thread pool (RFC 0044 deferred)
- ❌ Consensus (architecture rejects global consensus)

---

---

## VII. KẾT QUẢ IMPLEMENTATION (đã build thành công)

### Files created:
| File | Purpose |
|------|---------|
| `core/runtime/authorization_manager.hpp` | AuthorizationManager class |
| `core/runtime/authorization_manager.cpp` | Capability mapping + authorization check |
| `docs/SPRINT_37_STATUS.md` | This document |

### Files modified:
| File | Changes |
|------|---------|
| `core/runtime/runtime_bridge.hpp` | Added Dispatcher&, SessionManager&, AuthorizationManager members |
| `core/runtime/runtime_bridge.cpp` | Authorization check in bridge(), Bytes fix, session lookup |
| `core/runtime/CMakeLists.txt` | Added authorization_manager.cpp |
| `core/opcode/opcode.h` | Added BOOTSTRAP_SNAPSHOT, BOOTSTRAP_INFO, JOIN, LEAVE, JOIN_INFO, GOV_LIST, GOV_STATUS, GOV_INFO, RECOVERY, FILE_OP, PROCESS |
| `cmd/smo-node/main.cpp` | SessionManager, MeshManager, Authority, GovernanceEngine, all contract registrations, all opcode routes, PacketDispatcher handlers, SessionManager tick |

### Build status:
- `smo_runtime` — ✅ builds
- `smo-node` — ✅ builds (warnings only)

### Registered contracts (Sprint 37):
| Contract | Opcodes | Status |
|----------|---------|--------|
| EchoContract | ECHO (0x06) | ✅ Legacy |
| BootstrapContract | BOOTSTRAP_REQ (0x0105), BOOTSTRAP_SNAPSHOT (0x30), BOOTSTRAP_INFO (0x31) | ✅ Anonymous |
| JoinContract | JOIN (0x33), LEAVE (0x34), JOIN_INFO (0x35) | ✅ Anonymous |
| GovernanceContract | GOV_PROPOSE (0x24), GOV_VOTE (0x25), GOV_COMMIT (0x26), GOV_LIST (0x27), GOV_STATUS (0x28), GOV_INFO (0x29) | ✅ Requires session |

### Deferred (Sprint 38+):
- RecoveryContract, FileContract, ProcessContract (CRL not implemented yet)
- PolicyEngine integration (dead code, needs refactor)
- TrustManager integration into runtime pipeline
- Scheduler thread pool (RFC 0044)

---

## VI. TRUST ENGINE — THUẬT TOÁN CHI TIẾT

### TrustComponents (4 dimensions)
```
citizen     = online time, heartbeat stability          weight = 0.2
execution   = contract success ratio                    weight = 0.5  ← quan trọng nhất
witness     = witness participation and accuracy        weight = 0.2
consistency = result agreement with majority            weight = 0.1
```

### Composite Score
```
composite = citizen*0.2 + execution*0.5 + witness*0.2 + consistency*0.1
clamped [0.0, 1.0]
```

### Trust Levels
```
Absolute: ≥ 0.9  (trust anchor)
High:     ≥ 0.7
Medium:   ≥ 0.4
Low:      ≥ 0.2
None:     < 0.2
```

### Scoring Operations
| Operation | Effect | Code location |
|-----------|--------|---------------|
| record_success | execution += 0.01 * weight | trust.cpp:227-235 |
| record_failure | execution -= 0.02 * weight | trust.cpp:237-244 |
| record_offline | citizen -= citizen_penalty_offline (0.001) | trust.cpp:246-253 |
| apply_attestation | witness = existing*0.7 + attestation*0.3 | trust.cpp:333-341 |
| decay (tick) | all dimensions *= 0.5^(days/30) | trust.cpp:367-387 |
| trust_anchor | composite = 1.0 (override) | trust.cpp:255-281 |

### Decay Model
```
half_life = 30 days
factor = 0.5 ^ (elapsed_days / 30)
dimension *= factor
```

Ví dụ: sau 30 ngày không hoạt động → factor = 0.5, score giảm một nửa.
Sau 60 ngày → factor = 0.25.

### Attestation Flow
1. Witness tạo `Attestation { witness_id, subject_id, claimed_score, timestamp, signature }`
2. Receiver gọi `verify_attestation()` — check timestamp window, signature, score range
3. Receiver gọi `apply_attestation()` — blend vào subject's witness component

### Digest Gossip
1. `produce_digest()` — snapshot tất cả scores, increment sequence counter
2. Gossip gửi TrustDigest đến peers
3. `apply_digest()` — newer sequence wins, merge scores

### PolicyEngine Trust Integration (planned, NOT implemented)
- `PolicyRule` có `min_trust_score` / `max_trust_score` (int32_t)
- `PolicyEvaluationContext` có `trust_score` field
- `evaluate_impl()` kiểm tra `context.trust_score` vs thresholds
- **HIỆN TẠI**: `context.trust_score` không được populate từ TrustManager
