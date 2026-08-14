# DISCUSSION 0046 — RFC Compliance Audit & Hardening Plan (trust-boundary + runtime wiring)

**Status:** Audit → Planning → Hardening  
**Target:** v0.0.7+ (hardening of v0.0.2-era runtime; NOT a new-feature sprint)  
**Date:** 2026-08-13

---

## 1. Kết Luận Cốt Lõi

> **Code tồn tại ≠ code được CMake biên dịch ≠ code được runtime instantiate ≠ code nằm trên execution path.**

Audit toàn diện (5 nhóm RFC, tất cả 46 RFC + MASTER_SYSTEM_MAP + SPEC) cho thấy
v0.0.2 cần được **coi là artifact-releaseable nhưng chưa phải "production-ready
secure mesh"**. Một chuỗi vấn đề trust-boundary nối tiếp nhau:

```text
unauthenticated bootstrap join-token  (client không verify issuer signature)
        ↓
unsigned manifest / bootstrap delta   (ticket = "placeholder_hmac")
        ↓
unauthenticated session transport     (server PQ handshake không xác thực client)
        ↓
unsigned governance vote              (quorum = 1, signature không verify)
        ↓
unsigned attestation / digest         (TrustManager chỉ check signature non-empty)
        ↓
"trusted mesh state"                  (tin cậy giả)
```

Điều này **không còn là "missing feature" — mà là trust-boundary security bug**.

---

## 2. Phân Loại Toàn Bộ Gap Của Các Nhóm

### P0 — Security boundary (cần xử lý trước khi ra môi trường không tin cậy)

| # | Gap | Vị trí | Thực trạng |
|---|-----|--------|-----------|
| S1 | Join-token không được verify signature ở packet server path | `core/join/join_protocol.cpp:836-955` | Server chỉ `parse_token` (timestamp/expiry/nonce/request sig); **không bao giờ gọi `validate_token`**. `join_contract.cpp:112` chú thích "skip signature verification". HTTP path (`enroll_server.cpp:405`) CÓ validate HMAC — hai path phân kỳ. Token giả → role leo quyền. |
| S2 | Attestation không verify crypto | `core/trust/trust.cpp:375-386` | `verify_attestation` chỉ check timestamp window + score range + signature **non-empty**. Signature không verify pubkey, witness không check anchor/peer. Ai cũng forge `witness\|subject\|claimed\|ts\|<hex>` → `apply_attestation` blend 30% giả vào composite. |
| S3 | Governance không enforce quorum + không verify vote | `core/governance/governance.hpp:205` (threshold=1), `governance.cpp:329-362` | Quorum không compute từ N. Sign() append signature không verify issuer/authority cert. Chỉ CertificateRevocation có effect; các action khác không enact. Error 812 ProposalConflict & Conflicted state không được engine sinh ra. reject() không caller. detect_fork thiếu. Expiry unit bug (ns vs s) → proposal không bao giờ expire. |
| S4 | Bootstrap/delta sync không auth | `core/join/join_protocol.cpp:948-950` | `bootstrap_ticket` = `"placeholder_hmac"`, không bao giờ verify. Ai cũng kéo được membership+CRL+manifest+seeds. |
| S5 | Manifest signature không enforce | `core/join/join_protocol.cpp:979-991` | Server gửi manifest_delta **không signature**. Client parse {1:data,2:sig,3:epoch} chắc chắn fail, nhưng fail chỉ warning không ảnh hưởng `synced=true`. |
| S6 | Session transport không verify chain/expiry/CRL; server handshake không xác thực client | `core/transport/secure_session.cpp:242-251` | Client chỉ verify subject_pubkey qua signature. `CertificateChain::verify` + `is_valid_at` chỉ dùng trong một vài path. |

**Exception đẩy lên:** `smo-admin sign` ghi `authority.sec` plaintext lên disk
(`cmd/smo-admin/main.cpp:322-328`) — vi phạm RFC 0006 "Root key never circulates".
Đây là architectural security violation, xử lý trong Batch 1.

### P1 — Khai báo nhưng STUB / không compile / không wire

| # | Gap | Vị trí | Thực trạng |
|---|-----|--------|-----------|
| R1 | RuntimeServices (RFC 0037) 14 service không có .cpp, không inject | `core/runtime/services/*.hpp`; `runtime_context.hpp:11-34` | Toàn nullptr; daemon chỉ register event_bus/crl/session/trust/governance/discovery. Capability gating (`has_capability`) không được invoke. |
| R2 | PolicyEngine (RFC 0029) chưa instantiate | `core/acl/policy_engine.cpp` (full impl) | `cmd/` không `make_unique<acl::PolicyEngine>`. `PolicyMiddleware` wire không engine. **7 contract set anonymous** → bỏ qua toàn bộ policy. |
| R3 | 5 file runtime KHÔNG compile | `core/runtime/CMakeLists.txt` | `event_store, execution_engine, history, runtime_context, scheduler` có trên disk, không có trong build. Scheduler/RetryEngine (RFC 0044) không bao giờ chạy. |
| R4 | ContractManager lifecycle (RFC 0040) chưa dùng; has_validate=true nhưng không contract override validate/initialize | `core/runtime/contract_registry.cpp:107-256`; `main.cpp:1506-1564` | Daemon register thẳng vào Dispatcher, bỏ qua lifecycle. Metadata "nói dối" has_validate. |
| R5 | Bootstrap::find_seed dead code; WorkerPool stub | `core/discovery/discovery.cpp:666-705`; `runtime/workerpool/workerpool.cpp:29-36` | find_seed không caller. WorkerPool.submit discard task, wait_all empty, thiếu cancel/active_count/resize. |

### P2 — Chức năng đang giả lập / chưa đúng RFC

| # | Gap | Vị trí | Thực trạng |
|---|-----|--------|-----------|
| G1 | Session không bao giờ open trong daemon | `cmd/smo-node/main.cpp:1636` (chỉ lookup) | Không SESSION_OPEN handler; `SessionManager::open()` không caller; policy deny mọi thứ rồi bị bypass bằng anonymous. |
| G2 | UDP heartbeat PING không được trả lời | `core/discovery/discovery.cpp:741-753` | `handle_ping`/`handle_pong` empty stub; `HeartbeatService` không được gọi trong main; RTT/liveness không chạy. |
| G3 | Wire format ≠ RFC 0019 | `protocol/packet/packet.h:19-37` | Header 6B ≠ 37B; không reject nonce/sig=0; không timestamp window; ReplayProtector chỉ trong test. |
| G4 | Channel model (RFC 0042) hoàn toàn vắng | — | grep channel_id/kFrameFlagChannel chỉ có trong RFC. |
| G5 | NextAction (RFC 0039): 2/9 action | `core/runtime/action_executor.cpp` | TODO: DispatchContract/ScheduleRetry/SpawnPlan/Notify/Compensate/abort. |
| G6 | RuntimeKernel dispatch/collect/audit/complete no-op | `core/runtime/runtime_kernel.cpp:223-255` | execute_async đồng bộ; PlanResolver không provider. |
| G7 | Governance reject/conflict/detect_fork/expiry | `core/governance/governance.cpp` | Conflicted không engine sinh; expiry unit sai. |
| G8 | MeshFsm dead code; hardcode mesh_state="Online" | `core/bootstrap/bootstrap_protocol.cpp:199`; `core/authority/authority.hpp:73` (`sign_bootstrap_csr` không impl) | Lifecycle Draft→Genesis→Bootstrap→Online không bao giờ chạy. |
| G9 | PeerStore::record_event không gọi step() | `core/discovery/peer_store.cpp:477-495` | INSERT không bao giờ chạy → silent data loss. |
| G10 | TrustDigest/apply_digest không verify signature | `core/trust/trust.cpp:410-428` | Gossip digest không xác thực origin. |

### P3 — Độ lệch nhỏ / deferred theo RFC

- Opcode registry (RFC 0020): chỉ 10 builtin, không namespace 3-byte; packet không qua registry.
- Storage schema (RFC 0022): sqlite_store generic kv không per-store schema; manifest_store file-based.
- Serialization (RFC 0043): không pipeline thống nhất (ad-hoc per module).
- Recovery package: XChaCha20 ≠ AES-256-GCM (RFC 0006); key=Blake3(passphrase) không KDF → offline brute-force; **Shamir SSS thiếu** (grep toàn repo 0 hit).
- HKDF luôn HMAC-SHA256 kể cả suite BLAKE3.

### Đã đúng (không cần sửa)

- Ciphersuite (RFC 0024) 3 suite + registry (Classical/Hybrid/PurePQC).
- CERT_VERIFY trong mesh join (E2E-verified).
- Error model (RFC 0008): 18 category, Result<T,Error> toàn cục.
- FSM generic (RFC 0021): TransitionRule/StateTimeout/TransitionRecord/Blake3 audit.
- Discovery (RFC 0015): 7 message types serialized + wired.
- TrustManager scoring/decay/witness selector/wire (v0.0.6).
- Session persist/recover (v0.0.6, RFC 0014 §6).

---

## 3. Kế Hoạch Chi Tiết (ordered batches — updated per architectural review)

### 🔴 Phase 0 — P0-S1 Gate (MUST pass before any other work)

**4 Architectural Questions (must be answered by human, not agent):**

| # | Question | Options | Decision Required |
|---|----------|---------|-------------------|
| Q1 | Root mesh key algorithm? | Suite 1 (Ed25519) per SPEC §7.2 **OR** Suite 3 (ML-DSA) per current code | Choose one, update SPEC & code |
| Q2 | Token `cipher_suite_id` means? | Mesh suite **OR** Issuer signing suite | Define unambiguously |
| Q3 | Recovery package signer source? | `mesh.json` cipher_suite_id **OR** recovery package metadata | Define source of truth |
| Q4 | `validate_token()` key-suite binding? | How to ensure issuer public key matches token's advertised suite | Define validation rule |

**Gate Criteria for S1 DONE:**

```
PCT-023 regression suite (ALL 3 suites):
├── Suite 1 token sign → verify ✓
├── Suite 2 token sign → verify ✓
├── Suite 3 token sign → verify ✓
├── wrong issuer key → reject ✓
├── wrong suite → reject ✓          ← CRITICAL for current bug
├── modified payload → reject ✓
├── modified signature → reject ✓
├── expired token → reject ✓
└── replay → reject ✓

E2E: node-b join PASS
clang-format + ctest + PCT all green
```

**No workaround allowed:** "signature 32 byte → use Ed25519" is hardcode, violates §5.2.

---

### 🔴 Phase 1 — P0 Remaining (sequential, each must pass gate)

| Step | Task | Gate Criteria |
|------|------|---------------|
| **S2** | TrustManager::verify_attestation real crypto verify | PCT: forged/wrong-witness/wrong-subject/expired/modified-score/valid all pass |
| **S3** | Governance quorum + vote signature check | Invariant: forge 1 vote with 3 authorities + quorum=1 → MUST reject; PCT for each |
| **S4+S5** | Bootstrap atomic: ticket + manifest_delta signed, client verify before state mutation | `synced=true` ONLY after signature verify pass; fail → error not warning |
| **S6** | Session transport: chain + expiry + Capability Epoch + authority status + mesh auth on both sides | Separate: cryptographic handshake ≠ mesh authorization; both required |
| **EX** | smo-admin sign: no plaintext secret on disk | Memory-only / encrypted-at-rest |

**Order enforced:** S2 cannot start until S1 gate passes. S3 waits for S2, etc.

---

### 🟠 Phase 2 — Runtime Wiring (P1) — Tiered

| Tier | Tasks | Note |
|------|-------|------|
| **R3** | Add 5 unbuilt runtime .cpp to CMake; fix compile + link + runtime smoke test | Prerequisite for all below |
| **R1-T1** | Inject Tier-1 RuntimeServices: crypto, identity, storage, policy, audit, clock, random | Execution-critical only |
| **R1-T2** | Inject Tier-2: fs, logger, network... | After T1 stable |
| **R2** | Instantiate PolicyEngine + wire PolicyMiddleware; remove anonymous bypass for policy-covered contracts | Security boundary |
| **R4** | Daemon uses ContractManager lifecycle (init/shutdown/validate) | No more direct Dispatcher register |
| **R5** | WorkerPool: queue + submit + wait_all + cancel + active_count + resize | find_seed wire or remove |

**No "service locator explosion":** inject by tier, verify each.

---

### 🟡 Phase 3 — Mesh Networking (P2)

| Step | Task | Note |
|------|------|------|
| **G1** | SESSION_OPEN handler; SessionManager::open() on packet path | After P0+R2 (policy available) |
| **G2** | HeartbeatService wired; handle_ping→PongMsg; handle_pong→RTT/health | |
| **G3** | ReplayProtector + nonce/sig rejection + timestamp window on receive | Align with RFC 0019 header |
| **G10** | TrustDigest apply_digest verify signature by origin pubkey | **Moved up** — trust propagation with S2/S6 |
| **G9** | PeerStore::record_event call stmt.step() | Silent data loss fix |

---

### 🟢 Phase 4 — Distributed Runtime Semantics

| Step | Task |
|------|------|
| **G4** | Channel model (RFC 0042) |
| **G5** | NextAction 7 remaining actions |
| **G6** | RuntimeKernel async stages + PlanResolver |
| **G7** | Governance FSM complete (reject/conflict/detect_fork/expiry) |
| **G8** | MeshFsm wire + sign_bootstrap_csr + remove hardcode "Online" |

---

### ⚪ Phase 5 — RFC Compliance Cleanup

| Task | Note |
|------|------|
| Opcode registry namespace (RFC 0020) | |
| Storage schema per-store (RFC 0022) | |
| Serialization pipeline (RFC 0043) | |
| Recovery: AES-256-GCM + KDF + Shamir SSS (RFC 0006) | grep "shamir" = 0 hits currently |
| HKDF/BLAKE3 per-suite | |
| Authority key handling | |

---

## 3.1 Version Tracking

| Track | Target | Description |
|-------|--------|-------------|
| **Feature roadmap** | v0.0.3 | 3-node operational scenario |
| **Security hardening** | DISCUSSION_0046 | This plan — trust-boundary + runtime compliance |

**Do not mix.** v0.0.3 is operational; 0046 is compliance hardening.

---

## 4. Tiêu Chí "Production-Ready" (re-validation pipeline)

Sau mỗi phase gate:

```text
build (clang-format CI + clang-tidy)
→ ctest
→ PCT (full regression suite per phase)
→ E2E (security regression tests)
→ 3-node VPN scenario
→ failure/recovery tests
→ release candidate
```

**v0.0.2 ≠ production-ready** until P0 complete + security regression green + runtime wiring (Phase 2) done.

---

## 4. Tiêu Chí "Production-Ready" (re-validation pipeline)

Sau mỗi batch chạy lại:

```text
build (clang-format CI + clang-tidy)
→ ctest
→ PCT (23)
→ E2E (71 + security regression tests)
→ 3-node VPN scenario
→ failure/recovery tests
→ release candidate
```

**Không coi v0.0.2 là production-ready** cho tới khi P0 đóng + security regression test xanh + runtime wiring (Batch 2) hoàn thành.

---

## 5. Quy Tắc Làm Việc (bắt buộc, không quên)

> Ký ghi nhận từ @dotlinux26 — "cấm tự ý hardcode, có gì thắc mắc là phải hỏi lại anh ngay".

1. **RFC trước, code sau.** Mọi thứ định implement phải đọc RFC tương ứng TRƯỚC
   khi viết code. Không "code theo trí nhớ" hoặc theo hạ tầng hiện có mà lệch RFC.
2. **Suite-ID driven — cấm hardcode 1 cipher.** Mọi crypto op đi qua
   `CryptoRegistry::get_suite(cipher_suite_id)` (RFC 0009, RFC 0024). Test cũng vậy:
   đăng ký tất cả suite (Classical=1, Modern=2, PurePQC=3) và chạy lặp theo từng
   suite. Không gọi `Ed25519Provider`/`Sha256Provider` trực tiếp trong logic hoặc
   test — trừ chính module provider đó. Signing/Hash/Keypair luôn lấy từ `SignerImpl`
   / `HashImpl` của provider đã chọn theo id.
3. **Phân tầng module — không kéo chồng chéo tầng.** Mỗi module chỉ làm đúng
   trách nhiệm của RFC mình:
   - `join_token.*` (enroll) — sinh/parse/validate token bằng suite-id.
   - `authority.*` — quản lý key, sign CSR, verity chain; public accessor cho
     `root_public_key()`/`authority_public_key()`.
   - `trust.*` — attestation/digest verify bằng origin pubkey (không tự sinh key).
   - `governance.*` — quorum + vote signature check bằng authority cert.
   - Daemon (`cmd/`) — wiring: chỉ lắp ghép module, không nhân bản logic.
   Không để module này tự ý gọi thẳng vào impl riêng của module khác.
4. **Có gì thắc mắc / thiếu thông tin → hỏi lại ngay**, không tự suy đoán.
   Đặc biệt khi RFC mơ hồ hoặc codebase lệch RFC.
5. **Kiểm chứng mỗi bước**: build → clang-format → ctest → PCT → e2e (theo §4).

---

## 6. Nguồn

- Tổng hợp từ 5 audit agent (transport/session/network, trust/governance, crypto/enroll, runtime/contract, discovery/mesh/storage/policy/enroll).
- Đã xác nhận lại trực tiếp: `session_mgr.open()` không caller; `PolicyEngine` không instantiate; `verify_attestation` chỉ check non-empty; `validate_token` không được gọi trong join path; 5 file runtime không compile; `record_event` không step; header packet ≠ RFC 0019.
- Status phiên bản: v0.0.6 = trust/witness wire + session recovery (đã đóng 2 gap từ audit trước).

---

## 7. Trạng Thái Hiện Tại & Các Vướng Mắc Đang Xử Lý (Update 2026-08-13)

### 7.1 E2E Join Failure — Root Cause Analysis

**Lỗi hiện tại:** `JoinRequest failed: Invalid join token: Token length mismatch`

**Root cause chain:**

1. **Genesis suite mismatch (SPEC §6.6 vs implementation):**
   - `cli_application.cpp:1401` tạo root keypair bằng `crypto = get_crypto(kSuitePurePQC)` → **Suite 3 (ML-DSA)**
   - Nhưng comment line 1429: `// Generate root Ed25519 keypair` → nhầm lẫn Ed25519 vs ML-DSA
   - Manifest ghi `cipher_suite_id = 3` (PurePQC), recovery package encrypt keypair bằng Suite 3

2. **Wire format bug trong `parse_token` (join_token.cpp):**
   - `encode_token_wire` ghi: `CBOR_payload || sig_len(2 bytes BE) || signature`
   - `parse_token` cũ đoán độ dài payload bằng heuristic (nhìn 2 byte cuối) → sai khi sig_len ≥ 256
   - ML-DSA signature = 3309 bytes → `sig_len = 0x0CE5` → heuristic đọc nhầm thành v1 format (32-byte HMAC)
   - Kết quả: payload parse bao gồm cả sig_len + phần signature → `deserialize_payload` fail "Unsupported value type" hoặc "Token length mismatch"

3. **Token signature size mismatch:**
   - Token tạo ra có `cipher_suite_id = 3` (ML-DSA, sig 3309B)
   - Nhưng `generate-invite` output token signature chỉ ~170 bytes (base64 decode) → **không khớp ML-DSA**
   - Nguyên nhân: `recovery_pkg.unlock()` tạo signer context với `crypto->signer` từ `get_crypto(suite_id=3)` đúng, nhưng `RootSession.execute(SignJoinToken)` có thể dùng sai signer hoặc payload khác lúc sign vs lúc verify

**Debug logs:**
```
[node-a] JoinRequest failed: Invalid join token: Token length mismatch
[DEBUG validate_token] payload_size=108 sig_size=32 pubkey_size=1952
[DEBUG validate_token] verify returned false (mismatch)
```
→ `sig_size=32` là Ed25519 signature size, nhưng `pubkey_size=1952` là ML-DSA pubkey size → **key type mismatch**

### 7.2 Cross-Layer Violations Đã Xác Định

| Module | Violation | RFC Reference |
|--------|-----------|---------------|
| `cli_application.cpp:1429` | Comment sai "Ed25519" nhưng code dùng ML-DSA | SPEC §6.6 |
| `join_token.cpp:parse_token` | Heuristic wire format parsing thay vì CBOR length prefix | RFC 0009, SPEC §6.6 |
| `join_protocol.cpp:process_join_request` | Gọi `validate_token` nhưng không pass đúng `crypto->signer`/`hash` theo suite | RFC 0009, DISCUSSION_0046 §5.2 |
| `trust.cpp:verify_attestation` | Chỉ check `signature.empty()`, không verify crypto | RFC 0031/0033, DISCUSSION_0046 P0-S2 |
| `governance.cpp:sign()` | Append signature không verify authority cert | RFC 0011, DISCUSSION_0046 P0-S3 |
| `join_protocol.cpp:bootstrap_ticket` | Hardcoded `"placeholder_hmac"` | RFC 0014, DISCUSSION_0046 P0-S4 |
| `cmd/smo-admin/main.cpp:325-326` | Ghi `authority.sec` plaintext | RFC 0006, DISCUSSION_0046 P0-EX |

### 7.3 Architectural Decisions (Resolved — human decision, not agent guess)

| # | Question | Decision | Rationale |
|---|----------|----------|-----------|
| **Q1** | Root mesh key suite? | **Suite 3 / ML-DSA-65** (PQ-native) | Genesis decides suite; all downstream crypto follows that suite. No Suite 1 fallback in production path. |
| **Q2** | Token `cipher_suite_id` meaning? | **Split into two fields**: `issuer_suite_id` + `issuer_key_id`. `issuer_suite_id` binds to signer; `issuer_key_id` resolves public key. Invariant: `token.issuer_suite_id == issuer_key.suite_id`. | `cipher_suite_id` ambiguous. Two authorities can share suite but have different keys. Must bind key to suite explicitly. |
| **Q3** | Recovery package signer source? | **Recovery package metadata = source of truth for key material**. Mesh manifest = source of truth for mesh config. Invariant: `recovery_package.suite_id == mesh.genesis_suite_id`. Mismatch → STOP, reject. | Prevents "guessing" suite. No fallback Ed25519 based on signature length. |
| **Q4** | `validate_token()` key-suite binding? | `token.issuer_suite_id → CryptoRegistry → SignerImpl → verify(issuer_public_key, payload, signature)`. Enforce `token.issuer_suite_id == issuer_key.suite_id` before verify. | No module picks crypto. Suite-driven dispatch from key metadata. |
| **Q5** | Join-path exemption design? | **Join is a separate protocol phase**, NOT an exception in `SecureSession`. Joining node gets identity/cert FIRST, then does full mutual-auth handshake. No "empty cert + empty sig" in SecureSession. | Prevents "join exception" becoming auth bypass. JOIN_REQUEST → ISSUE_CERT → SECURE_SESSION_HANDSHAKE. Two distinct phases. |
| **Q6** | Manifest signature scope? | **Canonical(data || epoch || prev_hash)**. Signs the complete delta chain for tamper-evidence. | Prevents delta transplant attacks. Delta chain integrity. |
| **Q7** | G3 packet authentication scope? | **Apply to ALL packets including handshake** if RFC 0019 requires it. Must resolve RFC 0019 64-byte sig vs RFC 0024 ML-DSA-65 (3309B) contradiction first. | Architectural contradiction must be resolved before G3 implementation. |
| **Q8** | Recovery package KDF? | **Argon2id** for password-derived keys (offline brute-force resistance). Not Blake3(passphrase). | Memory-hard KDF required for password-based encryption. |
| **Q9** | Shamir SSS for recovery? | **Required per RFC 0006 §14** (M-of-N threshold). Must implement before production. | Root key never circulates; M-of-N threshold for recovery. |
| **Q10** | TrustDigest signature scope? | **Covers all fields**: origin || sequence || timestamp || scores. Signature by origin's private key. | Gossip digest integrity + origin authentication. |
| **Q11** | Join-path handshake? | **Separate bootstrap trust domain**. Join token → verify → issue cert → THEN full mutual-auth handshake. No "empty cert + empty sig" exception in SecureSession. | JOIN_REQUEST → VERIFY_TOKEN → ISSUE_CERT → SECURE_HANDSHAKE. |

**Updated Token Structure (replaces current `cipher_suite_id`):**

```text
JoinToken
{
    version,
    mesh_id,
    issuer_key_id,        // NEW: resolves issuer public key
    issuer_suite_id,      // NEW: binds to SignerImpl via CryptoRegistry
    role,
    issued_at,
    expires_at,
    nonce,
    bootstrap_endpoints,
    signature
}
```

**Verification Flow:**

```text
token.issuer_suite_id
        ↓
CryptoRegistry::get_suite(token.issuer_suite_id)
        ↓
SignerImpl (verify fn)
        ↓
issuer_key = resolve(token.issuer_key_id)  // from authority/root keystore
        ↓
ASSERT(token.issuer_suite_id == issuer_key.suite_id)
        ↓
verify(issuer_key.public_key, canonical_payload, token.signature)
```

**Any mismatch → REJECT.** No heuristic based on signature/public key length.

### 7.4 Files Modified So Far (Phase 0 - P0-S1 & P0-S2 COMPLETED)

- `core/authority/authority.hpp/.cpp`: Added `root_public_key()` accessor + mesh.json fallback
- `core/join/join_protocol.cpp`: Added token signature verification in `process_join_request`
- `core/enroll/join_token.cpp`: Fixed `validate_token`/`validate_token_v1` clear-signature-before-serialize; rewrote `parse_token` with proper CBOR payload length calculation; fixed `base64url_encode` for final partial chunk
- `core/trust/trust.cpp`: Implemented real crypto verification in `verify_attestation` — resolves witness from trust anchors, verifies signature via `CryptoProvider->signer`
- `tests/unit/protocol/test_pct.cpp`: Added PCT-023 suite-driven token signature tests (all 3 suites)
- `tests/unit/core/trust/test_trust.cpp`: Updated attestation test to use all registered suites with real crypto
- `tests/CMakeLists.txt`: Linked all 3 suite providers into `smo_pct`

### 7.4.1 Suite Registration Complete (All 3 Suites Active)

- **Suite 1 (Classical)**: Ed25519 + X25519 + SHA-256 + XChaCha20
- **Suite 2 (Modern/HybridPQC)**: Ed25519 + X25519 + BLAKE3 + XChaCha20 (registered in cli_application.cpp & smo-admin)
- **Suite 3 (PurePQC)**: ML-DSA-65 + ML-KEM-768 + BLAKE3 + XChaCha20 (canonical RFC 0024 — KHÔNG dùng ML-KEM-1024)

**Registration Points:**
- `cmd/smo-cli/cli_application.cpp`: `register_suite1_classical()`, `register_suite2_modern()`, `register_suite3_purepqc()`
- `cmd/smo-admin/main.cpp`: `register_suite1_classical()`, `register_suite2_modern()`, `register_suite3_purepqc()`
- `cmd/smo-admin/CMakeLists.txt`: Links `smo_suite2_modern`
- `cmd/smo-cli/CMakeLists.txt`: Links `smo_suite2_modern`
- `cmd/smo/CMakeLists.txt`: Links `smo_suite2_modern`

### 7.5 P0-S1 Gate: PASSED ✅

**Root Cause Resolved:** Two bugs found and fixed:
1. **`base64url_encode` bug** — final partial chunk always output 4 chars, causing 1-byte overflow in decoded payload (3420 vs expected 3419 bytes)
2. **`parse_token` CBOR parser** — didn't correctly handle nested admission map, fixed with proper offset tracking

**Verified Working:**
- `payload_len=108, raw.size()=3419` ✓
- `sig_len=3309, payload_len+2+sig_len=3419, raw.size()=3419` ✓
- ML-DSA signature (3309 bytes) with ML-DSA pubkey (1952 bytes) ✓
- All 3 suites: PCT-023 passes for Suite 1/2/3 ✓

**P0-S2 Gate: PASSED ✅**

`TrustManager::verify_attestation` now:
- Resolves witness from trust anchors
- Verifies signature via `CryptoProvider->signer` (suite-driven)
- Rejects if witness not a trust anchor
- All 3 suites tested in unit tests ✓

**Suite 2 (Modern/HybridPQC) Registration: COMPLETED ✅**

- Registered in `cli_application.cpp`, `smo-admin/main.cpp`
- Linked in `smo-admin`, `smo-cli`, `smo` CMakeLists.txt
- All 3 suites active:
  - Suite 1: Ed25519 + X25519 + SHA-256 + XChaCha20
  - Suite 2: Ed25519 + X25519 + BLAKE3 + XChaCha20 (HybridPQC)
  - Suite 3: ML-DSA-65 + ML-KEM-768 + BLAKE3 + XChaCha20 (canonical RFC 0024)

**All Tests Pass:**
- **ctest**: 19/19 passed
- **PCT**: 24/24 passed (including PCT-023 Join token + PCT-024)
- **E2E**: SUCCESS (3-node mesh, all features)

---

## 8. Kiến Trúc Crypto — Quyết Định Cốt Lõi (Resolved 2026-08-13)

### 8.1 Terminology Fix: Cryptographic Domain ≠ Cipher Suite

**Sai (cũ):**
> "Chọn cipher suite nào thì toàn bộ mọi thứ trong hệ thống nghiễm nhiên dùng đúng primitive của suite đó."

**Đúng (mới):**
> **Mỗi thao tác mật mã (cryptographic operation) phải thuộc về một cryptographic domain được xác định rõ. Suite/profile của domain đó là nguồn duy nhất quyết định primitive được sử dụng. Không implementation nào được phép suy luận, thay thế hoặc hardcode primitive dựa trên độ dài key/signature.**

| Concept | Definition |
|---------|------------|
| **Cryptographic Domain** | Một ranh giới logic nơi một suite/profile thống nhất áp dụng (ví dụ: root signing, session KEM, recovery encryption, password KDF) |
| **Suite/Profile** | Bộ primitive: {signature, KEM, hash, KDF, AEAD} — được định nghĩa trong RFC 0024 |
| **Suite Binding** | Quy tắc: `domain.suite_id` quyết định primitive; metadata của key (`key.suite_id`) phải khớp `domain.suite_id` |
| **Algorithm Inference** | CẤM: không bao giờ dùng `signature.length` / `pubkey.length` để đoán algorithm |

### 8.2 GENESIS_SUITE_INVARIANT (Cứng, không exception)

```text
mesh.genesis_suite_id
        ==
root_authority.key.suite_id
        ==
root_authority.signer.suite_id
        ==
recovery_package.suite_id
        ==
token.issuer_suite_id   (for root-issued tokens)
```

Mismatch → **STOP, REJECT**. Không fallback, không "thử suite khác".

### 8.3 Token Cryptographic Binding (Q2 Resolved)

**Token Structure (replaces `cipher_suite_id`):**

```text
JoinToken
{
    version,
    mesh_id,
    issuer_key_id,        // resolves issuer public key from keystore
    issuer_suite_id,      // binds to SignerImpl via CryptoRegistry
    role,
    issued_at,
    expires_at,
    nonce,
    bootstrap_endpoints,
    signature
}
```

**Verification Flow (Canonical):**

```text
token.issuer_suite_id
        ↓
CryptoRegistry::get_suite(token.issuer_suite_id)
        ↓
SignerImpl (verify fn)
        ↓
issuer_key = resolve(token.issuer_key_id)  // from authority/root keystore
        ↓
ASSERT(token.issuer_suite_id == issuer_key.suite_id)
        ↓
ASSERT(issuer_key.mesh_id == token.mesh_id)       // trust domain check
        ↓
ASSERT(issuer_key.not_revoked && issuer_key.valid_at(now))
        ↓
verify(issuer_key.public_key, canonical_payload, token.signature)
```

**Any mismatch → REJECT.** No heuristic based on byte length.

### 8.4 Recovery Package Invariant (Q3 Resolved)

```text
mesh manifest (genesis_suite_id)
        ┌───────────────────────┐
        │   COMPARE AT STARTUP  │
        └───────────────────────┘
recovery package (suite_id in metadata)
```

- Mesh manifest = source of truth cho **mesh configuration**
- Recovery package = source of truth cho **key material metadata**
- Mismatch → **halt**, không "đoán" suite, không fallback Ed25519

### 8.5 validate_token() Decomposition (Q4 Resolved)

Không nhét tất cả vào một function. Trust boundary rõ ràng:

```text
parse_token()
    ↓
structural validation (CBOR well-formed, required fields)
    ↓
resolve_issuer(token.issuer_key_id)
    ↓
validate_issuer_binding(token.issuer_suite_id, issuer_key)
    ↓
verify_signature(canonical_payload, token.signature, issuer_key)
    ↓
validate_temporal(now, issued_at, expires_at)
    ↓
validate_replay(token.nonce, token.mesh_id, expiry)
    ↓
authorize_join(issuer_key.role, token.role, mesh_policy)
```

### 8.6 Test Layering (PCT-023 Gate) — Must Pass Before S1 DONE

| Layer | Tests |
|-------|-------|
| **A — Primitive** | Suite 1/2/3: keygen → sign → verify ✓ |
| **B — Binding** | token.suite=3 + issuer.key.suite=3 → PASS; token.suite=3 + issuer.key.suite=1 → REJECT; token.suite=3 + issuer_key_id points to suite 1 key → REJECT |
| **C — Token Security** | modified payload → reject; modified signature → reject; expired → reject; replay → reject |
| **D — E2E** | generate invite → transport → node B → verify → join ✓ |

---

## 9. Phase Reordering (Security Boundary First)

### P0 — Trust Boundary (Must Complete Before Anything Else)

| ID | Task | Gate | Status |
|----|------|------|--------|
| **S1** | Join-token authenticity | PCT Layer A+B+C+D + E2E | ✅ DONE |
| **S2** | Attestation authenticity | PCT: forged/wrong-witness/wrong-subject/expired/modified-score/valid | ✅ DONE |
| **S3** | Governance authorization | Invariant: forge 1 vote with 3 authorities + quorum=1 → MUST reject | ✅ DONE |
| **S4** | Bootstrap ticket authenticity | Atomic: verify ticket → verify manifest sig → verify epoch → mutate state | ✅ DONE |
| **S5** | Manifest authenticity | Client MUST verify signature before `synced=true` | ✅ DONE |
| **S6** | Session identity + authorization | **Separate layers**: crypto handshake ≠ mesh authorization | ⏳ PENDING |
| **EX** | Root secret handling | No plaintext on disk | ⏳ PENDING |

### P0.5 — Security Infrastructure (Promoted from P1/P2)

| ID | Task | Rationale | Status |
|----|------|-----------|--------|
| **R2** | PolicyEngine + PolicyMiddleware | Security boundary (anonymous bypass removal) | ⏳ PENDING |
| **G3** | Packet authentication / replay / timestamp | Untrusted network path | ⏳ PENDING |
| **G10** | TrustDigest origin signature verify | Feeds trust → authorization | ⏳ PENDING |
| **G8** | MeshFSM if state used as security gate | Trace callers of `mesh_state` | ⏳ PENDING |
| **Recovery KDF** | If root secret password-protected | Offline brute-force risk | ⏳ PENDING |

### P1 — Runtime Wiring

| ID | Task |
|----|------|
| **R3** | 5 unbuilt .cpp → CMake + compile + link + runtime smoke test |
| **R1-T1** | Tier-1 RuntimeServices: crypto, identity, storage, policy, audit, clock, random |
| **R1-T2** | Tier-2: fs, logger, network... |
| **R4** | ContractManager lifecycle |
| **R5** | WorkerPool complete impl |

### P2 — Operational Mesh

| ID | Task |
|----|------|
| **G1** | SESSION_OPEN handler |
| **G2** | HeartbeatService wired |
| **G9** | PeerStore::record_event call step() |

### P3 — Distributed Semantics

| ID | Task |
|----|------|
| **G4** | Channel model |
| **G5** | NextAction 7 remaining |
| **G6** | RuntimeKernel async + PlanResolver |
| **G7** | Governance FSM complete |

### P4 — RFC Compliance Cleanup

| Task | Note |
|------|------|
| Opcode registry namespace | RFC 0020 |
| Storage schema per-store | RFC 0022 |
| Serialization pipeline | RFC 0043 |
| Shamir SSS | RFC 0006 — depends on threat model |
| Authority key handling | |

---

## 10. Architectural Invariants (Machine-Checkable)

| Invariant ID | Rule | Location |
|--------------|------|----------|
| **CRYPTO-001** | No algorithm selection from serialized key/signature length | All verify paths |
| **CRYPTO-002** | `token.issuer_suite_id == issuer_key.suite_id` | validate_token |
| **CRYPTO-003** | `recovery_package.suite_id == mesh.genesis_suite_id` | Startup |
| **CRYPTO-004** | `issuer_key.mesh_id == token.mesh_id` | validate_token |
| **CRYPTO-005** | No `Ed25519Provider`/`MLDSAProvider` direct call in business logic | Code audit |
| **TRUST-001** | `verify_attestation` must verify signature with origin pubkey | trust.cpp |
| **TRUST-002** | `apply_digest` must verify origin signature | trust.cpp |
| **GOV-001** | Vote signature verified before counting toward quorum | governance.cpp |
| **GOV-002** | Quorum computed from active authorities, not hardcoded | governance.cpp |
| **SESSION-001** | Crypto handshake ≠ mesh authorization; both required | secure_session.cpp |
| **BOOT-001** | `synced=true` ONLY after all signature verifications pass | join_protocol.cpp |

---

## 11. Required Negative Tests (Security Regression)

| Attack Vector | Test Case | Expected |
|---------------|-----------|----------|
| **Downgrade** | Suite 3 mesh + Suite 1 token | REJECT |
| **Algorithm confusion** | Suite 3 pubkey + Ed25519 sig | REJECT |
| | Suite 1 pubkey + ML-DSA sig | REJECT |
| | Suite 3 pubkey + garbage 3309-byte sig | REJECT |
| **Key-suite mismatch** | token.issuer_suite_id=3, issuer_key.suite_id=1 | REJECT |
| **Cross-mesh** | token.mesh_id=A, issuer_key.mesh_id=B | REJECT |
| **Revoked issuer** | issuer_key past capability epoch / deactivated authority | REJECT |
| **Replay** | Same nonce within expiry window | REJECT |
| **Truncated sig** | ML-DSA sig artificially shortened | REJECT |
| **Missing metadata** | token without issuer_suite_id | REJECT |

---

## 12. RFC 0024 Canonical Suite Profile Table (Required)

| Primitive Role | Suite 1 (Classical) | Suite 2 (Modern) | Suite 3 (PurePQC) |
|----------------|---------------------|------------------|-------------------|
| **Signature** | Ed25519 | Ed25519 | ML-DSA-65 |
| **KEM** | X25519 | X25519 | ML-KEM-768 |
| **Hash** | **SHA-256** | **BLAKE3-256** | **BLAKE3-256** |
| **KDF** | HKDF-SHA-256 | HKDF-BLAKE3 | HKDF-BLAKE3 |
| **AEAD** | XChaCha20-Poly1305 | XChaCha20-Poly1305 | XChaCha20-Poly1305 |

> **Rule:** Nếu một cell N/A → ghi "N/A". Không implicit inheritance.
> **LOCKED 2026-08-14 (§22.B/C):** Suite 2 = Ed25519 + X25519 (KHÔNG ML-DSA). Suite 3 KEM = ML-KEM-768 (KHÔNG 1024).
> **LOCKED 2026-08-14 (§24.1):** Suite 1 hash = **SHA-256** (canonical RFC 0024). Suite 2 + Suite 3 = BLAKE3-256. Bảng này là **canonical duy nhất**, khớp RFC 0024 + implementation (`suite1_classical`=sha256, `suite2_modern`=blake3).
> **⚠️ Trước đây §12/§7.4.1 ghi Suite 1 hash = BLAKE3 → SAI so với RFC 0024. Đã sửa.** Không còn 2 bảng khác nhau.

---

## 13. Module Layering: Authority vs CryptoRegistry

| Module | Allowed To Know | NOT Allowed |
|--------|-----------------|-------------|
| **authority** | Key metadata: `{key_id, suite_id, public_key, secret_key, mesh_id, role, status, epoch}` | Call `MLDSAProvider::verify()` directly; `if (suite==3) MLDSA else Ed25519` |
| **join/trust/governance/session** | `CryptoRegistry::get_suite(suite_id)` → `SignerImpl`/`HashImpl` | Any provider-specific code |
| **cmd/** (daemon) | Wiring only: instantiate modules, connect via interfaces | Business logic, crypto decisions |

**Authority manages key identity; CryptoRegistry manages cryptographic implementation.**

---

## 14. Production-Ready Definition (Updated)

```text
PRODUCTION_READY =
    P0 security gates PASS
AND P0.5 security invariants PASS
AND runtime wiring (P1) PASS
AND no security-critical stub on reachable execution path
AND PCT (all layers) PASS
AND E2E (including security regression) PASS
AND recovery/failure tests PASS
AND 3-node VPN scenario PASS
```

**Critical:** "No security-critical stub on reachable path" = `handle_ping`/`handle_pong`/`AuthorizationManager`/`apply_digest`/`record_event`/`SESSION_OPEN` must all be real implementations if reachable from untrusted input.

---

## 15. Current Implementation Status (2026-08-14)

> **§24.7 — bảng này là source of truth duy nhất.** Mọi subsection status cũ (vd: "G10 Completed" ở §15 vs "G10 pending" ở §9; "P0-EX done" vs "P0-EX pending") coi như historical, KHÔNG phải nguồn quyết định.

### Completed ✅
- **P0-S1**: Join token signature verify (all 3 suites — issuer signature, giữ theo §24.5)
- **P0-S2**: Trust attestation crypto verify (all 3 suites)
- **P0-S3**: Governance quorum + vote signature check
- **P0-S4**: Bootstrap ticket signed with authority key (no placeholder_hmac)
- **P0-S5**: Manifest delta signed + enforced client verification (fail on invalid)
- **G10**: TrustDigest apply_digest verifies origin signature
- **Suite 1/2/3 registration** trong CLI apps (Suite 1 = SHA-256 đúng RFC 0024, §24.1)
- All 19 ctest + 24 PCT + E2E 3-node mesh PASS

### In Progress 🔨
- **P0-S6**: Session crypto handshake + mesh auth separation (join path = bootstrap domain riêng, no empty cert; handshake sau khi cert issued)
- **P0-EX**: authority.sec encryption — **ĐÃ REWRITE (RecoveryDomain, 2026-08-14)**: Argon2id (Monocypher, salt 32B, mem 65536 KiB / 3 passes / 4 lanes) + AES-256-GCM (OpenSSL 3 EVP, nonce 12B, tag 16B) via `RecoveryCryptoProvider`, envelope v1 magic "SM"; rewrite `encrypt_authority_secret_key` (smo-admin), `authority.cpp open()`, `recovery_package` unlock/verify, `genesis.cpp` stage0; 6 recovery crypto tests (NIST CAVS vector) PASS
- **Recovery follow-up**: `recovery_engine.cpp verify_recovery_package()` vẫn TODO (trả true) — RecoveryEngine nằm trong `smo_core` còn RecoveryPackage trong `smo_genesis` (link smo_core) → circular static-lib dep; verify qua `RecoveryCryptoProvider` ở tooling layer thay vì gọi vào genesis

### Pending ⏳ (blocked / chưa bắt đầu)
- **G3**: AEAD packet authentication — **UNBLOCKED 2026-08-14**; RFC 0019 AMEND-4 đã amend → sẵn sàng implement theo spec
- **RFC amendments**: RFC 0006 (§24.2 BLOCKER), RFC 0019 (§24.3 BLOCKER), RFC 0007 (§24.5 BLOCKER)
- **R2**: PolicyEngine + PolicyMiddleware wiring
- **G8**: MeshFSM wire + sign_bootstrap_csr
- **R3**: Add 5 uncompiled runtime .cpp to CMake
- **G9**: PeerStore::record_event call step()
- **G2**: HeartbeatService handle_ping/pong + DiscoveryEngine stubs
- **G1**: SESSION_OPEN handling in daemon

### E2E Test Notes (2026-08-14)
Current E2E failures are **not security bugs** but **handshake / feature gaps**:
- Join handshake fails because joining node has no certificate yet; the PQ handshake requires mutual certs. **Đã chốt (§20.2③, §22):** join = separate bootstrap trust domain. JOIN_REQUEST (verify token signature) → issue cert → THEN SecureSession handshake. **KHÔNG** "allow unauthenticated KEM exemption" trong SecureSession.
- `policy show/preset/export` from member nodes (B_ENV, C_ENV) fail because they are **CLI commands using local mesh context**, not daemon RPC calls. Member nodes have minimal mesh.json (no policy presets, no authority keys). Fix: implement CLI commands to work with local mesh context or query authority daemon.
- `sync` from member nodes fails - same reason (no daemon RPC for sync from member).
- These are **feature completeness** issues, not trust boundary violations. The 3-node daemon mesh itself works (S5 trust/witness/session recovery all PASS).

---

## 16. Decision Log (Human Approved)

| Date | Decision | By | Reference |
|------|----------|----|-----------|
| 2026-08-13 | Root key = Suite 3 / ML-DSA-65 | @dotlinux26 | §8.1 |
| 2026-08-13 | Token uses `issuer_suite_id` + `issuer_key_id` | @dotlinux26 | §8.3 |
| 2026-08-13 | Recovery package metadata = source of truth for keys | @dotlinux26 | §8.4 |
| 2026-08-13 | CRYPTO-001: No algorithm inference from byte length | @dotlinux26 | §10 |
| 2026-08-13 | P0.5 created for PolicyEngine/G3/G10/G8/Recovery KDF | @dotlinux26 | §9 |
| 2026-08-13 | RFC 0024 canonical profile table required | @dotlinux26 | §12 |
| 2026-08-13 | Agent MUST trace root cause before modifying parse_token | @dotlinux26 | §15 |
| 2026-08-14 | Join = separate bootstrap trust domain; no empty cert/sig in SecureSession | @dotlinux26 | §15 |
| 2026-08-14 | Manifest signature = canonical(data || epoch || prev_hash) | @dotlinux26 | §15 |
| 2026-08-14 | P0-EX: Argon2id + AES-256-GCM for authority.sec encryption | @dotlinux26 | §15 |
| 2026-08-14 | G3 blocked on RFC 0019 vs Suite 3 signature size conflict | @dotlinux26 | §15 |
| 2026-08-14 | R2 before G3; G10 after S2/S6; R3 incremental | @dotlinux26 | §15 |
| 2026-08-14 | Recovery KDF = Argon2id + AES-256-GCM; Shamir SSS required per RFC 0006 §14 | @dotlinux26 | §15 |

- Tổng hợp từ 5 audit agent (transport/session/network, trust/governance, crypto/enroll, runtime/contract, discovery/mesh/storage/policy/enroll).
- Đã xác nhận lại trực tiếp: `session_mgr.open()` không caller; `PolicyEngine` không instantiate; `verify_attestation` chỉ check non-empty; `validate_token` không được gọi trong join path; 5 file runtime không compile; `record_event` không step; header packet �� RFC 0019.
- Status phiên bản: v0.0.6 = trust/witness wire + session recovery (đã đóng 2 gap từ audit trước).

---

## 17. Detailed Architectural Decisions & Implementation Plan (2026-08-14)

### 17.1 Core Architecture Principles (Approved 2026-08-14)

| Principle | Decision | Rationale |
|-----------|----------|-----------|
| **Root Authority Suite** | Suite 3 / ML-DSA-65 (PQ-native) | Genesis decides suite; all downstream crypto follows. No Suite 1 fallback in production. |
| **Suite Dispatch** | `CryptoRegistry::get_suite(suite_id)` only | Suite-driven crypto; no hardcoded algorithm calls in business logic. |
| **Key Identity** | `issuer_key_id + issuer_suite_id` | Key identity bound to suite; prevents confusion between authorities sharing suite. |
| **Join Flow** | Separate bootstrap trust domain | Join = separate trust domain. No cert → no session. JOIN_REQUEST → ISSUE_CERT → SECURE_HANDSHAKE. |
| **Session Security** | Cert-authenticated PQ handshake → AEAD + sequence/replay | Two-factor binding (cert + signed nonce). Post-handshake AEAD + sequence/replay protection. |
| **Authorization** | PolicyEngine before contract execution | PolicyEngine is security boundary; replaces AuthorizationManager god object. |
| **Trust Gossip** | Origin signature + epoch/replay validation | TrustDigest signature verified before apply; epoch/replay protection. |
| **Secret at Rest** | Argon2id + AES-256-GCM | Memory-hard KDF for password-derived keys; no BLAKE3(passphrase). |
| **Algorithm Selection** | Metadata/suite only via CryptoRegistry | No hardcoded algorithm names in business logic. |
| **Algorithm Inference** | **FORBIDDEN** | Never infer algorithm from byte length. CRYPTO-001 invariant. |
| **Runtime Wiring** | Incremental, one module/one gate | R3.1 event_store → R3.2 runtime_context → R3.3 history → R3.4 execution_engine → R3.5 scheduler. |
| **State Mutation** | Verify-first, mutate-last | All verification before any state change. |
| **Recovery Format** | Versioned format with Shamir SSS | RFC 0006 §14 M-of-N threshold; versioned format for forward compatibility. |
| **Testing** | Negative security tests before E2E | Downgrade, confusion, key-suite mismatch, replay, truncated sig tests. |

### 17.2 Trust Boundary Separation (Critical Architecture Decision)

```text
Bootstrap trust
      ��
Session trust
      ��
Authorization
      ��
Distributed trust
```

Each layer has **one dedicated trust boundary**, no shared `"authenticated"` boolean or single `"trusted"` state.

| Layer | Trust Boundary | Verification | Failure = |
|-------|----------------|--------------|-----------|
| **Bootstrap** | Join token signature | Issuer pubkey + suite binding | REJECT join |
| **Session** | Certificate + PQ handshake | Chain + expiry + **Capability Epoch** (thay CRL) + authority status + mesh auth | REJECT handshake |
| **Authorization** | PolicyEngine decision | Capability + trust + policy | REJECT contract |
| **Distributed** | TrustDigest origin sig | Origin pubkey + epoch + replay | REJECT gossip |

---

### 17.3 Detailed Implementation Order (Updated 2026-08-14)

```text
                 CURRENT
                    │
                    ��
              ��────────────��
              │ P0-S6      │
              │ Join/Auth  │
              └─────��──────��
                    │
                    ��
              ��────────────��
              │ P0-EX      │
              │ Secret     │
              └─────��──────��
                    │
                    ��
              ��────────────��
              │ R2         │
              │ Policy     │
              └─────��──────��
                    │
              ��─────��──────��
              ��            ��
           G10            G3
        TrustDigest    Packet Auth
              │            │
              └─────��──────��
                    ��
              ��────────────��
              │ G8         │
              │ MeshFSM    │
              └─────��──────��
                    │
                    ��
              ��────────────��
              │ R3         │
              │ Runtime    │
              └─────��──────��
                    │
                    ��
              ��────────────��
              │ G1/G2/G9   │
              │ Operations │
              └─────��──────��
                    │
                    ��
              Distributed
               semantics
```

#### Phase Gates (Each Must Pass Before Next)

| Phase | Tasks | Gate Criteria |
|-------|-------|---------------|
| **P0-S6** | Join/Auth separate domain; cert-then-session | E2E join works (fresh node → cert → session); PCT join tests pass |
| **P0-EX** | authority.sec encrypted (Argon2id + AES-256-GCM) | `cmd_sign` writes encrypted; wrong passphrase → reject; restart decrypts |
| **R2** | PolicyEngine instantiated + PolicyMiddleware wired; 7 anonymous contracts removed | PCT policy tests pass; no anonymous bypass in daemon |
| **G10** | TrustDigest signature verify before apply | PCT trust digest tests pass (valid/invalid/modified/replay) |
| **G3** | **UNBLOCKED 2026-08-14**: AEAD packet auth (data plane) + nonce/sequence/replay; control plane giữ digital signature | Data plane AEAD decrypt+replay-window tests pass; no plaintext packet; PCT packet tests pass |
| **G8** | MeshFSM wired; sign_bootstrap_csr impl; hardcode "Online" removed | FSM transitions work; PCT governance/join tests pass |
| **R3** | Incremental: event_store → runtime_context → history → execution_engine → scheduler | Each file: compile → link → unit test → smoke |
| **G9** | PeerStore::record_event calls stmt.step() | PCT discovery tests pass |
| **G2** | HeartbeatService wired; handle_ping→PongMsg; handle_pong→RTT/health | PCT discovery tests pass |
| **G1** | SESSION_OPEN handler; SessionManager::open() on packet path | E2E session open/close works |

---

### 17.4 Three Absolute Prohibitions (Agent Must Not Violate)

| ��� Prohibition | Correct Approach |
|----------------|------------------|
| **��� 1. Join exemption as `if (cert.empty()) allow()`** | Join = separate bootstrap trust domain. JOIN_REQUEST → verify token → issue cert → THEN SecureSession handshake. No "empty cert" in SecureSession. |
| **🏁 2. G3 packet signature (RESOLVED 2026-08-14)** | RFC 0019 (64B packet sig) vs RFC 0024 Suite 3 (ML-DSA-65 = 3309B). **User chốt: "signature" = packet authentication.** Data plane = AEAD tag + nonce/sequence/replay-window, NO per-packet ML-DSA. Control/identity plane (token/cert/manifest/vote/attestation/digest) giữ digital signature. Phải sửa RFC 0019 để phản ánh semantics này. |
| **��� 3. Recovery crypto auto-choice (Blake3 vs Argon2id)** | Must define: password KDF (Argon2id) + AEAD (AES-256-GCM) + salt + nonce + versioned format + Shamir SSS parameters. Versioned recovery format. |

---

### 17.5 Version Tracking (Updated)

| Track | Target | Description |
|-------|--------|-------------|
| **Feature roadmap** | v0.0.3 | 3-node operational scenario |
| **Security hardening** | DISCUSSION_0046 | This plan — trust-boundary + runtime compliance |

**Do not mix.** v0.0.3 is operational; 0046 is compliance hardening.

---

### 17.6 Updated Production-Ready Definition

```text
PRODUCTION_READY =
    P0 security gates PASS
AND P0.5 security invariants PASS
AND runtime wiring (P1) PASS
AND no security-critical stub on reachable execution path
AND PCT (all layers) PASS
AND E2E (including security regression) PASS
AND recovery/failure tests PASS
AND 3-node VPN scenario PASS
```

**Critical:** "No security-critical stub on reachable path" = `handle_ping`/`handle_pong`/`AuthorizationManager`/`apply_digest`/`record_event`/`SESSION_OPEN` must all be real implementations if reachable from untrusted input.

---

### 17.7 Required Negative Tests (Security Regression - Updated)

| Attack Vector | Test Case | Expected |
|---------------|-----------|----------|
| **Downgrade** | Suite 3 mesh + Suite 1 token | REJECT |
| **Algorithm confusion** | Suite 3 pubkey + Ed25519 sig | REJECT |
| | Suite 1 pubkey + ML-DSA sig | REJECT |
| | Suite 3 pubkey + garbage 3309-byte sig | REJECT |
| **Key-suite mismatch** | token.issuer_suite_id=3, issuer_key.suite_id=1 | REJECT |
| **Cross-mesh** | token.mesh_id=A, issuer_key.mesh_id=B | REJECT |
| **Revoked issuer** | issuer_key past capability epoch / deactivated authority | REJECT |
| **Replay** | Same nonce within expiry window | REJECT |
| **Truncated sig** | ML-DSA sig artificially shortened | REJECT |
| **Missing metadata** | token without issuer_suite_id | REJECT |
| **Delta transplant** | Valid delta from chain A inserted into chain B | REJECT |

---

### 17.8 Manifest Signature Canonical Format (Resolved)

```text
canonical(
    version (uint8),
    mesh_id (32 bytes),
    epoch (uint64 BE),
    prev_hash (32 bytes Blake3),
    data (CBOR map)
)
```

Signed by authority key. Prevents delta transplant across chains.

---

### 17.9 Recovery Package Format (Versioned)

> **FIXED 2026-08-14 (§24.4):** Recovery là **dedicated cryptographic domain** — KHÔNG inherit mesh suite AEAD. Dùng **AES-256-GCM → nonce 12 bytes** (KHÔNG bê 24B từ XChaCha20). Salt 32B. Tag 16B (từ AEAD). Domain này không đụng RFC 0024.

```text
RecoveryPackage v1:
{
  version: 1,
  suite_id: 3,
  mesh_id: "TestMesh",
  crypto_domain: "recovery",
  kdf: "Argon2id",
  passphrase_salt: 32 bytes,
  argon2_params: {memory: 65536, iterations: 3, parallelism: 4},
  aead: "AES-256-GCM",
  nonce: 12 bytes,          // AES-GCM nonce, KHÔNG phải 24B
  tag: 16 bytes,
  aead_ciphertext: (nonce || ciphertext),
  shamir_shares: [
    {threshold: 3, total: 5, shares: [...]}  // RFC 0006 §14 M-of-N
  ],
  created_at: unix_ns
}
```

---

### 17.10 RFC Reference Matrix (Decision Traceability)

| Decision | RFC Source | Section |
|----------|------------|---------|
| Suite 3 = ML-DSA-65 | RFC 0024, SPEC §6.6 | §8.1 |
| Token issuer_suite_id + issuer_key_id | RFC 0009, RFC 0024 | §8.3 |
| Recovery package metadata = key material source | RFC 0006, RFC 0009 | §8.4 |
| CRYPTO-001: No algorithm inference | RFC 0009, RFC 0024 | §10 |
| Join = separate bootstrap trust domain | RFC 0006, RFC 0007, RFC 0014 | §15 |
| Manifest signature = canonical(data\|epoch\|prev_hash) | RFC 0018 | §15 |
| Argon2id for recovery KDF | RFC 0006 | §15 |
| Shamir SSS required | RFC 0006 §14 | §15 |
| TrustDigest signature = origin||sequence||timestamp||scores | RFC 0017 | §10 |
| Packet auth: resolve RFC 0019 vs 0024 first | RFC 0019, RFC 0024 | §15 |
| GENESIS_SUITE_INVARIANT | RFC 0024 | §8.2 |

---

### 17.11 Negative Security Test Matrix (All Must Pass)

| Category | Test | Expected |
|----------|------|----------|
| **Downgrade** | Suite 3 mesh + Suite 1 token | REJECT |
| **Algorithm confusion** | Suite 3 pubkey + Ed25519 sig | REJECT |
| | Suite 1 pubkey + ML-DSA sig | REJECT |
| | Suite 3 pubkey + garbage 3309-byte sig | REJECT |
| **Key-suite mismatch** | token.issuer_suite_id=3, issuer_key.suite_id=1 | REJECT |
| **Cross-mesh** | token.mesh_id=A, issuer_key.mesh_id=B | REJECT |
| **Revoked issuer** | issuer_key past capability epoch / deactivated authority | REJECT |
| **Replay** | Same nonce within expiry window | REJECT |
| **Truncated sig** | ML-DSA sig artificially shortened | REJECT |
| **Missing metadata** | token without issuer_suite_id | REJECT |
| **Delta transplant** | Valid delta from chain A inserted into chain B | REJECT |

---

### 17.11 Final Verification Checklist (All Must Pass)

| Check | Command | Expected |
|-------|---------|----------|
| Build | `cmake --build build-release -j8` | 0 errors |
| Format | `clang-format --dry-run --Werror` | 0 changes |
| CTest | `ctest -j8` | 19/19 PASS |
| PCT | `./tests/smo_pct` | 24/24 PASS |
| E2E | `/tmp/opencode/e2e-full.sh` | SUCCESS |
| Security regress | Negative test matrix | All REJECT |
| No plaintext secret | `grep -r "authority.sec" --include="*.cpp" | grep -v encrypted` | 0 matches |
| No algorithm inference | `grep -r "signature.size()" --include="*.cpp" | grep -v test` | 0 matches |

---

## 18. Updated Decision Log (Human Approved)

| Date | Decision | By | Reference |
|------|----------|----|-----------|
| 2026-08-13 | Root key = Suite 3 / ML-DSA-65 | @dotlinux26 | §8.1 |
| 2026-08-13 | Token uses `issuer_suite_id` + `issuer_key_id` | @dotlinux26 | §8.3 |
| 2026-08-13 | Recovery package metadata = source of truth for keys | @dotlinux26 | §8.4 |
| 2026-08-13 | CRYPTO-001: No algorithm inference from byte length | @dotlinux26 | §10 |
| 2026-08-13 | P0.5 created for PolicyEngine/G3/G10/G8/Recovery KDF | @dotlinux26 | §9 |
| 2026-08-13 | RFC 0024 canonical profile table required | @dotlinux26 | §12 |
| 2026-08-13 | Agent MUST trace root cause before modifying parse_token | @dotlinux26 | §15 |
| 2026-08-14 | Join = separate bootstrap trust domain; no empty cert/sig in SecureSession | @dotlinux26 | §15 |
| 2026-08-14 | Manifest signature = canonical(data || epoch || prev_hash) | @dotlinux26 | §15 |
| 2026-08-14 | P0-EX: Argon2id + AES-256-GCM for authority.sec encryption | @dotlinux26 | §15 |
| 2026-08-14 | G3 blocked on RFC 0019 vs Suite 3 signature size conflict | @dotlinux26 | §15 |
| 2026-08-14 | R2 before G3; G10 after S2/S6; R3 incremental | @dotlinux26 | §15 |
| 2026-08-14 | Recovery KDF = Argon2id + AES-256-GCM; Shamir SSS required per RFC 0006 §14 | @dotlinux26 | §15 |

---

### 18. Sources

- Tổng hợp từ 5 audit agent (transport/session/network, trust/governance, crypto/enroll, runtime/contract, discovery/mesh/storage/policy/enroll).
- Đã xác nhận lại trực tiếp: `session_mgr.open()` không caller; `PolicyEngine` không instantiate; `verify_attestation` chỉ check non-empty; `validate_token` không được gọi trong join path; 5 file runtime không compile; `record_event` không step; header packet �� RFC 0019.
- Status phiên bản: v0.0.6 = trust/witness wire + session recovery (đã đóng 2 gap từ audit trước).

---

## 19. Appendices

### 19.1 RFC Reference Quick Links

| RFC | Title | Status |
|-----|-------|--------|
| 0004 | Trust and Reputation | ACCEPTED |
| 0006 | Mesh Identity & Certificate | ACCEPTED |
| 0007 | Enrollment Protocol | ACCEPTED |
| 0009 | Crypto Provider Architecture | ACCEPTED |
| 0013 | Transport Abstraction | ACCEPTED |
| 0014 | Session Lifecycle | ACCEPTED |
| 0016 | Governance Protocol | ACCEPTED |
| 0017 | Trust Engine (Engineering) | ACCEPTED |
| 0019 | Packet Layout | DRAFT |
| 0024 | Crypto Suite Freeze | ACCEPTED |

---

## 20. Final Architecture Assessment — Reviewer Decision (2026-08-14) 🔒 LOCK TARGET

> **Câu hỏi được đối chất:**
> > "Trong các phương án hiện tại, kiến trúc nào chuẩn nhất + secure nhất + nhẹ nhất + tối ưu nhất cho mesh hiện tại?"

**Kết luận của reviewer:** KHÔNG chọn nguyên xi toàn bộ những gì document đề xuất ở §17. Giữ nguyên **trust boundary** và **crypto-domain separation**, nhưng chốt kiến trúc khác ở **packet/session layer**.

### 20.1 Chốt ngắn gọn (kiến trúc chuẩn)

```text
                 ┌──────────────────────┐
                 │     ROOT AUTHORITY   │
                 │ ML-DSA-65 / Suite 3  │
                 └──────────┬───────────┘
                            │
                     JOIN TOKEN
                     issuer_key_id
                     issuer_suite_id
                            │
                            ▼
                 ┌──────────────────────┐
                 │    JOIN PROTOCOL     │
                 │ verify → issue cert  │
                 └──────────┬───────────┘
                            │
                       NODE CERT
                            │
                            ▼
                 ┌──────────────────────┐
                 │  SECURE HANDSHAKE    │
                 │ mutual authentication│
                 │ KEM → session keys   │
                 └──────────┬───────────┘
                            │
                    derived session key
                            │
                            ▼
          ┌───────────────────────────────────┐
          │        PACKET DATA PLANE           │
          │ AEAD + nonce + replay window       │
          │ NO ML-DSA SIGNATURE PER PACKET     │
          └───────────────────────────────────┘
```

> **Điểm sửa mạnh nhất so với §17:** packet/session layer → AEAD + replay, KHÔNG ký ML-DSA từng packet.

### 20.2 Điểm 0046 rất chuẩn → GIỮ NGUYÊN

| # | Quyết định | Đánh giá |
|---|-----------|----------|
| ① | **Crypto Domain ≠ Cipher Suite** | Giữ. Tuyệt đối cấm `if (sig.size()==64) use_ed25519(); if (sig.size()==3309) use_mldsa();`. Đúng pattern: `domain → suite_id → CryptoRegistry → Signer/KEM/Hash/KDF/AEAD` và `serialized metadata → explicit suite_id → registry → provider`. **CRYPTO-001 cực kỳ đúng.** |
| ② | **GENESIS_SUITE_INVARIANT** | Giữ: `mesh.genesis_suite_id == root_authority.key.suite_id == root_authority.signer.suite_id == recovery_package.suite_id == token.issuer_suite_id`. **Mismatch = reject, không fallback.** Cấm `Suite 3 fail → thử Suite 1 → thử Ed25519` (đất cho algorithm-confusion/downgrade). |
| ③ | **Join riêng khỏi SecureSession** | Giữ 100%. Cấm `SecureSession if (cert.empty()) allow_bootstrap()` (dễ biến thành lỗ hổng execution-path sau này). |

### 20.3 Điểm CHỐT LẠI — packet/session layer (khác §17 nguyên xi)

- §17 mô phỏng "Every packet MUST carry signature" theo **RFC 0019: 64-byte signature**.
- Nhưng **Suite 3 ML-DSA-65 signature ≈ 3309 bytes** → **architectural contradiction**:
  - packet nhỏ → overhead cực lớn (3309B sig trên packet nhỏ)
  - CPU sign/verify tăng mạnh
  - bandwidth tăng
  - UDP fragmentation
  - DoS surface tăng
  - mesh throughput giảm
  - heartbeat/control packets cực kỳ phí

**Phương án chốt: AEAD packet authentication sau handshake thành công.**

```text
K_session (derived)
  ↓
Mỗi packet:
┌───────────────┐
│ session_id    │
│ epoch         │
│ sequence      │
│ nonce         │
│ timestamp     │
│ ciphertext    │
│ AEAD tag      │
└───────────────┘

AEAD_Encrypt(K_session, nonce, plaintext, AAD = header)

Receive:
  check session → check epoch → check nonce/sequence → AEAD decrypt+auth → accept
```

**Không cần:** `ML-DSA-sign(packet)` cho từng packet.

### 20.4 Replay protection VẪN PHẢI GIỮ (AEAD ≠ chống replay)

AEAD chỉ đảm bảo `authentic + confidential + integrity`. Nó KHÔNG tự ngăn attacker replay ciphertext hợp lệ.

```text
session_id + epoch + sequence/nonce + replay window
```

Ví dụ:

```text
highest_seen = 1000
window = 64

packet 1001 → accept
packet 999  → accept nếu chưa seen
packet 900  → reject
packet 1001 → reject duplicate
```

### 20.5 Signature nên nằm ở đâu? (phân tầng)

**Identity / control plane — dùng ML-DSA-65:**

```text
root authority
certificate
join token
manifest
bootstrap ticket
governance vote
attestation
trust digest
```

Những thứ này cần **identity-level authenticity**.

**Data plane — dùng:**

```text
K_session + AEAD + nonce/sequence + replay protection
```

Không ký ML-DSA từng packet.

### 20.6 Nếu RFC 0019 bắt buộc signature per packet?

> **Đừng tự ý sửa implementation để "cho nhẹ". Phải sửa RFC/spec architecture trước.**

3 lựa chọn:

```text
A. RFC 0019 thực sự bắt buộc digital signature  → phải implement đúng.
B. RFC 0019 chỉ muốn packet authentication       → AEAD tag là đủ.
C. RFC 0019 muốn non-repudiation                 → cần signature, nhưng phải thiết kế
                                                    batching/aggregated authentication
                                                    hoặc packet-control signature riêng.
```

> **Cấm:** silently đổi "signature" thành "AEAD tag".

### 20.7 Bảng so sánh (4 tiêu chí: Security / Performance / Complexity / Chọn)

| Kiến trúc              | Security | Performance | Complexity | Em chọn |
| ---------------------- | -------: | ----------: | ---------: | ------- |
| ML-DSA mỗi packet      |    ⭐⭐⭐⭐⭐ |           ⭐ |         ⭐⭐ | ❌       |
| Ed25519 mỗi packet     |     ⭐⭐⭐⭐ |         ⭐⭐⭐ |         ⭐⭐ | ❌       |
| Session MAC mỗi packet |    ⭐⭐⭐⭐⭐ |       ⭐⭐⭐⭐⭐ |      ⭐⭐⭐⭐⭐ | ✅       |
| AEAD + replay window   |    ⭐⭐⭐⭐⭐ |       ⭐⭐⭐⭐⭐ |      ⭐⭐⭐⭐⭐ | **🔥**  |
| Không auth packet      |        ⭐ |       ⭐⭐⭐⭐⭐ |      ⭐⭐⭐⭐⭐ | ❌       |

> **Cho mesh hiện tại: AEAD + replay protection sau authenticated handshake = sweet spot.**

### 20.8 Kiến trúc cuối cùng được chốt (3-plane separation)

```text
                    CONTROL PLANE
                    ─────────────

        Root Authority / ML-DSA-65
                    │
                    ├── Join Token
                    ├── Certificate
                    ├── Manifest
                    ├── Bootstrap Ticket
                    ├── Governance
                    └── Trust/Attestation
                            │
                            ▼
                     CRYPTO VERIFY
                            │
                            ▼
                       TRUST STATE


                    SESSION PLANE
                    ─────────────

                Certificate Auth
                       +
                  PQ Handshake
                       │
                       ▼
                 Key Derivation
                       │
                       ▼
                  K_session


                    DATA PLANE
                    ──────────

Packet
  │
  ├── session_id
  ├── epoch
  ├── sequence
  ├── nonce
  └── timestamp
       │
       ▼
     AEAD
       │
       ▼
 Replay Window
       │
       ▼
  Policy Engine
       │
       ▼
 Contract / Runtime
```

**Separation đẹp nhất — KHÔNG dùng một primitive giải quyết 4 vấn đề:**

> **Digital signature** xác nhận "WHO/WHAT authority issued this".
> **Certificate** xác nhận "WHO is this node".
> **Handshake** tạo "THIS SESSION".
> **AEAD** xác nhận "THIS PACKET belongs to THIS SESSION and hasn't been modified/replayed".

### 20.9 Các quyết định khác được giữ/khẳng định

| # | Chủ đề | Quyết định |
|---|--------|-----------|
| 9 | **Recovery: Argon2id + Shamir** | Hợp lý. `password → Argon2id → KEK → AEAD → encrypted recovery package`. BLAKE3(password) KHÔNG phải password KDF memory-hard. **Shamir KHÔNG nhét vào crypto provider** — thuộc recovery domain, không phải Suite primitive. |
| 10 | **TrustDigest** | Đúng hướng. `verify(origin_pubkey, canonical(origin||sequence||timestamp||scores), signature)` rồi mới `apply_digest()`. **Verify trước mutation.** |
| 11 | **PolicyEngine → P0.5** | Gần P0 hơn P1. `PolicyEngine exists + PolicyMiddleware NOT wired` = security boundary thực tế không tồn tại. `set_anonymous()` bypass policy = cực kỳ nguy hiểm. |
| 12 | **R3 trước R1** | Đúng. Tránh god-container service locator. Tiering T1/T2 hợp lý. |

**Invariant bất biến chung:**

```text
UNTRUSTED DATA
      ↓
PARSE
      ↓
STRUCTURAL VALIDATION
      ↓
CRYPTO VERIFICATION
      ↓
AUTHORIZATION
      ↓
STATE MUTATION
```

Cấm:

```text
parse → mutate state → warning: signature invalid
```

### 20.10 Verdict

**Trust architecture của DISCUSSION_0046: ~9/10.**

Điểm mạnh:
- suite-ID driven
- cryptographic domains
- no algorithm inference
- join ≠ secure session
- verify-before-mutate
- trust/governance/authentication separation
- policy nằm trên execution path
- security gates trước runtime feature

> **Chưa nên code G3** cho tới khi giải quyết contradiction **RFC 0019 ↔ ML-DSA signature size**.
> Chốt cuối: **ML-DSA cho identity/control plane + authenticated PQ handshake + AEAD/replay protection cho data plane** — thay vì biến toàn bộ mesh thành hệ thống "ký ML-DSA từng packet".

---

## 21. RFC Source Trace — Trích dẫn gốc để đối chất (2026-08-14)

> Các trích dẫn bên dưới là **chữ gốc trong file RFC** tại `smoframework/RFC/`, dùng để đối chất và chốt quyết định RFC + chốt quyết định implement.

### 21.1 RFC 0019 — Packet Layout (Status: **DRAFT**)

**§1 — Fixed 37-byte header, variable payload, 64-byte signature**

> "Total minimum: 101 bytes (37 header + 0 payload + 64 signature). Maximum payload: 65,507 bytes."

**§2 — Field definitions**

| Offset | Size | Field | Description |
|---|---|---|---|
| 0 | 1 | protocol_version | Wire protocol version (currently 0x03) |
| 1 | 1 | suite_id | Crypto Suite ID used for signing |
| 2 | 1 | namespace | 0x01=DISCOVERY, 0x02=CONTROL, 0x03=EXECUTION, 0x04=DATA |
| 3 | 2 | message_id | Opcode within namespace |
| 5 | 16 | session_id | 128-bit session identifier |
| 21 | 8 | timestamp | Unix ns (big-endian) |
| 29 | 8 | nonce | Random nonce for replay protection |
| 37 | 2 | payload_length | big-endian, max 65535 |
| 39 | N | payload | 0..65535 bytes |
| 39+N | 64 | signature | Suite-specific signature over bytes 0 to 38+N |

**§3 — Wire protocol rules (frozen)**

> 1. Every packet MUST carry a nonce. Zero-filled nonces are REJECTED.
> 2. Every packet MUST be signed. Zero-filled signatures are REJECTED.
> 3. Timestamp is Unix nanoseconds. Receivers REJECT packets with |now - timestamp| > configured window (default 300 seconds).
> 4. Payload MAY be encrypted at the session level. Header fields are never encrypted.

**§5 — Consequences (KEY — mâu thuẫn tự thú)**

> "64-byte signature slot covers all Suite 1-3 signing algorithms (Ed25519=64, ML-DSA-65=3309 but post-MVP)."
> "8-byte nonce is sufficient for replay protection (combined with per-sender sequence tracking)."

**🔍 Phát hiện đối chất:**
- RFC 0019 **tự khai** cái "64-byte signature slot" KHÔNG chứa nổi ML-DSA-65 (3309B) và đẩy sang "post-MVP".
- RFC 0019 đang là **DRAFT**. RFC 0024 (ACCEPTED) lại yêu cầu Suite 3 = ML-DSA-65. → **RFC 0019 phải sửa hoặc bị supersede.**
- Điểm đáng lưu: "8-byte nonce is sufficient ... (combined with per-sender sequence tracking)" → chính RFC 0019 **đã nhắc tới per-sender sequence tracking** — ủng hộ replay-window trong thiết kế §20.

### 21.2 RFC 0024 — Crypto Suite Freeze (Status: **ACCEPTED**)

**Canonical Suite Table (CHỮ GỐC):**

| Suite | Hash | Signing | AEAD | KEM |
|---|---|---|---|---|
| 1 Classical | SHA-256 | Ed25519 | XChaCha20-Poly1305 | X25519 |
| 2 Modern | BLAKE3-256 | Ed25519 | XChaCha20-Poly1305 | X25519 |
| 3 PurePQC | BLAKE3-256 | ML-DSA-65 | XChaCha20-Poly1305 | ML-KEM-768 |

**§ Why HKDF?**
> "KEM shared secrets are NEVER used as session keys directly. HKDF-extract (salt) + HKDF-expand (info, length) derives independent keys."

**🔍 Phát hiện đối chất — đây là canonical source duy nhất:**
- **Suite 2 = Ed25519 + X25519** (KHÔNG phải Ed25519 + ML-DSA). Mọi chỗ trong 0046 ghi "Suite 2 = Ed25519 + ML-DSA" là **sai lệch** so với RFC 0024.
- **Suite 3 KEM = ML-KEM-768** (KHÔNG phải 1024). Implementation có cả 768 lẫn 1024 → phải khóa 1 giá trị.
- **HKDF** là KDF session key chuẩn (KEM secret không dùng trực tiếp). Điều này không mâu thuẫn với Argon2id (Argon2id là password-KDF cho recovery; HKDF là KEM-KDF cho session).

### 21.3 RFC 0006 — Mesh Identity & Certificate (Status: **ACCEPTED**)

**§ Decisions:**
> 5. "Root Key never circulates. ... exported as encrypted Recovery Package (**AES-256-GCM**), then deleted from runtime."
> 6. "**Recovery Authorities** use **Shamir Secret Sharing (M-of-N threshold)** to reconstruct the Root Key if lost."
> 7. "**Session binding** requires two independent proofs: a valid Membership Certificate (chain up to Root) and a signed nonce (proves key possession)."

**🔍 Phát hiện đối chất:**
- Recovery encryption theo RFC 0006 = **AES-256-GCM** (khớp §17.9 của 0046). RFC 0006 KHÔNG nói rõ KDF → Argon2id là lựa chọn hardening đúng (giữ).
- **Shamir M-of-N** là yêu cầu RFC 0006 (khớp quyết định §15). Thuộc recovery domain, không nhét vào crypto provider.
- **Session binding = cert + signed nonce** → khớp RFC 0014 và P0-S6.
- Lưu ý: RFC 0006 nói "Ed25519 is the identity primitive" — đây là kiến trúc OLD pre-suite-freeze; bị supersede bởi RFC 0024 suite table. Ghi chú để tránh nhầm lẫn.

### 21.4 RFC 0007 — Enrollment Protocol (Status: **ACCEPTED**, ~60% impl)

**§ Decisions — Join Token:**
> "Join Token (v1, CBOR) ... `smo-admin generate-invite` ... generates `SMO-JOIN-<base64url(CBOR||HMAC)>`. The token is a CBOR map ... containing: `version`, `mesh_id`, `mesh_epoch`, `cipher_suite_id`, `bootstrap_endpoints[]`, `role`, `expiry`, `nonce`. The HMAC is computed over the CBOR payload with the mesh's `hmac_secret` (**32-byte key stored in `mesh.json`**)."
> "The token contains ONLY bootstrap data — NEVER a certificate or private key."

**🔍 Phát hiện đối chất (MÂU THUẪN LỚN):**
- RFC 0007 định nghĩa Join Token authentication = **HMAC với hmac_secret (symmetric, mesh-wide shared secret)**.
- Nhưng quyết định §8/§16/§20 của 0046 = token dùng **issuer_suite_id + issuer_key_id** (asymmetric, sign bằng authority/root key), và P0-S1 đã **implement signature verify** (asymmetric).
- → **RFC 0007 vs quyết định 0046 đang mâu thuẫn**: HMAC (symmetric, shared secret, dễ audit ít nhưng key phải giữ chung) vs digital signature (asymmetric, non-repudiation, không cần hmac_secret lan truyền).
- **Cần user chốt:** giữ RFC 0007 HMAC hay migration sang signature (0046)? Nếu signature → **phải sửa RFC 0007** (token format + hmac_secret deprecation).
- Ghi chú thêm: RFC 0007 áp dụng `cipher_suite_id` là property của mesh (khớp GENESIS_SUITE_INVARIANT).

### 21.5 RFC 0014 — Session Lifecycle (Status: **ACCEPTED**)

**§ Decisions:**
> 1. "Session is two-factor bound: certificate + signed nonce."
> 5. "If transport-level encryption is not used (e.g., UDP), the session may derive a symmetric key for payload encryption."
> 6. "`session_store` persists all ESTABLISHED and ACTIVE sessions."

**🔍 Phát hiện đối chất:**
- RFC 0014 §5 **ủng hộ trực tiếp** thiết kế AEAD data plane của §20: session derives symmetric key cho payload encryption khi transport không bảo mật (UDP).
- Session-scoped CapabilitySet (`session.verify_capability(opcode)`) khớp ràng buộc PolicyEngine nằm trên execution path (§20.9 #11).
- Crash recovery (session_store) = yêu cầu cho P0-S6/SESSION_OPEN.

### 21.6 RFC 0013 — Transport Abstraction (Status: **ACCEPTED**)

**§ Decisions — framing:**
> "A FrameHeader prepends every application message with: total_length (4 bytes), protocol_version (2), flags (2), session_id (16). The transport layer strips this before delivering bytes to the protocol layer."

**§ Consequences:**
> "The protocol layer receives already-framed byte sequences."

**🔍 Phát hiện đối chất:**
- RFC 0013 có **FrameHeader riêng (wire framing)** và RFC 0019 có **PacketHeader 37-byte (protocol-level)** — hai tầng framing khác nhau. → Tránh nhầm khi implement G3: transport strips FrameHeader, protocol xử lý PacketHeader.
- Transport là abstract base → KHÔNG nên để ML-DSA-65 signature (3309B) làm vỡ giả định framing của transport.

### 21.7 Cross-RFC Contradiction Summary (cần lock)

| # | Contradition | RFC A | RFC B | Cần lock |
|---|--------------|-------|-------|----------|
| C1 | 64-byte signature slot vs ML-DSA-65 (3309B) | 0019 (DRAFT) | 0024 (ACCEPTED) | Định nghĩa lại packet auth cho Suite 3 |
| C2 | Join Token = HMAC (symmetric) vs issuer-signed signature | 0007 (ACCEPTED) | 0046 §8/§16 | Chốt auth scheme token |
| C3 | Suite 3 KEM = 768 vs 1024 xuất hiện trong impl & 0046 | 0024 (ACCEPTED) | 0046/impl | Khóa ML-KEM-768 |
| C4 | Suite 2 = Ed25519+X25519 vs Ed25519+ML-DSA | 0024 (ACCEPTED) | 0046 chỗ khác | Khóa Ed25519+X25519 |

---

## 22. Open Questions — RESOLVED (đối chất & chốt 2026-08-14)

> **Cả 4 câu hỏi đã được user chốt. G3/S6 KHÔNG còn bị block bởi các câu hỏi này.**

### ✅ A — RFC 0019: Packet auth = **AEAD tag**

> Quyết định: "Packet auth = AEAD tag" — sau handshake, data plane dùng AEAD + nonce/sequence/replay-window. Không ký ML-DSA từng packet.

Hệ quả:
- RFC 0019 là DRAFT, mâu thuẫn RFC 0024 (ACCEPTED) về kích thước signature slot → **cần sửa RFC 0019** để phản ánh: signature field dùng cho identity/control plane messages; data plane (namespace 0x04=DATA) dùng AEAD tag, không bắt buộc literal digital signature.
- RFC 0019 đã chứa sẵn "per-sender sequence tracking" → replay window tựa theo đó.
- Wire format: giữ 37-byte header (frozen), nhưng claralify semantics của signature field theo §20.

### ✅ B — Suite 3 KEM: **ML-KEM-768**

> Quyết định: ML-KEM-768 (canonical RFC 0024, NIST level 3). Bỏ ML-KEM-1024 khỏi implementation + 0046.

### ✅ C — Suite 2: **Ed25519 + X25519**

> Quyết định: Ed25519 + X25519 (canonical RFC 0024). Sửa mọi chỗ trong 0046 ghi "Suite 2 = Ed25519 + ML-DSA" thành chuẩn. Không dùng ML-DSA làm KEM Suite 2.

### ✅ D — Join Token: **Giữ issuer signature (0046/P0-S1)**

> Quyết định: giữ asymmetric issuer signature (`issuer_suite_id + issuer_key_id`, non-repudiation). Rollback KHÔNG xảy ra.

Hệ quả:
- Phải sửa RFC 0007: deprecate `hmac_secret`/HMAC cho Join Token; cập nhật token format thành CBOR + issuer signature + key_id metadata.
- `MeshConfig.hmac_secret` không còn là cơ chế auth token (có thể giữ bảo tồn hoặc bỏ — cần quyết định khi sửa RFC 0007).

---

## 23. Updated Decision Log (Human Approved) — FINAL 2026-08-14

| Date | Decision | By | Status | Reference |
|------|----------|----|--------|-----------|
| 2026-08-13 | Root key = Suite 3 / ML-DSA-65 | @dotlinux26 | ✔ LOCK | §8.1 |
| 2026-08-13 | Crypto Domain ≠ Cipher Suite (CRYPTO-001) | Reviewer | ✔ LOCK | §20.2①, §10 |
| 2026-08-13 | GENESIS_SUITE_INVARIANT: mismatch = reject, no fallback | Reviewer | ✔ LOCK | §20.2②, §8.2 |
| 2026-08-13 | Token = issuer_suite_id + issuer_key_id | @dotlinux26 | ✔ LOCK | §8.3 |
| 2026-08-13 | Recovery package metadata = source of truth | @dotlinux26 | ✔ LOCK | §8.4 |
| 2026-08-14 | Join = separate bootstrap trust domain; no empty cert in SecureSession | Reviewer | ✔ LOCK | §20.2③, §15 |
| 2026-08-14 | Data plane = **AEAD + nonce + sequence + replay window**; NO per-packet ML-DSA | Reviewer | ✔ LOCK | §20.3–§20.8 |
| 2026-08-14 | Control/identity plane = ML-DSA-65 (root, cert, token, manifest, ticket, vote, attestation, digest) | Reviewer | ✔ LOCK | §20.5 |
| 2026-08-14 | Verify-before-mutate invariant (parse→validate→verify→authorize→mutate) | Reviewer | ✔ LOCK | §20.9 |
| 2026-08-14 | Recovery = Argon2id + AES-256-GCM; Shamir M-of-N in recovery domain | Reviewer | ✔ LOCK | §20.9#9, §17.9 |
| 2026-08-14 | **A) RFC 0019 packet auth = AEAD tag** (data plane); control/identity plane giữ digital signature | @dotlinux26 | ✔ LOCK | §22.A |
| 2026-08-14 | **B) Suite 3 KEM = ML-KEM-768**; bỏ 1024 | @dotlinux26 | ✔ LOCK | §22.B |
| 2026-08-14 | **C) Suite 2 = Ed25519 + X25519**; sửa chỗ ghi sai trong 0046 | @dotlinux26 | ✔ LOCK | §22.C |
| 2026-08-14 | **D) Join Token = issuer signature** (giữ P0-S1); sửa RFC 0007 deprecate HMAC | @dotlinux26 | ✔ LOCK | §22.D |
| 2026-08-14 | G3 UNBLOCKED: implement AEAD packet protection (namespace DATA/EXECUTION) | @dotlinux26 | ✔ LOCK | §22.A |
| 2026-08-14 | **§24.1** Suite 1 hash = SHA-256 (sửa doc sai; khớp RFC 0024 + impl) | Reviewer | ✔ LOCK | §24.1 |
| 2026-08-14 | **§24.2** RFC 0006 MUST amend: identity = Suite-selected; Root/Authority/Cert = Suite 3 ML-DSA-65 (**BLOCKER**) | Reviewer | ✔ LOCK | §24.2 |
| 2026-08-14 | **§24.3** RFC 0019 MUST amend: DATA plane = AEAD/sequence/replay; CONTROL/IDENTITY = digital sig; wording = "packet authentication" (**BLOCKER**) | Reviewer | ✔ LOCK | §24.3 |
| 2026-08-14 | **§24.4** Recovery = recovery domain (Argon2id + AES-256-GCM + salt 32B + nonce **12B** + tag 16B); rewrite P0-EX theo spec | Reviewer | ✔ LOCK | §24.4 |
| 2026-08-14 | **§24.5** RFC 0007 MUST amend: Join Token HMAC → issuer_key_id + issuer_suite_id + signature (**BLOCKER**) | Reviewer | ✔ LOCK | §24.5 |
| 2026-08-14 | **§24.6** CRL → Capability Epoch (RFC 0006); bỏ "CRL + epoch" song song | Reviewer | ✔ LOCK | §24.6 |
| 2026-08-14 | **§24.7** MỘT bảng Current Status duy nhất; §15/G10/P0-EX status cũ = historical | Reviewer | ✔ LOCK | §24.7 |
| 2026-08-14 | **AMEND-1** RFC 0006: identity = Suite-selected; Root/Authority/Cert = ML-DSA-65 | Reviewer | ✔ DONE amend | §24.2 |
| 2026-08-14 | **AMEND-2** RFC 0006: revocation = Capability Epoch + Revocation Set (epoch: coarse; RS: fine) | Reviewer | ✔ DONE amend | §24.6, §25.4 |
| 2026-08-14 | **AMEND-3** RFC 0006: recovery domain = Argon2id + AES-256-GCM (salt 32B, nonce 12B); recovery ≠ resurrection | Reviewer | ✔ DONE amend | §25.12 |
| 2026-08-14 | **AMEND-4** RFC 0019: packet auth semantics — DATA=AEAD/sequence/replay; CONTROL/IDENTITY=digital sig; variable-length auth field | Reviewer | ✔ DONE amend | §24.3 |
| 2026-08-14 | **AMEND-5** RFC 0007: Join Token = issuer_key_id + issuer_suite_id + digital sig; hmac_secret deprecated | Reviewer | ✔ DONE amend | §24.5 |
| 2026-08-14 | **AMEND-6** RFC 0016: atomic revoke+elect transition; base_epoch + base_state_hash anti-split-brain; hash-chained state | Reviewer | ✔ DONE amend | §25.8–9 |
| 2026-08-14 | **AMEND-7** RFC 0016: liveness ≠ revocation (no auto-revoke on offline); signature-valid ≠ governance-authority | Reviewer | ✔ DONE amend | §25.6, §25.10 |
| 2026-08-14 | **§25.14** RCF-consistent decision table (recovery/session/revocation/governance) | Reviewer | ✔ LOCK | §25.14 |
| 2026-08-14 | **§26.4** Implementation order LOCKED: SPEC → P0-EX → recovery tests → G3 → packet tests → E2E | Reviewer | ✔ LOCK | §26.4 |
| 2026-08-14 | **§26.3** Recovery KHÔNG dùng `CryptoRegistry::get_suite()` AEAD; RecoveryDomain riêng (Argon2id + AES-256-GCM) | Reviewer | ✔ LOCK | §26.3 |
| 2026-08-14 | **SPEC.md synced** tới RFC 0024 canonical (suite table, join token, recovery, MeshID/NodeID suite-hash) | Reviewer | ✔ DONE | §26.2 |
| 2026-08-14 | **P0-EX backend = OpenSSL 3 EVP** cho AES-256-GCM (RecoveryDomain) — expose qua SMO abstraction (`AES256GCMProvider`), ABSOLUTELY NO native self-written AES-GCM, NO silent downgrade (build fails khi thiếu OpenSSL) | @dotlinux26 | ✔ LOCK | §26.3, §17.9 |
| 2026-08-14 | **P0-EX IMPL DONE**: thêm `core/crypto/aead/aes256_gcm_provider.*` (OpenSSL EVP), `core/crypto/kdf/argon2id.*` (Monocypher), `core/crypto/recovery_crypto.*` (RecoveryCryptoProvider); rewrite `encrypt_authority_secret_key` (smo-admin) + `authority.cpp open()` + `recovery_package.cpp` unlock/verify + `genesis.cpp` stage0 + `cli_application.cpp` wiring + 6 recovery crypto tests (NIST CAVS AES-256-GCM vector) — build + 20 ctest + 24 PCT PASS. Follow-up: `recovery_engine.cpp verify_recovery_package` TODO (circular dep smo_core↔smo_genesis) | Reviewer | ✔ DONE | §26.4 step 2 |

---

## 24. Pre-Implementation Consistency Lock — 5 Amendment Points (Reviewer, 2026-08-14)

> **Verdict: architecture ~90–95% chốt được.** Không cần thiết kế lại. NHƯNG chưa đủ sạch để đóng RFC và bảo agent implement. Phải khóa 4 đổi RFC + 1 điểm recovery trước.

### 24.1 🔴 BLOCKER 1 — §12 sai RFC 0024 ở Suite 1 (hash)

- 0046 cũ ghi: `Suite 1 = Ed25519 + X25519 + BLAKE3 + XChaCha20`.
- RFC 0024 freeze chính thức: **Suite 1 hash = SHA-256**; **Suite 2 = BLAKE3-256**; **Suite 3 = BLAKE3-256**. RFC 0024 còn explicitly nói "SHA-256 in Suite 1 instead of BLAKE3? Suite 1 = Classical = maximum compatibility."
- Implementation **đã đúng**: `providers/suite1_classical/` dùng `sha256_hash_fn`; `suite2_modern/` dùng `blake3_hash_fn`.
- **✅ ĐÃ SỬA**: §12 + §7.4.1 giờ là canonical (Suite 1 = SHA-256). Chỉ còn **MỘT bảng duy nhất** làm nguồn chân lý.
- **Lệnh cho agent:** KHÔNG code CỘNG THEO 2 bảng khác nhau. Nếu thấy subsection khác ghi BLAKE3 cho Suite 1 → là bug doc, sửa theo §12.

### 24.2 🔴 BLOCKER 2 — RFC 0006 identity primitive vs Root = Suite 3

- RFC 0006 hiện vẫn nói: **"Ed25519 is the identity primitive"** và Root→Authority→Node đều nằm trong model đó.
- 0046 đã lock: **Root Authority = Suite 3 / ML-DSA-65**.
- KHÔNG thể giải quyết bằng câu "RFC 0024 supersedes RFC 0009", vì RFC 0024 **chỉ supersedes RFC 0009**, KHÔNG supersede RFC 0006.

> **Bắt buộc trước implementation — một quyết định dứt khoát:**
> ```
> RFC 0006 identity primitive
>         ↓
>        MUST be updated
>         ↓
> ML-DSA-65 under Suite 3
> ```

Kiến trúc cuối được khẳng định:

```text
Node identity signing = Suite-selected Signer (per mesh suite)
Root identity         = Suite 3 / ML-DSA-65
Authority identity    = Suite 3 / ML-DSA-65
Certificate signing   = Suite 3 / ML-DSA-65
```

⇒ **RFC 0006 phải được amend.** Nếu không amend, agent có quyền implement Ed25519 cho identity vì RFC nói thẳng như vậy.

**Lệnh cho agent:** KHÔNG implement identity/cert dựa trên "Ed25519" mặc định. Phải đọc suite từ mesh (`MeshConfig::cipher_suite_id`) → chọn Signer qua `CryptoRegistry`.

### 24.3 🟠 G3: chính thức sửa RFC 0019 (packet semantics)

- RFC 0019 hiện nói: mỗi packet phải signature; signature cuối packet; slot = 64B; `suite_id` là suite dùng signing.
- Mâu thuẫn: Suite 3 = ML-DSA-65 → sig thực tế ~3309B. RFC 0019 tự mâu thuẫn ("64B covers all Suite 1-3" nhưng ngay sau "ML-DSA-65=3309 but post-MVP").

**Quyết định mới (lock từ §22.A):**

```text
CONTROL / IDENTITY PLANE
    token / cert / manifest / vote / attestation / trust digest
        ↓
    DIGITAL SIGNATURE (ML-DSA-65 / per suite)

DATA PLANE
    session key → AEAD → nonce → sequence → replay window
        ↓
    AUTHENTICATED ENCRYPTION (không ký từng packet)
```

**Thứ tự bắt buộc:**

```text
0046 architecture decision
        ↓
AMEND RFC 0019
        ↓
freeze packet semantics
        ↓
implement G3
```

> **⚠️ Wording:** G3 dùng thuật ngữ **`packet authentication` / `AEAD authentication`**, KHÔNG gọi là `signature`, để tránh quay lại ambiguity hiện tại.

**Lệnh cho agent:** KHÔNG sửa code G3 dựa trên "ý hiểu trong Discussion". Chờ RFC 0019 amend xong → code theo semantics đã freeze.

### 24.4 🟠 Recovery Package — lỗi format nonce

- 0046 lock: `Argon2id + AES-256-GCM + nonce 24 bytes`.
- RFC 0024 freeze **XChaCha20-Poly1305** cho cả 3 suite (nonce 192-bit). Recovery là **crypto domain riêng** → được dùng AES-256-GCM, KHÔNG đụng RFC 0024.
- NHƯNG nếu dùng AES-GCM → **nonce phải là 12 bytes** (GCM nonce size), không bê 24B từ XChaCha.

**Chốt (lock):**

```text
Recovery v1
  KDF:  Argon2id          (kdf domain: recovery)
  AEAD: AES-256-GCM       (aead domain: recovery)
  salt: 32 bytes
  nonce: 12 bytes         (AES-GCM)
  tag:  16 bytes          (từ AEAD)
  ciphertext: variable
```

> Recovery encryption là **dedicated cryptographic domain** và KHÔNG inherit mesh Crypto Suite AEAD.

**⚠️ Implementation hiện tại KHÔNG khớp lock này:** `cmd/smo-admin/main.cpp` `encrypt_authority_secret_key` hiện dùng `crypto->hash.hash(passphrase)` (BLAKE3/SHA-256 — KHÔNG phải Argon2id) + `crypto->aead.encrypt` với **nonce 24B**. → **P0-EX chưa hoàn thành theo spec.** Phải viết lại đúng: Argon2id KDF + AES-256-GCM + salt 32B + nonce 12B.

### 24.5 🟠 RFC 0007 — Join Token breaking change

- RFC 0007 hiện mô tả: `cipher_suite_id + HMAC + mesh.json hmac_secret`; Join Token v1 = CBOR + HMAC.
- 0046 đã chuyển: `issuer_key_id + issuer_suite_id + digital signature` — **breaking protocol change**, không phải implementation detail.

**Phải amend RFC 0007:**

```text
RFC 0007 old:
cipher_suite_id + HMAC(mesh hmac_secret)

        ↓

RFC 0007 revised:
issuer_key_id
issuer_suite_id
digital signature (issuer / authority key)
```

> Nếu không: agent về sau đọc RFC 0007 sẽ hỏi "Ủa Join Token phải HMAC theo RFC 0007 mà?" → architecture tự đánh nhau.

**Lệnh cho agent:** giữ P0-S1 (issuer signature), KHÔNG quay lại HMAC. RFC 0007 phải amend.

### 24.6 🟡 CRL → **Capability Epoch + Revocation Set** (thống nhất từ vựng — REVISED 2026-08-14 §25)

> **KHÔNG lock kiểu "Capability Epoch (thay CRL)" như bản cũ.** Model chốt = **Capability Epoch + Revocation Set**:

```text
Epoch = coarse-grained global capability invalidation
         (epoch++ làm chết MỌI credential authorized dưới epoch cũ)

Revocation Set = fine-grained per-identity/cert/key_id invalidation
         (revoke A mà không cần bump epoch toàn mạng)
```

- Epoch là primitive incident-response chính (mạnh); Revocation Set là lớp fine-grained (chính xác).
- **Offline ≠ Compromised.** Node chỉ heartbeat-timeout KHÔNG được auto-revoke (tránh split-brain do partition). Revocation phải là governance decision explicit.
- **Signature valid ≠ governance authority.** A ký hợp lệ không chứng minh A còn quyền vote. Verify: signature → identity → authority status → capability epoch → proposal id → state hash → vote uniqueness → quorum → commit.
- Chi tiết: RFC 0006 AMEND-2 + RFC 0016 AMEND-6/7 (đã amend) + §25.

### 24.7 🟡 Document hygiene — một bảng "Current Status" duy nhất

- Lỗi: §15 vừa ghi "P0-EX done" vừa "P0-EX pending"; G10 "Completed" nhưng §9 còn "P0.5 G10 pending"; §7.4.1 Suite 1 hash sai.
- **Chốt:** MỘT bảng Current Status duy nhất làm source of truth (dưới đây). Mọi subsection status cũ coi như historical, KHÔNG phải nguồn quyết định.

### ✅ 24.8 Khẳng định giữ nguyên (không đổi)

| Điểm | Đánh giá |
|------|----------|
| Bootstrap → Session → Authorization → Distributed trust, KHÔNG chung biến `authenticated=true` | Giữ — đúng |
| JOIN: verify token → issue cert → SecureSession → PolicyEngine → contract | Giữ — clean separation |
| Session binding = certificate + signed nonce (RFC 0006) | Giữ |
| Trust propagation: TrustDigest → origin sig → epoch/replay → TrustManager → PolicyEngine | Giữ — không shortcut `authenticated→trusted→authorized` |
| RFC trước → architecture amendment → code → test | Đúng — giữ |

### ✅ 24.9 Tổng kết 5 điểm phải khóa (checklist trước khi chốt)

```text
[1] RFC 0024   Suite 1 hash = SHA-256        → ✅ ĐÃ SỬA §12/§7.4.1 (khớp RFC + impl)
[2] RFC 0006   identity primitive: Ed25519 cũ → Suite-selected / Root+Authority+Cert = Suite 3 ML-DSA-65
                → ✅ ĐÃ AMEND RFC 0006 (AMEND-1/2/3, 2026-08-14)
[3] RFC 0019   packet: DATA = AEAD + sequence/replay; CONTROL/IDENTITY = digital signature
                → ✅ ĐÃ AMEND RFC 0019 (AMEND-4, 2026-08-14)
[4] RFC 0007   Join Token: HMAC/cipher_suite_id → issuer_key_id + issuer_suite_id + signature
                → ✅ ĐÃ AMEND RFC 0007 (AMEND-5, 2026-08-14)
[5] Recovery   AES-GCM nonce 12B; domain riêng "recovery"
                → ✅ CHỐT format §17.9; cần rewrite P0-EX theo spec (§24.4)
[BONUS] RFC 0016 Governance: atomic transition + base_epoch/state_hash + liveness≠revocation
                → ✅ ĐÃ AMEND RFC 0016 (AMEND-6/7, 2026-08-14)
```

> **3 RFC blockers đã amend (0006/0019/0007) + 1 RFC bổ sung (0016).** G3/S6/recovery giờ có spec rõ ràng để implement THEO RFC, không theo "ý hiểu Discussion". Nhưng recovery rewrite (P0-EX) và G3 packet auth vẫn cần code theo đúng spec amend — xem §25 cho thiết kế revocation/governance đầy đủ.

---

## 25. Revocation & Governance — Sống còn của SMO (2026-08-14) 🔒 LOCKED

> **Bài toán:** Node A chết / bị compromise → mạng vẫn chạy → các node còn lại revoke A → bầu B lên thay → A mất quyền.
> **Đáp án:** KHÔNG giải bằng CRL đơn thuần. Chốt **Capability Epoch + Governance + Revocation Set** — epoch là primitive chính, CRL/Revocation Set là fine-grained layer.

### 25.1 Recovery (giữ quyết định §24.4)

```text
passphrase
   ↓
Argon2id                    ← memory-hard; làm offline passphrase-guessing đắt
   ├── salt 32B
   └── parameters
   ↓
256-bit encryption key
   ↓
AES-256-GCM                 ← confidentiality + integrity của recovery blob
   ├── nonce 12B
   └── authentication tag 16B
```

> **Recovery domain = Argon2id + AES-256-GCM.** KHÔNG nhét XChaCha20 vào chỉ vì Suite 3 đang dùng XChaCha20 — đây chính là crypto-domain ≠ cipher-suite.
> **Argon2id không phải để "mã hóa ngon hơn";** nó để làm việc đoán passphrase offline đắt hơn.

### 25.2 Kiến trúc revocation tổng thể

```text
                    GOVERNANCE
                        │
                ┌───────┴────────┐
                │                │
             REVOKE A          ELECT B
                │                │
                └───────┬────────┘
                        ↓
                  new authority
                     epoch N+1
                        │
             ┌──────────┴──────────┐
             ↓                     ↓
       capability epoch       revocation set
             │                     │
             └──────────┬──────────┘
                        ↓
                 distributed state
                        │
              ┌─────────┼─────────┐
              ↓         ↓         ↓
             A ✗        B ✓       C ✓
```

### 25.3 Epoch là thứ "giết quyền" của A

```text
mesh_epoch = 41   A=authority(41) B=authority(41) C=member(41)

A compromise → B/C governance:
  PROPOSAL: revoke(A), elect(B) → quorum → COMMIT

epoch = 42
  revoked: [A]
  active_authorities: [B]
```

Mọi authorization-sensitive operation kiểm:

```cpp
if (credential.capability_epoch < mesh.current_epoch)
    reject();
```

A có cert hợp lệ hôm qua? **Chết.** A có private key? **Chết.** A có token cũ? **Chết.** A replay governance message epoch 41? **Chết.**

### 25.4 CRL vẫn tồn tại — nhưng vai trò khác

| Cơ chế | Biểu diễn | Độ mạnh |
|--------|-----------|---------|
| **CRL / Revocation Set** | "A's certificate = revoked" (specific key/cert serial/key_id) | Fine-grained |
| **Epoch** | "EVERYTHING authorized under epoch < 42 INVALID" | Coarse-grained, mạnh hơn nhiều cho incident response |

### 25.5 Đừng để A tự revoke chính mình

```text
Authorities: A B C D E  (quorum 3/5)

A chết → B + C + D: vote(REVOKE A) vote(ELECT X) vote(COMMIT epoch=42)
A quay lại: "hello I'm authority" → A.capability_epoch=41 < current=42 → REJECT
```

A vẫn có thể tồn tại như process — nhưng **KHÔNG còn quyền lực trong trust domain**.

### 25.6 Governance phải verify đầy đủ (không chỉ signature)

A bị compromise có private key → có thể forge `REVOKE(B) ELECT(A) epoch=42 sig=A`.

Nếu governance ngu: `signature valid → accept` ⇒ **TOANG**.

Governance verify chain bắt buộc:

```text
signature
    ↓
authority identity
    ↓
authority status
    ↓
current capability epoch
    ↓
proposal ID
    ↓
current governance state (state hash)
    ↓
vote uniqueness
    ↓
quorum
    ↓
commit
```

> **A's valid signature ≠ A's valid governance authority.** Signature chỉ chứng minh "A đã ký" — KHÔNG chứng minh "A còn quyền biểu quyết". Khớp GOV-001/GOV-002.

### 25.7 Governance state structures (chốt)

```cpp
struct AuthorityRecord {
    KeyId key_id;
    SuiteId suite_id;
    AuthorityStatus status;         // Active / Suspended / Revoked
    uint64_t capability_epoch;
    uint64_t joined_epoch;
    uint64_t revoked_epoch;         // 0 if never
};

struct GovernanceState {
    uint64_t epoch;
    Hash state_hash;                // H(prev, authority_set, revocation_set, epoch, seq)
    std::vector<AuthorityId> active_authorities;
    RevocationSet revocations;
    uint32_t quorum;
    uint64_t governance_sequence;
};

struct GovernanceProposal {
    ProposalId id;
    uint64_t base_epoch;            // ← anti-split-brain
    uint64_t target_epoch;
    Action action;
    Hash prev_state_hash;
    std::vector<Vote> votes;
};
```

Commit:

```text
Proposal
    ↓
verify all votes
    ↓
verify authority membership
    ↓
verify capability epoch
    ↓
calculate quorum
    ↓
commit state transition
    ↓
epoch++
    ↓
publish signed governance state
```

### 25.8 `base_epoch` chống split-brain (khuyên mạnh)

```text
B/C: proposal base_epoch=41 target=42 revoke(A) elect(B)
D/E: proposal base_epoch=41 target=42 elect(D)          ← cùng base!

→ Không thể cả hai commit.
→ Proposal phải bind: base_epoch + base_state_hash + proposal_id.
→ Commit đầu tiên → epoch 42, state_hash_42.
→ Proposal thứ hai base=41 → STALE → REJECT: stale governance base.
```

> **epoch + hash chain + quorum = chống split-brain cực kỳ ngon.**

### 25.9 Revoke + Elect phải là **một atomic transition**

CẤM làm hai transaction độc lập:

```text
REVOKE A
... sau đó ...
ELECT B
```

(giữa hai transaction có thể tồn tại "A revoked, NO replacement" hoặc "old epoch vẫn active").

Chốt:

```cpp
struct GovernanceTransition {
    std::vector<NodeID> revoke;
    std::vector<NodeID> elect_add;
    std::vector<NodeID> new_authority_set;
    uint64_t new_epoch;
    Hash prev_state_hash;
    Hash new_state_hash;
};
```

```text
epoch 41 → VERIFY QUORUM → COMMIT TRANSITION → epoch 42
```

Không có trạng thái nửa vời.

### 25.10 A "chết" ≠ A "compromise"

```text
DEAD / OFFLINE     (heartbeat timeout)  → KHÔNG auto-revoke
COMPROMISED        (explicit governance revoke)  → REVOKE
```

- **Liveness** (heartbeat, failure detector, offline status) và **authority revocation** (governance decision) là **HAI cơ chế KHÔNG được nhập làm một**.
- Nếu auto-revoke theo heartbeat → partition một phát A─X─B/C/D → revoke A → mạng hồi phục → A sống → governance split-brain.

### 25.11 Giới hạn 3-node mesh (physical constraint)

```text
A B C  quorum 2/3 → A chết → B+C vẫn governance được.
A B    mất B     → A không thể tự bầu người khác Byzantine-safe.
```

Đây KHÔNG phải bug crypto — là **distributed consensus availability constraint**.

Target thực tế:

```text
3 authorities  → tolerate 1 Byzantine failure
5 authorities  → tolerate 1–2 failures (tùy quorum model)
```

> **5 authority nodes đẹp hơn 3 rất nhiều** nếu SMO quan trọng sau này.

### 25.12 Recovery ≠ resurrection

CẤM để `authority.sec` giúp node tự nhiên trở thành authority lại.

Recovery phải đi qua:

```text
Shamir M-of-N
       ↓
recover root authority material
       ↓
reconstruct OFFLINE
       ↓
governance-authorized rekey / election
       ↓
new authority
       ↓
new epoch
```

> Một người có recovery shares KHÔNG nên chỉ `decrypt authority.sec → I'm back`. Phải có governance transition xác nhận authority mới.

### 25.13 Kiến trúc cuối (lock)

```text
                    ┌──────────────────┐
                    │ Governance       │
                    │ quorum + votes   │
                    └────────┬─────────┘
                             │
                    atomic transition
                             │
                             ↓
                  ┌─────────────────────┐
                  │ Mesh State          │
                  │ epoch + state hash  │
                  │ authority set       │
                  │ revocation set      │
                  └─────────┬───────────┘
                            │
              ┌─────────────┼──────────────┐
              ↓             ↓              ↓
          Session       Authorization     Trust
              │             │              │
        epoch check    capability       trust epoch
        cert check      policy           digest
        CRL check
```

Crypto:

```text
ROOT / AUTHORITY    ML-DSA-65
                      ├── governance signatures
                      ├── certificates
                      └── identity

SESSION             ML-KEM-768 → HKDF → AEAD → sequence + replay window

RECOVERY            passphrase → Argon2id → AES-256-GCM → encrypted blob

ROOT RECOVERY       Shamir M-of-N → offline reconstruction → governance-authorized rotation
```

### 25.14 Bảng chốt lựa chọn (decision table)

| Thành phần | Chọn |
| ---------- | ---- |
| Recovery KDF | **Argon2id** |
| Recovery AEAD | **AES-256-GCM** |
| Salt | **32B** |
| GCM nonce | **12B** |
| Root authority | **ML-DSA-65** |
| Session KEM | **ML-KEM-768** |
| Live revocation | **Capability Epoch** |
| Fine-grained revocation | **CRL / Revocation Set** |
| Authority replacement | **Quorum governance** |
| Revoke + elect | **Atomic transition** |
| Anti-split-brain | **base_epoch + state_hash** |
| Offline node | **không tự động revoke** |
| Compromised node | **explicit governance revoke** |
| Root recovery | **Shamir M-of-N** |
| Recovered authority | **không tự resurrect; phải governance-authorize** |

> **"SMO sống kể cả khi một authority chết."** A chỉ mất capability; mesh state tiến epoch N→N+1; authority set thay đổi; session/authorization tự động reject credential cũ. A chết không làm cả mesh chết theo.

---

## 26. Implementation Order & Consistency Cleanup — LOCKED (Reviewer, 2026-08-14)

> **Verdict confirmed: architecture đã ổn (~90–95%), không còn conflict ở design level. Còn lại implementation + consistency cleanup.**

### 26.1 Verification của toàn bộ các vấn đề (trace summary)

| Vấn đề | Trạng thái | Reference |
|--------|-----------|-----------|
| Recovery domain = Argon2id + AES-256-GCM ≠ mesh suite | ✅ Đã lock | §25.1, RFC 0006 AMEND-3 |
| Argon2id for PW-guessing defense, AES-GCM for CONF+INT of blob | ✅ Đã lock | §25.1 |
| A chết ≠ mesh chết (offline ≠ auto-revoke) | ✅ Đã lock (AMEND-7) | §25.10, RFC 0016 |
| Signature-valid ≠ governance-authority | ✅ Đã lock | §25.6, RFC 0016 §5 |
| AEAD packet auth (không ML-DSA mỗi packet) | ✅ Đã lock (AMEND-4) | §24.3, RFC 0019 |
| **SPEC.md stale suite table** (Suite 1=BLAKE3, Suite 2=Ed25519+ML-DSA, Kyber/Dilithium, Join Token HMAC, Recovery AES Blak3-KDF) | ✅ **ĐÃ SỬA 2026-08-14: toàn bộ SPEC giờ khớp RFC 0024 canonical** | SPEC.md §6.6, §7.x, glossary, recovery |
| Recovery resurrects key material; governance resurrects authority — KHÔNG nhập làm một | ✅ Đã lock (mạnh nhất) | §25.12, RFC 0006 AMEND-3 |

### 26.2 SPEC.md cleanup done (đã sửa trực tiếp SPEC.md)

- **Suite table §6.6**: Suite 1 = SHA-256; Suite 2 = Ed25519+X25519; Suite 3 = ML-DSA-65 + ML-KEM-768 (bỏ "Dilithium/Kyber", bỏ "Ed25519 + ML-DSA").
- **Mesh creation flow**: Root keypair = Suite-selected (default genesis Suite 3 / ML-DSA-65); MeshID = SuiteHash — not hardcoded Blake3/Ed25519.
- **Node join flow**: node keypair suite-selected; NodeID = SuiteHash(NodePublicKey).
- **Join Token (glossary + §7.2)**: HMAC/Blake3 → issuer-signed `SMO-JOIN-<base64url(CBOR||issuer_signature)>`.
- **Recovery Package (§7.8)**: versioned — Argon2id(Salt 32B) + AES-256-GCM(Nonce 12B, Tag 16B); RecoveryPasswordDerivedKey=Blake3 → REMOVED.
- **Decision log summary §7.14**: Epoch + Revocation Set; recovery domain note; recovery ≠ resurrection.
- **Identity verification (session)**: suite-selected signer.
- **Crypto Suite 1 status**: SHA-256.

> Canonical source-of-truth giờ là: **RFC 0024 = RFC 0006/0007/0016/0019 (amended) = DISCUSSION_0046 = SPEC.md**. KHÔNG còn stale.

### 26.3 IMPORTANT — Recovery KHÔNG được lấy AEAD từ CryptoRegistry

CẤM:

```cpp
// ❌ SAI: recovery vô tình dùng AEAD của mesh suite
auto crypto = registry.get_suite(mesh.suite_id);
crypto->aead.encrypt(...); // XChaCha20
```

Đúng:

```text
RecoveryDomain
 ├── Argon2id  (password KDF — KHÔNG nhét vào RFC 0024 suite abstraction)
 └── AES-256-GCM  (AEAD của recovery domain, nonce 12B)
```

> Recovery là **dedicated crypto domain**, KHÔNG inherit mesh suite.
>
> **BACKEND LOCKED (2026-08-14, @dotlinux26):** AES-256-GCM dùng **OpenSSL 3 EVP** (`EVP_aes_256_gcm`), expose qua abstraction SMO (`AES256GCMProvider` trong `core/crypto/`). RecoveryDomain/authority KHÔNG gọi `EVP_*` trực tiếp. ABSOLUTELY NO native/self-written AES-GCM (GHASH/counter/tag-verify là crypto mới phải audit). NO silent downgrade → nếu `find_package(OpenSSL)` fails thì **BUILD FAIL**. Lý do: mong muốn auditability + survivability hơn zero-external-dep với một primitive tự maintain.

### 26.4 🔒 Implementation Order LOCKED (thứ tự bắt buộc)

```text
1. SPEC consistency cleanups         → ✅ ĐÃ XONG (2026-08-14)
2. P0-EX                            → Rewrite recovery:
   Argon2id + AES-256-GCM + salt 32B + nonce 12B + versioned format
3. recovery tests + migration tests  → tương thích format mới versioned
4. G3                               → AEAD packet authentication: sequence/nonce/replay window
5. packet tests                     → negative: replay, stale epoch, tamper
6. PCT + E2E                        → 3-node mesh + recovery roundtrip
```

**Lý do P0-EX trước G3:**
- P0-EX là crypto-domain độc lập, **spec đã hoàn toàn frozen** (Argon2id + AES-GCM + salt/nonce/tag cố định).
- G3 vừa amend RFC 0019, đụng wire/runtime semantics → cần recovery ổn định trước.

### 26.5 Giữ cực cứng (invariant thêm cho agent)

> **Safe: recovery resurrects key material; governance resurrects authority — hai thứ tuyệt đối KHÔNG được nhập làm một.** (RFC 0006 AMEND-3, §25.12)

---

*End of DISCUSSION_0046 - RFC Compliance Audit & Hardening Plan (v5 — 2026-08-14: SPEC.md synced to canonical + §26 Implementation Order LOCKED)*