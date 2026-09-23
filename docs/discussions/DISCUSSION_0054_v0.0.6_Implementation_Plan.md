# DISCUSSION 0054 — v0.0.6 Implementation Plan: Runtime Wiring + RFC Compliance Cleanup

**Status:** IN PROGRESS (C1 P0-S6 complete)  
**Target:** v0.0.6  
**Supersedes:** DISCUSSION_0053  

---

## 1. Philosophy: Security Boundary First → Runtime Wiring → Operational Mesh → RFC Compliance

v0.0.6 completes the **security boundary** (P0-S6 session auth separation, P0-EX RecoveryEngine verify) before wiring runtime services.  
v0.0.6 wires **RuntimeServices** (R1-R5) incrementally — 5 .cpp files added to CMake in dependency order.  
v0.0.6 completes **operational mesh** (G1 SESSION_OPEN, G8 MeshFSM + sign_bootstrap_csr) — enabling production mesh lifecycle.  
v0.0.6 bundles **RFC Compliance Sprint** (Opcode Registry + Storage Schema + Serialization Pipeline) — 3 RFCs, tightly coupled via CBOR.

> **Mục tiêu:** Production-ready secure mesh with fully wired runtime — all security boundaries enforced, all runtime services injected, mesh lifecycle operational, RFC 0020/0022/0043 compile-time clean.

---

## 2. Scope from 0053 Recommended (7 Items in 4 Tiers)

| Tier | # | Candidate | Source (0053) | Description |
|------|---|-----------|---------------|-------------|
| **Tier 0** | **1** | **P0-S6: Session Crypto Handshake + Mesh Auth Separation** | 0053:30, 0053:108 | Separate bootstrap trust domain: JOIN_REQUEST → verify token → issue cert → THEN SecureSession handshake. No empty cert/sig exception. Capability Epoch replaces CRL. |
| **Tier 0** | **2** | **P0-EX: RecoveryEngine verify_recovery_package()** | 0053:31, 0053:109 | `recovery_engine.cpp verify_recovery_package()` implementation; circular dep resolution (smo_core vs smo_genesis); Argon2id + AES-256-GCM already implemented. |
| **Tier 1** | **3** | **R2: PolicyEngine + PolicyMiddleware Wiring** | 0053:32, 0053:115 | Instantiate PolicyEngine in daemon; wire PolicyMiddleware; remove anonymous bypass for 7 policy-covered contracts; security boundary enforcement. |
| **Tier 1** | **4** | **R3: Runtime Services Wiring (5 .cpp Incremental)** | 0053:33, 0053:116 | Add 5 unbuilt runtime .cpp to CMake: event_store, runtime_context, history, execution_engine, scheduler. Tier-1: crypto, identity, storage, policy, audit, clock, random. Tier-2: fs, logger, network. |
| **Tier 2** | **5** | **G1: SESSION_OPEN Handler** | 0053:36, 0053:122 | SessionManager::open() on packet path; SESSION_OPEN opcode handling; session state machine. |
| **Tier 2** | **6** | **G8: MeshFSM Wire + sign_bootstrap_csr** | 0053:39, 0053:123 | Wire MeshFSM lifecycle (Draft→Genesis→Bootstrap→Online); implement sign_bootstrap_csr; remove hardcoded "Online". |
| **Tier 3** | **7** | **RFC Compliance Sprint: Opcode Registry + Storage Schema + Serialization Pipeline** | 0053:40-42, 0053:129 | Bundle C11+C12+C13: 3-byte namespace allocation + packet validation via registry; 8 SQLite stores frozen schemas/migrations/WAL/backup; Unified CBOR pipeline (Packet↔ContextValue↔ContractInput↔ContractResult), SchemaRegistry, content-type byte. |

---

## 3. Work Items Table

Each item: tasks, dependencies, `[ ] OPEN`, source file:line from 0053.

### C1 — P0-S6: Session Crypto Handshake + Mesh Auth Separation

| Task | Depends | Status | Source |
|------|---------|--------|--------|
| C1.1 Implement JOIN_REQUEST handler: verify join token → issue node certificate | P0-S1..S5 done; crypto suites registered; join token verify working | `[x] DONE` | 0053:30, 0046:720, 0046:866 |
| C1.2 SecureSession handshake: require cert + sig (remove empty cert/sig exception) | C1.1 | `[x] DONE` | 0053:30, 0046:866 |
| C1.3 Capability Epoch implementation: epoch-based revocation replacing CRL | C1.1 | `[x] DONE` | 0053:30, 0046:17.2 |
| C1.4 E2E integration test: fresh node → token verify → cert issue → SecureSession handshake | C1.1-C1.3 | `[x] DONE` | 0053:190 |

### C2 — P0-EX: RecoveryEngine verify_recovery_package()

| Task | Depends | Status | Source |
|------|---------|--------|--------|
| C2.1 Implement `verify_recovery_package()` in `recovery_engine.cpp` | Recovery crypto done (Argon2id + AES-256-GCM); RecoveryDomain in tooling layer | `[x] DONE` | 0053:31, 0046:721, 0046:722, 0046:867 |
| C2.2 Resolve circular dependency: smo_core ↔ smo_genesis (move RecoveryEngine to smo_genesis or interface) | C2.1 | `[x] DONE` | 0053:31, 0046:722 |
| C2.3 Gate test: wrong passphrase → reject; restart decrypts authority.sec | C2.1-C2.2 | `[x] DONE` | 0053:158, 0053:191 |

### C3 — R2: PolicyEngine + PolicyMiddleware Wiring

| Task | Depends | Status | Source |
|------|---------|--------|--------|
| C3.1 Instantiate PolicyEngine in daemon bootstrap (core/acl/policy_engine.cpp) | P0-S6 complete (auth separation) | `[ ] OPEN` | 0053:32, 0046:726, 0046:868 |
| C3.2 Wire PolicyMiddleware into packet path (after auth, before dispatch) | C3.1 | `[ ] OPEN` | 0053:32, 0046:155 |
| C3.3 Remove anonymous bypass for 7 policy-covered contracts | C3.2 | `[ ] OPEN` | 0053:32, 0046:868 |
| C3.4 PCT policy tests pass; no anonymous bypass | C3.3 | `[ ] OPEN` | 0053:163, 0053:192 |

### C4 — R3: Runtime Services Wiring (5 .cpp Incremental)

| Task | Depends | Status | Source |
|------|---------|--------|--------|
| C4.1 Add `event_store.cpp` to CMake; compile → link → unit test | CMake fix | `[ ] OPEN` | 0053:33, 0046:728, 0046:148 |
| C4.2 Add `runtime_context.cpp` to CMake; inject Tier-1 services (crypto, identity, storage, policy, audit, clock, random) | C4.1 | `[ ] OPEN` | 0053:33, 0046:148, 0046:872 |
| C4.3 Add `history.cpp` to CMake; compile → link → unit test | C4.2 | `[ ] OPEN` | 0053:33, 0046:872 |
| C4.4 Add `execution_engine.cpp` to CMake; compile → link → unit test | C4.3 | `[ ] OPEN` | 0053:33, 0046:872 |
| C4.5 Add `scheduler.cpp` to CMake; compile → link → unit test; RetryEngine (RFC 0044) runs | C4.4 | `[ ] OPEN` | 0053:33, 0046:872 |
| C4.6 Smoke test: all 5 .cpp compile + link + unit test + smoke | C4.1-C4.5 | `[ ] OPEN` | 0053:168, 0053:193 |

### C5 — G1: SESSION_OPEN Handler

| Task | Depends | Status | Source |
|------|---------|--------|--------|
| C5.1 Implement SessionManager::open() on packet path (core/session/session_manager.cpp) | R2 (PolicyEngine for authorization); P0-S6 (session auth) | `[ ] OPEN` | 0053:36, 0046:731, 0046:875, 0046:68 |
| C5.2 Add SESSION_OPEN opcode handling in dispatcher | C5.1 | `[ ] OPEN` | 0053:36, 0046:68, 0014 |
| C5.3 Session state machine: PENDING → OPEN → CLOSED/FAILED | C5.2 | `[ ] OPEN` | 0053:36, 0046:68 |
| C5.4 Gate: SESSION_OPEN works; contract execution over sessions enabled | C5.3 | `[ ] OPEN` | 0053:174, 0053:196 |

### C6 — G8: MeshFSM Wire + sign_bootstrap_csr

| Task | Depends | Status | Source |
|------|---------|--------|--------|
| C6.1 Wire MeshFSM lifecycle transitions: Draft → Genesis → Bootstrap → Online | R4 (ContractManager); P0-S4/S5 (bootstrap/manifest auth) | `[ ] OPEN` | 0053:39, 0046:729, 0046:871, 0046:75 |
| C6.2 Implement `sign_bootstrap_csr` in MeshFSM (core/mesh/mesh_fsm.cpp) | C6.1 | `[ ] OPEN` | 0053:39, 0046:75, 0034 |
| C6.3 Remove hardcoded "Online" mesh_state; use FSM state | C6.2 | `[ ] OPEN` | 0053:39, 0046:75 |
| C6.4 Gate: MeshFSM transitions work; sign_bootstrap_csr produces valid CSR | C6.3 | `[ ] OPEN` | 0053:174, 0053:197 |

### C7 — RFC Compliance Sprint: Opcode Registry + Storage Schema + Serialization Pipeline

| Task | Depends | Status | Source |
|------|---------|--------|--------|
| C7.1 RFC 0020: Implement 3-byte namespace allocation constexpr table (core/protocol/opcode_registry.cpp) | RFC 0019 packet layout alignment; G3 packet auth done | `[ ] OPEN` | 0053:40, 0046:191, 0046:614, 0020:11, 0020:83 |
| C7.2 RFC 0020: Packet validation via registry; sequential message IDs per functional group | C7.1 | `[ ] OPEN` | 0053:40, 0020:83 |
| C7.3 RFC 0022: Define 8 SQLite stores (node, mesh, session, trust, audit, dag, peer, governance) with frozen schemas | Serialization pipeline (C7.5) for CBOR blobs | `[ ] OPEN` | 0053:41, 0046:192, 0046:615, 0022:20 |
| C7.4 RFC 0022: Implement migrations, WAL mode, backup API for each store | C7.3 | `[ ] OPEN` | 0053:41, 0022:194 |
| C7.5 RFC 0043: Unified CBOR pipeline: Packet.payload ↔ ContextValue ↔ ContractInput ↔ ContractResult | Storage schema (C7.3) for blob encoding; CBOR library | `[ ] OPEN` | 0053:42, 0046:193, 0046:616, 0043:34 |
| C7.6 RFC 0043: SchemaRegistry validation; ContextValue recursive variant; content-type byte | C7.5 | `[ ] OPEN` | 0053:42, 0043:2.2, 0043:2.3, 0043:2.6 |
| C7.7 Gate: All 3 RFCs compile-time clean; packet validation via registry; schema migrations work | C7.1-C7.6 | `[ ] OPEN` | 0053:180, 0053:198-200 |

---

## 4. Dependency Graph + Gates (from 0053 §17.3)

```text
CURRENT (P0-S6, P0-EX in progress)
         │
         ▼
┌────────────────────────┐
│ P0-S6: Session Auth    │ → Gate: E2E join works (fresh node → cert → session)
└───────────┬────────────┘
            │
            ▼
┌────────────────────────┐
│ P0-EX: RecoveryEngine  │ → Gate: wrong passphrase → reject; restart decrypts
└───────────┬────────────┘
            │
            ▼
┌────────────────────────┐
│ R2: PolicyEngine       │ → Gate: PCT policy tests pass; no anonymous bypass
└───────────┬────────────┘
            │
            ▼
┌────────────────────────┐
│ R3: Runtime 5 .cpp     │ → Gate: Each file: compile → link → unit test → smoke
│ (incremental tiers)    │
└───────────┬────────────┘
            │
            ▼
┌────────────────────────┐
│ G1 + G8 (parallel)     │ → Gate: SESSION_OPEN works; MeshFSM transitions work
│ SESSION_OPEN + MeshFSM │
└───────────┬────────────┘
            │
            ▼
┌────────────────────────┐
│ RFC Compliance Sprint  │ → Gate: All 3 RFCs (0020, 0022, 0043) compile-time clean
│ Opcode + Storage + CBOR│     Packet validation via registry; schema migrations work
└────────────────────────┘
```

---

## 5. Success Criteria Checklist (from 0053)

```
[x] P0-S6: E2E join works (fresh node → token verify → cert issue → SecureSession handshake)
[x] P0-EX: RecoveryEngine verify_recovery_package() passes; circular dep resolved
[ ] R2: PolicyEngine instantiated + PolicyMiddleware wired; 7 contracts no longer anonymous
[ ] R3: All 5 runtime .cpp compile + link + unit test + smoke test
[ ] R4: Daemon uses ContractManager init/shutdown/validate lifecycle
[ ] R5: WorkerPool submit/wait_all/cancel/active_count/resize functional
[ ] G1: SESSION_OPEN handler on packet path; SessionManager::open() called
[ ] G8: MeshFSM Draft→Genesis→Bootstrap→Online transitions; sign_bootstrap_csr impl
[ ] RFC 0020: Opcode registry constexpr table; packet validation via registry
[ ] RFC 0022: 8 SQLite stores with frozen schemas, migrations, WAL, backup
[ ] RFC 0043: Unified CBOR pipeline; SchemaRegistry validation; ContextValue recursive variant
[ ] All 25+ ctest PASS
[ ] All 24+ PCT PASS (including new policy, session, RFC compliance tests)
[ ] E2E 3-node mesh: join, session, contract exec, governance, trust gossip all PASS
[ ] Security regression tests: downgrade, confusion, key-suite mismatch, replay, truncated sig all REJECT
[ ] clang-format + clang-tidy clean
```

---

## 6. Do-Not-Mix: Explicitly Out of Scope for v0.0.6 (Deferred to v0.0.7+)

| Item | Reason |
|------|--------|
| **G2, G9** (HeartbeatService, PeerStore step) | Low-risk operational fixes; can batch post-v0.0.6 |
| **G4** (Channel Model) | Depends on Opcode Registry + Serialization; distributed semantics |
| **G5, G6, G7** (NextAction, RuntimeKernel async, Governance FSM) | Distributed runtime semantics; depend on R3 (scheduler) + C13 |
| **C14** (Shamir SSS) | Recovery crypto done; not blocking mesh operations; can parallel |
| **C15** (Authority Key Handling) | Partially done in P0-EX; rotation/chains post-v0.0.6 |
| **C20, C21** (Full SWIM, Full TrustEngine) | Stage 5 items; current gossip + binary trust sufficient for v0.0.6 scale |

---

## 7. Footer

**Baselined from:**
- DISCUSSION_0053 (Research Report — v0.0.6 candidates + gap analysis + impl order)
- DISCUSSION_0046 (RFC Compliance Audit — Phase 5 items, P0-S6, R1-R5, G1-G10, §17.3 impl order)
- DISCUSSION_0052 (v0.0.5 Implementation Plan — philosophy, v0.0.6 roadmap: "Runtime wiring (R1-R5, G1-G10) + RFC compliance cleanup")
- DISCUSSION_0051 (v0.0.5 Research Report — gap analysis R1-R5, G1-G10, recommended v0.0.6 scope)

**Version Roadmap Context:**
```
v0.0.1       Protocol
v0.0.2       Production runtime foundation (LAN/VPN)
v0.0.3       Real deployment verification (3-node VPN mesh) ✅ DONE
v0.0.4       Network capability: STUN, hole punch, relay, ICE-Lite ✅ DONE
v0.0.5       Observability + Packaging + Benchmarks + Recovery SSS ✅ IN PROGRESS
v0.0.6       **Runtime wiring (R1-R5, G1-G10) + RFC compliance cleanup** ← THIS PLAN
v0.0.7       Full ICE + TURN + Mesh Federation
v0.0.8       SMIR → WASM SDK + Distributed Runtime (EventBus, NextAction)
v0.1         Stable platform
```

---

**End of Implementation Plan** — Ready for sprint execution.