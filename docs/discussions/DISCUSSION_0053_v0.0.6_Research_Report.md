# DISCUSSION 0053 — v0.0.6 Research Report: Runtime Wiring + RFC Compliance Cleanup

**Status:** Research Complete  
**Date:** 2026-09-23  
**Sources:** DISCUSSION_0046 (RFC Compliance Audit), DISCUSSION_0052 (v0.0.5 Implementation Plan), DISCUSSION_0051 (v0.0.5 Research Report), RFC 0015, 0017, 0020, 0022, 0043

---

## Executive Summary

This report identifies the **v0.0.6 scope candidates** based on:
1. **DISCUSSION_0046** — Phases P0-S6 through P4 (RFC Compliance Audit & Hardening Plan)
2. **DISCUSSION_0052** — Explicitly states v0.0.6 target: "Runtime wiring (R1-R5, G1-G10) + RFC compliance cleanup"
3. **DISCUSSION_0051** — Recommends v0.0.6 for "Runtime wiring (R1-R5, G1-G10) + RFC compliance cleanup"
4. **RFC 0015/0017/0020/0022/0043** — Stage 5 and compliance items

**Current State (per 0046 §15, 2026-08-14):**
- ✅ P0-S1..S5, G3, G10, all 3 cipher suites — **COMPLETE**
- 🔨 P0-S6 (session crypto handshake + mesh auth separation), P0-EX (authority.sec encryption rewrite done, recovery_engine verify TODO) — **IN PROGRESS**
- ⏳ R1-R5, G1, G2, G4-G9, Phase 5 RFC cleanup — **PENDING**

**v0.0.6 Charter:** Complete runtime wiring (R1-R5, G1-G10) and RFC compliance cleanup (Opcode Registry namespace, Storage Schema per-store, Serialization Pipeline, Shamir SSS, Authority key handling) — enabling production-ready secure mesh with fully wired runtime.

---

## Table of v0.0.6 Candidates

| # | Candidate Name | Source (file:line) | Description | Effort | Dependencies | Priority |
|---|----------------|-------------------|-------------|--------|--------------|----------|
| **C1** | **P0-S6: Session Crypto Handshake + Mesh Auth Separation** | 0046:720, 0046:866, 0046:17.2 | Separate bootstrap trust domain: JOIN_REQUEST → verify token → issue cert → THEN SecureSession handshake. No empty cert/sig exception in SecureSession. Capability Epoch replaces CRL. | 8 days | P0-S1..S5 done; crypto suites registered; join token verify working | **P0** (security boundary) |
| **C2** | **P0-EX: Authority Secret Encryption (RecoveryEngine verify)** | 0046:721, 0046:722, 0046:867 | `recovery_engine.cpp verify_recovery_package()` implementation; circular dep resolution (smo_core vs smo_genesis); Argon2id + AES-256-GCM already implemented | 3 days | Recovery crypto done; RecoveryDomain in tooling layer | **P0** (security boundary) |
| **C3** | **R2: PolicyEngine + PolicyMiddleware Wiring** | 0046:726, 0046:868, 0046:155, 0029 | Instantiate PolicyEngine in daemon; wire PolicyMiddleware; remove anonymous bypass for 7 policy-covered contracts; security boundary enforcement | 5 days | P0-S6 complete (auth separation); PolicyEngine impl exists in core/acl/ | **P0.5** (security infrastructure) |
| **C4** | **R3: Runtime Services Wiring (Incremental 5 .cpp)** | 0046:728, 0046:872, 0046:148, 0037 | Add 5 unbuilt runtime .cpp to CMake: event_store, runtime_context, history, execution_engine, scheduler. Tier-1: crypto, identity, storage, policy, audit, clock, random. Tier-2: fs, logger, network. | 10 days | CMake fix; R2 (PolicyEngine) for Tier-1 policy service | **P1** (runtime wiring) |
| **C5** | **R4: ContractManager Lifecycle Integration** | 0046:728, 0046:156, 0046:61, 0040 | Daemon uses ContractManager init/shutdown/validate instead of direct Dispatcher register; metadata has_validate must be real | 4 days | R3 (runtime_context); ContractManager impl exists | **P1** (runtime wiring) |
| **C6** | **R5: WorkerPool Complete Implementation** | 0046:728, 0046:157, 0046:62 | queue + submit + wait_all + cancel + active_count + resize; find_seed wire or remove dead code | 3 days | R3 (scheduler); WorkerPool stub exists | **P1** (runtime wiring) |
| **C7** | **G1: SESSION_OPEN Handler** | 0046:731, 0046:875, 0046:68, 0014 | SessionManager::open() on packet path; SESSION_OPEN opcode handling; session state machine | 4 days | R2 (PolicyEngine for authorization); P0-S6 (session auth) | **P2** (operational mesh) |
| **C8** | **G2: HeartbeatService + DiscoveryEngine Stubs** | 0046:732, 0046:874, 0046:69, 0015 | Wire HeartbeatService; handle_ping → PongMsg; handle_pong → RTT/health; DiscoveryEngine tick() | 3 days | R3 (runtime services); Discovery impl exists | **P2** (operational mesh) |
| **C9** | **G9: PeerStore::record_event Call step()** | 0046:732, 0046:873, 0046:76 | Fix silent data loss: INSERT in record_event must call stmt.step() | 1 day | None (isolated fix) | **P2** (operational mesh) |
| **C10** | **G8: MeshFSM Wire + sign_bootstrap_csr** | 0046:729, 0046:871, 0046:75, 0034 | Wire MeshFSM lifecycle (Draft→Genesis→Bootstrap→Online); implement sign_bootstrap_csr; remove hardcoded "Online" | 5 days | R4 (ContractManager); P0-S4/S5 (bootstrap/manifest auth) | **P2** (operational mesh) |
| **C11** | **Opcode Registry Namespace (RFC 0020)** | 0046:191, 0046:614, 0020:11, 0020:83 | 3-byte namespace allocation; packet validation via registry; sequential message IDs per functional group; compile-time constexpr registry | 5 days | RFC 0019 packet layout alignment; G3 packet auth done | **P1** (RFC compliance) |
| **C12** | **Storage Schema per-Store (RFC 0022)** | 0046:192, 0046:615, 0022:20 | 8 SQLite stores (node, mesh, session, trust, audit, dag, peer, governance) with frozen schemas, migrations, WAL mode, backup API | 8 days | Serialization pipeline (C13) for CBOR blobs | **P1** (RFC compliance) |
| **C13** | **Serialization Pipeline (RFC 0043)** | 0046:193, 0046:616, 0043:34 | Unified CBOR pipeline: Packet.payload ↔ ContextValue ↔ ContractInput ↔ ContractResult; SchemaRegistry validation; content-type byte | 10 days | Storage schema (C12) for blob encoding; CBOR library | **P1** (RFC compliance) |
| **C14** | **Shamir SSS Recovery (RFC 0006 §14)** | 0046:194, 0046:617, 0046:784, 0051:36 | M-of-N threshold secret sharing; versioned RecoveryPackage v2; split/recover CLI; integration test | 5 days | Recovery crypto (Argon2id + AES-256-GCM done per 0051:C8) | **P1** (RFC compliance) |
| **C15** | **Authority Key Handling** | 0046:196, 0046:619, 0046:13, 0006 | Root key never circulates; authority.sec encrypted at rest; key rotation; certificate chain management | 4 days | P0-EX done; P0-S6 (cert issuance) | **P1** (RFC compliance) |
| **C16** | **G4: Channel Model (RFC 0042)** | 0046:805, 0042:14 | Channel abstraction for bulk data; CHANNEL_OPEN, CHUNK, ACK, NACK, FIN, CANCEL opcodes | 6 days | C11 (Opcode Registry Data namespace); Serialization pipeline | **P2** (distributed semantics) |
| **C17** | **G5: NextAction 7 Remaining Actions** | 0046:806, 0046:72, 0039:500 | DispatchContract, ScheduleRetry, SpawnPlan, Notify, Compensate, Abort, EmitEvent | 6 days | C13 (serialization for NextAction CBOR); RuntimeKernel async | **P3** (distributed semantics) |
| **C18** | **G6: RuntimeKernel Async + PlanResolver** | 0046:807, 0046:73, 0044 | execute_async true async; PlanResolver provider; stages: dispatch/collect/audit/complete | 8 days | R3 (scheduler, execution_engine); C17 (NextAction) | **P3** (distributed semantics) |
| **C19** | **G7: Governance FSM Complete** | 0046:808, 0046:74, 0016 | reject/conflict/detect_fork/expiry; Conflicted state engine-generated; expiry unit fix (ns vs s) | 4 days | P0-S3 (governance quorum + vote verify done) | **P2** (distributed semantics) |
| **C20** | **Full SWIM Gossip (RFC 0015 Stage 5)** | 0046:616, 0015:4, 0015:14, 0051:40 | Replace basic UDP HELLO/PING with SWIM: failure detection, dissemination, compression, delta sync | 10 days | G2 (HeartbeatService); MembershipTable; PeerRecord | **P2** (deferred Stage 5) |
| **C21** | **Full TrustEngine (RFC 0017 Stage 5)** | 0046:617, 0017:4, 0017:106, 0051:41 | Continuous scoring (citizen/execution/witness/consistency), decay, penalty, witness selection, digest gossip, attestation verification | 8 days | TrustManager wired; WitnessSelector done; attest crypto done | **P2** (deferred Stage 5) |

---

## Gap Analysis: R1-R5, G1-G10 Status & RFC Compliance Gaps

### Runtime Wiring (R1-R5) — from DISCUSSION_0046 §2 P1

| ID | Gap | Status | Blocking | Notes |
|----|-----|--------|----------|-------|
| **R1** | RuntimeServices (14 services) not injected; all nullptr; capability gating not invoked | ⏳ **PENDING** | R3 (5 .cpp must compile first) | Tier-1: crypto, identity, storage, policy, audit, clock, random. Tier-2: fs, logger, network |
| **R2** | PolicyEngine not instantiated; PolicyMiddleware not wired; 7 contracts anonymous → bypass policy | ⏳ **PENDING** | P0-S6 (auth separation) | core/acl/policy_engine.cpp full impl exists; security boundary |
| **R3** | 5 runtime files not in CMake: event_store, execution_engine, history, runtime_context, scheduler | ⏳ **PENDING** | None (CMake only) | Scheduler/RetryEngine (RFC 0044) never runs; incremental add: event_store → runtime_context → history → execution_engine → scheduler |
| **R4** | ContractManager lifecycle unused; daemon registers direct to Dispatcher; has_validate=false metadata lies | ⏳ **PENDING** | R3 (runtime_context) | RFC 0040 contract lifecycle; must replace direct Dispatcher register |
| **R5** | WorkerPool stub: submit discards, wait_all empty, missing cancel/active_count/resize; find_seed dead code | ⏳ **PENDING** | R3 (scheduler) | core/runtime/workerpool/workerpool.cpp:29-36 |

### Mesh Networking / Operations (G1-G10) — from DISCUSSION_0046 §2 P2

| ID | Gap | Status | Blocking | Notes |
|----|-----|--------|----------|-------|
| **G1** | SESSION_OPEN never called; SessionManager::open() not on packet path; policy deny then bypass via anonymous | ⏳ **PENDING** | R2 (PolicyEngine); P0-S6 | RFC 0014 session lifecycle |
| **G2** | UDP heartbeat PING/PONG empty stubs; HeartbeatService not called in main; RTT/liveness not running | ⏳ **PENDING** | R3 (DiscoveryEngine tick) | RFC 0015 HealthMonitor |
| **G3** | Wire format ≠ RFC 0019; header 6B ≠ 37B; no nonce/sig rejection; ReplayProtector only in test | ✅ **DONE** (2026-09-17) | — | AEAD packet auth + replay enforcement + negative tests; 25/25 ctest pass |
| **G4** | Channel model (RFC 0042) entirely absent; grep channel_id/kFrameFlagChannel only in RFC | ⏳ **PENDING** | C11 (Opcode Registry Data ns); C13 | 6 DATA opcodes defined in RFC 0020 |
| **G5** | NextAction: only 2/9 actions implemented (Execute, StoreContext); 7 TODO | ⏳ **PENDING** | C13 (NextAction CBOR); C18 (RuntimeKernel) | RFC 0039 |
| **G6** | RuntimeKernel dispatch/collect/audit/complete no-op; execute_async synchronous; PlanResolver missing | ⏳ **PENDING** | R3 (execution_engine, scheduler) | RFC 0044 EventBus + ActionExecutor |
| **G7** | Governance: reject/conflict/detect_fork/expiry missing; Conflicted not engine-generated; expiry unit bug (ns vs s) | ⏳ **PENDING** | P0-S3 (quorum + vote verify done) | RFC 0016 |
| **G8** | MeshFsm dead code; hardcoded mesh_state="Online"; sign_bootstrap_csr not impl | ⏳ **PENDING** | R4 (ContractManager); P0-S4/S5 | RFC 0034 bootstrap protocol |
| **G9** | PeerStore::record_event INSERT never calls stmt.step() → silent data loss | ⏳ **PENDING** | None (1-line fix) | core/discovery/peer_store.cpp:477-495 |
| **G10** | TrustDigest apply_digest verify signature by origin pubkey | ✅ **DONE** | — | Moved up per 0046 §9; trust propagation with S2/S6 |

### RFC Compliance Cleanup (Phase 5) — from DISCUSSION_0046 §187-197

| RFC | Item | Status | Gap |
|-----|------|--------|-----|
| **0020** | Opcode registry namespace (3-byte) | ⏳ **PENDING** | Packet validation via registry; compile-time constexpr table |
| **0022** | Storage schema per-store (8 SQLite dbs) | ⏳ **PENDING** | Frozen tables, migrations, WAL, backup API |
| **0043** | Serialization pipeline (CBOR unified) | ⏳ **PENDING** | ContextValue recursive variant; SchemaRegistry; Packet↔Request converters |
| **0006 §14** | Shamir SSS (M-of-N threshold) | ⏳ **PENDING** | Recovery crypto done; split/recover CLI; versioned format v2 |
| — | Authority key handling | ⏳ **PENDING** | Root key never circulates; rotation; chain management |

### Stage 5 Deferred (Not Blocking v0.0.6)

| RFC | Item | Status | Target |
|-----|------|--------|--------|
| **0015** | Full SWIM gossip | ⏳ **DEFERRED** | v0.0.7+ |
| **0017** | Full TrustEngine (scoring, decay, witness selection) | ⏳ **DEFERRED** | v0.0.7+ |

---

## Recommended v0.0.6 Scope (Prioritized, 7 Items Max)

Based on **security boundary first** (0046 §9, §17.1), **dependency order** (0046 §17.3), and **v0.0.6 charter** (0052, 0051):

### ✅ Tier 0 — Must Complete Before v0.0.6 Release (Security Boundary)

| # | Item | Rationale |
|---|------|-----------|
| **1** | **P0-S6: Session Crypto Handshake + Mesh Auth Separation** | Final P0 security gate; enables real session establishment; blocks R2, G1 |
| **2** | **P0-EX: RecoveryEngine verify_recovery_package()** | Completes authority secret encryption; circular dep resolution; security invariant |

### ✅ Tier 1 — Core Runtime Wiring (Enables All Above)

| # | Item | Rationale |
|---|------|-----------|
| **3** | **R2: PolicyEngine + PolicyMiddleware Wiring** | Security boundary; removes anonymous bypass for 7 contracts; required before G1 |
| **4** | **R3: Runtime Services Wiring (5 .cpp incremental)** | Prerequisite for R1, R4, R5, G2, G6, G8; unblocks scheduler, execution_engine |

### ✅ Tier 2 — Operational Mesh Completion

| # | Item | Rationale |
|---|------|-----------|
| **5** | **G1: SESSION_OPEN Handler** | Completes session lifecycle; enables contract execution over sessions |
| **6** | **G8: MeshFSM Wire + sign_bootstrap_csr** | Removes hardcoded "Online"; enables proper mesh lifecycle; governance dependency |

### ✅ Tier 3 — RFC Compliance Cleanup (Phase 5)

| # | Item | Rationale |
|---|------|-----------|
| **7** | **C11+C12+C13: Opcode Registry + Storage Schema + Serialization Pipeline** | **Bundle as single "RFC Compliance Sprint"** — tightly coupled (CBOR blobs in storage, opcode validation in packet path, schema validation in pipeline); 3 RFCs, 23 days combined; completes Phase 5 |

---

## Deferred to v0.0.7+ (Explicitly Out of v0.0.6 Scope)

| Item | Reason |
|------|--------|
| **G2, G9** (HeartbeatService, PeerStore step) | Low-risk operational fixes; can batch post-v0.0.6 |
| **G4** (Channel Model) | Depends on Opcode Registry + Serialization; distributed semantics |
| **G5, G6, G7** (NextAction, RuntimeKernel async, Governance FSM) | Distributed runtime semantics; depend on R3 (scheduler) + C13 |
| **C14** (Shamir SSS) | Recovery crypto done; not blocking mesh operations; can parallel |
| **C15** (Authority Key Handling) | Partially done in P0-EX; rotation/chains post-v0.0.6 |
| **C20, C21** (Full SWIM, Full TrustEngine) | Stage 5 items; current gossip + binary trust sufficient for v0.0.6 scale |

---

## Implementation Order & Gates (Per 0046 §17.3)

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

## Success Criteria for v0.0.6 Release

```
[ ] P0-S6: E2E join works (fresh node → token verify → cert issue → SecureSession handshake)
[ ] P0-EX: RecoveryEngine verify_recovery_package() passes; circular dep resolved
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

## Appendix: Source References

| Source | Key Sections |
|--------|--------------|
| DISCUSSION_0046 | §2 (gap classification P0-P3), §3 (phases), §9 (phase reordering), §15 (status), §17.3 (impl order), §17.6 (production-ready def) |
| DISCUSSION_0052 | §1 (philosophy), §21 (v0.0.6 roadmap: "Runtime wiring (R1-R5, G1-G10) + RFC compliance cleanup") |
| DISCUSSION_0051 | §3 (v0.0.5 candidates), §5 (gap analysis R1-R5, G1-G10), §6 (recommended v0.0.6 scope) |
| RFC 0015 | §4 (MVP UDP only), §14 (Stage 5 SWIM deferred), §89 (GossipProtocol interface) |
| RFC 0017 | §4 (Stage 5 deferred), §9 (TrustEngine interface), §106 (consequences: binary trust for MVP) |
| RFC 0020 | §11 (3-byte namespace), §17 (4 frozen namespaces), §28-61 (registered messages), §83 (registration rules) |
| RFC 0022 | §11 (SQLite direct), §18 (8 stores), §33 (metadata cols), §41-192 (per-store schemas), §194 (migrations) |
| RFC 0043 | §2.1 (pipeline), §2.2 (CBOR canonical), §2.3 (ContextValue recursive), §2.6 (SchemaValidation), §2.7 (Packet↔Request), §5 (migration path) |

---

**End of Report** — Ready for discussion review and v0.0.6 sprint planning.