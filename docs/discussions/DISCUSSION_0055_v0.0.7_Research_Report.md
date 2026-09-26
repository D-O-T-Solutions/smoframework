# DISCUSSION 0055 — v0.0.7 Research Report: Full ICE + TURN + Mesh Federation + Distributed Runtime Core

**Status:** Research Complete  
**Date:** 2026-09-24  
**Sources:** DISCUSSION_0042 (N10), DISCUSSION_0046 (C15-C21), DISCUSSION_0054 (deferred), RFC 0015/0017/0039/0042/0044

---

## Executive Summary

This report identifies the **v0.0.7 scope candidates** based on four source streams:

1. **DISCUSSION_0042 §3 N10 (v0.0.4 Preview)** — Four items explicitly deferred: Full ICE+TURN, Mesh Federation, SMIR→WASM SDK, Performance benchmarks as CI gates
2. **DISCUSSION_0046 C15-C21 (RFC Compliance Audit Phase 4-5)** — Seven deferred items from the hardening plan: Authority Key Handling, Channel Model, NextAction 7 remaining, RuntimeKernel Async+PlanResolver, Governance FSM, Full SWIM Gossip, Full TrustEngine
3. **DISCUSSION_0054 (v0.0.6 Implementation Plan)** — Explicitly deferred to v0.0.7+: G2/G9 (Heartbeat/PeerStore), G4 (Channel Model), G5/G6/G7 (NextAction/RuntimeKernel/Governance), C14/C15/C20/C21 (Shamir SSS, Authority Keys, SWIM, TrustEngine)
4. **RFC 0015/0017/0039/0042/0044** — Stage 5 deferred items and architectural foundations

**Current State (per 0054, 2026-09-23):**
- ✅ v0.0.6 security boundary (P0-S6, P0-EX) — COMPLETE
- ✅ v0.0.6 runtime wiring (R2, R3, R4 partial) — IN PROGRESS / COMPLETE
- ✅ v0.0.6 RFC Compliance Sprint (Opcode Registry, Storage Schema, Serialization Pipeline) — COMPLETE
- ⏳ G8 MeshFSM Wire + sign_bootstrap_csr — OPEN
- ⏳ All v0.0.7 candidates — DEFERRED

**v0.0.7 Charter (per roadmap in 0051/0052/0053/0054):**
> **v0.0.7: Full ICE + TURN + Mesh Federation**

This aligns with DISCUSSION_0042 N10 preview items. However, the deferred runtime items (Channel Model, NextAction, RuntimeKernel async, Governance FSM) are **prerequisites** for v0.0.8 "SMIR → WASM SDK + Distributed Runtime" and should be partially addressed in v0.0.7 to unblock v0.0.8.

---

## Table of v0.0.7 Candidates

| # | Candidate Name | Source (file:line) | Description | Effort | Dependencies | Priority |
|---|----------------|-------------------|-------------|--------|--------------|----------|
| **C1** | **Full ICE + TURN (RFC 8445/8656)** | 0042:304, 0050:57, 0027:538 | Replace ICE-Lite with full ICE: candidate gathering, connectivity checks, nomination, TURN relay (RFC 8656) for symmetric NAT. STUN/TURN server deployment. | 20 days | N1-N5 (v0.0.4) complete; libp2p/Pion integration or custom impl | **P0** (v0.0.7 charter) |
| **C2** | **Mesh Federation (Cross-Mesh Routing)** | 0042:305, 0050:58 | Inter-mesh communication: mesh-to-mesh routing, gateway nodes, policy federation, cross-mesh governance, trust anchor exchange. | 25 days | Full ICE (C1); Membership scaling; Governance v2; Opcode Registry (0020 done) | **P0** (v0.0.7 charter) |
| **C3** | **Channel Model (RFC 0042)** | 0046:805, 0042:14, 0054:138 | Channel abstraction for multiplexing: CHANNEL_OPEN, CHUNK, ACK, NACK, FIN, CANCEL opcodes. Four-layer hierarchy (Connection→Session→Channel→Invocation). Lazy creation, flow control per channel. | 15 days | Opcode Registry (C11 done); Serialization Pipeline (C13 done); SessionManager wired | **P1** (unblocks v0.0.8) |
| **C4** | **NextAction 7 Remaining Actions (RFC 0039)** | 0046:806, 0046:72, 0039:500 | Implement DispatchContract, ScheduleRetry, SpawnPlan, Notify, Compensate, Abort, EmitEvent. Only Execute + StoreContext done in v0.0.6. | 12 days | Serialization Pipeline (C13 done); ActionExecutor scaffolding | **P1** (unblocks v0.0.8) |
| **C5** | **RuntimeKernel Async + PlanResolver (RFC 0044)** | 0046:807, 0046:73, 0044 | execute_async true async; PlanResolver provider; stages: dispatch/collect/audit/complete. Scheduler + WorkerPool + ActionExecutor integration. | 18 days | R3 (scheduler, execution_engine done); C4 (NextAction); C3 (Channel) | **P1** (unblocks v0.0.8) |
| **C6** | **Governance FSM Complete (RFC 0016)** | 0046:808, 0046:74, 0016 | reject/conflict/detect_fork/expiry; Conflicted state engine-generated; expiry unit fix (ns vs s); quorum from active authorities. | 8 days | P0-S3 (quorum + vote verify done); Opcode Registry (0020 done) | **P1** (production readiness) |
| **C7** | **Authority Key Handling** | 0046:196, 0046:619, 0046:13, 0006 | Root key never circulates; authority.sec encrypted at rest; key rotation; certificate chain management; HSM/remote signer support. | 10 days | P0-EX done; P0-S6 (cert issuance); RecoveryEngine verify done | **P2** (security hardening) |
| **C8** | **Full SWIM Gossip (RFC 0015 Stage 5)** | 0046:616, 0015:4, 0015:14, 0051:40 | Replace basic UDP HELLO/PING with SWIM: failure detection, dissemination, compression, delta sync, suspicion-based probing, indirect checks. | 15 days | G2 (HeartbeatService); MembershipTable; PeerRecord; Channel Model (C3) for gossip transport | **P2** (deferred Stage 5) |
| **C9** | **Full TrustEngine (RFC 0017 Stage 5)** | 0046:617, 0017:4, 0017:106, 0051:41 | Continuous scoring (citizen/execution/witness/consistency), decay, penalty, witness selection, digest gossip, attestation verification. Rolling window aggregates. | 12 days | TrustManager wired; WitnessSelector done; attest crypto done; Channel Model (C3) for digest gossip | **P2** (deferred Stage 5) |
| **C10** | **SMIR → WASM SDK** | 0042:306, 0050:59, 0035:500, 0037:301 | WASM contract runtime: wasmtime/wasm3 embed, host functions (FS/Process/Vault/Network/Crypto), gas metering, SDK tooling. | 30 days | RuntimeServices wired (R1); ContractManager lifecycle (R4); ABI freeze (RFC 0036); C3/C4/C5 done | **P3** (v0.0.8 target) |
| **C11** | **Performance Benchmarks as CI Gates** | 0042:307, 0050:60, 0042:278 | Automated benchmarks in CI: 5000 TCP sessions, 2000 UDP targets, 1000 msg/s gossip, 10k node anti-entropy <30s; regression gates. | 8 days | Benchmark harness (N8); CI infrastructure; reproducible WAN test env | **P2** (observability) |

---

## Gap Analysis: v0.0.6 Deferred Items Now Ready

| Item | v0.0.6 Status | v0.0.7 Readiness | Notes |
|------|---------------|------------------|-------|
| **G2: HeartbeatService + DiscoveryEngine Stubs** | ⏳ DEFERRED | ✅ **READY** | Low-risk; DiscoveryEngine UDP wiring done in 0039 Phase 8b; only handle_ping/pong stubs + RTT wiring needed |
| **G9: PeerStore::record_event Call step()** | ⏳ DEFERRED | ✅ **READY** | 1-line fix; silent data loss in INSERT; isolated, no dependencies |
| **G4: Channel Model (RFC 0042)** | ⏳ DEFERRED | ✅ **READY** | Prereqs met: Opcode Registry (C11 done), Serialization Pipeline (C13 done), SessionManager wired |
| **G5: NextAction 7 Remaining Actions** | ⏳ DEFERRED | ✅ **READY** | Prereqs met: Serialization Pipeline (C13 done); ActionExecutor scaffolding exists in RFC 0044 |
| **G6: RuntimeKernel Async + PlanResolver** | ⏳ DEFERRED | ✅ **READY** | Prereqs met: R3 (scheduler, execution_engine compiled); C4/C3 can be done in parallel |
| **G7: Governance FSM Complete** | ⏳ DEFERRED | ✅ **READY** | Prereqs met: P0-S3 (quorum + vote verify done); Opcode Registry (0020 done) |
| **C14: Shamir SSS Recovery** | ⏳ DEFERRED | ✅ **READY** | Recovery crypto (Argon2id + AES-256-GCM) done; versioned format v2 exists; CLI split/combine exists |
| **C15: Authority Key Handling** | ⏳ DEFERRED | ⚠️ **PARTIAL** | P0-EX encryption done; rotation/chains/HSM support needed; not blocking mesh ops |
| **C20: Full SWIM Gossip** | ⏳ DEFERRED | ⚠️ **PARTIAL** | Requires G2 + Channel Model; current gossip sufficient for v0.0.7 scale |
| **C21: Full TrustEngine** | ⏳ DEFERRED | ⚠️ **PARTIAL** | Requires C3 for digest gossip; binary trust sufficient for v0.0.7 scale |

**Key Insight:** All v0.0.6 deferred items except C15/C20/C21 are **implementation-ready** — prerequisites from v0.0.6 (Opcode Registry, Storage Schema, Serialization Pipeline, Runtime Services wiring) are now complete. The only architectural gaps are C3 (Channel Model) which unblocks C8/C21.

---

## Recommended v0.0.7 Scope (7 Items)

Based on **v0.0.7 charter** ("Full ICE + TURN + Mesh Federation"), **dependency order**, and **v0.0.8 unblocking**:

### Tier 0 — v0.0.7 Charter Items (Must Complete)

| # | Item | Rationale |
|---|------|-----------|
| **1** | **C1: Full ICE + TURN (RFC 8445/8656)** | Core v0.0.7 deliverable; enables symmetric NAT traversal; required for Mesh Federation |
| **2** | **C2: Mesh Federation (Cross-Mesh Routing)** | Core v0.0.7 deliverable; multi-mesh topology; gateway nodes; policy federation |

### Tier 1 — Distributed Runtime Foundation (Unblocks v0.0.8)

| # | Item | Rationale |
|---|------|-----------|
| **3** | **C3: Channel Model (RFC 0042)** | Enables multiplexed transport; required for Data Protocol (RFC 0042); unblocks Full SWIM/TrustEngine gossip over channels |
| **4** | **C4: NextAction 7 Remaining Actions (RFC 0039)** | Completes action model; required for ActionExecutor (RFC 0044); unblocks contract chaining, retries, events |
| **5** | **C5: RuntimeKernel Async + PlanResolver (RFC 0044)** | True async execution; Scheduler+WorkerPool+ActionExecutor integration; unblocks distributed runtime semantics |

### Tier 2 — Production Readiness

| # | Item | Rationale |
|---|------|-----------|
| **6** | **C6: Governance FSM Complete (RFC 0016)** | Completes governance lifecycle; reject/conflict/fork detection; expiry fix; required for Mesh Federation policy sync |
| **7** | **C7: Authority Key Handling** | Root key rotation; HSM support; certificate chain management; security hardening for production federation |

### Explicitly Deferred to v0.0.8+

| Item | Reason |
|------|--------|
| **C8: Full SWIM Gossip (RFC 0015 Stage 5)** | Requires Channel Model (C3) for transport; current gossip sufficient for single-mesh v0.0.7 |
| **C9: Full TrustEngine (RFC 0017 Stage 5)** | Requires Channel Model (C3) for digest gossip; binary trust sufficient for v0.0.7 |
| **C10: SMIR → WASM SDK** | Depends on C3/C4/C5 (Distributed Runtime core); v0.0.8 target per roadmap |
| **C11: Performance Benchmarks as CI Gates** | Important but not blocking v0.0.7; can parallel with v0.0.7 execution |

---

## Implementation Order & Gates

```text
v0.0.6 COMPLETE (P0-S6, P0-EX, R2, R3, R4, G1, RFC Sprint)
          │
          ▼
┌──────────────────────────────────────────────────────┐
│ PARALLEL TRACK A: NETWORKING (Tier 0)                │
│ C1: Full ICE + TURN  ────────────────────────────────┤  → Gate: 3-node WAN (symmetric NAT) mesh via TURN
│ C2: Mesh Federation  ◄───────────────────────────────┤  → Gate: Cross-mesh contract exec + policy sync
└──────────────────────┬───────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────┐
│ PARALLEL TRACK B: DISTRIBUTED RUNTIME (Tier 1)       │
│ C3: Channel Model    ────────────────────────────────┤  → Gate: Multiplexed session with 4 channels
│ C4: NextAction 7     ◄───────────────────────────────┤  → Gate: All 9 action types execute in E2E test
│ C5: RuntimeKernel Async + PlanResolver ◄────────────┤  → Gate: Async contract chain completes without blocking
└──────────────────────┬───────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────┐
│ TIER 2: PRODUCTION HARDENING (Sequential)            │
│ C6: Governance FSM Complete                          │  → Gate: Fork detection + expiry work in 3-mesh federation
│ C7: Authority Key Handling                           │  → Gate: Key rotation + HSM integration test PASS
└──────────────────────────────────────────────────────┘
                       │
                       ▼
                    v0.0.7 RELEASE
```

**Gate Criteria for v0.0.7 Release:**

```
[ ] C1: Full ICE — 3-node symmetric NAT mesh establishes via TURN relay; STUN/TURN server deployed
[ ] C2: Mesh Federation — Cross-mesh contract execution; gateway node routes; policy federation sync
[ ] C3: Channel Model — Session carries 4 concurrent channels (Control/Exec/Data/Discovery); flow control works
[ ] C4: NextAction — DispatchContract, ScheduleRetry, SpawnPlan, Notify, Compensate, Abort, EmitEvent all functional
[ ] C5: RuntimeKernel Async — execute_async non-blocking; PlanResolver resolves plan DAG; Scheduler+WorkerPool integrated
[ ] C6: Governance FSM — reject/conflict/detect_fork/expiry operational; Conflicted state generated; quorum from active authorities
[ ] C7: Authority Key Handling — Root key rotation; authority.sec HSM-backed; cert chain validation on join
[ ] All 25+ ctest PASS
[ ] All 30+ PCT PASS (including new ICE/Federation/Channel/NextAction tests)
[ ] E2E 3-mesh federation: join, cross-mesh contract exec, governance sync, key rotation all PASS
[ ] Security regression tests: downgrade, confusion, key-suite mismatch, replay, truncated sig all REJECT
[ ] clang-format + clang-tidy clean
```

---

## Effort Estimate Summary

| Item | Effort | Track |
|------|--------|-------|
| C1: Full ICE + TURN | 20 days | Networking (A) |
| C2: Mesh Federation | 25 days | Networking (A) |
| C3: Channel Model | 15 days | Runtime (B) |
| C4: NextAction 7 Remaining | 12 days | Runtime (B) |
| C5: RuntimeKernel Async + PlanResolver | 18 days | Runtime (B) |
| C6: Governance FSM Complete | 8 days | Hardening |
| C7: Authority Key Handling | 10 days | Hardening |
| **Total** | **~108 engineering days** | |

**Parallelization:** Track A (C1+C2) and Track B (C3+C4+C5) can run concurrently. C6/C7 sequential after tracks converge.

---

## Appendix: Source References

| Source | Key Sections |
|--------|--------------|
| DISCUSSION_0042_v0.0.3_Plan.md | §3 N10 (v0.0.4 preview items), §4 effort table |
| DISCUSSION_0046_RFC_Compliance_Audit_Hardening_Plan.md | §2 gap classification P2, §3 Phase 4-5, §15 status, §17.3 impl order |
| DISCUSSION_0053_v0.0.6_Research_Report.md | §2 candidates table (C15-C21), §4 gap analysis, §5 deferred |
| DISCUSSION_0054_v0.0.6_Implementation_Plan.md | §2 scope table, §6 deferred items, §7 roadmap |
| DISCUSSION_0051_v0.0.5_Research_Report.md | §2 candidates C2-C5, §3 gap analysis GAP-056-060 |
| RFC 0015-discovery-engine.md | §2 Decision 2 (MVP vs Stage 5 SWIM), §4 Interfaces |
| RFC 0017-trust-engine.md | §2 Decisions, §5 Interfaces, §6 Consequences (Stage 5) |
| RFC 0039-nextaction-model.md | §2.1 Action Types (9 actions), §2.4 PlanExecutor Integration |
| RFC 0042-session-channel-model.md | §2 Design (4-layer hierarchy, Channel, Flow Control), §4 Wire Protocol |
| RFC 0044-runtime-scheduler.md | §2 Architecture, §3 Design (Scheduler, JobQueue, WorkerPool, ActionExecutor) |

---

**End of Report** — Ready for discussion review and v0.0.7 sprint planning.