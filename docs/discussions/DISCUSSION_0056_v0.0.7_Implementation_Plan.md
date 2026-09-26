# DISCUSSION 0056 — v0.0.7 Implementation Plan: Full ICE + TURN + Mesh Federation + Distributed Runtime Core

**Status:** OPEN (phase new, baselined from 0055)  
**Target:** v0.0.7  
**Supersedes:** DISCUSSION_0055 (Research Report)

---

## 1. Philosophy: Networking Charter + Distributed Runtime Foundation

v0.0.7 delivers the **v0.0.7 charter** ("Full ICE + TURN + Mesh Federation" — per DISCUSSION_0042 N10, 0051/0052/0053/0054 roadmap) while laying the **distributed runtime foundation** (Channel Model, NextAction 7, RuntimeKernel Async + PlanResolver) required to unblock v0.0.8 "SMIR → WASM SDK + Distributed Runtime". Governance FSM Complete and Authority Key Handling provide production hardening for federation deployments.

> **Mục tiêu:** Production-ready mesh federation with full NAT traversal (ICE/TURN), cross-mesh routing, and a complete distributed runtime core — enabling v0.0.8 WASM SDK and Stage 5 gossip/trust.

---

## 2. Scope from 0055 Recommended (7 Items in 3 Tiers)

| Tier | # | Candidate | Source (0055) | Description |
|------|---|-----------|---------------|-------------|
| **Tier 0** | **1** | **C1: Full ICE + TURN (RFC 8445/8656)** | 0055:36, 0055:69 | Replace ICE-Lite with full ICE: candidate gathering, connectivity checks, nomination, TURN relay (RFC 8656) for symmetric NAT. STUN/TURN server deployment. | ✅ DONE
| **Tier 0** | **2** | **C2: Mesh Federation (Cross-Mesh Routing)** | 0055:37, 0055:78 | Inter-mesh communication: mesh-to-mesh routing, gateway nodes, policy federation, cross-mesh governance, trust anchor exchange. |
| **Tier 1** | **3** | **C3: Channel Model (RFC 0042)** | 0055:38, 0055:84 | Channel abstraction for multiplexing: CHANNEL_OPEN, CHUNK, ACK, NACK, FIN, CANCEL opcodes. Four-layer hierarchy (Connection→Session→Channel→Invocation). Lazy creation, flow control per channel. |
| **Tier 1** | **4** | **C4: NextAction 7 Remaining Actions (RFC 0039)** | 0055:39, 0055:85 | Implement DispatchContract, ScheduleRetry, SpawnPlan, Notify, Compensate, Abort, EmitEvent. Only Execute + StoreContext done in v0.0.6. |
| **Tier 1** | **5** | **C5: RuntimeKernel Async + PlanResolver (RFC 0044)** | 0055:40, 0055:86 | execute_async true async; PlanResolver provider; stages: dispatch/collect/audit/complete. Scheduler + WorkerPool + ActionExecutor integration. |
| **Tier 2** | **6** | **C6: Governance FSM Complete (RFC 0016)** | 0055:41, 0055:92 | reject/conflict/detect_fork/expiry; Conflicted state engine-generated; expiry unit fix (ns vs s); quorum from active authorities. |
| **Tier 2** | **7** | **C7: Authority Key Handling** | 0055:42, 0055:93 | Root key never circulates; authority.sec encrypted at rest; key rotation; certificate chain management; HSM/remote signer support. |

---

## 3. Work Items Table

Each item: tasks, dependencies, `[ ] OPEN`, source file:line from 0055.

### C1 — Full ICE + TURN (RFC 8445/8656)

| Task | Depends | Status | Source |
|------|---------|--------|--------|
| C1.1 Implement full ICE candidate gathering (host, srflx, relay) | N1-N5 (v0.0.4) complete; ICE-Lite baseline | `[x] DONE` | 0055:36, 0050:57, 0027:538 |
| C1.2 Implement connectivity checks + nomination (controlling/controlled) | C1.1 | `[x] DONE` | 0055:36, 0042:304, RFC 8445 §5-6 |
| C1.3 Implement TURN client (RFC 8656): allocate, refresh, send/channel data | C1.1 | `[x] DONE` | 0055:36, 0050:57, RFC 8656 |
| C1.4 STUN/TURN server deployment config + integration test | C1.2, C1.3 | `[x] DONE` | 0055:36, 0042:304 |
| C1.5 Gate test: 3-node WAN mesh (symmetric NAT) establishes via TURN relay | C1.1-C1.4 | `[x] DONE` | 0055:140 |

### C2 — Mesh Federation (Cross-Mesh Routing)

| Task | Depends | Status | Source |
|------|---------|--------|--------|
| C2.1 Gateway node implementation: cross-mesh routing table + policy | C1 (Full ICE for WAN links); Opcode Registry (0020 done) | `[ ] OPEN` | 0055:37, 0042:305, 0050:58 |
| C2.2 Mesh-to-mesh session establishment (federation handshake) | C2.1 | `[ ] OPEN` | 0055:37, 0050:58 |
| C2.3 Policy federation: cross-mesh ACL sync + trust anchor exchange | C2.2; P0-S6 (cert issuance); Governance FSM (C6) | `[ ] OPEN` | 0055:37, 0050:58 |
| C2.4 Cross-mesh contract execution path (gateway routing) | C2.3 | `[ ] OPEN` | 0055:37, 0050:58 |
| C2.5 Gate test: Cross-mesh contract exec + policy sync between 2 meshes | C2.1-C2.4 | `[ ] OPEN` | 0055:141 |

### C3 — Channel Model (RFC 0042)

| Task | Depends | Status | Source |
|------|---------|--------|--------|
| C3.1 Define Channel opcodes (CHANNEL_OPEN, CHUNK, ACK, NACK, FIN, CANCEL) in Opcode Registry | RFC 0020 (C11 done); RFC 0042 §4 | `[ ] OPEN` | 0055:38, 0046:805, 0042:14 |
| C3.2 Implement Channel struct + state machine (Open→Flowing→Closing→Closed) | C3.1; SessionManager wired (G1 done) | `[ ] OPEN` | 0055:38, 0042:500, RFC 0042 §2 |
| C3.3 Implement per-channel flow control (window, backpressure, prioritization) | C3.2 | `[ ] OPEN` | 0055:38, RFC 0042 §2.3 |
| C3.4 Wire Channel layer into Session packet path (lazy creation) | C3.3 | `[ ] OPEN` | 0055:38, 0054:138 |
| C3.5 Gate test: Session carries 4 concurrent channels (Control/Exec/Data/Discovery); flow control works | C3.1-C3.4 | `[ ] OPEN` | 0055:142 |

### C4 — NextAction 7 Remaining Actions (RFC 0039)

| Task | Depends | Status | Source |
|------|---------|--------|--------|
| C4.1 Implement DispatchContract action (forward to target node/contract) | Serialization Pipeline (C13 done); ActionExecutor scaffold | `[ ] OPEN` | 0055:39, 0046:806, 0039:500 |
| C4.2 Implement ScheduleRetry action (exponential backoff, max attempts) | C4.1 | `[ ] OPEN` | 0055:39, 0039:500 |
| C4.3 Implement SpawnPlan action (DAG plan creation + execution) | C4.1; PlanResolver (C5) | `[ ] OPEN` | 0055:39, 0039:500 |
| C4.4 Implement Notify action (event emission to subscribers) | C4.1 | `[ ] OPEN` | 0055:39, 0039:500 |
| C4.5 Implement Compensate action (saga rollback handler) | C4.1 | `[ ] OPEN` | 0055:39, 0039:500 |
| C4.6 Implement Abort action (forced termination + cleanup) | C4.1 | `[ ] OPEN` | 0055:39, 0039:500 |
| C4.7 Implement EmitEvent action (audit/event store integration) | C4.1 | `[ ] OPEN` | 0055:39, 0039:500 |
| C4.8 Gate test: All 9 action types (Execute, StoreContext + 7 new) execute in E2E test | C4.1-C4.7 | `[ ] OPEN` | 0055:143 |

### C5 — RuntimeKernel Async + PlanResolver (RFC 0044)

| Task | Depends | Status | Source |
|------|---------|--------|--------|
| C5.1 Implement `execute_async` true non-blocking path in RuntimeKernel | R3 (scheduler, execution_engine compiled); C4 (NextAction) | `[ ] OPEN` | 0055:40, 0046:807, 0044 |
| C5.2 Implement PlanResolver provider (plan DAG resolution, dependency ordering) | C5.1; C4.3 (SpawnPlan) | `[ ] OPEN` | 0055:40, 0044 §3 |
| C5.3 Implement PlanExecutor stages: dispatch → collect → audit → complete | C5.2; ActionExecutor (RFC 0044) | `[ ] OPEN` | 0055:40, 0044 §3 |
| C5.4 Integrate Scheduler + WorkerPool + ActionExecutor for async execution | C5.3; R3 complete | `[ ] OPEN` | 0055:40, 0044 |
| C5.5 Gate test: Async contract chain completes without blocking; PlanResolver resolves DAG | C5.1-C5.4 | `[ ] OPEN` | 0055:144 |

### C6 — Governance FSM Complete (RFC 0016)

| Task | Depends | Status | Source |
|------|---------|--------|--------|
| C6.1 Implement reject action (quorum from active authorities) | P0-S3 (quorum + vote verify done); Opcode Registry (0020 done) | `[ ] OPEN` | 0055:41, 0046:808, 0016 |
| C6.2 Implement conflict action + Conflicted state (engine-generated) | C6.1 | `[ ] OPEN` | 0055:41, 0016 §3 |
| C6.3 Implement detect_fork action (divergent state detection) | C6.2 | `[ ] OPEN` | 0055:41, 0016 §3 |
| C6.4 Fix expiry unit (ns vs s) + implement expiry action | C6.1 | `[ ] OPEN` | 0055:41, 0016 §3 |
| C6.5 Gate test: Fork detection + expiry work in 3-mesh federation | C6.1-C6.4 | `[ ] OPEN` | 0055:145 |

### C7 — Authority Key Handling

| Task | Depends | Status | Source |
|------|---------|--------|--------|
| C7.1 Implement root key never-circulates invariant (offline CA pattern) | P0-EX done; P0-S6 (cert issuance); RecoveryEngine verify done | `[ ] OPEN` | 0055:42, 0046:196, 0046:619, 0046:13 |
| C7.2 authority.sec encrypted at rest (HSM/remote signer integration) | C7.1 | `[ ] OPEN` | 0055:42, 0006 |
| C7.3 Implement authority key rotation (re-key + cert re-issuance) | C7.2 | `[ ] OPEN` | 0055:42, 0046:619 |
| C7.4 Certificate chain management (intermediate CA, path validation) | C7.3 | `[ ] OPEN` | 0055:42, 0006 |
| C7.5 Gate test: Key rotation + HSM integration test PASS; cert chain validation on join | C7.1-C7.4 | `[ ] OPEN` | 0055:146 |

---

## 4. Dependency Graph + Gates (from 0055 §106)

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

---

## 5. Success Criteria Checklist (from 0055 §137)

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

## 6. Do-Not-Mix: Explicitly Out of Scope for v0.0.7 (Deferred to v0.0.8+)

| Item | Reason |
|------|--------|
| **C8: Full SWIM Gossip (RFC 0015 Stage 5)** | Requires Channel Model (C3) for transport; current gossip sufficient for single-mesh v0.0.7 |
| **C9: Full TrustEngine (RFC 0017 Stage 5)** | Requires Channel Model (C3) for digest gossip; binary trust sufficient for v0.0.7 |
| **C10: SMIR → WASM SDK** | Depends on C3/C4/C5 (Distributed Runtime core); v0.0.8 target per roadmap |
| **C11: Performance Benchmarks as CI Gates** | Important but not blocking v0.0.7; can parallel with v0.0.7 execution |

---

## 7. Footer

**Baselined from:**
- DISCUSSION_0055 (Research Report — v0.0.7 candidates + gap analysis + impl order)
- DISCUSSION_0042_v0.0.3_Plan.md (§3 N10 v0.0.4 preview items)
- DISCUSSION_0046_RFC_Compliance_Audit_Hardening_Plan.md (§2 P2 gap classification, §3 Phase 4-5, §17.3 impl order)
- DISCUSSION_0054_v0.0.6_Implementation_Plan.md (§2 scope, §6 deferred, §7 roadmap)
- DISCUSSION_0053_v0.0.6_Research_Report.md (§2 C15-C21, §4 gap analysis, §5 deferred)

**Version Roadmap Context:**
```
v0.0.1       Protocol
v0.0.2       Production runtime foundation (LAN/VPN)
v0.0.3       Real deployment verification (3-node VPN mesh) ✅ DONE
v0.0.4       Network capability: STUN, hole punch, relay, ICE-Lite ✅ DONE
v0.0.5       Observability + Packaging + Benchmarks + Recovery SSS ✅ DONE
v0.0.6       Runtime wiring (R1-R5, G1-G10) + RFC compliance cleanup ✅ COMPLETE
v0.0.7       **Full ICE + TURN + Mesh Federation + Distributed Runtime Core** ← THIS PLAN (C1 ✅ DONE)
v0.0.8       SMIR → WASM SDK + Distributed Runtime (EventBus, NextAction, RuntimeKernel)
v0.1         Stable platform
```

---

**End of Implementation Plan** — Ready for sprint execution.