# DISCUSSION 0051 — v0.0.5 Research Report: UNUSED GAP Items & Scope Candidates

**Status:** Research Complete  
**Date:** 2026-09-22  
**Sources:** DISCUSSION_0042, DISCUSSION_0045, DISCUSSION_0050, RFC docs, DEPLOYMENT_GUIDE.md, DISCUSSION_0046

---

## Executive Summary

This report identifies **unimplemented GAP items** from v0.0.2–v0.0.4 phases and defines **v0.0.5 scope candidates**. Key findings:

1. **v0.0.4 NAT Traversal (N1–N5) is COMPLETE** — STUN, UDP hole punch, Relay (TURN-Lite), ICE-Lite, WAN test suite all done (DISCUSSION_0050 §3).
2. **v0.0.5 was originally "Observability"** (DISCUSSION_0045 §6/§9) — Prometheus, Grafana, distributed tracing, smo-web UI.
3. **Four major deferred items from N10 (DISCUSSION_0042 §3 N10)** remain untouched:
   - Full ICE (RFC 8445) with TURN
   - Mesh federation (cross-mesh routing)
   - Smart contract SDK (SMIR → WASM)
   - Performance benchmarks as CI gates
4. **Packaging track (v0.0.3 Sprint D) has 2/3 items PENDING** — RPM, Docker.
5. **RFC Compliance Audit (DISCUSSION_0046)** reveals additional GAP items in Phase 5 (RFC cleanup) and Shamir SSS for recovery (RFC 0006 §14).

---

## Table of v0.0.5 Candidates

| # | Candidate Name | Source (file:line) | Description | Effort Estimate | Dependencies | Priority |
|---|----------------|-------------------|-------------|-----------------|--------------|----------|
| **C1** | **Observability Stack** | 0045:24, 0045:206 | Prometheus metrics endpoint, Grafana dashboards, distributed tracing (OpenTelemetry/Jaeger), smo-web UI | 10 days | v0.0.4 networking stable; metrics instrumentation in place | **P0** (original v0.0.5 scope) |
| **C2** | **Full ICE + TURN (RFC 8445/8656)** | 0042:304, 0050:57, 0027:538-541 | Replace ICE-Lite with full ICE: candidate gathering, connectivity checks, nomination, TURN relay (RFC 8656) for symmetric NAT | 15 days | N1–N5 complete; libp2p/Pion integration or custom impl | **P1** (deferred from N10) |
| **C3** | **Mesh Federation (Cross-Mesh Routing)** | 0042:305, 0050:58 | Inter-mesh communication: mesh-to-mesh routing, gateway nodes, policy federation, cross-mesh governance | 20 days | Full ICE (C2); membership scaling; governance v2 | **P2** (deferred from N10) |
| **C4** | **SMIR → WASM SDK** | 0042:306, 0050:59, 0035:500, 0037:301, 0040:396 | WASM contract runtime: wasmtime/wasm3 embed, host functions (FS/Process/Vault/Network/Crypto), gas metering, SDK tooling | 25 days | RuntimeServices wired (R3 in 0046); ContractManager lifecycle (R4); ABI freeze (RFC 0036) | **P1** (deferred from N10) |
| **C5** | **Performance Benchmarks as CI Gates** | 0042:307, 0050:60, 0042:278-283 | Automated benchmarks in CI: 5000 TCP sessions, 2000 UDP targets, 1000 msg/s gossip, 10k node anti-entropy <30s; regression gates | 8 days | Benchmark harness (N8); CI infrastructure; reproducible WAN test env | **P1** (deferred from N10) |
| **C6** | **RPM Package** | 0045:123, 0045:244, 0045:287, 0050:68-72 | Fedora/RHEL .rpm via CPack; publish to COPR/repo | 3 days | CPack RPM generator; spec file; CI publish pipeline | **P0** (packaging debt from v0.0.3) |
| **C7** | **Docker Image** | 0045:244, 0045:287, 0050:68-72 | Multi-arch Docker image (amd64/arm64); slim runtime; GitHub Container Registry | 3 days | Dockerfile; multi-stage build; CI publish | **P0** (packaging debt from v0.0.3) |
| **C8** | **Shamir SSS Recovery (RFC 0006 §14)** | 0046:84, 0046:617, 0046:784 | M-of-N threshold secret sharing for root key recovery; versioned recovery format | 5 days | Recovery crypto (Argon2id + AES-256-GCM done); RFC 0006 amendment | **P1** (RFC compliance) |
| **C9** | **Opcode Registry Namespace (RFC 0020)** | 0046:191, 0020:26, 0020:85 | 3-byte namespace allocation; packet validation via registry; sequential message IDs per group | 5 days | RFC 0019 packet layout alignment; G3 packet auth done | **P2** (RFC compliance) |
| **C10** | **Storage Schema per-Store (RFC 0022)** | 0046:192, 0022 | SQLite schema per store (manifest, session, node, DAG, policy, audit); migrations | 5 days | Serialization pipeline (RFC 0043) | **P2** (RFC compliance) |
| **C11** | **Serialization Pipeline (RFC 0043)** | 0046:193, 0043 | Unified CBOR/JSON pipeline replacing ad-hoc per-module serialization | 8 days | Schema (C10); Codegen integration | **P2** (RFC compliance) |
| **C12** | **Full SWIM Gossip (RFC 0015 Stage 5)** | 0015:4, 0015:14, 0027:542 | Replace basic UDP HELLO/PING with SWIM: failure detection, dissemination, compression | 10 days | Membership sync; gossip compression; delta sync | **P2** (deferred from Stage 5) |
| **C13** | **Full TrustEngine (RFC 0017 Stage 5)** | 0017:4, 0046:94 | Binary trust for MVP done; full engine: continuous scoring, witness selection, attestation verification | 8 days | TrustManager wired (v0.0.6); WitnessSelector done; attest crypto done | **P2** (deferred from Stage 5) |
| **C14** | **EventBus + ActionExecutor (RFC 0044)** | 0044:249, 0044:344, 0044:358 | EventBus for async events; ActionExecutor for NextAction dispatch (DispatchContract, ScheduleRetry, SpawnPlan, Notify, Compensate, Abort) | 10 days | RuntimeKernel async (G6); PlanResolver; RuntimeServices wired | **P2** (distributed runtime) |
| **C15** | **QR Code / HTTP Enrollment (RFC 0007)** | 0007:28, 0007:40 | QR code rendering for air-gap enrollment; HTTP enrollment transport for cloud/enterprise | 5 days | Join token format stable; CLI transport abstraction | **P3** (future) |

---

## Gap Analysis: Unused/Unimplemented GAP Items from Earlier Phases

| GAP ID | Description | Origin | Status | Notes |
|--------|-------------|--------|--------|-------|
| **GAP-001..012** | 12 CLI operations (exec, deploy, undeploy, contract status, policy show, trace, filesystem, process, transfer, discover, export, governance list) | DISCUSSION_0045 §10 | ✅ **DONE** (v0.0.3 Sprint B) | All implemented in `cmd/smo-cli`; verified by e2e-full.sh |
| **P0-S1..S6** | Security boundary gaps: join-token verify, attestation crypto, governance quorum, bootstrap ticket, manifest sig, session auth | DISCUSSION_0046 §2 | ✅ **DONE** (P0-S1..S5, G10, G3) | P0-S6 (session auth separation) + P0-EX (secret at rest) IN PROGRESS |
| **R1-R5** | Runtime wiring: RuntimeServices, PolicyEngine, 5 unbuilt .cpp, ContractManager lifecycle, WorkerPool | DISCUSSION_0046 §2 | ⏳ **PARTIAL** | R3 (5 .cpp) pending; R2 (PolicyEngine) pending; R1 pending |
| **G1-G10** | Mesh networking/ops: SESSION_OPEN, heartbeat, packet auth, channel model, NextAction, RuntimeKernel, governance FSM, MeshFSM, PeerStore step, TrustDigest | DISCUSSION_0046 §2 | ⏳ **PARTIAL** | G3 (packet auth) DONE 2026-09-17; G10 DONE; G1,G2,G9,G8,G4,G5,G6,G7 pending |
| **Phase 5 RFC Cleanup** | Opcode registry namespace, Storage schema per-store, Serialization pipeline, Shamir SSS, Authority key handling | DISCUSSION_0046 §187-197 | ⏳ **PENDING** | All deferred to post-v0.0.4 |
| **RFC 0015 Stage 5** | Full SWIM gossip | RFC 0015:4,14 | ⏳ **DEFERRED** | Basic UDP HELLO/PING only |
| **RFC 0017 Stage 5** | Full TrustEngine | RFC 0017:4 | ⏳ **DEFERRED** | Binary trust for MVP done; full engine deferred |
| **N10 Items** | Full ICE+TURN, Mesh federation, SMIR→WASM, Perf benchmarks CI | DISCUSSION_0042:298-307 | ⏳ **DEFERRED** | Explicitly marked "planning only — no implementation" |
| **Packaging D.9-D.10** | RPM package, Docker image | DISCUSSION_0045:122-124, 286-287 | ❌ **PENDING** | DEB done; RPM + Docker not started |
| **QR/HTTP Enrollment** | Air-gap QR code, HTTP transport | RFC 0007:28,40 | ⏳ **DEFERRED** | Future enrollment transports |

---

## Packaging Track Status (from v0.0.3 Sprint D)

| Package | Status | Source | Notes |
|---------|--------|--------|-------|
| **DEB** | ✅ **DONE** | 0045:59, 0045:114, 0050:68 | `smo_0.0.2_amd64.deb` (69 MB); CPack generator works |
| **RPM** | ❌ **PENDING** | 0045:123, 0045:244, 0045:287, 0050:68-72 | "Not implemented (P2)" — Fedora/RHEL target |
| **Docker** | ❌ **PENDING** | 0045:244, 0045:287, 0050:68-72 | Multi-arch (amd64/arm64); slim runtime image needed |
| **Tarball** | ✅ **DONE** | 0045:60 | `smo-0.0.2-x86_64.tar.gz` portable binary |
| **Systemd Unit** | ✅ **DONE** | 0045:117, 0045:284 | `scripts/smo-node.service` installed by deploy scripts |

**Gap:** RPM + Docker are the only packaging items not delivered from v0.0.3 Sprint D success criteria (0045:244).

---

## Recommended v0.0.5 Scope (3-5 Items Max)

Based on: **original v0.0.5 charter (Observability)**, **packaging debt**, **deferred N10 items**, and **RFC compliance needs**:

### ✅ Recommended Scope (5 items)

| Priority | Item | Rationale |
|----------|------|-----------|
| **1** | **Observability Stack (C1)** | Original v0.0.5 charter; enables production operations; Prometheus metrics already partially instrumented (smo_stun_latency, smo_hole_punch_*, smo_relay_*, smo_nat_test_status from v0.0.4) |
| **2** | **RPM Package (C6)** | Packaging debt from v0.0.3; required for Fedora/RHEL adoption; low effort (3 days) |
| **3** | **Docker Image (C7)** | Packaging debt from v0.0.3; essential for cloud/CI deployment; low effort (3 days) |
| **4** | **Performance Benchmarks as CI Gates (C5)** | Deferred from N10; critical for v0.1 stability claim; leverages existing benchmark harness (N8) |
| **5** | **Shamir SSS Recovery (C8)** | RFC 0006 §14 mandatory; security-critical for production; recovery crypto (Argon2id + AES-256-GCM) already done |

### ❌ Deferred to v0.0.6+

| Item | Reason |
|------|--------|
| Full ICE + TURN (C2) | Requires libp2p/Pion integration or major custom impl; v0.0.4 ICE-Lite sufficient for most NAT scenarios |
| Mesh Federation (C3) | Depends on Full ICE; complex cross-mesh governance; premature before single-mesh stability |
| SMIR → WASM SDK (C4) | Depends on RuntimeServices wiring (R1), ContractManager lifecycle (R4), PolicyEngine (R2) — all pending in 0046 |
| RFC Compliance Cleanup (C9-C11) | Important but not blocking v0.0.5 observability/packaging goals |
| Full SWIM/TrustEngine (C12,C13) | Stage 5 items; current gossip + trust sufficient for v0.0.5 scale |
| EventBus/ActionExecutor (C14) | Distributed runtime semantics; depends on RuntimeKernel async (G6) |
| QR/HTTP Enrollment (C15) | Nice-to-have; not blocking production deployments |

---

## Version Roadmap Context

```
v0.0.1       Protocol
v0.0.2       Production runtime foundation (LAN/VPN)
v0.0.3       Real deployment verification (3-node VPN mesh) ✅ DONE
v0.0.4       Network capability: STUN, hole punch, relay, ICE-Lite ✅ DONE
v0.0.5       **Observability + Packaging + Benchmarks + Recovery SSS** ← RECOMMENDED SCOPE
v0.0.6       Runtime wiring (R1-R5, G1-G10) + RFC compliance cleanup
v0.0.7       Full ICE + TURN + Mesh Federation
v0.0.8       SMIR → WASM SDK + Distributed Runtime (EventBus, NextAction)
v0.1         Stable platform
```

---

## Appendix: Source References

| Source | Key Sections |
|--------|--------------|
| DISCUSSION_0042_v0.0.3_Plan.md | §3 N10 (v0.0.4 preview items), §4 effort table, §6 success criteria |
| DISCUSSION_0045_v0.0.3_Implementation_Plan.md | §1 philosophy, §6 roadmap, §8 success criteria, §10 progress tracking (RPM/Docker pending) |
| DISCUSSION_0045_v0.0.3_3Node_Mesh_Scenario.md | §3.3 gaps table, §5 success criteria (DEB+RPM+Docker) |
| DISCUSSION_0050_v0.0.4_NAT_Traversal_Plan.md | §3 N1-N5 complete, §4 deferred items, §5 packaging pending |
| RFC 0015, 0017, 0027, 0032, 0035, 0037, 0040, 0044 | Future/deferred markers, WASM readiness, Stage 5 items |
| DISCUSSION_0046_RFC_Compliance_Audit_Hardening_Plan.md | §2 gap classification, §3 phases, §9 phase reordering, §15 status, §17.3 impl order |
| DEPLOYMENT_GUIDE.md | §13 ADR (package: DEB via CPack), packaging status verified |

---

**End of Report** — Ready for discussion review.