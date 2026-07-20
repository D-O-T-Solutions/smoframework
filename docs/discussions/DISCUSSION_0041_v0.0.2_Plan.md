# DISCUSSION 0041 — Release 0.0.2: From Developer Preview to Production Readiness

**Status:** Planning  
**Target:** v0.0.2 (production-ready)  
**Parent:** v0.0.1-rc — 19/19 tests, E2E smoke pass  
**RFCs:** 0001–0044  

---

## 1. Motivation

v0.0.1-rc delivered a protocol-complete developer preview:

- Protocol freeze with 6 architecture review fixes
- 17 protocol compliance tests (PCT-001–017)
- 19/19 ctest suite + 8/8 E2E smoke checks
- Full crypto suite support (Classical, Modern, PurePQC)
- Native contracts: Join, Bootstrap, Governance, Recovery, File, Process

**v0.0.2 bridges the gap from developer preview to production-ready mesh runtime.** Every item below addresses a concrete limitation documented in §12 of DISCUSSION_0040.

This roadmap is **production-driven, not feature-driven**. All epics focus on convergence, FSM correctness, anti-replay, CI/CD, packaging, observability, HA, and hardening — the things a real distributed system needs before new features.

---

## 2. Sprint Plan — 12 Epics

### P1 — Anti-Entropy Service (Gossip Convergence)

*RFC: DISCUSSION_0040 §10.5*

Without anti-entropy, long-term gossip convergence is not guaranteed:

```
partition → heal → gossip packet loss → state forever inconsistent
```

**Design:** 4 independent Merkle trees, each hashed with Blake3:

| Tree | Scope | Bucket Size |
|------|-------|-------------|
| Membership | Peer records (node_id, role, state, epoch) | 256 entries |
| CRL | Revoked certificate fingerprints | 256 entries |
| Policy | Active policy rules + version | 64 entries |
| Contract Registry | Known contract IDs + versions | 64 entries |

Each tree has its own root hash. Global root = Blake3(all 4 roots + epoch). On mismatch during sync, only the divergent tree's delta is requested — not the entire world state.

**Tasks:**
- [ ] P1.1 Implement `AntiEntropyService` — periodic Merkle comparison every 30 min with 3 random peers
- [ ] P1.2 4 independent Merkle trees: Membership, CRL, Policy, Contract Registry
- [ ] P1.3 Wire `CAP_ANTI_ENTROPY` (bit 4, reserved in `join_protocol.hpp:51`) into capability negotiation
- [ ] P1.4 Handle repair: request only divergent tree's delta on hash mismatch
- [ ] P1.5 Add `PCT-018: Anti-entropy Merkle verification` test
- [ ] P1.6 Integration test: partition 2 nodes for 60s, rejoin, verify all 4 trees converge within 2 cycles

---

### P2 — Real Gossip Readiness (FSM GOSSIP_SYNC)

*Bug: DISCUSSION_0039 §7, auto_enroll.cpp:718-726*

The Join FSM transitions `WAIT_SYNC → GOSSIP_STARTED → GOSSIP_COMPLETE → READY` **immediately** without waiting for actual gossip I/O. The node reports READY before any network gossip has occurred.

**Design:** Node is READY only when all 3 conditions are met:

```
received gossip from ≥ 1 peer
AND
sent gossip to ≥ 1 peer
AND
heartbeat service active (received ≥ 1 heartbeat)
```

**Tasks:**
- [ ] P2.1 Replace stub in `auto_enroll.cpp:718-726` with actual GossipEngine probe
- [ ] P2.2 Implement 3-condition readiness: rx_gossip, tx_gossip, heartbeat_active
- [ ] P2.3 Add `GOSSIP_PROBE_TIMEOUT` (configurable, default 15s) with retry to BOOTSTRAP_SYNC
- [ ] P2.4 Add `PCT-019: Gossip readiness probe` test
- [ ] P2.5 Integration test: verify FSM stays in WAIT_GOSSIP until all 3 conditions met

---

### P3 — CI/CD Pipeline

*Gap: no CI/CD infra exists*

No automated build, test, sanitizer, or release pipeline. For a C++ project handling untrusted network input, sanitizers are non-negotiable.

**Sanitizer matrix:**

| Config | ASAN | UBSAN | TSAN |
|--------|------|-------|------|
| Debug | ✅ | ✅ | — |
| Release | — | — | — |
| ASAN | ✅ | ✅ | — |
| TSAN | — | — | ✅ |

**Tasks:**
- [ ] P3.1 Create `.github/workflows/ci.yml` — 4 configs × 2 PQC options = 8 jobs
- [ ] P3.2 Add `WITH_PQC=ON` and `WITH_PQC=OFF` matrix builds
- [ ] P3.3 Run full ctest suite + E2E smoke test on every PR
- [ ] P3.4 Add `clang-tidy` static analysis
- [ ] P3.5 Add `codespell` for doc typos
- [ ] P3.6 Add Doxygen doc generation check

---

### P4 — Install Targets & Packaging

*Gap: no `install()` in CMake, no CPack*

Currently only build-tree artifacts exist. No `make install`, no `find_package(SMO)`, no `.deb`.

**Tasks:**
- [ ] P4.1 Add `install(TARGETS ...)` for smo-core, smo-protocol, smo-transport static libs
- [ ] P4.2 Add `install(TARGETS ...)` for smo-node, smo-cli, smo-admin binaries
- [ ] P4.3 Add `install(DIRECTORY ...)` for public headers (`include/smo/`)
- [ ] P4.4 Add `install(EXPORT SMO)` so external projects can `find_package(SMO)`
- [ ] P4.5 Add CPack config for `.deb` packaging
- [ ] P4.6 Verify `make install` + `find_package(SMO)` on clean Ubuntu 24.04

---

### P5 — Policy Store Integration

*Gap: storage/CMakeLists.txt:14 — policy_store commented out*

The `policy_store` subdirectory has an SqliteStore API mismatch. Policy deltas are currently stubs returning `{}`.

**Tasks:**
- [ ] P5.1 Audit `storage/policy_store` API vs current `SqliteStore` interface
- [ ] P5.2 Fix API mismatch (column naming → align with `Policy` struct fields)
- [ ] P5.3 Re-enable `add_subdirectory(policy_store)` in `storage/CMakeLists.txt`
- [ ] P5.4 Wire policy store into `SyncService` policy delta handler
- [ ] P5.5 Remove policy delta stub in `smo-node` daemon (lines 1057-1065)
- [ ] P5.6 Add `PCT-020: Policy store CRUD` test

---

### P6 — Nonce Dedup & JOIN_REQUEST Anti-Replay

*Gap: no nonce dedup in production — DISCUSSION_0040 §12*

JOIN_REQUEST replay is possible within timestamp TTL.

**Design:** Nonce TTL = token expiry. An invite token valid for 5 minutes means the nonce cache TTL is also 5 minutes. No need to maintain two independent timers.

**Tasks:**
- [ ] P6.1 Add nonce cache to `join_protocol.cpp:process_join_request()` — keyed by Blake3(nonce + node_id)
- [ ] P6.2 Nonce TTL = token.expiry_unix_sec, not hardcoded
- [ ] P6.3 Return error code 219 on replay detection
- [ ] P6.4 Add `PCT-021: JOIN_REQUEST nonce dedup` test

---

### ~~P7 — NAT Traversal for Discovery~~ *(Postponed to v0.0.3)*

*Gap: discovery only works on same subnet/LAN — DISCUSSION_0040 §12*

STUN, ICE, hole-punching, relay — this is an entire connectivity subsystem. 5 days is not enough to do it properly, and forcing it into v0.0.2 would delay the release.

**Decision:** v0.0.2 targets production in LAN/VPN environments. Internet mesh is deferred to **v0.0.3** or **v0.1.0**.

*Cross-reference: [DISCUSSION_0040 §12](DISCUSSION_0040_Release_0.0.1_Plan.md#12-known-limitations-in-001)*

---

### P8 — Production Hardening

*Basket of quality items from DISCUSSION_0040 §12*

**Tasks:**
- [ ] P8.1 Audit history queries: implement `StorageService::query_audit()` with time-range + node filter
- [ ] P8.2 HTTP enroll server cleanup: remove or isolate legacy `enroll_server` path in `smo-admin`
- [ ] P8.3 Authority HA: support 2+ authority nodes — use embedded Raft (etcd or braft) instead of custom leader election
- [ ] P8.4 Compiler pipeline: wire SMIR stages for custom contract definitions
- [ ] P8.5 Graceful shutdown: verify all timers/fds cleaned in `smo-node` signal handler

---

### P9 — Release v0.0.2

**Tasks:**
- [ ] P9.1 Bump version in root `CMakeLists.txt` to 3.1.0
- [ ] P9.2 Update feature status table in README.md
- [ ] P9.3 Run full test suite + E2E smoke
- [ ] P9.4 `git tag v0.0.2 && git push origin v0.0.2`
- [ ] P9.5 Draft GitHub release notes with changelog

---

### P10 — Metrics & Observability

Production without metrics is blind. Every distributed runtime needs:

| Metric | Source | Export |
|--------|--------|--------|
| Heartbeat RTT | HeartbeatService | Histogram |
| Gossip latency | GossipEngine | Histogram |
| Connected peers | MembershipTable | Gauge |
| Contract execution latency | Runtime Kernel | Histogram |
| Queue depth | Dispatcher | Gauge |
| Memory / RSS | /proc/self/status | Gauge |
| CPU usage | /proc/self/stat | Gauge |

**Tasks:**
- [ ] P10.1 Implement `MetricsService` with registry for gauges, counters, histograms
- [ ] P10.2 Expose `/metrics` endpoint via HTTP (Prometheus text format)
- [ ] P10.3 Instrument HeartbeatService, GossipEngine, Dispatcher, Runtime Kernel
- [ ] P10.4 Instrument MembershipTable (peer count by state/role)
- [ ] P10.5 Add `PCT-023: Metrics endpoint` integration test

---

### P11 — Structured Logging

*Status quo: printf + spdlog mixed, no uniform schema*

Log aggregation (ELK/Loki) is painful without a consistent schema.

**Design:**

```json
{
  "timestamp": "2026-07-20T10:30:00.123Z",
  "node_id": "a1b2c3d4...",
  "mesh_id": "mesh-smo-dev",
  "session_id": "550e8400-...",
  "component": "GossipEngine",
  "level": "info",
  "message": "fanout complete",
  "peer_count": 5,
  "rtt_ms": 42
}
```

**Tasks:**
- [ ] P11.1 Define `LogEntry` struct with all standard fields
- [ ] P11.2 Replace `printf` + raw `spdlog` calls with structured logger
- [ ] P11.3 Add JSON + plaintext formatters (configurable)
- [ ] P11.4 Node identity auto-injected into every log line
- [ ] P11.5 Add `PCT-024: Structured log format` test

---

### P12 — Config Versioning & Migration

*Gap: config evolves without schema version*

No `config_version` or `schema_version` means breaking changes cannot be detected or migrated.

**Tasks:**
- [ ] P12.1 Add `config_version` and `schema_version` fields to `MeshConfig`
- [ ] P12.2 Implement migration path: `schema_version < current` → auto-upgrade on load
- [ ] P12.3 Add `PCT-025: Config version migration` test

---

## 3. Effort Estimate

| Epic | Effort | Dependencies | Priority |
|------|--------|-------------|----------|
| P1 Anti-Entropy | 6 days | none | Medium |
| P2 Gossip Readiness | 2 days | P1 (partial) | High |
| P3 CI/CD | 2 days | none | High |
| P4 Packaging | 2 days | none | High |
| P5 Policy Store | 3 days | none | Medium |
| P6 Nonce Dedup | 1 day | none | Medium |
| ~~P7 NAT Traversal~~ | ~~postponed~~ | — | — |
| P8 Hardening | 5 days | P5 | Medium |
| P9 Release | 1 day | P1–P8 | — |
| P10 Metrics | 4 days | none | Medium |
| P11 Structured Logging | 3 days | none | Medium |
| P12 Config Versioning | 2 days | none | Low |

**Total (v0.0.2):** ~31 engineering days.

---

## 4. Open Questions

| # | Question | Proposed Answer |
|---|----------|----------------|
| Q1 | Anti-Entropy — own service or part of GossipEngine? | Separate `AntiEntropyService` holding reference to `GossipEngine` + `MembershipTable`. Cleaner separation of concerns. |
| Q2 | Merkle bucket size? | 256 entries/bucket (membership, CRL), 64 entries/bucket (policy, contracts). Keeps per-bucket hash small. |
| Q3 | CPack generator? | Start with `.deb` (Ubuntu 24.04), add `.tgz` portable binary. RPM deferred. |
| Q4 | Policy store — reuse SqliteStore or custom? | Reuse `SqliteStore`. The mismatch is column naming — align with `Policy` struct fields. |
| Q5 | Authority HA — custom leader election or off-the-shelf? | **Off-the-shelf.** Use embedded Raft (etcd/raft or braft). Do not write custom consensus for v0.0.2. |
| Q6 | CI runner? | GitHub-hosted (ubuntu-24.04) for OSS. Self-hosted for private builds. |
| Q7 | Metrics format? | Prometheus text format. `/metrics` endpoint via embedded HTTP (no external dependency). |
| Q8 | Log format — JSON always or configurable? | Configurable. Default = JSON for production, plaintext for development. |

---

## 5. Success Criteria

```
☐ All P1–P12 items verified in CI (P7 postponed)
☐ Test suite ≥ 25 tests (19 existing + 6 new PCTs + integration)
☐ ASAN/UBSAN green on every PR
☐ E2E smoke test passes with 0 failures
☐ `make install` produces relocatable system install
☐ `find_package(SMO)` works from external project
☐ `.deb` package installs and runs on clean Ubuntu 24.04
☐ Gossip FSM waits for all 3 readiness conditions before READY
☐ Anti-entropy converges 2 partitioned nodes within 2 cycles (4 trees)
☐ Prometheus `/metrics` endpoint exposes ≥ 6 metrics
☐ Log output conforms to structured schema
☐ Config version migration works: schema_version < current → auto-upgrade
☐ GitHub Actions CI green on every PR
```

---

## 6. References

- [DISCUSSION_0040 §10.5](DISCUSSION_0040_Release_0.0.1_Plan.md#105-anti-entropy-service-post-001) — Anti-entropy design
- [DISCUSSION_0040 §12](DISCUSSION_0040_Release_0.0.1_Plan.md#12-known-limitations-in-001) — Known limitations
- [DISCUSSION_0039 §7](DISCUSSION_0039_Mesh_Lifecycle_Complete.md#7-remaining-gaps-phase-8) — Gossip readiness gap
- [RFC 0024](../RFC/0024-crypto-suite-freeze.md) — Crypto suite specification
- [RFC 0034](../RFC/0034-bootstrap-snapshot.md) — Bootstrap protocol
- [SPEC.md §IX](../SPEC.md) — State machine definitions
