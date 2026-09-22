# DISCUSSION 0052 — v0.0.5 Implementation Plan: Observability + Packaging + Benchmarks + Recovery

**Status:** OPEN (phase new, baselined from 0051)  
**Target:** v0.0.5  
**Supersedes:** DISCUSSION_0051  

---

## 1. Triết Lý: Integration over Invention — Leverage Mature Standards

v0.0.5 không tạo mới network feature (đã xong ở v0.0.4).  
v0.0.5 không viết custom observability stack — dùng **Prometheus**, **OpenTelemetry**, **Grafana** chuẩn công nghiệp.  
v0.0.5 không viết custom packaging — dùng **CPack**, **Docker multi-stage**, **GitHub Container Registry**.  
v0.0.5 không viết custom benchmark harness — dùng **Google Benchmark / Catch2** đã có ở N8.  
v0.0.5 không viết custom crypto — dùng **Argon2id + AES-256-GCM** đã có trong recovery stack.

> Mục tiêu: **production-ready observability + distribution artifacts + CI gates + root-key recovery** — tất cả built on mature libraries.

---

## 2. Scope từ 0051 Recommended (5 Items)

| Priority | Candidate | Source (0051) | Description |
|----------|-----------|---------------|-------------|
| **1** | **C1 Observability Stack** | 0051:29, 0051:86 | Prometheus `/metrics`, Grafana dashboards, OpenTelemetry tracing, smo-web UI stub |
| **2** | **C6 RPM Package** | 0051:34, 0051:87 | CPack RPM generator, `.spec` file, CI publish to COPR/GHCR |
| **3** | **C7 Docker Image** | 0051:35, 0051:88 | Multi-arch (amd64/arm64) slim runtime, multi-stage Dockerfile, GHCR publish |
| **4** | **C5 Benchmarks CI Gates** | 0051:33, 0051:89 | CI benchmark harness, regression gates: 5k TCP, 2k UDP, 1k msg/s, 10k anti-entropy <30s |
| **5** | **C8 Shamir SSS Recovery** | 0051:36, 0051:90 | M-of-N threshold recovery, versioned format, Argon2id + AES-256-GCM |

---

## 3. Work Items Table

Each item: tasks, dependencies, `[ ] OPEN`, source file:line reference.

### C1 — Observability Stack

| Task | Depends | Status | Source |
|------|---------|--------|--------|
| C1.1 Add Prometheus metrics endpoint (`/metrics` HTTP) on smo-node admin port | v0.0.4 metrics (smo_stun_latency, smo_hole_punch_*, smo_relay_*, smo_nat_test_status) | `[x] DONE` | 0051:29, 0050:68 |
| C1.2 Instrument core paths: gossip, anti-entropy, session, contract exec, NAT traversal | C1.1 | `[x] DONE` | 0051:29 |
| C1.3 Grafana dashboard JSON: mesh health, NAT traversal, gossip, sessions, contracts | C1.1 | `[ ] OPEN` | 0051:29 |
| C1.4 OpenTelemetry tracing: W3C tracecontext, OTLP exporter (Jaeger/Tempo) | C1.1 | `[x] DONE` | 0051:29, 0046:193 |
| C1.5 smo-web UI stub: React + Vite, reads `/metrics`, shows node status, mesh topology | C1.1, C1.3 | `[ ] OPEN` | 0051:29, 0045:210 |

### C6 — RPM Package

| Task | Depends | Status | Source |
|------|---------|--------|--------|
| C6.1 CPack RPM generator config (`CPackRpm.cmake`) | DEB working (0045:59) | `[ ] OPEN` | 0051:34, 0045:123 |
| C6.2 RPM spec file: dependencies, systemd unit, file layout, post/preun scripts | C6.1 | `[ ] OPEN` | 0051:34, 0045:287 |
| C6.3 CI publish pipeline: build RPM on Fedora 39/40, sign, push to COPR + GHCR | C6.2 | `[ ] OPEN` | 0051:34, 0050:72 |
| C6.4 Test: `dnf install ./smo-0.0.5-1.fc39.x86_64.rpm && smo-node --version` | C6.3 | `[ ] OPEN` | 0045:244 |

### C7 — Docker Image

| Task | Depends | Status | Source |
|------|---------|--------|--------|
| C7.1 Multi-stage Dockerfile: build stage (Ubuntu 22.04 + deps) → runtime stage (distroless/scratch + smo-node binary) | DEB/RPM artifacts | `[ ] OPEN` | 0051:35, 0045:287 |
| C7.2 Multi-arch build: `docker buildx build --platform linux/amd64,linux/arm64` | C7.1 | `[ ] OPEN` | 0051:35 |
| C7.3 GHCR publish: `ghcr.io/smoframework/smo-node:0.0.5`, `latest`, `sha-<commit>` tags | C7.2 | `[ ] OPEN` | 0051:35, 0050:72 |
| C7.4 Runtime test: `docker run --rm ghcr.io/smoframework/smo-node:0.0.5 smo-node --version` | C7.3 | `[ ] OPEN` | 0045:244 |
| C7.5 Docker Compose for 3-node mesh (dev/test): smo-node + OpenVPN client | C7.1 | `[ ] OPEN` | 0045:130 |

### C5 — Benchmarks CI Gates

| Task | Depends | Status | Source |
|------|---------|--------|--------|
| C5.1 CI benchmark harness: Google Benchmark + Catch2 integration in `bench/` | N8 harness (0042:278) | `[ ] OPEN` | 0051:33, 0042:278 |
| C5.2 TCP session benchmark: 5000 concurrent sessions, measure latency/p99 | C5.1 | `[ ] OPEN` | 0051:33, 0042:280 |
| C5.3 UDP target benchmark: 2000 concurrent UDP hole-punch targets | C5.1 | `[ ] OPEN` | 0051:33, 0042:281 |
| C5.4 Gossip throughput: 1000 msg/s sustained, measure CPU/mem | C5.1 | `[ ] OPEN` | 0051:33, 0042:282 |
| C5.5 Anti-entropy benchmark: 10k nodes, Merkle sync < 30s | C5.1 | `[ ] OPEN` | 0051:33, 0042:283 |
| C5.6 Regression gates in CI: fail if any benchmark regresses >10% vs baseline | C5.1-C5.5 | `[ ] OPEN` | 0051:33, 0042:283 |
| C5.7 Benchmark artifact upload: JSON results to GH Actions summary | C5.6 | `[ ] OPEN` | 0051:89 |

### C8 — Shamir SSS Recovery (RFC 0006 §14)

| Task | Depends | Status | Source |
|------|---------|--------|--------|
| C8.1 M-of-N threshold secret sharing: `shamir_split(secret, N, M)` → shares, `shamir_recover(shares[M])` → secret | Recovery crypto done (Argon2id + AES-256-GCM) | `[ ] OPEN` | 0051:36, 0046:84, 0046:617 |
| C8.2 Versioned recovery format: `RecoveryPackage v2` with `shamir_shares[]`, `threshold`, `version`, `kdf_params` | C8.1 | `[ ] OPEN` | 0051:36, 0046:784 |
| C8.3 CLI: `smo recovery split --threshold M --shares N --output recovery.pkg` | C8.2 | `[ ] OPEN` | 0051:36, 0046:84 |
| C8.4 CLI: `smo recovery combine --input share1.pkg share2.pkg ... --output root.key` | C8.2 | `[ ] OPEN` | 0051:36, 0046:617 |
| C8.5 Unit tests: round-trip split/recover, wrong threshold fails, tampered share fails | C8.1-C8.4 | `[ ] OPEN` | 0046:84 |
| C8.6 Integration test: authority node recovery from M-of-N shares after disaster | C8.5 | `[ ] OPEN` | 0046:784 |

---

## 4. Dependency Graph

```
                    ┌─────────────┐
                    │  v0.0.4     │
                    │  Complete   │
                    └──────┬──────┘
                           │
        ┌──────────────────┼──────────────────┐
        ▼                  ▼                  ▼
   ┌─────────┐       ┌─────────┐       ┌─────────┐
   │   C1    │       │   C6    │       │   C7    │
   │Observab.│       │   RPM   │       │ Docker  │
   └────┬────┘       └────┬────┘       └────┬────┘
        │                 │                 │
        │ uses v0.0.4     │ independent     │ independent
        │ metrics         │                 │
        ▼                 ▼                 ▼
   ┌─────────────────────────────────────────┐
   │            C5 Benchmarks CI             │
   │         (uses N8 harness)               │
   └────────────────────┬────────────────────┘
                        │
                        ▼
               ┌─────────────────┐
               │   C8 Shamir SSS │
               │ (uses existing  │
               │  crypto stack)  │
               └─────────────────┘
```

- **C6/C7**: Independent, can run in parallel
- **C1**: Uses v0.0.4 metrics instrumentation (already in codebase)
- **C5**: Uses N8 benchmark harness from v0.0.2 (0042:278)
- **C8**: Uses existing Argon2id + AES-256-GCM from recovery stack

---

## 5. Success Criteria (from 0045 §8 + Packaging)

```
[ ] DEB + RPM + Docker image published to GHCR/COPR
[ ] 25/25 ctest PASS (unit + integration)
[ ] PCT 26/26 PASS (protocol compliance tests)
[ ] CI green: build, test, benchmark, publish all pass
[ ] Prometheus /metrics endpoint exposes: gossip, sessions, contracts, NAT, anti-entropy
[ ] Grafana dashboards importable, show real-time mesh state
[ ] OpenTelemetry traces exportable to Jaeger/Tempo
[ ] smo-web UI stub loads, displays mesh topology + node health
[ ] Shamir SSS test: split 5-of-3, recover with 3 shares → PASS
[ ] Benchmarks: 5000 TCP, 2000 UDP, 1000 msg/s, 10k anti-entropy <30s — all within 10% of baseline
[ ] RPM install test: dnf install on Fedora 39/40 → smo-node runs
[ ] Docker test: docker run ghcr.io/smoframework/smo-node:0.0.5 → runs
[ ] clang-tidy: zero errors
```

---

## 6. Do-Not-Mix: Explicitly Out of Scope for v0.0.5

| Item | Reason | Target |
|------|--------|--------|
| **Full ICE + TURN (RFC 8445/8656)** | Requires libp2p/Pion or major custom impl; ICE-Lite sufficient | v0.0.7 |
| **Mesh Federation (Cross-Mesh Routing)** | Depends on Full ICE; complex governance; premature | v0.0.7 |
| **SMIR → WASM SDK** | Depends on RuntimeServices (R1), ContractManager (R4), PolicyEngine (R2) — all pending | v0.0.8 |
| **RFC Compliance Cleanup (Opcode Registry, Storage Schema, Serialization Pipeline)** | Important but not blocking v0.0.5 goals | v0.0.6 |
| **Full SWIM Gossip (RFC 0015 Stage 5)** | Current gossip sufficient for v0.0.5 scale | v0.0.6 |
| **Full TrustEngine (RFC 0017 Stage 5)** | Binary trust sufficient for MVP | v0.0.6 |
| **EventBus + ActionExecutor (RFC 0044)** | Distributed runtime semantics; depends on RuntimeKernel async | v0.0.8 |
| **QR Code / HTTP Enrollment (RFC 0007)** | Nice-to-have; not blocking production | v0.1+ |

---

## 7. Sprint Breakdown (Estimated 19 Engineering Days)

| Sprint | Focus | Items | Effort |
|--------|-------|-------|--------|
| **S1** | Observability Core | C1.1, C1.2, C1.4 (metrics + tracing) | 5 days |
| **S2** | Observability UI + Packaging | C1.3, C1.5, C6.1, C6.2, C7.1 | 5 days |
| **S3** | Packaging Publish + Benchmarks | C6.3, C6.4, C7.2, C7.3, C7.4, C5.1, C5.2 | 5 days |
| **S4** | Benchmarks Gates + Shamir SSS | C5.3-C5.7, C8.1-C8.6 | 4 days |

**Total:** ~19 engineering days

---

## 8. Progress Tracking

| Sprint | Task | Trạng thái | File |
|--------|------|-----------|------|
| **S1** | Prometheus `/metrics` endpoint on admin port | `[x] DONE` | `cmd/smo-node/main.cpp` |
| **S1** | Core path instrumentation (gossip, anti-entropy, session, exec, NAT) | `[x] DONE` | `src/mesh/`, `src/runtime/` |
| **S1** | OpenTelemetry tracing + OTLP exporter | `[x] DONE` | `src/observability/` |
| **S2** | Grafana dashboard JSON (mesh, NAT, gossip, sessions, contracts) | `[ ] OPEN` | `docs/grafana/` |
| **S2** | smo-web UI stub (React + Vite) | `[ ] OPEN` | `web/` |
| **S2** | CPack RPM generator config | `[ ] OPEN` | `CMakeLists.txt`, `CPackRpm.cmake` |
| **S2** | RPM spec file + systemd unit | `[ ] OPEN` | `packaging/rpm/smo.spec` |
| **S2** | Multi-stage Dockerfile (build + distroless runtime) | `[ ] OPEN` | `Dockerfile` |
| **S3** | CI publish: RPM to COPR, Docker to GHCR | `[ ] OPEN` | `.github/workflows/publish.yml` |
| **S3** | RPM/Docker install verification tests | `[ ] OPEN` | `.github/workflows/test-pkg.yml` |
| **S3** | Benchmark harness integration (Google Benchmark + Catch2) | `[ ] OPEN` | `bench/` |
| **S3** | TCP 5k sessions benchmark | `[ ] OPEN` | `bench/tcp_sessions.cpp` |
| **S4** | UDP 2k targets + Gossip 1k msg/s + Anti-entropy 10k <30s benchmarks | `[ ] OPEN` | `bench/` |
| **S4** | Regression gates in CI (10% threshold) | `[ ] OPEN` | `.github/workflows/benchmark.yml` |
| **S4** | Shamir SSS split/recover core | `[ ] OPEN` | `src/crypto/shamir.cpp` |
| **S4** | Versioned RecoveryPackage v2 format | `[ ] OPEN` | `src/crypto/recovery.cpp` |
| **S4** | CLI: `smo recovery split/combine` | `[ ] OPEN` | `cmd/smo-cli/recovery_commands.cpp` |
| **S4** | Shamir unit + integration tests | `[ ] OPEN` | `tests/crypto/shamir_test.cpp` |

---

## 9. Footer

**Baselined from:**
- DISCUSSION_0051 (Research Report — v0.0.5 candidates + gap analysis)
- DISCUSSION_0042 N10 (deferred items: Full ICE, Federation, WASM SDK, Benchmarks CI)
- DISCUSSION_0045 (v0.0.3 Implementation Plan — philosophy, success criteria §8, packaging track)
- DISCUSSION_0046 (RFC Compliance Audit — Phase 5 items, Shamir SSS RFC 0006 §14)
- DISCUSSION_0050 (v0.0.4 NAT Traversal Plan — N1-N5 complete, packaging pending)

**Version Roadmap Context:**
```
v0.0.1       Protocol
v0.0.2       Production runtime foundation (LAN/VPN)
v0.0.3       Real deployment verification (3-node VPN mesh) ✅ DONE
v0.0.4       Network capability: STUN, hole punch, relay, ICE-Lite ✅ DONE
v0.0.5       **Observability + Packaging + Benchmarks + Recovery SSS** ← THIS PLAN
v0.0.6       Runtime wiring (R1-R5, G1-G10) + RFC compliance cleanup
v0.0.7       Full ICE + TURN + Mesh Federation
v0.0.8       SMIR → WASM SDK + Distributed Runtime (EventBus, NextAction)
v0.1         Stable platform
```

---

**End of Implementation Plan** — Ready for sprint execution.