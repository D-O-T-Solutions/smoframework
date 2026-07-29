# DISCUSSION 0045 — v0.0.3: 3-Node Mesh Scenario (1 Cloud + 2 Local via VPN)

**Status:** Planning  
**Target:** v0.0.3  
**Parent:** DISCUSSION_0041, DISCUSSION_0042, DISCUSSION_0044

---

## 1. Problems Encountered During v0.0.2

### 1.1 Build System & Toolchain

| Issue | Category | Root Cause | Fix |
|-------|----------|------------|-----|
| clang-tidy `clang-diagnostic-error` ~30+ errors | Code | Move ctor/assign with incomplete pimpl, const-ref output iterators, Result deref, std::find type mismatch | Fix in DISCUSSION_0044 |
| `runtime/` not in CMake | Build topology | Root CMakeLists.txt didn't `add_subdirectory(runtime)` | Added |
| `cmd/smo/` not in build | Build topology | Same — orphaned dir | Added + shared CLIApplication |
| `yaml-cpp` include missing | CMake deps | `workflow_contracts.cpp` not in build (untracked) | Excluded from CI scan |
| `gtest/gtest.h` not found | CMake deps | `test_runtime.cpp` not in build (untracked) | Excluded from CI scan |
| `<chrono>` consteval error | Toolchain | GCC 13 libstdc++ + clang-14 incompatibility | Known, CI uses GCC 12 — unaffected |
| `nlohmann/json.hpp` missing | Dependency | `workflow_contracts.cpp` requires nlohmann-json | File excluded from build, needs dependency setup |

### 1.2 Key Lesson

> **3 categories of "error" found in CI:**
> - **A — Code bug** (logic error, UB, type mismatch) → must fix
> - **B — Build topology** (CMake orphan, missing add_subdirectory) → must integrate
> - **C — Toolchain** (compiler version incompatibility, missing 3rd-party) → document, suppress, or add dependency

Distinguishing these saves enormous time. Treating a toolchain false positive as a code bug leads to wild goose chases.

---

## 2. What v0.0.2 Delivers

### 2.1 Feature Inventory

```
Protocol:      PCT-001–022, 024 ✅  (24/24 protocol compliance tests)
Crypto:        Suite1 classical (Ed25519/X25519/BLAKE3)
               Suite2 modern  (Monocypher)
               Suite3 PQC    (ML-DSA-65, ML-KEM-768 via liboqs)
               AEAD: XChaCha20-Poly1305, AES-256-GCM
Transport:     TCP + TLS, QUIC (experimental), Relay
Mesh:          Create, join, list, publish, serve, invite, health, leave
CLI:           smo / smo-cli — REPL shell, exec, deploy, select, context, governance
Admin:         smo-admin — create-mesh, sign CSR, enroll server
Node:          smo-node — daemon, runtime, dispatcher, policy engine
Storage:       SQLite3-backed audit store, policy store, DAG store, node store
Runtime:       Scheduler, executor, worker pool, FSM, sandbox, audit, recovery
Governance:    Proposal engine, quorum tiers (membership/constitution/unanimous)
Genesis:       Bootstrap wizard, manifest, recovery package, slot ring
Recovery:      Soft/hard recovery engine, epoch management, passphrase
```

### 2.2 Packages

```
smo_0.0.2_amd64.deb      (69 MB) — Debian/Ubuntu install
smo-0.0.2-x86_64.tar.gz  (69 MB) — portable tarball
```

### 2.3 Binaries

| Binary | Role |
|--------|------|
| `smo` | End-user CLI (REPL + command mode) |
| `smo-cli` | Identical to `smo` (shared source) |
| `smo-admin` | Mesh administration (create, certify, enroll) |
| `smo-node` | Node daemon (runtime, transport, contracts) |

---

## 3. v0.0.3 Vision: 3-Node Mesh (1 Cloud + 2 Local via VPN)

### 3.1 Topology

```
                    ┌──────────────┐
                    │  Cloud Node   │
                    │  203.0.113.10 │
                    │  smo-node     │
                    │  (authority)  │
                    └──────┬───────┘
                           │ WireGuard VPN
                    ┌──────┴───────┐
                    │              │
           ┌────────┴───┐   ┌─────┴────────┐
           │ Local A     │   │ Local B       │
           │ 10.0.0.2    │   │ 10.0.0.3      │
           │ smo-node    │   │ smo-node      │
           │ (worker)    │   │ (worker)      │
           └─────────────┘   └──────────────┘
```

### 3.2 Full Scenario (Kịch bản hoàn chỉnh)

#### Phase 0 — Prerequisites

- 3 machines with Ubuntu 22.04+
- WireGuard VPN configured (cloud as hub, locals as peers)
- `smo_0.0.2_amd64.deb` installed on all 3
- Port 5454 (or custom) open on cloud firewall

```bash
# Each machine
sudo dpkg -i smo_0.0.2_amd64.deb
```

#### Phase 1 — Cloud: Bootstrap Mesh

```bash
# Cloud node — create genesis mesh
cloud$ smo-admin --mesh production create-mesh

# Cloud node — generate join tokens for 2 authority slots
cloud$ smo mesh invite --role Authority --profile server
cloud$ smo mesh invite --role Worker --profile server

# Cloud node — start enroll server
cloud$ smo-admin --mesh production serve --port 5454
```

#### Phase 2 — Local A: Join as Authority

```bash
# Local A — install + join with authority token
local-a$ smo mesh join --token "SMO-JOIN-xxxx..."
local-a$ smo-node --mesh production --join-token "SMO-JOIN-xxxx..." &

# Verify
local-a$ smo mesh list
local-a$ smo status
```

#### Phase 3 — Local B: Join as Worker

```bash
# Local B — install + join with worker token
local-b$ smo mesh join --token "SMO-JOIN-yyyy..."
local-b$ smo-node --mesh production --worker &

# Verify cluster
local-b$ smo select --role Worker
local-b$ smo exec "uptime"        # runs on all workers
```

#### Phase 4 — Daily Operations via REPL

```bash
# Any machine — open interactive shell
$ smo

# Explore mesh
mesh list
mesh use production

# Select nodes
select --cloud-only
select --role Authority
select --os linux --arch amd64

# Execute commands
exec "uptime"
exec "df -h"
exec "systemctl status smo-node"

# Deploy contract
deploy examples/hello.wasm --policy enterprise

# Governance
governance propose --action AddWorker --tier membership
governance list
governance status
```

#### Phase 5 — Failure Scenarios

```bash
# Node goes offline
health-check: Local B unreachable
→ Auto-evacuate contracts to Local A
→ Governance initiates recovery

# Manual recovery
recovery status
recovery restore --passphrase "***"

# Force recovery (epoch bump)
recovery force --passphrase "***"  # invalidates all certs
```

### 3.3 What's Missing (v0.0.3 Gaps)

| Capability | Status | Priority |
|-----------|--------|----------|
| WireGuard auto-setup | Not implemented | P0 — needed for demo |
| `smo-node` as systemd service | Not implemented | P0 |
| `smo-node` auto-discovery via mDNS/DNS-SD | Not implemented | P1 |
| Health monitoring + auto-evacuation | Partial | P1 |
| Anti-entropy / gossip protocol | DISCUSSION_0043 epic P1 | P1 |
| Metrics dashboard (prometheus) | Not implemented | P2 |
| `smo-web` web UI | Not implemented | P2 |
| RPM package (Fedora/RHEL) | Not implemented | P2 |
| Docker image | Not implemented | P2 |
| Mesh auto-scaling (add workers dynamically) | Not implemented | P2 |
| Certificate auto-renewal | Not implemented | P2 |
| RBAC / multi-tenant | Not implemented | P3 |

### 3.4 Proposed Sprint Plan for v0.0.3

**Sprint A — Foundation (3d)**

| # | Task | Output |
|---|------|--------|
| 1 | WireGuard VPN quickstart script | `scripts/setup-vpn.sh` — hub + 2 peers |
| 2 | `smo-node` systemd unit + install | `/etc/systemd/system/smo-node.service` |
| 3 | `smo install` — one-command setup | Installs DEB, configures VPN, starts node |
| 4 | End-to-end smoke test (3 machines) | CI matrix with 3-node cluster test |

**Sprint B — Reliability (3d)**

| # | Task | Output |
|---|------|--------|
| 5 | Node health heartbeat + timeout | Configurable interval, auto-mark offline |
| 6 | Contract auto-evacuation on node loss | Migrate contracts to healthy nodes |
| 7 | Gossip membership protocol | DISCUSSION_0043 P1 — basic anti-entropy |
| 8 | `smo mesh health` — cluster dashboard | Online/offline per node, contract distribution |

**Sprint C — Polish (2d)**

| # | Task | Output |
|---|------|--------|
| 9 | Metrics endpoint (Prometheus) | `/metrics` on smo-node |
| 10 | Docker image | `smo-node:latest` multi-arch |
| 11 | RPM package | `.rpm` for Fedora/RHEL |
| 12 | Documentation | 3-node walkthrough in README |

---

## 4. Quick Demo Script (1 Cloud + 2 Local)

```bash
# ===== CLOUD =====
sudo dpkg -i smo_0.0.2_amd64.deb
smo-admin --mesh demo create-mesh
smo mesh invite --role Authority > /tmp/token-auth.txt
smo mesh invite --role Worker   > /tmp/token-worker.txt
smo-admin --mesh demo serve &

# ===== LOCAL A =====
sudo dpkg -i smo_0.0.2_amd64.deb
smo mesh join --token "$(cat /tmp/token-auth.txt)"
smo-node --mesh demo &

# ===== LOCAL B =====
sudo dpkg -i smo_0.0.2_amd64.deb
smo mesh join --token "$(cat /tmp/token-worker.txt)"
smo-node --mesh demo &

# ===== VERIFY =====
smo mesh list
smo select --role Worker
smo exec "hostname"
smo governance status
```

---

## 5. Success Criteria for v0.0.3

```
[ ] 3-machine mesh up and running via script
[ ] smo-node as systemd service on all 3
[ ] WireGuard VPN set up automatically
[ ] All 24 PCT tests still green
[ ] clang-tidy: zero errors
[ ] DEB + RPM + Docker packages published
[ ] E2E test: deploy contract → exec → undeploy across 3 nodes
[ ] Failure test: kill one node → contracts migrate → auto-recover
```
