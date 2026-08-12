# DISCUSSION 0045 — v0.0.3 Implementation Plan: Real Deployment Verification

**Status:** Planning → Implementation  
**Target:** v0.0.3  
**Supersedes:** DISCUSSION_0042

---

## 1. Triết Lý: v0.0.3 Không Phải Feature Sprint

v0.0.3 không thêm network feature (STUN, ICE, relay, hole punch).

v0.0.3 là **Real Deployment Verification**:

> SMO chạy được thật trên 3 máy chưa?

Nếu coi timeline:

```
v0.0.1      → Protocol
v0.0.2      → Production runtime foundation
v0.0.3      → Real deployment verification
v0.0.4      → Network capability (STUN/ICE/NAT/Relay)
v0.0.5      → Observability (Prometheus, Grafana, Tracing)
v0.1        → Stable platform
```

---

## 2. Topology Mục Tiêu

```
Cloud VPS (public IP)
  │
  OpenVPN (10.8.0.0/24)
  │
  ┌───────────────┐
  │               │
Local A        Local B
(worker)       (worker)
```

3 máy thật. OpenVPN tạo L3 network. Cloud: `10.8.0.1`, Local A: `10.8.0.2`, Local B: `10.8.0.3`.

SMO chỉ thấy `10.8.0.x` — không cần NAT traversal.

Mục tiêu: verify toàn bộ protocol stack trên máy thật.

---

## 3. Sprint Plan (4 Sprint)

### Sprint A — Mesh Bring-up

*Mục tiêu: 3 node join cùng mesh, heartbeat, gossip, anti-entropy sync.*

- [ ] A.1 Deploy cloud VPS (DigitalOcean / Hetzner / AWS) — Ubuntu 22.04
- [ ] A.2 WireGuard setup: hub (cloud) + 2 peers (local)
- [ ] A.3 Build SMO từ source trên cloud (hoặc copy binary)
- [ ] A.4 `smo create` trên cloud → authority node
- [ ] A.5 `smo join` trên local A → join mesh
- [ ] A.6 `smo join` trên local B → join mesh
- [ ] A.7 Verify heartbeat giữa 3 node (Ping/Pong)
- [ ] A.8 Verify gossip propagation (membership table đồng bộ)
- [ ] A.9 Verify anti-entropy sync (Merkle tree + version vector)
- [ ] A.10 Verify bootstrap snapshot (node mới join nhận snapshot)
- [ ] A.11 `smo mesh status` — 3/3 online

**Pass criteria:** 3 node cùng mesh, heartbeat/gossip/anti-entropy hoạt động.

---

### Sprint B — Operations

*Mục tiêu: exec, deploy, governance, audit, history chạy trên 3 node.*

- [ ] B.1 `smo exec` — contract chạy trên worker
- [ ] B.2 `smo deploy` — deploy contract từ CLI
- [ ] B.3 `smo undeploy` — undeploy contract
- [ ] B.4 Governance: proposal → vote → commit (M-of-N)
- [ ] B.5 Audit log: exec history trên mỗi node
- [ ] B.6 Storage: session/node/DAG/policy store — query được
- [ ] B.7 Session lifecycle: open → contract → close
- [ ] B.8 Trust score exchange giữa các node

**Pass criteria:** toàn bộ operation workflow chạy được.

---

### Sprint C — Chaos Testing

*Mục tiêu: verify failover, recovery, split-brain.*

| Test | Steps | Expected |
|------|-------|----------|
| C.1 Kill authority | kill cloud smo-node | Worker detect DEGRADED, gossip converge |
| C.2 Restart authority | restart cloud smo-node | Worker re-join, state sync |
| C.3 Kill worker A | kill local A smo-node | Cloud + B detect OFFLINE |
| C.4 Restart worker A | restart local A | Anti-entropy sync, contract migrate |
| C.5 Network partition | iptables DROP cloud ↔ local A (60s) | Gossip converge sau rejoin |
| C.6 Split-brain | A \| B,C (60s) | Merge via anti-entropy |
| C.7 Epoch change | governance proposal bump epoch | All node accept new epoch |
| C.8 Recovery | Hard recovery từ RecoveryPackage | Node restore state |
| C.9 Concurrency | 3 node đồng thời deploy contract | No conflict, all consistent |

**Pass criteria:** tất cả chaos scenario pass, không mất dữ liệu.

---

### Sprint D — Packaging & Documentation

*Mục tiêu: dễ dàng triển khai trên máy mới.*

- [x] D.1 `scripts/deploy-cloud.sh` — one-command deploy lên VPS
- [x] D.2 `scripts/deploy-local.sh` — one-command deploy trên local
- [x] D.3 `scripts/deploy.sh` — entry point (auto-detect cloud/local)
- [x] D.4 `scripts/smo-node.service` — systemd unit
- [x] D.5 `scripts/setup-openvpn-pki.sh` — OpenVPN cert generator (openssl-based)
- [x] D.6 `scripts/openvpn/server.conf` — OpenVPN server config
- [x] D.7 `scripts/openvpn/client.conf` — OpenVPN client config template
- [x] D.8 `scripts/chaos-test.sh` — chaos test suite (C.1–C.4)
- [ ] D.9 DEB package (đã có từ v0.0.2, cần update)
- [ ] D.10 RPM package cho Fedora/RHEL
- [ ] D.11 `docs/DEPLOYMENT_GUIDE.md` — 3/5/10/20/100 node

**Pass criteria:** máy mới → `apt install ./smo.deb && smo-node --init --join` → trong mesh 5 phút.

---

## 4. Deployment Guide (Sprint D Output)

Đây là output có giá trị nhất của v0.0.3:

```
DEPLOYMENT_GUIDE.md

1. Prerequisites
   - Cloud VPS (2GB RAM, Ubuntu 22.04)
   - 2 local machines (Linux)
   - WireGuard installed

2. 3-Node Topology
   - Step-by-step: VPS → WireGuard hub → local peers
   - build/install SMO
   - smo create / smo join
   - Verification checklist

3. 5-Node Topology
   - Extend from 3-node
   - Multi-worker setup

4. 10-Node Topology
   - Subnet segmentation
   - Gossip tuning

5. 20-Node Topology
   - Scaling considerations

6. 100-Node Topology
   - Theoretical limits
   - Benchmark expectations

7. Failure Scenarios
   - What to do when...
   - Recovery procedures

8. Operations Checklist
   - Daily ops
   - Backup
   - Upgrade
```

---

## 5. So Sánh: Approach Cũ vs Mới

| Khía cạnh | Cũ (bản merge) | Mới (sau review) |
|-----------|---------------|-------------------|
| Focus | Thêm STUN/ICE/relay | Verify deployment thật |
| Sprint 0 | WAN test harness | Mesh bring-up (Sprint A) |
| Sprint 1 | STUN client | Operations (Sprint B) |
| Sprint cuối | Packaging + Release | Chaos Testing (Sprint C) |
| Giá trị output | Code mới | Deployment Guide |
| Rủi ro | Phình scope, chưa verify core | Core verified trước |
| STUN/ICE | v0.0.3 | v0.0.4 |

---

## 6. Roadmap Mới (After Review)

```
v0.0.1       Protocol
v0.0.2       Production runtime
v0.0.3       Real deployment verification (3-5 máy thật)
               ├── Sprint A: Mesh bring-up
               ├── Sprint B: Operations
               ├── Sprint C: Chaos testing
               └── Sprint D: Packaging + Deployment Guide

v0.0.4       Network capability
               ├── STUN client + mapped address
               ├── UDP hole punch
               ├── ICE Lite (host → STUN → relay)
               └── Relay forward-only

v0.0.5       Observability
               ├── Prometheus metrics
               ├── Grafana dashboards
               ├── Distributed tracing
               └── smo-web UI

v0.1         Stable platform
```

---

## 7. Effort Estimate

| Sprint | Nội dung | Effort |
|--------|----------|--------|
| A | Mesh bring-up | 5 ngày |
| B | Operations | 4 ngày |
| C | Chaos testing | 5 ngày |
| D | Packaging + Deployment Guide | 3 ngày |

**Total:** ~17 engineering days

---

## 8. Success Criteria

```
[ ] 3 máy thật (1 cloud + 2 local) join cùng mesh
[ ] heartbeat, gossip, anti-entropy sync hoạt động
[ ] smo exec chạy contract trên worker
[ ] smo deploy / undeploy workflow
[ ] Governance: proposal → vote → commit
[ ] Audit log: lịch sử exec trên mỗi node
[ ] Chaos: kill authority → DEGRADED → restart → sync
[ ] Chaos: kill worker → OFFLINE → restart → anti-entropy
[ ] Chaos: network partition 60s → rejoin → converge
[ ] Chaos: split-brain → merge via anti-entropy
[ ] Chaos: epoch change → all node accept
[ ] DEB, RPM, Docker image
[ ] systemd unit cho smo-node
[ ] scripts/deploy-cloud.sh + scripts/deploy-local.sh
[ ] DEPLOYMENT_GUIDE.md cho 3/5/10/20/100 node
[ ] 24 PCT tests vẫn green
[ ] clang-tidy: zero errors
```

---

## 9. So sánh với v0.0.3 cũ (DISCUSSION_0042)

DISCUSSION_0042 đề xuất: STUN, ICE, hole punch, relay, WAN harness.

DISCUSSION_0045 (bản này) thay bằng: deploy thật, chaos, operations, deployment guide.

Lý do: STUN/ICE là feature mới — nên để v0.0.4. v0.0.3 là verify core đã ổn định trên máy thật trước khi mở rộng network capability.

---

## 10. Progress Tracking

| Sprint | Task | Trạng thái | File |
|--------|------|-----------|------|
| **A** | 3-node mesh bring-up (genesis → publish → init-authority → 3 daemons) | ✅ Done | `/tmp/opencode/e2e-full.sh` |
| **A** | Member daemon PQ-secured seed bootstrap | ✅ Fixed | `cmd/smo-node/main.cpp:1083` |
| **A** | Authority WelcomeMsg returns seed identity | ✅ Fixed | `cmd/smo-node/main.cpp:1746` |
| **A** | Mesh publish preserves GenesisManifest fields | ✅ Fixed | `cmd/smo-admin/main.cpp:1036` |
| **B** | Fix: `smo` CLI crash khi SMO_DATA_DIR unset | ✅ Fixed | `cmd/smo/main.cpp:12` |
| **B** | Fix: `smo mesh publish` calls `smo-admin` via PATH | ✅ Fixed (sibling binary) | `cmd/smo-cli/cli_application.cpp:1016` |
| **B** | Fix: Genesis crypto placeholder → real suite3 PQC | ✅ Fixed | `cmd/smo-cli/cli_application.cpp:1121` |
| **B** | Fix: `trace` parser mapped to History instead of Trace | ✅ Fixed | `cmd/smo-cli/intent_parser.cpp:93` |
| **B** | Operations CLI functional test coverage | ✅ Done (47 PASS) | `/tmp/opencode/e2e-full.sh` |
| **C** | Chaos test suite | ✅ Done | `scripts/chaos-test.sh` |
| **D** | OpenVPN server config | ✅ Done | `scripts/openvpn/server.conf` |
| **D** | OpenVPN client config | ✅ Done | `scripts/openvpn/client.conf` |
| **D** | OpenVPN PKI generator | ✅ Done | `scripts/setup-openvpn-pki.sh` |
| **D** | Cloud deploy script | ✅ Done | `scripts/deploy-cloud.sh` |
| **D** | Local deploy script | ✅ Done | `scripts/deploy-local.sh` |
| **D** | Deploy entry point | ✅ Done | `scripts/deploy.sh` |
| **D** | Systemd service | ✅ Done | `scripts/smo-node.service` |
| **D** | Deployment Guide | ✅ Done | `docs/DEPLOYMENT_GUIDE.md` |
| **D** | RPM package | ❌ Pending | |
| **D** | Docker image | ❌ Pending | |

### v0.0.3 Known Issues (updated 2026-08-12)

| # | Issue | Ảnh hưởng | Status |
|---|-------|-----------|--------|
| BUG-001 | `smo` CLI crash: `getenv("SMO_DATA_DIR")` returns nullptr | Mọi lệnh `smo ...` crash khi ko có SMO_DATA_DIR | ✅ Fixed |
| BUG-002 | `smo genesis create` dùng crypto provider placeholder → recovery.pkg rỗng | `generate-invite` fail: *"recovery package has no encrypted keypair"* | ✅ Fixed (suite3 PQC) |
| BUG-003 | Genesis join codes `SMO-BOOT-<name>-000` chỉ là slot index, ko có mã thật | UI misleading — in code ko dùng được | ✅ Fixed (real SMO-JOIN- tokens) |
| BUG-004 | `smo mesh --publish` shell-out `smo-admin` binary → "not found" nếu ko trong PATH | Publish fail từ `smo` CLI | ✅ Fixed (sibling binary lookup) |
| BUG-005 | Member daemon seed bootstrap dùng raw TCP → block authority PQ handshake | 3-node E2E fail: node-c join refused | ✅ Fixed (PQ client handshake) |
| BUG-006 | `mesh publish` ghi đè mesh.json mất `root_public_key` | `genesis status` / `mesh health` fail | ✅ Fixed (preserve manifest fields) |
| BUG-007 | `trace` parser map sang IntentType::History | `smo trace abc` in ra history | ✅ Fixed (map to Trace) |
| GAP-001–012 | 12 features documented nhưng stub `(not yet implemented)` | Sprint B Operations / Sprint C Observability | ❌ OPEN (see RFC 0032 gap report) |

### File map

```
scripts/
├── deploy.sh                  ← Entry point: bash deploy.sh cloud|local
├── deploy-cloud.sh            ← Cloud VPS setup (OpenVPN + SMO auth)
├── deploy-local.sh            ← Local machine setup (OpenVPN client + SMO worker)
├── smo-node.service           ← Systemd unit
├── setup-openvpn-pki.sh       ← PKI generator (openssl, không cần easy-rsa)
├── chaos-test.sh              ← Chaos test suite (destroy + verify)
└── openvpn/
    ├── server.conf            ← OpenVPN server config (cloud)
    └── client.conf            ← OpenVPN client template
```
