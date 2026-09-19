# DISCUSSION_0049 — Post-Refactor Modularization Audit (God Object Sweep)

**Status:** Audit — In Progress
**Target:** Verify every module boundary after the refactor wave; confirm NO component regressed into a God Object; freeze remaining phase checklist
**Depends on:** DISCUSSION_0048 (PQ handshake debug), GOD_OBJECT_CLEANUP_PLAN.md (15-phase migration)
**Date:** 2026-09-19
**Baseline commit:** `5fb9f16` (fix: canonical mesh_id for authority AAD + seed bootstrap client identity)

---

## 1. Problem Statement

After multiple refactor waves (G3 packet auth P1–P8, connection/bootstrap/network decomposition,
gossip membership events, UDP discovery handler, heartbeat sender-id correlation), the previous
checklist marked **Phase 1–5/14 as `[✓]` (Done)**.

This audit re-checks those marks against the **actual working tree**. Ground truth (line counts,
file existence, inline logic) was verified directly from source — not from memory.

**Headline finding:** the `[✓]` marks for Phase 1, 2, 3, 5 and 14 were **premature**. `main.cpp`
is still **2,383 lines** and still performs the daemon-kernel work inline. Several supporting
classes exist (`packet_dispatcher`, `bootstrap_client`, `raw_protocol_handler`, typed transport),
but the composition root (`NodeRuntime`), `ConnectionManager`, and `UdpServer` **do not exist**.

---

## 2. Ground-Truth Inventory (verified 2026-09-19)

### 2.1 `cmd/smo-node/main.cpp` — 2,383 lines

Committed sections found inline (line numbers from `git show 5fb9f16` / working tree):

| Region | Lines | Responsibility |
|---|---|---|
| Vault set up | 67–482 | Identity / cert / authority loading |
| SecureTransportSession wrapper | 651–680 | Adapter: `SecureSession` → `TransportSession` |
| Arg parse + mode dispatch | 681–871 | CLI flags (bootstrap, listen, join, ...) |
| Structured Logger | 872–937 | Logger init |
| UDP Transport §5.20 | 938–1026 | `udp_transport->listen`, discovery engine wiring |
| Bootstrap summary | 1027–1138 | Peer records, HelloMsg answers |
| **Seed bootstrap (inline)** | 1139–1233 | `tcp->connect` + `release_fd` + `SecureSession` + PQ handshake (+ WELCOME). **Does NOT use `BootstrapClient` class** |
| Runtime components | 1234–1374 | EventBus, discovery, decision engine, gossip, session mgr, health monitor |
| SyncService | 1375–1543 | `SyncService` + `MembershipSync` wiring (lambdas inline) |
| Contract registration | 1544–1665 | 12+ `register_contract` calls inline |
| RuntimeBridge | 1666–1810 | opcode → contract (THIN) |
| NodeLifecycleFSM | 1811–1826 | FSM exists, but lifecycle owned by main |
| PacketDispatcher setup | 1827–1852 | `dispatcher.register_handler` × ~20 inline |
| **Raw protocol dispatch** | 1853–2054 | Try-join-first raw CBOR handler, HelloMsg/PingMsg/WelcomeMsg/GOSP inline |
| EventBus wiring | 2055–2108 | manual subscribe calls |
| Service registry | 2109–2139 | manual register |
| Telemetry | 2140–2268 | `telemetry.tick` inline in main loop |
| **Main loop** | 2140–2363 | `while(true)` — poll, anti-entropy, readiness, UDP read+dispatch, PeerStore sync, TCP accept+PQ handshake+`dispatcher.dispatch_packet_session` |
| Shutdown | 2365–2383 | manual teardown |

### 2.2 Components that DO exist (real, compiled)

- `core/bootstrap/bootstrap_client.{hpp,cpp}` — exists (101+45 lines) but **not referenced by main** (main still inlines seed connect at 1139–1233)
- `core/network/packet_dispatcher.{hpp,cpp}` — exists; called from main accept loop (`dispatch_packet_session`)
- `core/network/raw_protocol_handler.hpp` — exists (108 lines)
- `core/transport/framing.{hpp,cpp}` — `ConnectionType` enum + version handshake
- `core/network/udp/udp_transport.{hpp,cpp}` — UDP transport
- `core/network/tcp/{connector,listener,session}.hpp` — typed TCP abstractions
- `core/network/sync/membership_sync.{hpp,cpp}` — rich gossip membership events

### 2.3 Components that DO NOT exist (Phase gap)

| Phase | Component | State |
|---|---|---|
| Phase 1 | `core/runtime/node_runtime.{hpp,cpp}` | **MISSING** — no composition root |
| Phase 2 | `core/network/connection_manager.{hpp,cpp}` | **MISSING** — accept loop still in main |
| Phase 3 | `core/network/udp_server.{hpp,cpp}` | **MISSING** — UDP read loop still in main |
| Phase 4 | `BootstrapClient` USED by main | **NOT wired** — class orphaned |
| Phase 5 | Raw protocol dispatch removal | **NOT done** — raw handler at 1853+ inline |

---

## 3. What This Means (architecture verdict)

The architecture is **not dead** — this is the healthy direction: 80% of runtime work still runs
through `core/` APIs (packet_dispatcher, typed transport, sync/gossip/heartbeat engines). But main
is **not a thin orchestrator yet**; it is a **daemon kernel** that wires and drives everything.

**Main is not a God Object "rename trap" problem.** It is the expected end-state of a prototype
that has grown helpers, but has not yet extracted its top-level Composition Root /
ConnectionManager / UdpServer. The refactor was **directionally correct**; the `[✓]` marks were
wrong.

---

## 4. Corrected Phase Checklist

### 4.1 Status confirma

| Phase | Content | Verified status | Evidence |
|---|---|---|---|
| P0 | Freeze baseline | ⚠️ NOT frozen | pre-5fb9f16 rebuild not re-verified; 3-node not yet re-run |
| P1 | NodeRuntime | ❌ not done | `node_runtime.hpp` missing |
| P2 | ConnectionManager | ❌ not done | accept loop `main.cpp:2297–2360` |
| P3 | UdpServer | ❌ not done | UDP loop `main.cpp:2270–2288` |
| P4 | BootstrapClient wiring | ❌ class exists, not used | main inlines seed connect `1139–1233` |
| P5 | Raw dispatch removal | ❌ not done | raw handler `1853+`; only *some* demux moved to PacketDispatcher |
| P6 | SyncService standard wiring | ❌ pending (lambdas inline 1375+) |
| P7 | Gossip standard handlers | ❌ pending |
| P8 | Mesh config cleanup | ❌ pending |
| P9 | Runtime registration cleanup | ❌ pending |
| P10 | EventBus cleanup | ❌ pending (manual subscribe 2055+) |
| P11 | Session/Identity/Cert cleanup | ❌ pending |
| P12 | Telemetry cleanup | ❌ pending (telemetry tick inline 2150+) |
| P13 | Lifecycle cleanup | ❌ pending (FSM 1811 exists but lifecyle owned by main) |
| P14 | God Object sweep, main ≤300 | ❌ main = 2,383 lines |
| P15 | Final regression | ❌ pending |

### 4.2 Decision

- **Do NOT roll back.** The extracted `core/` classes are real and used.
- **Re-baseline first:** rebuild, 25/25 ctest, 24/24 PCT, 3-node A/B/C READY — only then tag `v0.0.3-audit`.
- **Then extract in dependency order:** NodeRuntime (composition root) → ConnectionManager (accept loop) → UdpServer (UDP loop) → wire BootstrapClient → move raw dispatch into services.
- **Phase 14 gate:** `main.cpp` ≤ ~300 lines AND zero forbidden patterns (no `socket()/recvfrom()/sendto()/deserialize/dispatch/SQL/JSON inline`).

---

## 5. Related Crypto Note (MFG: unrelated to God Object)

The `ML-DSA-65/44` + `authority.sec: recovery envelope: unsupported format` issues seen around the
sessions are **crypto-layer regression**, not architecture.

- `ML-DSA-65` is the canonical algorithm (sk = 4032 B) — confirmed `core/crypto/signer/mldsa_provider.hpp` clean with HEAD.
- Mixed `liboqs.so.11` vs `so.12` between `smo-admin` and `smo-node` produces "size OK but verify fails" — check `ldd` + `OQS_VERSION` if failures persist after a **fresh mesh regeneration**.
- Stale `authority.sec` written by older code (before versioned SMO envelope) fails new loader. **Fix: regenerate mesh** (`rm -rf ~/.smo/meshes/testmesh && smo-admin mesh init ... && smo-admin sign node.csr.smor`) — do not debug crypto before that.
- `~/.smo/meshes/testmesh/meshes/testmesh` double-path suspicion: verify `mesh.json` location; pass the correct `--mesh-dir`.

Order: freeze architecture → regenerate mesh → regression run → then Phase 6+. Do not mix crypto debugging into the God Object sweep.

---

## 6. Next Actions

1. Rebuild `smo-node` / `smo-admin` from `5fb9f16`, run `25/25 ctest` + `24/24 PCT`, capture baseline log → mark P0 frozen.
2. Create `core/runtime/node_runtime.{hpp,cpp}` (composition root owns EventBus/discovery/gossip/session/telemetry/lifecycle; `initialize/start/run/shutdown`).
3. Create `core/network/connection_manager.{hpp,cpp}` — move accept loop (poll, version handshake, demux, PQ handshake, `dispatch_packet_session`) out of main.
4. Create `core/network/udp_server.{hpp,cpp}` — own UDP listener + datagram → DiscoveryEngine.
5. Wire `BootstrapClient` into node start (replace inline seed connect at `main.cpp:1139–1233`).
6. Route remaining raw CBOR paths (join/BootstrapSync/HelloMsg/PingMsg/GOSP) via PacketDispatcher → JoinService / DiscoveryEngine / GossipEngine.
7. Phase 14 gate: main ≤300 lines, forbidden-patterns grep clean.
8. Update `GOD_OBJECT_ANALYSIS_FULL.md` + this doc to reflect real inventory at each gate.

---

## 7. Files Referenced

- `cmd/smo-node/main.cpp` (2,383 lines)
- `core/bootstrap/bootstrap_client.{hpp,cpp}` (unused by main)
- `core/network/packet_dispatcher.{hpp,cpp}`
- `core/network/raw_protocol_handler.hpp`
- `core/transport/framing.{hpp,cpp}` (`ConnectionType`)
- `core/network/udp/udp_transport.{hpp,cpp}`, `core/network/tcp/*`
- `docs/architecture/GOD_OBJECT_ANALYSIS_FULL.md`
- `docs/architecture/GOD_OBJECT_CLEANUP_PLAN.md`