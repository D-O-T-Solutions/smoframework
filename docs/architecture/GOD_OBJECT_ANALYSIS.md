# God Object Analysis — `cmd/smo-node/main.cpp`

**Date:** 2026-09-18  
**Status:** Baseline established — Phase 3 runtime working, refactor begins

---

## Executive Summary

`cmd/smo-node/main.cpp` (**2,504 lines**) is a **massive God Object** handling responsibilities across 10+ subsystems. It acts as central coordinator, socket manager, protocol parser, dispatch logic, subsystem initializer, configuration parser, and event bus subscriber — all in a single translation unit.

---

## 1. Critical Networking Layer Violations (P0)

| File:Line | Responsibility | Should Be Owned By |
|-----------|---------------|-------------------|
| `main.cpp:2303-2355` | Raw `recvfrom()` + manual discovery frame parsing | `UdpTransport` / `DiscoveryEngine` |
| `main.cpp:1947-1986` | Raw handler: manual `HelloMsg::deserialize`, `PingMsg::deserialize`, `WelcomeMsg` | `DiscoveryEngine` |
| `main.cpp:1151-1255` | Seed bootstrap: raw TCP connect + PQ handshake + HELLO/WELCOME | `BootstrapOrchestrator` |
| `gossip.cpp:302-355` | `GossipEngine` uses raw `socket`/`connect`/`send` + manual version handshake | `Transport` abstraction |

---

## 2. Module Boundary Violations

| Violation | Locations | Details |
|-----------|-----------|---------|
| **Direct `fd()` access** | `main.cpp:2306`, `2394`, `1178` | Callers reach into transport internals |
| **Raw syscalls** | `gossip.cpp:302-355`, `main.cpp:2313-2314` | Bypasses `Transport` abstraction |
| **Duplicate dispatch logic** | `main.cpp:2328-2352` | Re-implements `dispatch_discovery_datagram` |

---

## 3. Other Entry Points — Same Pattern

| File | Lines | Key Issues |
|------|-------|------------|
| `cmd/smo-admin/main.cpp` | 2,200+ | Inline JSON parsing, manual crypto, `MeshAuthority` ops |
| `cmd/smo-cli/cli_application.cpp` | 2,000+ | 30+ intent handlers, `std::system()` calls |
| `core/enroll/auto_enroll.cpp` | 950 | FSM + PQ handshake + CBOR + cert verify in one function |

---

## 4. Missing Abstractions (6-8 Needed)

| Priority | Abstraction | Eliminates |
|----------|-------------|------------|
| P0 | `ConnectionManager` | JOIN/SYNC/DATA demux + PQ handshake (~200 lines) |
| P0 | `UdpDatagramHandler` in `UdpTransport` | Raw `recvfrom` in main |
| P0 | `GossipEngine` → `Transport` | Raw sockets in gossip |
| P1 | `MeshConfig` + `MeshManager::load_config()` | 4+ duplicate JSON parsers |
| P1 | `SecureSessionFactory` | 3+ manual `SecureSession::Config` constructions |
| P1 | EventBus subscriptions in contract constructors | 14 inline subscriptions |
| P2 | `BootstrapOrchestrator` | Seed bootstrap duplication |
| P2 | `CatalogStore` | Raw SQLite in main |

---

## 5. Target Architecture (Thin Coordinator ~200-400 lines)

```
main.cpp (coordinator only)
  ├── ConnectionManager (accept loop, demux, PQ handshake)
  ├── UdpTransport (UDP recv loop → DiscoveryEngine)
  ├── TransportRegistry (scheme → Transport)
  ├── SecureSessionFactory (PQ config)
  ├── MeshManager (MeshConfig, CatalogStore)
  ├── RuntimeBridge (auto-register opcode routes)
  ├── SyncService (AntiEntropy, delta providers)
  ├── GossipEngine (uses Transport, self-registers deltas)
  ├── DiscoveryEngine (UDP + TCP discovery)
  ├── HeartbeatService (driven by SyncService)
  └── BootstrapOrchestrator (seed connection)
```

---

## 6. Incremental Refactor Plan

### Phase 3.5 — Extract UDP Handling
- Create `UdpDiscoveryHandler` (✓ header/cpp done)
- Wire into build + `main.cpp`
- Replace raw `recvfrom` block with `handler.poll(now_ns)`
- Verify: 25/25 ctest + 24/24 PCT + A/B/C READY

### Phase 3.6 — Extract Connection Manager
- TCP accept + connection-type demux + PQ handshake
- Replace raw accept/dispatch in main
- Verify: same test suite

### Phase 3.7 — GossipEngine → Transport Abstraction
- Replace raw `socket`/`connect`/`send` with `Transport::connect()`
- Verify: same test suite

### Phase 4 — HelloMsg Endpoint Propagation
- After boundary clean

### Phase 5 — Heartbeat Kill/Restart Liveness
- After Phase 4

---

## 7. Key Principle

> **Do not add features to `main.cpp`.**  
> Refactor boundaries first. Each extraction must:
> 1. Reduce coupling
> 2. Keep behavior identical (all tests pass)
> 3. Move responsibility to correct subsystem

---

## 8. Current Status (Pre-Phase 3.5)

- **Runtime verified:** A/B/C READY, gossip bidirectional, `ping_misses=0`
- **Tests:** 25/25 ctest, 24/24 PCT
- **Next:** Wire `UdpDiscoveryHandler` into build + main.cpp, verify