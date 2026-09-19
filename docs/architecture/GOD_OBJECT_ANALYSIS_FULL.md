# God Object Analysis — `cmd/smo-node/main.cpp` (Complete)

**Date:** 2026-09-18  
**Status:** Phase 3 runtime working — refactor baseline established  
**Lines:** 2453  
**Target:** ~200 lines (thin coordinator)

---

## Executive Summary

`cmd/smo-node/main.cpp` (2453 lines) is a **massive God Object** handling responsibilities across 12+ subsystems. It acts as central coordinator, socket manager, protocol parser, dispatch logic, subsystem initializer, configuration parser, event bus subscriber, and telemetry manager — all in a single translation unit.

**Key finding:** 80% of violations bypass existing `core/` module APIs that already have correct interfaces.

---

## Violations by Category

### 1. Transport/Connection Handling (P0)

| File:Line | Logic in main.cpp | Should Be In Module | Module Exists? | Priority |
|-----------|-------------------|---------------------|----------------|----------|
| 2315-2429 | TCP accept loop, version handshake, connection type demux (JOIN/SYNC/DATA), PQ handshake, session dispatch | `core/transport/ConnectionManager` | ❌ Needs creation | P0 |
| 2344-2354 | `version_handshake_server()` call | `core/transport/version_handshake.hpp` | ✅ Exists in `framing.hpp` | P0 |
| 2356-2375 | JOIN connection handling (FieldTransportSession, dispatcher.dispatch_session) | `core/join/JoinService` + `core/transport/ConnectionHandler` | ✅ JoinService exists | P0 |
| 2377-2419 | SYNC/DATA: PQ handshake, SecureSession creation, dispatch | `core/transport/ConnectionManager` | ❌ Partial | P0 |
| 930-931 | TransportRegistry registration (hardcoded) | `core/transport/TransportRegistry::auto_register()` | ✅ Exists but not used | P1 |

**Details:** The entire TCP accept loop (lines 2315-2429) with version handshake, PQ handshake, and connection-type demux should be encapsulated in a `ConnectionManager` class. This logic includes:
- Accepting connections
- Running version handshake to determine connection type
- For JOIN: creating FieldTransportSession and dispatching
- For SYNC: PQ handshake + raw CBOR dispatch
- For DATA: PQ handshake + G3 packet dispatch with SessionManager

---

### 2. UDP Datagram Handling (P0)

| File:Line | Logic in main.cpp | Should Be In Module | Module Exists? | Priority |
|-----------|-------------------|---------------------|----------------|----------|
| 939-954 | UDP transport creation, listen, listener extraction | `core/network/udp/UdpServer` constructor | ✅ UdpDiscoveryHandler exists | P0 |
| 1003-1004 | UdpDiscoveryHandler construction with manual wiring | Factory method | ✅ Exists | P0 |
| 2303-2306 | Manual `udp_discovery_handler.poll()` in main loop | Internal to UdpServer | ✅ Exists | P0 |

---

### 3. Discovery Protocol Handling (P0)

| File:Line | Logic in main.cpp | Should Be In Module | Module Exists? | Priority |
|-----------|-------------------|---------------------|----------------|----------|
| 1880-1986 | Raw handler for HelloMsg/PingMsg/WelcomeMsg with manual dispatch logic | `core/discovery/DiscoveryEngine::register_raw_handler()` | ✅ Exists but not used | P0 |
| 1946-1969 | HelloMsg handling + WelcomeMsg response construction | `DiscoveryEngine::handle_hello()` already exists | ✅ Exists | P0 |
| 1971-1980 | PingMsg → PongMsg response | `DiscoveryEngine::handle_ping()` exists | ✅ Exists | P0 |
| 957-966 | DiscoveryEngine + MembershipSync wiring | Auto-wired in DiscoveryEngine constructor | ✅ Exists | P1 |

---

### 4. Seed Bootstrap (P0)

| File:Line | Logic in main.cpp | Should Be In Module | Module Exists? | Priority |
|-----------|-------------------|---------------------|----------------|----------|
| 1150-1254 | Seed bootstrap: connect, PQ handshake, HELLO send, WELCOME recv, discovery_engine.handle_welcome() | `core/bootstrap/BootstrapClient` | ❌ Needs creation | P0 |
| 1166-1176 | Raw TCP connect via tcp_ptr->connect() | Should use TransportRegistry | ✅ Exists | P0 |
| 1178-1211 | PQ handshake (client) with cert/key loading | `SecureSession` client handshake | ✅ Exists | P0 |
| 1214-1250 | HELLO/WELCOME exchange inside SecureSession | `Bootstrap::find_seed()` exists but for UDP | ✅ Partial | P0 |

---

### 5. Sync Service Delta Wiring (P0)

| File:Line | Logic in main.cpp | Should Be In Module | Module Exists? | Priority |
|-----------|-------------------|---------------------|----------------|----------|
| 1403-1519 | SyncService creation + 5 delta callbacks (CRL, Policy, Manifest, Routing, Contracts) | `SyncService::register_standard_deltas()` | ✅ SyncService exists | P0 |
| 1416-1445 | CRL delta callback with manual serialization | Single call with stores | ❌ Needs API addition | P0 |
| 1456-1485 | Policy delta callback | Same | ❌ Needs API addition | P0 |
| 1489-1519 | Manifest delta callback | Same | ❌ Needs API addition | P0 |

---

### 6. Gossip Engine Delta Wiring (P0)

| File:Line | Logic in main.cpp | Should Be In Module | Module Exists? | Priority |
|-----------|-------------------|---------------------|----------------|----------|
| 1533-1569 | GossipEngine delta handlers for Manifest, Policy with manual deserialization | `GossipEngine::register_standard_delta_handlers()` | ✅ API exists | P0 |
| 1544-1569 | Policy delta deserialization + policy_store.put() | Should be built-in | ❌ Needs API addition | P0 |

---

### 7. Contract/Opcode Registration (P1)

| File:Line | Logic in main.cpp | Should Be In Module | Module Exists? | Priority |
|-----------|-------------------|---------------------|----------------|----------|
| 1576-1637 | 10 contract registrations in runtime_dispatcher | `RuntimeRegistry::register_core_contracts()` | ❌ Needs creation | P1 |
| 1656-1691 | 18 route registrations in RuntimeBridge | `RuntimeBridge::register_core_routes()` | ❌ Needs creation | P1 |

---

### 8. EventBus Subscriptions (P1)

| File:Line | Logic in main.cpp | Should Be In Module | Module Exists? | Priority |
|-----------|-------------------|---------------------|----------------|----------|
| 1988-2126 | 15 EventBus subscriptions for RecoveryApproved, SecurityAlert, NodeDisconnected, AuditLogged, Proposal*, Recovery* | Each module self-subscribes on construction | ✅ EventBus exists | P1 |

---

### 9. Mesh Config Loading/Parsing (P1)

| File:Line | Logic in main.cpp | Should Be In Module | Module Exists? | Priority |
|-----------|-------------------|---------------------|----------------|----------|
| 1034-1143 | Manual JSON parsing of mesh.json (string find/substr) | `MeshManager::load_mesh_config()` exists | ✅ Exists but not used | P1 |
| 1284-1391 | MeshManager initialization + authority_mesh_id extraction + catalog DB SQL | `MeshManager::initialize()` + `MeshConfig` | ✅ Exists | P1 |

---

### 10. Raw Protocol Dispatch (P0)

| File:Line | Logic in main.cpp | Should Be In Module | Module Exists? | Priority |
|-----------|-------------------|---------------------|----------------|----------|
| 1880-1986 | Raw handler with join protocol + discovery protocol | `PacketDispatcher` protocol chaining | ✅ PacketDispatcher has `register_raw_handler` | P0 |
| 1896-1938 | Join protocol handling (JoinRequest, BootstrapSyncRequest) | `JoinService::handle_join_request()` exists | ✅ Exists | P0 |

---

### 11. Session Management (P1)

| File:Line | Logic in main.cpp | Should Be In Module | Module Exists? | Priority |
|-----------|-------------------|---------------------|----------------|----------|
| 1268-1281 | SessionManager creation + recover() | `SessionManager::create_with_recovery(data_dir)` | ✅ Exists | P1 |
| 1610-1637 | TrustContract wiring with TrustManager + signer lambda | `TrustContract` constructor should accept these | ✅ Exists | P1 |

---

### 12. Telemetry/Metrics (P1)

| File:Line | Logic in main.cpp | Should Be In Module | Module Exists? | Priority |
|-----------|-------------------|---------------------|----------------|----------|
| 1571-2156 | Telemetry health checks, metrics registration, Prometheus export | `Telemetry::init_daemon()` | ✅ Telemetry exists | P1 |
| 2145-2149 | Health check lambdas (all return true) | Real health checks in each module | ✅ API exists | P2 |
| 2284-2297 | Metric gauges + Prometheus file export in main loop | `Telemetry::tick()` should handle this | ✅ Exists | P1 |

---

## Additional Violations

| Category | File:Line | Logic | Module |
|----------|-----------|-------|--------|
| **Anti-Entropy** | 2175-2219 | DaemonSyncBackend + AntiEntropyService creation | `sync::AntiEntropyService` exists |
| **Identity/Cert Loading** | 869-927 | Identity, server_cert, root_pubkey loading | `Identity::load_from_file()` exists |
| **Middleware Pipeline** | 1640-1650 | PolicyMiddleware setup with anonymous routes | `MiddlewarePipeline` exists |
| **Node Lifecycle FSM** | 1838-1852 | FSM event sequence | `NodeLifecycleFSM` exists |
| **Runtime Kernel/Bridge** | 1261-1691 | RuntimeKernel, Dispatcher, Bridge, ActionExecutor wiring | All exist |

---

## Recommended Module Architecture

### New Modules Needed (P0)

| Module | Path | Responsibility |
|--------|------|----------------|
| ConnectionManager | `core/transport/connection_manager.hpp` | TCP accept loop, version handshake, PQ handshake, connection demux |
| BootstrapClient | `core/bootstrap/bootstrap_client.hpp` | Client-side seed bootstrap (connect → PQ handshake → HELLO/WELCOME) |
| UdpServer | `core/network/udp/udp_server.hpp` | Owns UDP listener + polling internally |

---

### Existing Modules Needing API Additions (P0)

| Module | Missing API |
|--------|-------------|
| SyncService | `register_standard_deltas(CRL*, PolicyStore*, ManifestStore*, RoutingStore*, ContractStore*)` |
| GossipEngine | `register_standard_delta_handlers(PolicyStore*, ManifestStore*, CRL*, ...)` |
| PacketDispatcher | `register_discovery_raw_handler(DiscoveryEngine&)` + `register_join_raw_handler(JoinService&)` |
| RuntimeBridge | `register_core_contracts(MeshManager&, Authority&, GovernanceEngine*, CRL*, SessionManager&, TrustManager&, data_dir)` |
| Telemetry | `init_daemon_metrics()` + `tick_metrics()` |

---

### Existing Modules That Should Self-Subscribe (P1)

| Module | Event to Subscribe |
|--------|-------------------|
| CRL | `RecoveryApproved` |
| SessionManager | `RecoveryApproved` (already has `on_recovery_approved`) |
| DiscoveryEngine | `NodeDisconnected` |
| GovernanceEngine | `ProposalCreated`, `ProposalVoted`, `ProposalCommitted`, `ProposalRejected` |
| TrustManager | `SecurityAlert` |

---

## Migration Priority

| Priority | Modules to Create/Modify | Effort |
|----------|-------------------------|--------|
| **P0** | ConnectionManager, BootstrapClient, SyncService/GossipEngine standard deltas, PacketDispatcher raw handler chaining | High |
| **P1** | RuntimeBridge core contracts, Telemetry daemon init, MeshManager config loading, EventBus auto-subscriptions | Medium |
| **P2** | Health check implementations, Prometheus export scheduling | Low |

---

## Key Insight

> **The `core/` modules already exist with correct APIs for 80% of the violations.**  
> The problem is that `main.cpp` **bypasses these APIs** and manually wires everything.

**The fix is primarily:**
1. Add missing convenience methods to existing modules (SyncService, GossipEngine, RuntimeBridge, Telemetry)
2. Create 2-3 new thin wrapper modules (ConnectionManager, BootstrapClient, UdpServer)
3. Move manual wiring from `main.cpp` into module initialization methods

---

## Expected Result

| Metric | Current | Target |
|--------|---------|--------|
| `main.cpp` lines | 2453 | ~200 |
| Responsibilities | 12+ | 1 (orchestration only) |
| Module coupling | High (bypasses APIs) | Low (uses module APIs) |

---

## Phase Plan

```
Phase 3.5: Extract UdpServer / UdpDiscoveryHandler ownership  ✓ DONE
Phase 3.6: Extract ConnectionManager (TCP accept + PQ handshake + demux)
Phase 3.7: Extract BootstrapClient (seed bootstrap sequence)
Phase 3.8: SyncService/GossipEngine standard delta APIs
Phase 3.9: PacketDispatcher raw handler chaining + RuntimeBridge core contracts
Phase 3.10: Telemetry daemon init + EventBus auto-subscriptions
Phase 4: HelloMsg endpoint propagation (Phase 4 runtime goal)
Phase 5: Heartbeat kill/restart liveness test (Phase 5 runtime goal)
```

**After each phase:** `build` → `25/25 ctest` → `24/24 PCT` → 3-node A/B/C READY verification.

---

*Generated from subagent analysis 2026-09-18*