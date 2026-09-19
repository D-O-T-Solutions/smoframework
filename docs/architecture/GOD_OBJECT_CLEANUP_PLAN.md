# GOD OBJECT CLEANUP — `cmd/smo-node/main.cpp`

## Migration Plan with Gate Tests

**Objective:** Reduce `main.cpp` from 2453 lines to ~200-300 lines of pure orchestration, while maintaining 100% test pass and 3-node runtime correctness at every step.

**Philosophy:** Sequential phases with mandatory gate tests. No phase proceeds until all gates pass.

---

## Phase 0 — Freeze Baseline

- [ ] Record baseline state
  - [ ] `cmake --build build -j`
  - [ ] `25/25 ctest`
  - [ ] `24/24 PCT`
  - [ ] 3-node A/B/C runtime
  - [ ] A/B/C `READY`
  - [ ] gossip TX/RX > 0
  - [ ] heartbeat `ping_misses=0`
- [ ] Commit/tag baseline before refactor
- [ ] No behavior/protocol changes in this phase

**Gate:** baseline pass.

---

## Phase 1 — Create `NodeRuntime` Composition Root

- [ ] Create `core/runtime/node_runtime.hpp/.cpp`
- [ ] Define ownership/lifecycle of all subsystems
- [ ] Move object ownership from `main.cpp` into `NodeRuntime`
- [ ] `initialize()` — construction + dependency injection
- [ ] `start()` — start services
- [ ] `run()` — event loop
- [ ] `shutdown()` — teardown
- [ ] `main.cpp` → parse CLI → `NodeRuntime` → `initialize/start/run`
- [ ] **No logic moved yet; only composition boundary created**

**Gate:** build + 25/25 + 24/24 + A/B/C READY.

---

## Phase 2 — Extract `ConnectionManager` (P0)

### Move from `main.cpp`:

- [ ] TCP listener ownership
- [ ] `poll()` / accept
- [ ] Version handshake
- [ ] Connection-type detection
- [ ] JOIN/SYNC/DATA demux
- [ ] PQ server handshake
- [ ] `SecureSession` creation
- [ ] Session dispatch

### Target API:

```cpp
ConnectionManager
 ├── start()
 ├── poll()
 ├── handle_connection()
 ├── handle_join()
 ├── handle_sync()
 └── handle_data()
```

### Invariants:

- [ ] `main.cpp` never calls `accept()`
- [ ] `main.cpp` never calls `version_handshake_server()`
- [ ] `main.cpp` never directly creates `FieldTransportSession`
- [ ] `main.cpp` never directly creates `SecureSession`
- [ ] `main.cpp` never demuxes protocol
- [ ] Review `TransportListener::fd()` — remove if `ConnectionManager` owns socket

**Gate:** build + tests + A/B/C READY.

---

## Phase 3 — Extract UDP Ownership (P0)

- [ ] `UdpDiscoveryHandler` / `UdpServer` owns UDP listener
- [ ] Move `recvfrom()` out of `main.cpp`
- [ ] Move `sockaddr_in` handling out of `main.cpp`
- [ ] Move `inet_ntop()` out of `main.cpp`
- [ ] Move datagram → `DiscoveryEngine` dispatch out of `main.cpp`
- [ ] `main.cpp` only calls `udp_discovery.start()` / `poll()`
- [ ] If no consumer needs raw fd → remove `UdpListener::fd()`

**Gate:** build + tests + A/B/C + UDP discovery.

---

## Phase 4 — Extract `BootstrapClient` (P0)

Move entire sequence:

```
seed endpoint
  → TCP connect
  → PQ client handshake
  → HELLO
  → WELCOME
  → discovery_engine.handle_welcome()
  → membership update
```

- [ ] Create `core/bootstrap/bootstrap_client.hpp/.cpp`
- [ ] `main.cpp` never knows handshake sequence
- [ ] `main.cpp` never loads cert/key for bootstrap
- [ ] BootstrapClient uses `TransportRegistry`
- [ ] BootstrapClient uses `SecureSession`
- [ ] BootstrapClient returns typed result
- [ ] `NodeRuntime` calls: `bootstrap_client.bootstrap(seed)`

**Gate:** build + tests + A/B/C enrollment.

---

## Phase 5 — Eliminate Raw Discovery/Protocol Dispatch (P0)

- [ ] Audit all raw handlers in `main.cpp`
- [ ] `HelloMsg` → `DiscoveryEngine`
- [ ] `PingMsg` → `DiscoveryEngine`
- [ ] `WelcomeMsg` → `DiscoveryEngine`
- [ ] `JoinRequest` → `JoinService`
- [ ] `BootstrapSyncRequest` → `JoinService`
- [ ] `GOSP` → `GossipEngine`
- [ ] `PacketDispatcher` becomes sole protocol demux
- [ ] Remove manual `deserialize()` from `main.cpp`
- [ ] Remove protocol-specific response construction from `main.cpp`

**Target:**

```
incoming bytes
      ↓
PacketDispatcher
      ↓
protocol service
```

**Gate:** build + tests + A/B/C gossip/heartbeat.

---

## Phase 6 — SyncService Standard Wiring (P0)

- [ ] Audit 5 delta callbacks in `main.cpp`
- [ ] Design `StandardDeltaProvider` / registry
- [ ] Move CRL delta registration
- [ ] Move Policy delta registration
- [ ] Move Manifest delta registration
- [ ] Move Routing delta registration
- [ ] Move Contract delta registration
- [ ] `SyncService` exposes single initialization API
- [ ] Remove serialization lambdas from `main.cpp`

**Target:**

```cpp
sync_service.register_standard_providers(...);
```

**Gate:** build + tests + PCT + A/B/C sync.

---

## Phase 7 — Gossip Standard Handlers (P0)

- [ ] Move Manifest gossip handler
- [ ] Move Policy gossip handler
- [ ] Move deserialization out of `main.cpp`
- [ ] Move store update out of `main.cpp`
- [ ] Register standard handlers at subsystem boundary
- [ ] GossipEngine owns GOSP encode/decode + delta processing
- [ ] `main.cpp` never knows GOSP payload format

**Target:**

```
GossipEngine
 ├── transport
 ├── encode/decode
 ├── delta provider
 └── delta handler
```

**Gate:** A/B/C gossip propagation.

---

## Phase 8 — Mesh Configuration Cleanup (P1)

- [ ] Remove manual `mesh.json` string parsing (`find()`/`substr()`)
- [ ] Use `MeshManager::load_mesh_config()`
- [ ] Use `MeshConfig` typed struct
- [ ] Move `authority_mesh_id` resolution into MeshManager
- [ ] Move catalog DB initialization out of `main.cpp`
- [ ] `NodeRuntime` receives typed configuration
- [ ] No `find()`/`substr()` JSON parsing in daemon entrypoint

**Gate:** clean config startup + tests + A/B/C.

---

## Phase 9 — Runtime Registration Cleanup (P1)

### Contracts

- [ ] Create `RuntimeRegistry::register_core_contracts()`
- [ ] Move ~10 contract registrations
- [ ] Remove hardcoded registration from `main.cpp`

### Routes

- [ ] Create `RuntimeBridge::register_core_routes()`
- [ ] Move ~18 route registrations
- [ ] Remove route wiring from `main.cpp`

### Middleware

- [ ] Move PolicyMiddleware setup
- [ ] Move anonymous route configuration

**Target:**

```cpp
RuntimeBridge::initialize(...);
```

**Gate:** PCT must pass fully.

---

## Phase 10 — EventBus Cleanup (P1)

- [ ] Audit all 15 subscriptions
- [ ] Determine true owner of each event
- [ ] Create `register_event_handlers()` / `initialize_events()` per subsystem
- [ ] CRL → RecoveryApproved
- [ ] SessionManager → RecoveryApproved
- [ ] DiscoveryEngine → NodeDisconnected
- [ ] GovernanceEngine → Proposal*
- [ ] Recovery-related handlers
- [ ] TrustManager → SecurityAlert
- [ ] Audit handlers
- [ ] `main.cpp` contains NO callback implementation
- [ ] Composition root only calls initialization

**Gate:** event-related ctests + PCT + runtime.

---

## Phase 11 — Session/Identity/Certificate Cleanup (P1)

- [ ] Identity loading → Identity API
- [ ] Server certificate loading → certificate subsystem
- [ ] Root public key loading → identity/certificate subsystem
- [ ] Session recovery → SessionManager API
- [ ] TrustContract dependency wiring → dedicated initializer/factory
- [ ] Remove filesystem/certificate parsing from `main.cpp`

**Target:** `main.cpp` doesn't know cert file paths or deserialization logic.

**Gate:** startup + enrollment + tests.

---

## Phase 12 — Telemetry Cleanup (P1/P2)

- [ ] Move metric registration out of `main.cpp`
- [ ] Move health checks out of `main.cpp`
- [ ] Move Prometheus export out of main loop
- [ ] `Telemetry::init_daemon()`
- [ ] `Telemetry::tick()`
- [ ] Module-specific health providers
- [ ] Remove periodic metric bookkeeping from `main.cpp`

**Target:**

```
NodeRuntime
   ↓
telemetry.tick()
```

**Gate:** metrics timestamp/freshness + tests.

---

## Phase 13 — Lifecycle Cleanup

- [ ] Move NodeLifecycleFSM orchestration into `NodeRuntime`
- [ ] `initialize → starting → active → degraded → stopping`
- [ ] SIGTERM/SIGINT handling
- [ ] Graceful shutdown
- [ ] Service stop ordering
- [ ] Socket close ordering
- [ ] Flush telemetry
- [ ] Database close
- [ ] Remove `pkill -9` dependency from runtime harness
- [ ] **Also addresses 9.7 graceful shutdown**

**Gate:**

```
SIGTERM
 ↓
graceful shutdown
 ↓
process exits 0
```

(no `SIGKILL` needed)

---

## Phase 14 — God Object Sweep (Forbidden Checklist)

- [ ] `wc -l main.cpp`
- [ ] grep for raw socket APIs: `accept()`, `connect()`, `recv()`, `send()`, `recvfrom()`
- [ ] grep for `sockaddr_*`, `inet_*`
- [ ] grep for protocol deserialize calls
- [ ] grep for protocol dispatch logic
- [ ] grep for database SQL (`sqlite3_*`)
- [ ] grep for JSON parsing (`find()`, `substr()`, `cbor::`)
- [ ] grep for EventBus `.subscribe` with lambda bodies
- [ ] grep for contract registration
- [ ] grep for route registration
- [ ] grep for delta callback lambdas
- [ ] grep for certificate loading (`load_file_binary`, `.cert.smoc`)
- [ ] grep for manual `new` / subsystem ownership

### Forbidden in final `main.cpp`:

```
accept()
connect()
recv()
send()
recvfrom()
sockaddr_*
inet_*
protocol deserialize
protocol dispatch
database SQL
JSON parsing
EventBus callback bodies
contract registration
route registration
delta serialization
certificate loading
```

---

## Phase 15 — Final Architecture Verification

- [ ] `main.cpp` ≤ ~200-300 lines
- [ ] `main.cpp` only contains:
  - [ ] CLI/options parsing
  - [ ] `NodeRuntime` construction
  - [ ] `initialize()`
  - [ ] `start()`
  - [ ] `run()`
  - [ ] exit/error handling
- [ ] No subsystem implementation detail
- [ ] No raw networking
- [ ] No protocol parsing
- [ ] No business logic

### Final Regression Suite

- [ ] Clean rebuild
- [ ] `25/25 ctest`
- [ ] `24/24 PCT`
- [ ] 3-node A/B/C
- [ ] Bootstrap enrollment
- [ ] Membership propagation
- [ ] Gossip TX/RX
- [ ] Heartbeat
- [ ] Kill/restart liveness
- [ ] Graceful SIGTERM shutdown
- [ ] Metrics
- [ ] Registry correctness
- [ ] No `[DEBUG]` strings
- [ ] No `display_name=''` regression
- [ ] Update `DISCUSSION_0048`
- [ ] Update `GOD_OBJECT_ANALYSIS_FULL.md`

---

## Execution Order (Locked)

```
0  Baseline
↓
1  NodeRuntime
↓
2  ConnectionManager
↓
3  UDP Ownership
↓
4  BootstrapClient
↓
5  Protocol/Raw Dispatch
↓
6  SyncService
↓
7  GossipEngine
↓
8  MeshConfig
↓
9  Runtime Contracts/Routes
↓
10 EventBus
↓
11 Identity/Session
↓
12 Telemetry
↓
13 Lifecycle + Graceful Shutdown
↓
14 God-Object Sweep
↓
15 Full Regression
```

---

## Phase Gate Template (Every Phase)

```
IMPLEMENT
   ↓
BUILD
   ↓
25/25 CTEST
   ↓
24/24 PCT
   ↓
3-NODE RUNTIME (A/B/C READY, gossip TX/RX > 0, ping_misses=0)
   ↓
DOC (update DISCUSSION_0048 + GOD_OBJECT_ANALYSIS_FULL.md)
   ↓
NEXT PHASE
```

**No phase proceeds without ALL gates passing.**

---

## Success Criteria

| Metric | Baseline | Target |
|--------|----------|--------|
| `main.cpp` lines | 2453 | ~200-300 |
| Responsibilities | 12+ | 1 (orchestration) |
| Module coupling | High (bypasses APIs) | Low (uses module APIs) |
| Test pass rate | 100% | 100% |
| 3-node readiness | Works | Works |

**Note:** Line count is a byproduct. The real goal is **clean boundary separation**. If final `main.cpp` is 280 lines but boundaries are clean, that's better than 200 lines with a new God Object.

---

*Generated 2026-09-18 — Locked for sequential execution*