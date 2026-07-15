# Discussion — Protocol, Authentication, Transport & Networking

**DO NOT implement from this file.** This is a collaborative discussion document for reviewing old SMF protocol decisions and deciding what to carry forward, what to redesign, and what to leave behind.

**Canonical implementation reference:** [SPEC.md](../SPEC.md)
**Architecture rationale:** [ARCHITECTURE.md](../ARCHITECTURE.md)
**Legacy reference:** [reference/OLD_SHELLMAP/](../reference/OLD_SHELLMAP/)

---

## 1. Old SMF Protocol Stack (Summary)

The old SMF used a fully custom protocol stack over UDP. Key characteristics:

- **86-byte binary header** with magic bytes `SM`, opcode, flags, sequence number, SHA-256 node IDs, nonce, payload length
- **UDP MTU:** 1400 bytes, **max payload:** ~1306 bytes
- **Hybrid post-quantum key exchange:** Kyber-512 + X25519 ECDH over 3-way handshake (HELLO → WELCOME → AUTH)
- **Falcon-512** for node identity and signatures
- **AES-256-GCM** for payload encryption, keys derived via HKDF-SHA256
- **Custom message types:** ~25 opcodes from 0x01–0xFF covering handshake, ping, filesystem, P2P discovery, relay, verification, discovery
- **NAT hole punching:** P2P_FIND_NODE_REQ/RES/ASSIST/HOLE_PUNCH (0x60–0x63)
- **Relay protocol:** RELAY_REQ/RELAY_FWD (0x70–0x71) for nodes behind strict NAT
- **Server verification:** 3-step VERIFY_REQ/PROBE/PROBE_ACK (0x80–0x82) to confirm public reachability
- **UPnP port mapping** via MiniUPnP library with external IP fallback
- **Heartbeat:** PING every 15s, timeout after 3 consecutive misses (45s), 8-byte timestamp payload, same opcode for request and response
- **Anti-replay:** monotonic nonce counter per sender

---

## 2. Discussion Points

### 2.1 Transport Layer — UDP + Custom Binary Header vs Abstraction

**Old SMF:** Fully custom 86-byte binary header over raw UDP. Magic bytes, manual framing, manual MTU management.

**SMO spec:** Transport is abstracted behind a `Transport` interface (SPEC.md §IV Layer 7). TCP is the initial implementation. QUIC is planned.

**Questions:**

- Should SMO retain a UDP transport path alongside TCP?
  - Old SMF chose UDP for P2P mesh networking (hole punching, relay). TCP does not work well with hole punching.
  - But SMO is not a file-sync tool anymore. It is an execution runtime. Is low-latency P2P required, or is TCP/QUIC sufficient for contract delivery?
  - If UDP is kept, should we keep the old 86-byte header design or start fresh?

- The old SMF's `true source discovery` (kernel `recvfrom()` address, never trust packet payload) is a strong anti-spoofing pattern. Should this be adopted into SMO's transport abstraction?

### 2.2 Post-Quantum Handshake — Keep, Simplify, or Redesign?

**Old SMF:** 3-way handshake combining Kyber-512 + X25519 + Falcon-512. Both sides contribute Kyber shared secrets (bidirectional KEM). Key derivation: HKDF-SHA256(lexicographically_sorted(Kyber_SS_responder, Kyber_SS_initiator) || ECDH_SS).

**SMO spec:** Phase 1 uses Ed25519 + XChaCha20-Poly1305 + Blake3 (SPEC.md §XV.1). Phase 2 adds post-quantum.

**Questions:**

- The old hybrid design (Kyber-512 + X25519) is sound and battle-tested in the old codebase. Should SMO adopt the same hybrid KEM approach in Phase 2, or should it use a simpler composition (e.g., Kyber-only with X25519 as optimization)?
- The old 3-way handshake (HELLO/WELCOME/AUTH) takes 1.5 RTT. Is this acceptable for SMO's use case (incident response), or do we want 0-RTT or 1-RTT?
- The old code stored Kyber keypairs on disk (shellmap/system/). SMO's node lifecycle defines KEY_GENERATION. Should Kyber keys be ephemeral per session or persistent per node?

### 2.3 Node Identity — Falcon-512 vs Ed25519

**Old SMF:** Node ID = SHA-256(Falcon-512 public key). Falcon signatures on messages.

**SMO spec:** Ed25519 for signing and identity (SPEC.md §XV.1).

**Questions:**

- Old SMF used Falcon-512 (post-quantum). SMO Phase 1 uses Ed25519 (classical). Is the plan to add Falcon (or Dilithium) in Phase 2, or to stay with Ed25519 + hybrid signatures?
- The old SMF's `NodeID = SHA256(public_key)` pattern is deterministic and clean. SMO's public-key-as-identity follows the same model. Should we document this as a shared pattern?

### 2.4 NAT Traversal and Mesh Connectivity

**Old SMF:** Multi-strategy approach:
1. UPnP port mapping (with robust public IP detection via 6 fallback services)
2. P2P hole punching (4-message protocol: FIND_NODE_REQ/RES/ASSIST/HOLE_PUNCH)
3. Relay fallback (RELAY_REQ/RELAY_FWD) with 5-second timeout detection
4. Server verification (3-step reachability check)

**SMO spec:** Mentions relay as a future transport module (SPEC.md §V: transport/relay/). No details yet on hole punching or UPnP.

**Questions:**

- Incident response use cases typically involve managed infrastructure (servers with public IPs or VPN). Does SMO need P2P hole punching at all, or is TCP/QUIC + relay sufficient?
- If hole punching is needed, should we reuse the old SMF's 4-message protocol (0x60–0x63) or design something simpler?
- The old UPnP implementation with 6 external IP fallback services is surprisingly robust. Should SMO include UPnP as an optional module, or exclude it entirely?

### 2.5 Heartbeat and Liveness Detection

**Old SMF:**
- Interval: 15 seconds
- Timeout: 45 seconds (3 missed PINGs)
- Single opcode (0x04) used for both PING request and response
- 8-byte timestamp payload for RTT calculation
- Separate timeout for handshake (5s), activity (30min), and heartbeat (45s)

**SMO spec:** Heartbeat is mentioned (SPEC.md §IX) as part of the gossip/membership protocol. Payload includes: node status, latency, public key fingerprint, trust digest, capability digest, protocol version.

**Questions:**

- Old SMF's PING is a simple echo. SMO's heartbeat is richer (includes trust, capability, and protocol digests). Should SMO keep a lightweight PING for liveness-only and use a separate message type for digest exchange?
- The old 15s/45s timing was tuned for NAT keepalive (routers close mappings after 30-60s). If SMO uses TCP/QUIC, NAT keepalive is handled by the transport layer. Should we still have an application-level heartbeat?
- Should heartbeat be part of the transport interface, or part of the trust/gossip module?

### 2.6 Message Type Design

**Old SMF:** ~25 opcodes in a single flat namespace (0x01–0xFF). Mix of handshake, filesystem, P2P, relay, and Web3 commands.

**SMO spec:** Opcodes are defined in `core/opcode/opcode.h` (SPEC.md §XVIII). MVP has 5 opcodes (LS, PUT, GET, EXEC, QUARANTINE). Post-MVP adds MKDIR, RM, CP, CUSTOM. SMO does NOT have filesystem transfer as a built-in concern — contract references data by hash, separate channel for large data.

**Questions:**

- The old SMF had opcodes for file transfer (FS_DATA_REQ/RES, FS_PUT_META, FS_PUT_DATA). SMO explicitly separates contract from data. Should SMO still define data channel opcodes, or leave data transfer to the application layer?
- The old SMF's `ACK_REQUIRED` flag (0x10) and per-message ACK mechanism adds reliability on top of UDP. If SMO uses TCP/QUIC, this is handled by the transport. Should SMO's protocol layer still define ACK semantics for operations (not packets)?
- Should SMO adopt the old SMF's pattern of a single flat opcode namespace, or use a hierarchical/scoped namespace (e.g., message type + opcode)?

### 2.7 Anti-Replay

**Old SMF:** Monotonic nonce counter per sender, tracked in `nonce_map_`. Nonce must be strictly greater than last seen.

**SMO spec:** ReplayProtector class in `protocol/replay/replay.h` (SPEC.md §VI.2). Nonce + timestamp window.

**Questions:**

- The old SMF's per-sender monotonic nonce is simpler but does not handle clock-based attacks. SMO's combination of nonce + timestamp window is more robust. Should we keep the SMO design as-is?
- Should the timestamp window be configurable per-node (local policy)?
- Should we adopt the old SMF's `packet_nonce_count = max(packet_nonce, last_nonce + 1)` pattern to handle out-of-order delivery gracefully?

### 2.8 Cryptographic Primitives — Summary Table

| Algorithm | Old SMF | SMO Phase 1 | SMO Phase 2 (future) |
|---|---|---|---|
| Identity / Signing | Falcon-512 | Ed25519 | Ed25519 + Dilithium? |
| Key Exchange | Kyber-512 + X25519 | (session-based) | Kyber + X25519? |
| Payload Encryption | AES-256-GCM | XChaCha20-Poly1305 | XChaCha20-Poly1305 |
| Hashing | SHA-256 | Blake3 | Blake3 |
| Key Derivation | HKDF-SHA256 | (TBD per transport) | (TBD) |

**Questions:**

- XChaCha20-Poly1305 vs AES-256-GCM: Both are well-regarded. Should SMO support both with algorithm agility, or standardize on XChaCha20-Poly1305 as the spec says?
- Blake3 vs SHA-256: Blake3 is significantly faster. Should SMO use Blake3 for everything (node ID derivation, hashing, commitment), or does SHA-256 availability in hardware change the tradeoff?

---

## 3. Proposed Design Candidates for SMO

These are possible approaches. Discuss and decide.

### Option A: Keep SMO spec as-is (TCP/QUIC, Ed25519, XChaCha20-Poly1305, Blake3)

- Simplest implementation path
- No NAT traversal complexity (TCP handles connectivity)
- Incident response use case does not require P2P mesh
- Post-quantum added in Phase 2 when needed

### Option B: SMO spec + UDP transport path from old SMF

- Add a UDP transport implementation alongside TCP
- Reuse old SMF's hole punching and relay protocols
- Keep the hybrid KEM handshake for the UDP path
- Requires maintaining two transport implementations

### Option C: SMO spec + simplified UDP for mesh discovery only

- UDP used only for bootstrap/discovery/heartbeat
- All contract execution goes over TCP/QUIC
- No file transfer over UDP (SMO does not do file transfer)
- Leanest compromise

---

## 4. Decisions Needed

- [x] Transport: TCP+UDP (UDP for discovery/heartbeat only; TCP for contracts/execution/witness/capability)
- [x] Post-quantum crypto: Phase 2 addition (Phase 1: Ed25519 + XChaCha20-Poly1305 + Blake3)
- [x] NAT traversal: Required for mesh (self-implement RFCs, no third-party libraries)
- [x] Heartbeat: Membership protocol layer, NOT transport
- [x] Message type namespace: Hierarchical (DISCOVERY, CONTROL, EXECUTION, DATA)
- [x] Data transfer channel: Separate Data Protocol (chunk-based, independent stream)
- [x] Crypto agility: Crypto Suite ID (protocol references Suite ID, not algorithm names)
- [x] Old SMF 3-way handshake (HELLO/WELCOME/AUTH): DROPPED — replaced by Session + Contract
- [x] Third-party networking libraries: DO NOT USE — self-implement from RFCs
- [x] Connectivity Layer: Separate from Transport (STUN, ICE, NAT traversal)

---

## 5. Networking Philosophy — Recorded Decisions (15 July 2026)

This section records architectural decisions made during the protocol discussion. Each entry captures the problem, the decision, and the rationale.

---

### 5.1 Four Protocol Layers

**Problem:** The old SMF had one flat protocol trying to do everything — handshake, file transfer, P2P discovery, relay, heartbeat, execution. This made the protocol rigid and hard to evolve.

**Decision:** SMO defines exactly four protocol layers, each with a distinct responsibility:

```
┌────────────────────────────────────────────┐
│ DISCOVERY PROTOCOL                          │
│ HELLO · DISCOVER · NODE_INFO               │
│ HEARTBEAT · PING · OFFLINE                 │
├────────────────────────────────────────────┤
│ CONTROL PROTOCOL                            │
│ CONTRACT · CAPABILITY · POLICY             │
│ SESSION · WITNESS · TRUST_DIGEST           │
├────────────────────────────────────────────┤
│ EXECUTION PROTOCOL                          │
│ EXEC_START · EXEC_PROGRESS · EXEC_EVENT    │
│ EXEC_RESULT · EXEC_CANCEL · EXEC_TIMEOUT   │
├────────────────────────────────────────────┤
│ DATA PROTOCOL                               │
│ DATA_CHANNEL · CHUNK · ACK · FIN           │
└────────────────────────────────────────────┘
```

**Layer 1 — Discovery Protocol.** Responsibilities:
- Find nodes on the mesh (HELLO, DISCOVER, NODE_INFO)
- Maintain liveness (HEARTBEAT, PING, OFFLINE)
- Bootstrap new nodes into the mesh
- Transport: UDP only (connectionless, low overhead)
- NEVER carries contracts, capabilities, trust, or execution data

**Layer 2 — Control Protocol.** Responsibilities:
- Transmit contracts (proposal, acceptance, rejection)
- Exchange capability grants and revocation
- Manage sessions (open, close, renew)
- Coordinate witness attestation
- Gossip trust digests
- Transport: TCP only (reliable, ordered)
- This is THE protocol of SMO — everything that makes SMO "SMO" lives here

**Layer 3 — Execution Protocol.** Responsibilities:
- Track execution lifecycle after contract acceptance
- EXEC_START → EXEC_PROGRESS → EXEC_EVENT → (EXEC_CANCEL | EXEC_TIMEOUT) → EXEC_RESULT
- This is NOT the contract phase; this is the "doing work" phase
- Transport: TCP only

**Layer 4 — Data Protocol.** Responsibilities:
- Transfer bulk data referenced by contract (opcodes: PUT, GET)
- Chunked transfer with ACK and retry per chunk
- Independent stream — not multiplexed on the control connection
- Data channel is established separately, torn down after transfer
- Transport: TCP (or future: dedicated QUIC stream)

**Key rule:** A layer MUST NOT assume anything about the layers above it. Discovery does not know what a contract is. Control does not know how execution chunks data.

---

### 5.2 UDP vs TCP Decision

**Problem:** Which transport protocol for which job?

**Decision:**

| Layer | Transport | Rationale |
|---|---|---|
| Discovery | UDP | Connectionless, broadcast, NAT traversal, low overhead. No state needed. |
| Control | TCP | Reliable, ordered, stream-oriented. Contracts must not be lost or reordered. |
| Execution | TCP | Stateful, long-lived, progress reports must be in order. |
| Data | TCP or QUIC | Bulk transfer, flow control, independent stream. |

**Network topology reality:** Nodes in a mesh may be behind NAT, CGNAT, firewalls, Docker bridges, Kubernetes pods, or VPNs. TCP alone cannot solve node addressability. UDP is required for:
1. Hole punching (open NAT mappings)
2. STUN (discover public address)
3. Relay detection (fallback when direct UDP fails)
4. Heartbeat (keep NAT mappings alive)

**TCP is used when a bidirectional session is already established.** Getting that session established is the job of the Discovery layer over UDP.

**No QUIC in Phase 1.** The transport abstraction exists so QUIC can be added later without changing any protocol layer.

---

### 5.3 Dropping the Old SMF Handshake

**Problem:** Old SMF used a 3-way handshake (HELLO → WELCOME → AUTH) that mixed authentication (proving identity) with authorization (proving capability).

**Decision:** SMO does NOT use the old HELLO/WELCOME/AUTH handshake. Rationale:

1. **SMO has Session and Contract.** Authentication happens once per session. Authorization happens per contract. These are separate concerns.
2. **Old handshake mixed Kyber KEM + X25519 ECDH + Falcon signature in one flow.** This combined key exchange with identity verification with session establishment. In SMO:
   - Key exchange → Transport layer (during connection)
   - Identity verification → Session layer (post-connection, using Ed25519)
   - Authorization → Acl/Policy engine (per contract)
3. **Handshake should only establish a secure channel.** Nothing more. After the channel is up, the Session and Contract protocols handle the rest.

**Session establishment flow (SMO, not old SMF):**

```
1. Transport: TCP connection (or UDP-based session via Discovery)
2. Session: Key exchange (X25519 or Suite-negotiated)
3. Session: Identity exchange (Ed25519 public keys, signed nonce)
4. Session: Capability negotiation (what can this node do?)
5. → Ready for CONTROL protocol
```

---

### 5.4 Heartbeat Belongs to Membership, Not Transport

**Problem:** Old SMF implemented heartbeat as PING opcode (0x04) at the packet level, mixed with every other opcode.

**Decision:** Heartbeat is part of the **Membership Protocol**, which lives in the Discovery layer.

```
Transport only knows:
  - connected
  - disconnected
  - bytes_sent
  - bytes_received

Membership knows:
  - node_id → last_heartbeat
  - node_id → trust_digest
  - node_id → capability_digest
  - node_id → status (ALIVE, SUSPECT, DEAD)
  - node_id → address (IP:port, possibly multiple)
```

**Heartbeat payload (SMO):**
- Node ID (Ed25519 public key hash)
- Protocol version
- Node status (ALIVE, BUSY, DEGRADED, QUARANTINED)
- Trust digest (composite score — hint only, see §5.10)
- Capability digest (bitset hash)
- Timestamp

**Failure detection:** The old SMF's 3-PING timeout model is too primitive. SMO should study SWIM, Lifeguard, and memberlist algorithms. The membership layer MUST:
- Use a suspicion mechanism before declaring a node dead (reduce false positives)
- Propagate membership changes via gossip
- Handle network partitions gracefully

---

### 5.5 Hierarchical Opcode Namespace

**Problem:** Old SMF used a flat 8-bit opcode namespace (0x01–0xFF), mixing handshake, filesystem, P2P, relay, and Web3 commands. This made the protocol flat, non-extensible, and hard to route.

**Decision:** SMO uses a hierarchical opcode namespace with two levels:

```
Namespace      Opcode ID        Purpose
──────────     ─────────        ───────
DISCOVERY      0x01             Discovery protocol
  HELLO        0x01 0x01        Session initiation
  DISCOVER     0x01 0x02        Find nodes
  NODE_INFO    0x01 0x03        Node metadata exchange
  PING         0x01 0x04        Liveness check
  OFFLINE      0x01 0x05        Graceful departure

CONTROL        0x02             Control protocol
  CONTRACT_PROPOSAL   0x02 0x01
  CONTRACT_ACCEPT     0x02 0x02
  CONTRACT_REJECT     0x02 0x03
  CONTRACT_RESULT     0x02 0x04
  SESSION_OPEN        0x02 0x10
  SESSION_CLOSE       0x02 0x11
  WITNESS_REQUEST     0x02 0x20
  WITNESS_RESPONSE    0x02 0x21
  CAP_GRANT           0x02 0x30
  CAP_REVOKE          0x02 0x31

EXECUTION      0x03             Execution protocol
  EXEC_START   0x03 0x01
  EXEC_PROGRESS 0x03 0x02
  EXEC_EVENT   0x03 0x03
  EXEC_RESULT  0x03 0x04
  EXEC_CANCEL  0x03 0x05
  EXEC_TIMEOUT 0x03 0x06
  EXEC_ERROR   0x03 0x07

DATA           0x04             Data protocol
  CHANNEL_OPEN  0x04 0x01
  CHUNK         0x04 0x02
  ACK           0x04 0x03
  NACK          0x04 0x04
  FIN           0x04 0x05
  CANCEL        0x04 0x06
```

**Benefits:**
- Extensible: new namespaces can be added without colliding
- Routable: a relay node can forward based on namespace without understanding the payload
- Self-documenting: the namespace tells you what layer the message belongs to

---

### 5.6 Crypto Suite ID — Algorithm Agility

**Problem:** Old SMF hardcoded algorithms (Falcon-512, Kyber-512, AES-256-GCM, SHA-256). Changing algorithms required protocol changes.

**Decision:** Each SMO packet and session carries a **Crypto Suite ID**. The protocol NEVER references specific algorithms. It only references Suite IDs. The mapping from Suite ID to concrete algorithms is a local configuration.

```
Suite 1 (Phase 1 — classical)
  Identity/signing:    Ed25519
  Key exchange:        X25519
  Symmetric cipher:    XChaCha20-Poly1305
  Hash:                Blake3
  Key derivation:      Blake3-based KDF

Suite 2 (Phase 2 — hybrid PQC)
  Identity/signing:    Ed25519 + ML-DSA (Dilithium)
  Key exchange:        X25519 + ML-KEM (Kyber)
  Symmetric cipher:    XChaCha20-Poly1305
  Hash:                Blake3
  Key derivation:      Blake3-based KDF

Suite 3 (future — pure PQC)
  Identity/signing:    ML-DSA (Dilithium)
  Key exchange:        ML-KEM (Kyber)
  Symmetric cipher:    XChaCha20-Poly1305
  Hash:                Blake3
  Key derivation:      Blake3-based KDF
```

**Rules:**
- A node MUST implement Suite 1 (minimum baseline).
- A node MAY implement additional suites.
- During session establishment, nodes negotiate the highest mutually supported suite.
- The suite ID is part of the connection handshake, NOT part of every packet.

---

### 5.7 Connectivity Layer — STUN, ICE, NAT (No Third-Party Libraries)

**Problem:** NAT traversal requires STUN, ICE, and hole punching. Using third-party libraries (libnice, libjuice) introduces dependencies, CVEs, and audit complexity. Inventing custom NAT protocols creates incompatibility.

**Decision:** SMO implements its own STUN, ICE, and NAT traversal — following RFC specifications, NOT inventing new protocols.

```
SMO Networking Stack:

┌──────────────────────────────────────────┐
│ RUNTIME                                   │
│ (FSM, scheduler, executor, audit)        │
├──────────────────────────────────────────┤
│ PROTOCOL LAYER                            │
│ (Discovery, Control, Execution, Data)    │
├──────────────────────────────────────────┤
│ SESSION LAYER                             │
│ (keys, identity, capabilities)           │
├──────────────────────────────────────────┤
│ CONNECTIVITY LAYER                        │
│ (STUN RFC 8489, ICE RFC 8445,            │
│  NAT traversal, relay)                   │
├──────────────────────────────────────────┤
│ TRANSPORT LAYER                           │
│ (TCP, UDP, future QUIC)                  │
└──────────────────────────────────────────┘
```

**Self-implement rule:** Implement RFCs in SMO's own codebase. Do not add third-party networking libraries. The implementations live in `transport/stun/`, `transport/ice/`, `transport/nat/`, `transport/relay/`.

**RFCs to implement:**
- RFC 8489 — STUN (Session Traversal Utilities for NAT)
- RFC 8445 — ICE (Interactive Connectivity Establishment)
- RFC 8656 — TURN (Traversal Using Relays around NAT)
- RFC 5389 — Classic STUN (compatibility)

**Why self-implement:**
- Full control over code — critical for security-auditable networking code
- No dependency update hell
- Can optimize for SMO's specific use patterns
- Can add SMO-specific extensions (e.g., trust digest in STUN attributes)

---

### 5.8 Node Addressability — The Real Problem

**Problem:** TCP connections require reachable IP:port pairs. In a real mesh, nodes sit behind NAT, CGNAT, Docker, Kubernetes, VPNs, and firewalls. TCP alone cannot solve this.

**Decision:** Node addressability is solved at the **Connectivity Layer**, not at the Transport Layer. The connectivity layer produces a usable socket; transport consumes it.

```
Scenario                          Solution
────────                          ────────
Both nodes public IP              Direct TCP
One node behind NAT               UDP hole punch + TCP
Both nodes behind NAT             UDP hole punch + TCP
Symmetric NAT                     Relay via TURN
Kubernetes Pod                    Direct pod IP + TCP
VPN / WireGuard                   Direct TCP over tunnel
Docker bridge                     Docker DNS + TCP
CGNAT (carrier-grade NAT)         Relay via TURN
```

**The connectivity layer's job:**
1. Discover each node's public endpoints (STUN)
2. Gather candidates (local IP, server reflexive, relayed) — ICE
3. Exchange candidates between nodes (via Discovery protocol)
4. Attempt direct connectivity (UDP hole punch for UDP; then TCP)
5. Fall back to relay (TURN) if direct connectivity fails
6. Provide a connected socket to the Session layer

---

### 5.9 Membership Protocol — Beyond Primitive Heartbeat

**Problem:** Old SMF's failure detection was PING every 15s, timeout after 3 misses (45s). This is primitive and produces false positives under packet loss.

**Decision:** Membership protocol uses a SWIM-inspired failure detector:

- **Suspicion phase:** Before declaring a node dead, multicast a suspicion to the mesh. If another node has recent contact with the suspected node, it rebuts the suspicion.
- **Direct pings:** Each member pings a small subset of the membership (not all members) per interval — scales O(log N).
- **Indirect pings:** If a direct ping times out, ask a random member to ping the target (handles one-way network partitions).
- **Gossip propagation:** Membership changes (join, leave, suspicion, confirm) propagate via gossip, not broadcast.

**Configuration (initial):**
- Ping interval: 5 seconds (faster than SMF's 15s for faster detection)
- Direct ping timeout: 3 seconds
- Indirect ping count: 3 random members
- Suspicion timeout: 6 seconds
- Confirm dead timeout: 15 seconds (combines suspicion + direct checks)
- Gossip fanout: 3 nodes per round

**This is NOT a third-party dependency.** The membership protocol is implemented in SMO's `protocol/discovery/` module.

---

### 5.10 Trust Digests Are Hints, Not Authority

**Problem:** If trust scores are transmitted as authoritative values, a compromised node can lie about its own score and influence other nodes' decisions.

**Decision:** Trust digests transmitted over the wire are **hints only**. A receiving node:
1. Receives the trust digest from the wire
2. Compares it against its locally computed score for that node
3. Blends the two (weighted by the sender's own trust score)
4. Uses the blended value as ONE input to contract decisions

**The local trust computation is always authoritative.** Wire-transmitted digests are suggestions. This is consistent with SPEC.md Invariant I-13: Trust is eventually consistent, not absolute truth.

---

### 5.11 Architecture: Connectivity → Session → Protocol → Runtime

**Problem:** The old architecture had no clear boundary between connectivity, session, protocol, and runtime concerns.

**Decision:** SMO defines a strict 4-tier architecture for networking:

```
┌──────────────────────────────────────────────────┐
│ RUNTIME                                           │
│ FSM · Scheduler · Executor · Audit               │
│ Does not touch sockets. Does not know IP.         │
├──────────────────────────────────────────────────┤
│ PROTOCOL LAYER                                    │
│ Discovery · Control · Execution · Data            │
│ Message formats, opcodes, sequence, retry         │
├──────────────────────────────────────────────────┤
│ SESSION LAYER                                     │
│ Keys · Identity · Capability negotiation          │
│ Encryption context · Per-session state            │
├──────────────────────────────────────────────────┤
│ CONNECTIVITY LAYER                                │
│ STUN · ICE · NAT traversal · Relay               │
│ Produces a connected, ready-to-use socket         │
├──────────────────────────────────────────────────┤
│ TRANSPORT LAYER                                   │
│ TCP · UDP (future: QUIC, Unix socket)            │
│ Raw bytes in, raw bytes out                      │
└──────────────────────────────────────────────────┘
```

**Dependency direction:** Each layer depends only on the layer directly below it. The Runtime does not know what Connectivity is. The Connectivity layer does not know what a Contract is.

**The Contract layer (Control protocol) is strictly insulated from NAT traversal.** By the time a Contract message is sent, the Connectivity layer has already established and handed off a working session. This is the architectural guarantee that prevents networking complexity from leaking into the execution model.

---

### 5.12 Implementation Principles for Networking

1. **Implement ourselves. Design only where necessary.** Follow existing RFCs for STUN, ICE, NAT traversal. Do not invent new protocols for well-understood problems. Only design new protocols where SMO is creating something genuinely novel (e.g., the Contract protocol).

2. **No third-party networking libraries.** No libnice, no libjuice, no Pion, no Boost.Asio networking. SMO implements its own STUN, ICE, and transport. Rationale: security-critical code must be fully auditable and dependency-free.

3. **Algorithm → RFC → SMO Implementation.** Never go directly from "algorithm idea" to "SMO protocol." Always validate against existing RFCs and academic work (SWIM, HyParView, etc.).

4. **Protocol describes meaning. Transport describes bytes.** The Control protocol defines what a Contract is, how it is signed, and how it flows. The Transport layer decides whether to send those bytes over TCP, UDP, or a Unix socket. These are independent decisions.

5. **One protocol layer, one responsibility.** If a protocol message does two things, split it into two messages. If a protocol layer does two things, split it into two layers.

---

## 6. Action Items

- [ ] Update SPEC.md to reflect the 4-protocol-layer architecture
- [ ] Update SPEC.md to add the Connectivity layer
- [ ] Update SPEC.md crypto sections to use Suite ID instead of hardcoded algorithms
- [ ] Update SPEC.md to add hierarchical opcode namespace
- [ ] Update core/opcode/opcode.h for hierarchical namespace
- [ ] Create protocol/discovery/ module structure
- [ ] Implement STUN client (RFC 8489) in transport/stun/
- [ ] Implement ICE candidate gathering in transport/ice/
- [ ] Implement UDP hole punch in transport/nat/
- [ ] Implement relay/TURN in transport/relay/
- [ ] Implement SWIM-inspired membership in protocol/discovery/
- [ ] Remove old HELLO/WELCOME/AUTH from any reference code
- [ ] Document the Connectivity → Session → Protocol → Runtime architecture in ARCHITECTURE.md

---

## 7. Identity, Mesh Domain & Authority — Recorded Decisions (15 July 2026)

This section records architectural decisions about node identity, mesh membership, certificates, authority model, and capability governance.

---

### 7.1 Three Distinct Concepts: Identity, Membership, Capability

**Problem:** The old SMF mixed identity (who I am) with authorization (what I can do). A node's Falcon keypair was both its identity and its proof of authority.

**Decision:** SMO separates these into three distinct layers:

```
┌──────────────────────────────────────────────────┐
│ IDENTITY LAYER                                    │
│ NodeID · PublicKey · PrivateKey                   │
│ "Tôi là node X."                                  │
│ Immutable for the lifetime of the node.           │
├──────────────────────────────────────────────────┤
│ MEMBERSHIP LAYER                                   │
│ MeshID · MeshCertificate · IssuedBy               │
│ "Tôi thuộc Mesh Y với vai trò Z."                 │
│ Per-mesh. One node can have multiple memberships. │
├──────────────────────────────────────────────────┤
│ CAPABILITY LAYER                                   │
│ CapabilitySet · Epoch · Session                    │
│ "Trong Mesh Y, tôi được phép làm gì."             │
│ Determined by role in Membership Certificate.      │
├──────────────────────────────────────────────────┤
│ SESSION LAYER                                      │
│ SessionID · ContractContext · ActiveCapabilities   │
│ "Lần thực thi contract này đang dùng quyền nào."  │
│ Ephemeral, per-contract or per-connection.         │
└──────────────────────────────────────────────────┘
```

**Rules:**
- Identity is local to the node. It does not change when joining a new mesh.
- Membership is per-mesh. A node may hold certificates for multiple meshes.
- Capability is derived from membership. The runtime checks capabilities, not roles.
- Session is ephemeral. It binds a specific capability subset to an active contract execution.

---

### 7.2 Mesh Domain

**Problem:** What defines a mesh? How do nodes know they belong to the same logical network?

**Decision:** A mesh is defined by its **Mesh Genesis** — a deterministic ID derived at creation time.

```
MeshID = Blake3(
    MeshRootPublicKey ||
    CreatedAtUnixMs ||
    32 random bytes
)
```

**Mesh creation flow:**

```
smo mesh create --name "SOC-Production"

↓

Generate Mesh Root Keypair (Ed25519 / Suite 1)

↓

Compute MeshID = Blake3(RootPK || time || random)

↓

Generate First Authority Keypair (Ed25519)

↓

Root signs Authority Certificate:
  AuthorityID
  MeshID
  Role: AUTHORITY
  Capabilities: [CAP_GRANT, CAP_REVOKE, CAP_QUARANTINE, CAP_SIGN_NODE, ...]
  IssuedBy: RootID
  Expires: never (or configurable)
  Signature: RootPrivateKey

↓

Export Recovery Package (AES-256 encrypted, password-protected)

↓

Authority certificate stored on node. Root key stored OFFLINE.

↓

DONE
```

**Mesh identity properties:**
- MeshID is globally unique (hash collision resistance)
- MeshID is immutable after creation
- Changing the Root requires generating a new MeshID (new mesh)
- Mesh name is a human label only. MeshID is the canonical identifier.

---

### 7.3 Membership Certificate

**Problem:** How does a node prove it is authorized to participate in a mesh?

**Decision:** Each node holds a **Membership Certificate** signed by an Authority of the mesh.

**Membership Certificate format:**

```
MembershipCertificate {
    NodeID:           Blake3(NodePublicKey)
    NodePublicKey:    Ed25519 public key bytes
    MeshID:           Blake3 hash identifying the mesh
    Role:             "AUTHORITY" | "CONTRIBUTOR" | "READER"
    Capabilities:     [CAP_FS_READ, CAP_HEARTBEAT, ...]  // expanded from Role
    Epoch:            uint64
    IssuedBy:         AuthorityID
    IssuedAt:         unix ms
    ExpiresAt:        unix ms (0 = never)
    Signature:        Authority's Ed25519 signature over all above fields
}
```

**Node join flow:**

```
smo node join --mesh <MeshID> --token <JoinToken>

↓

Generate node Ed25519 keypair (if first run)

↓

Send Certificate Signing Request (CSR) to mesh Authority:
  NodeID
  NodePublicKey
  MeshID
  Signed with NodePrivateKey (proves possession)

↓

Authority validates CSR, signs Membership Certificate

↓

Node receives and stores Membership Certificate

↓

Node is now a member of Mesh <MeshID>

↓

Begin Discovery protocol (heartbeat, gossip, contracts)
```

**The Join Token:**
- Generated by Authority: `Token = Blake3(AuthorityID || MeshID || Secret || Timestamp)`
- Distributed out-of-band (CLI, QR, file, USB)
- Single-use or time-limited
- Proves the node was invited by someone with Authority

**Key rule:** The node's private key is NEVER transmitted. It is generated on the node and stays on the node. The CSR is signed with the private key to prove possession.

---

### 7.4 Root Key vs Authority Key

**Problem:** Old SMF had no distinction between the mesh creator's key and operational keys. One key controlled everything — theft meant total compromise.

**Decision:** Two-tier key hierarchy:

| Key | Purpose | Storage | Usage Frequency |
|---|---|---|---|
| **Mesh Root Key** | Bootstrap, recovery, rotate Authorities | OFFLINE (USB, YubiKey, cold storage, paper) | Once per mesh lifetime (ideally never) |
| **Authority Key** | Daily operations: sign certificates, grant capabilities, revoke | Online (node runtime) | Every contract, every join |

**Mesh Root Key is NEVER online.** It is:
- Generated during `smo mesh create`
- Used immediately to sign the first Authority certificate
- Exported as an encrypted Recovery Package (AES-256 + password)
- Then deleted from the runtime filesystem
- Only brought back for recovery or Root rotation

**Recovery Package format:**

```
recovery.smo {
    MeshRootPublicKey
    MeshRootPrivateKey   (encrypted with AES-256-GCM)
    MeshID
    CreatedAt
    RecoveryPasswordDerivedKey  (Blake3 of password + salt)
    Salt
}
```

**CLI warning on creation:**

```
======================================================

  MESH ROOT KEY GENERATED.

  THIS KEY CONTROLS THE ENTIRE MESH.

  WITHOUT IT, YOU CANNOT:
    - Recover a compromised mesh
    - Rotate Authority keys
    - Create a new mesh with the same identity

  STORE THE RECOVERY PACKAGE OFFLINE.

  DO NOT KEEP IT ON THIS MACHINE.

======================================================
```

---

### 7.5 Multiple Authorities (Not One)

**Problem:** Single Authority is a single point of failure. If it goes offline, no new nodes can join, no certificates can be rotated.

**Decision:** A mesh MUST have at least one Authority and SHOULD have multiple. Authorities are independent — they all hold the same `Role: AUTHORITY` but with different keypairs.

**Adding an Authority:**

```
smo mesh authority add --node <NodeID>

↓

Existing Authority signs a new Authority certificate

↓

Target node now holds Authority role

↓

Target node begins participating in Authority responsibilities
```

**Removing an Authority:**

```
smo mesh authority revoke --node <NodeID>

↓

Any Authority issues a REVOKE_CERT contract

↓

Contract propagates via gossip

↓

All nodes update their local trust store

↓

Revoked node loses Authority capabilities
```

**Revocation IS a contract (SPEC.md §VII).** This is the SMO way:
- `Opcode: REVOKE_CERT`
- Participants: Issuer (Authority), Target (revoked node), Witness (another Authority)
- Recorded in audit store by all three
- Propagated via gossip to the mesh

**Number of Authorities in MVP:** Start with 1 Root + 1 Authority. Add more as the mesh grows. Do NOT require 5 from day one.

---

### 7.6 Capability Epoch

**Problem:** Certificate revocation lists (CRLs) require checking against a growing list. In a mesh with gossip, maintaining a consistent CRL across all nodes is complex.

**Decision:** SMO uses **Capability Epoch** as a lightweight revocation mechanism.

```
Mesh-wide Epoch counter. Incremented when:
  - An Authority is revoked
  - A major capability change occurs
  - Emergency lockdown

Each Membership Certificate carries the Epoch at which it was issued.

When verifying a certificate:
  if cert.Epoch < mesh.CurrentEpoch → REJECT
  (node must request a new certificate)
```

**Epoch increment is itself a contract:**

```
Opcode: EPOCH_INCREMENT
Payload: new_epoch_number
Signers: N of M Authorities (threshold TBD)
Propagation: gossip
```

This means:
- No blacklist needed
- Old certificates self-invalidate
- Nodes must re-enroll after an epoch increment
- Emergency: Authority increments epoch → all non-re-enrolled nodes lose access

---

### 7.7 Roles Are Presets (Not Hardcoded)

**Problem:** The old SMF and early SMO spec both risked hardcoding R/W/X as the only permission model. This limits flexibility.

**Decision:** The runtime knows ONLY capabilities. Roles (READER, CONTRIBUTOR, AUTHORITY) are presets — convenience groupings defined in configuration, not in the runtime.

```
PRESET: ROLE_READER
  CAP_HEARTBEAT
  CAP_VERIFY
  CAP_FS_READ
  CAP_SESSION_CREATE

PRESET: ROLE_CONTRIBUTOR
  = ROLE_READER +
  CAP_FS_WRITE
  CAP_EXEC_BASIC        (execute predefined commands only)

PRESET: ROLE_AUTHORITY
  = ROLE_CONTRIBUTOR +
  CAP_GRANT
  CAP_REVOKE
  CAP_QUARANTINE
  CAP_SIGN_NODE
  CAP_EPOCH_INCREMENT
  CAP_POLICY_CHANGE
  CAP_NODE_BOOTSTRAP
```

**Custom roles are possible.** An admin can define:

```
PRESET: ROLE_SOC_ANALYST
  CAP_FS_READ
  CAP_EXEC_BASIC
  CAP_QUARANTINE            (analyst can quarantine)
  but NOT CAP_GRANT
  but NOT CAP_REVOKE
```

The runtime does not know what "SOC_ANALYST" means. It only checks `CapabilitySet` against the contract's requirements.

---

### 7.8 Deferred to Post-MVP

These topics were discussed and explicitly deferred:

| Topic | Reason | Target Phase |
|---|---|---|
| Authority Election (vote in new Authority when all die) | Requires consensus protocol, complex, needs mesh stability first | Phase 3 |
| Threshold Signatures (M-of-N Authorities sign certificates) | Adds cryptographic complexity; MVP works with individual Authority signatures | Phase 3 |
| Automatic Authority promotion (Contributor auto-promotes when Authority dies) | Dangerous without election; risk of fork | Phase 3 |
| Distributed Root (no single Root key) | Requires DKG (Distributed Key Generation); advanced crypto | Phase 4 |
| Cross-mesh trust (one node in multiple meshes sharing attestations) | Requires inter-mesh protocol; not needed for MVP | Phase 4 |

**MVP identity model (simple, no single point of failure):**
- Multiple Authorities (at least 2 recommended)
- Root Key stored offline
- Membership Certificate with Epoch
- Revocation via Contract + Gossip
- Capability presets for READER, CONTRIBUTOR, AUTHORITY
- Custom roles via configuration only (runtime does not change)

---

### 7.9 Mesh Context Switching (Multiple Meshes)

**Problem:** A node may belong to multiple meshes (SOC, Production, Research). How does it switch between them?

**Decision:** The node holds multiple Membership Certificates, each for a different MeshID. The runtime maintains a concept of "active mesh context."

```
Node
├── Identity (Ed25519 keypair, immutable)
├── Membership: Mesh A (certificate, epoch, capabilities)
├── Membership: Mesh B (certificate, epoch, capabilities)
└── Membership: Mesh C (certificate, epoch, capabilities)
```

**Switching context:**
```
smo ctx use SOC-Production        ← CLI context switch
smo exec --mesh SOC-Production    ← per-command mesh selection
smo node join --mesh Research     ← join new mesh
smo node leave --mesh SOC         ← leave mesh
```

Each mesh context has its own:
- Route table (mesh members)
- Trust store (scores scoped to mesh)
- Capability set (from membership certificate)
- Contract history (audit store per mesh)

The node's Identity is shared across meshes. Everything else is per-mesh.

---

### 7.10 Summary: Identity & Decision Log

```
┌─────────────────────────────────────────────────────────────────┐
│ DECISION LOG SUMMARY                                            │
├─────────────────────────────────────────────────────────────────┤
│ 1. Identity ≠ Membership ≠ Capability ≠ Session                │
│    → Four distinct layers, never mixed                          │
│ 2. MeshID = Blake3(RootPK || time || random)                    │
│    → Deterministic, immutable, globally unique                  │
│ 3. Root Key is OFFLINE. Only used for bootstrap and recovery.   │
│ 4. Authority Key is ONLINE. Used for daily operations.          │
│ 5. Multiple Authorities from MVP. Not single Authority.         │
│ 6. Membership Certificate per node per mesh.                    │
│ 7. Private key NEVER leaves the node (CSR pattern).             │
│ 8. Revocation is a Contract (REVOKE_CERT) via gossip.           │
│ 9. Capability Epoch as lightweight revocation.                  │
│ 10. Roles are presets. Runtime only knows capabilities.         │
│ 11. Recovery Package (AES-encrypted) instead of "save 5 keys." │
│ 12. Authority election / threshold signatures → POST-MVP.       │
│ 13. Mesh context switching for multi-mesh nodes.                │
└─────────────────────────────────────────────────────────────────┘
```

---

## 8. Updated Action Items

- [ ] Update SPEC.md §X (Capability System) to add Epoch
- [ ] Add new section to SPEC.md: Mesh Identity and Membership Certificate
- [ ] Add new section to SPEC.md: Root Key, Authority Key, Recovery
- [ ] Add new section to SPEC.md: Capability Epoch as revocation mechanism
- [ ] Update SPEC.md §XVIII.2: add REVOKE_CERT and EPOCH_INCREMENT opcodes
- [ ] Create `core/mesh/` module: MeshID, MembershipCertificate, Epoch types
- [ ] Create `protocol/control/` module: REVOKE_CERT, EPOCH_INCREMENT messages
- [ ] Create `core/identity/` module: NodeIdentity, Keypair generation
- [ ] Add Mesh context switching to `cmd/smo-cli/`
- [ ] Update ARCHITECTURE.md with Identity → Membership → Capability → Session layers
- [ ] Add RFC 0006: Mesh Identity and Certificate Model

---

## 9. Certificate Chain, Recovery & Join Flow — Recorded Decisions (15 July 2026)

This section finalizes the identity and certificate model for SMO, based on the design principle:

> **Root Key NEVER circulates. Only Certificates circulate.**

---

### 9.1 Certificate Chain of Trust

**Problem:** How to prove that a node is authorized in a mesh without exposing root keys?

**Decision:** SMO builds a certificate chain:

```
ROOT (offline)
  │
  │ signs Authority.PublicKey
  ▼
AUTHORITY CERTIFICATE
  │
  │ signs Contributor.PublicKey
  ▼
CONTRIBUTOR CERTIFICATE
  │
  │ signs Reader.PublicKey (if policy allows)
  ▼
READER CERTIFICATE
```

Each certificate contains:

```json
{
  "mesh_id": "SOC-VN",
  "node_public_key": "base64...",
  "role": "AUTHORITY",
  "capabilities": ["CAP_GRANT", "CAP_REVOKE", "..."],
  "epoch": 1,
  "issued_by": "ROOT",
  "issued_at": "2026-07-15T00:00:00Z",
  "expires_at": "2032-07-15T00:00:00Z",
  "signature": "base64..."
}
```

**The Issued By chain is verifiable:**

```
Reader.cert → signed by → Authority.cert → signed by → Root.pub
```

Every node in the mesh can verify the full chain up to the Root public key (which is part of the Mesh Genesis data, not a secret).

---

### 9.2 Root Key NEVER Circulates

**Problem:** Some designs distribute root keys or authority keys to multiple parties. This creates exposure surface.

**Decision:** Root Private Key is generated during `smo mesh create`, used immediately to sign the first Authority certificate, then:

1. Exported as an encrypted Recovery Package (AES-256-GCM, password-protected)
2. DELETED from the runtime filesystem
3. Stored OFFLINE (USB, YubiKey, paper, cold storage)

**Only Certificates circulate.** A node NEVER holds a private key that belongs to another node. The Root Private Key is never:
- Sent over the network
- Encoded in a QR code
- Stored on a mesh node
- Accessible via API

**The consequence is that certificate issuance must happen via CSR (Certificate Signing Request):**

```
Node generates keypair → sends PublicKey to signer → receives Certificate back
```

This is the only flow.

---

### 9.3 Authority Claim Flow

**Problem:** How does a new Authority join an existing mesh without ever seeing the Root Private Key?

**Decision:** The Authority Claim flow follows the same CSR pattern as any other node:

```
Authority Candidate Node
  │
  │ 1. Generate Ed25519 keypair (local, never leaves)
  │
  │ 2. Export PublicKey to file
  ▼
[send via QR / file / USB / text / email / Discord]
  │
  ▼
Root Admin
  │
  │ 3. smo-admin authority issue --pubkey candidate.pub
  │    (Root signs Authority Certificate offline)
  │
  │ 4. Export Authority Certificate
  ▼
[send back via QR / file / clipboard / ...]
  │
  ▼
Authority Candidate Node
  │
  │ 5. smo-admin import authority.cert
  │
  ▼
Authority is now a mesh Authority
```

**The exchanged data is always:**
1. PublicKey (from candidate to admin) — NOT sensitive
2. Certificate (from admin to candidate) — signed, not secret

**No private key ever travels.**

---

### 9.4 Certificate Distribution Artifacts

**Problem:** Certificate data must survive diverse transport methods (QR, file, clipboard, NFC, Bluetooth, API).

**Decision:** A certificate is a **transport-independent artifact**. It has exactly one binary form and multiple encodings:

```
Internal representation:
  SmoCertificate struct (protobuf or custom binary, ~200-500 bytes)

Encodings:
  ├── Binary (.cert)           → file, USB, REST API
  ├── JSON                     → REST API, human-readable
  ├── CBOR/MessagePack         → QR, NFC (compact)
  ├── Base64                   → clipboard, text message
  ├── ASCII Armor              → email, Discord, documentation
  │    -----BEGIN SMO CERTIFICATE-----
  │    SMOC1:
  │    eyJtZXNoX2lkIjoiU09DLVZOIi...
  │    -----END SMO CERTIFICATE-----
  └── QR                       → SMO://CLAIM/<base64url>
```

**Import API — single entry point:**

```cpp
// Accept any encoding. Auto-detect format.
std::error_code ImportCertificate(std::string_view encoded);
std::error_code ImportCertificate(std::span<const uint8_t> binary);
```

The runtime auto-detects the encoding. No manual format selection needed.

---

### 9.5 Join Token — Not Certificate in QR

**Problem:** QR codes have limited capacity (~3KB). A full certificate may fit, but a simpler mechanism reduces complexity and adds security.

**Decision:** QR codes carry a **Join Token**, not a certificate.

```
QR content:
  SMO://JOIN
    ?mesh=soc-vn
    &token=abcefg123
    &bootstrap=node.company.com:5555
```

**Join flow:**

```
Node scans QR
  │
  │ 1. Parse Join Token: mesh=soc-vn, token=abcefg123
  │ 2. Connect to bootstrap node
  │ 3. Generate ephemeral keypair for this join attempt
  │ 4. Send CSR:
  │      {
  │        "mesh_id": "soc-vn",
  │        "join_token": "abcefg123",
  │        "node_public_key": "base64...",
  │        "node_id": "hash_of_pubkey",
  │        "signed_nonce": "base64..."  // proves key possession
  │      }
  │
  ▼
Authority (via bootstrap node)
  │
  │ 5. Validate join token (single-use, time-limited)
  │ 6. Verify signed nonce
  │ 7. Sign Membership Certificate
  │
  ▼
Node
  │
  │ 8. Receive and import Membership Certificate
  │ 9. Node is now a mesh member
  │
  ▼
Done
```

**Token properties:**
- Generated by Authority
- Single-use (consumed after first successful join)
- Time-limited (default: 10 minutes)
- No private key in token — token is purely an authorization secret
- Compromised token → attacker can join as a new node, but cannot impersonate existing nodes

---

### 9.6 Recovery Authorities (Threshold)

**Problem:** If the Root Key is truly lost (hardware failure, no backup), the mesh cannot be recovered. A single backup file is also a single point of failure.

**Decision:** SMO uses **Recovery Authorities** — a threshold-based mechanism to generate a new Root.

**Mesh creation with recovery:**

```
smo mesh create --recovery-group 5 --threshold 3

↓

Root Key generated as usual

↓

Root divides into 5 shares (Shamir Secret Sharing, threshold 3)

↓

Each share exported as a Recovery Share file:
  recovery-smo-share-1-of-5.smo
  recovery-smo-share-2-of-5.smo
  ...

↓

Each share stored on a different device / person

↓

Root Private Key deleted from runtime
```

**Recovery flow (Root lost):**

```
3 of 5 Recovery Share holders come together

  │
  │ smo mesh recover --shares 3-of-5
  │
  ▼

Shares combined → reconstruct Root Private Key

  │
  │ smo mesh authority rotate --new-root
  │
  ▼

New Root generated
New Authority certificates issued
Old certificates revoked via Epoch increment
```

**Recovery group members are NOT mesh Authorities by default.** They hold only a share of the Root key. They cannot sign contracts, join mesh operations, or issue certificates. Their sole power is Root recovery.

---

### 9.7 Authority Privilege Boundaries

**Problem:** If an Authority is compromised, what damage can it do?

**Decision:** Authority privileges are scoped by design:

| Action | Authority A | Authority B | Root |
|---|---|---|---|
| Sign Contributor certs | YES (its own) | YES (its own) | YES |
| Revoke its own certs | YES | YES | YES |
| Revoke B's certs | NO | NO | YES |
| Revoke Root | NO | NO | N/A |
| Create new Root | NO | NO | YES (via recovery) |
| Increment Epoch | NO (requires Root or M-of-N) | NO | YES |
| Read other nodes' keys | NO | NO | NO |

**Key limitation:** An Authority can only revoke certificates it personally issued. It cannot revoke certificates issued by other Authorities. This is enforced by the certificate's `issued_by` field — the revoking node must match the issuer in the certificate.

---

### 9.8 Certificate → Session Binding

**Problem:** How does a node prove its identity during a specific session or contract?

**Decision:** After the certificate is established, session-level authentication uses a **signed nonce** challenge:

```
1. Node A connects to Node B
2. Node B sends a random nonce (32 bytes)
3. Node A signs the nonce with its Ed25519 private key
4. Node B verifies:
   a. Signature matches Node A's PublicKey
   b. Node A's PublicKey matches the Membership Certificate
   c. Membership Certificate is signed by a known Authority
   d. Certificate Epoch >= mesh CurrentEpoch
   e. Certificate has not expired
5. → Session established
```

This gives SMO two independent security layers:
- **Membership layer:** Certificate proves you belong to the mesh
- **Session layer:** Signed nonce proves you are the certificate holder

Neither alone is sufficient. Both are required.

---

### 9.9 Summary: Certificate & Identity Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ ROOT (offline, recovery only)                                   │
│  │ signs Authority.PublicKey                                    │
├─────────────────────────────────────────────────────────────────┤
│ AUTHORITY CERTIFICATE                                           │
│  │ role=AUTHORITY                                               │
│  │ capabilities=[CAP_GRANT, CAP_REVOKE, CAP_SIGN_NODE, ...]    │
│  │ signs Contributor.PublicKey                                  │
├─────────────────────────────────────────────────────────────────┤
│ CONTRIBUTOR CERTIFICATE                                         │
│  │ role=CONTRIBUTOR                                             │
│  │ capabilities=[CAP_FS_WRITE, CAP_EXEC_BASIC, ...]            │
│  │ signs Reader.PublicKey (if policy allows)                    │
├─────────────────────────────────────────────────────────────────┤
│ READER CERTIFICATE                                              │
│  │ role=READER                                                  │
│  │ capabilities=[CAP_FS_READ, CAP_HEARTBEAT, CAP_VERIFY, ...]  │
├─────────────────────────────────────────────────────────────────┤
│ SESSION                                                         │
│  │ signed nonce proves key possession                           │
│  │ certificate proves mesh membership                           │
│  │ both required for contract execution                         │
└─────────────────────────────────────────────────────────────────┘
```

**Facts about this model:**
- Root Private Key NEVER circulates
- Private keys NEVER leave their host node
- Certificate chain is verifiable by any node
- Join Token is time-limited and single-use
- Recovery requires M-of-N threshold, not a single backup file
- Authority compromise is contained (cannot revoke other Authorities)
- Certificate is transport-independent (binary, JSON, CBOR, ASCII Armor, QR)
- Identity and Membership are separate concerns (same keypair, multiple meshes)

---

## 10. Updated Action Items

### SPEC.md updates needed:
- [ ] New chapter: Mesh Identity & Trust Infrastructure (MITI)
- [ ] Specify certificate chain: Root → Authority → Contributor → Reader
- [ ] Specify CSR flow for certificate issuance
- [ ] Specify Join Token format and lifecycle
- [ ] Specify Recovery Authorities (Shamir threshold)
- [ ] Specify Authority privilege boundaries
- [ ] Specify certificate → session binding (signed nonce)
- [ ] Specify artifact encoding (ASCII Armor format, CBOR, JSON)

### Code modules needed:
- [ ] `core/identity/` — Node identity, keypair generation, nonce signing
- [ ] `core/mesh/` — MeshID, MeshGenesis, MembershipCertificate, Epoch
- [ ] `protocol/control/` — CSR, CERTIFICATE, JOIN_TOKEN, RECOVER, REVOKE_CERT, EPOCH_INCREMENT messages
- [ ] `transport/certificate/` — Format detection, encoding/decoding (ASCII Armor, CBOR, JSON, binary)
- [ ] `cmd/smo-admin/` — `mesh create`, `authority issue`, `authority revoke`, `cert import`, `mesh recover`
- [ ] `cmd/smo-cli/` — `node join`, `ctx use`
- [ ] `tests/unit/identity/` — Certificate chain verification, CSR flow, epoch validation

### RFC:
- [ ] RFC 0006: Mesh Identity and Certificate Model

### Architecture documents:
- [ ] Update ARCHITECTURE.md: add Identity → Membership → Capability → Session layers
- [ ] Update ARCHITECTURE.md: add certificate chain diagram and trust model
- [ ] Update ARCHITECTURE.md: add enrollment protocol diagram

---

## 11. Enrollment Protocol — Recorded Decisions (15 July 2026)

This section records decisions about how a node's Public Key reaches an Authority for signing.

**Core principle:** SMO defines an **Enrollment Protocol**. It does NOT define how enrollment data is transported. QR, USB, clipboard, API, Bluetooth, NFC, Email, Discord, Signal — all valid carriers.

---

### 11.1 Identity Layer vs Enrollment Layer

**Problem:** Most systems mix "proving who you are" (identity) with "how you deliver proof to the authority" (enrollment). This makes it hard to support multiple enrollment methods.

**Decision:** Two distinct layers:

```
┌─────────────────────────────────────────────┐
│ IDENTITY LAYER                               │
│ Node generates Ed25519 keypair               │
│ Output: node.key (private), node.pub (32B)   │
│ Format: Ed25519 public key bytes             │
│                                             │
│ This is the same for EVERY enrollment method │
├─────────────────────────────────────────────┤
│ ENROLLMENT LAYER                             │
│ How does node.pub reach the Authority?       │
│                                             │
│ Carriers (all valid):                        │
│   QR (offline, no Internet) ⭐               │
│   USB / File copy                            │
│   Clipboard (copy-paste)                     │
│   REST API (POST /enroll)                    │
│   Bluetooth / NFC                            │
│   Email / Discord / Signal                   │
│   Web dashboard                              │
│                                             │
│ SMO does NOT pick one. SMO defines protocol. │
├─────────────────────────────────────────────┤
│ CERTIFICATION LAYER                          │
│ Authority receives node.pub                  │
│ Validates (policy, token, identity)          │
│ Signs MembershipCertificate                  │
│ Returns certificate                          │
└─────────────────────────────────────────────┘
```

**SMO defines:**
1. The Enrollment **Protocol** (request/response format)
2. The **Public Key artifact format** (ASCII Armor, JSON, binary)
3. The **Certificate artifact format** (ASCII Armor, JSON, binary)

**SMO does NOT define:**
- How the bits travel from Node A to Authority B

---

### 11.2 Enrollment Protocol Messages

**Problem:** What exactly is exchanged during enrollment?

**Decision:** Two protocol messages:

```
ENROLL_REQUEST  (Node → Authority)
ENROLL_RESPONSE (Authority → Node)
```

**ENROLL_REQUEST payload:**

```
node_name:        string (human-readable, e.g. "server-01")
mesh_id:          string (which mesh to join)
public_key:       bytes (Ed25519, 32 bytes)
fingerprint:      string (Blake3 of public_key, first 8 bytes hex)
join_token:       string (optional, for token-based enrollment)
signed_nonce:     bytes (optional, proves key possession)
requested_role:   string (optional, "READER" | "CONTRIBUTOR")
```

**ENROLL_RESPONSE payload:**

```
status:           "ACCEPTED" | "REJECTED" | "PENDING"
mesh_id:          string
certificate:      MembershipCertificate (if ACCEPTED)
reject_reason:    string (if REJECTED)
authority_info:   { public_key, fingerprint } (for chain verification)
```

**Binary encoding for QR (compact):** CBOR or MessagePack → Base64url → QR

**Text encoding for clipboard/human:** ASCII Armor

```
-----BEGIN SMO ENROLL REQUEST-----

SMOER1:
eyJtZXNoX2lkIjoiU09DLVZOIiw...

-----END SMO ENROLL REQUEST-----
```

---

### 11.3 QR-to-QR Enrollment Flow (Reference — Not Mandatory)

**Problem:** How to enroll a node with zero network infrastructure? (No API, no Internet, no shared filesystem)

**Decision:** The QR-to-QR flow is the reference enrollment method. It is NOT mandatory — any carrier works.

```
┌──────────────┐                    ┌──────────────┐
│   NODE       │                    │  AUTHORITY   │
│  (new)       │                    │  (admin)     │
└──────┬───────┘                    └──────┬───────┘
       │                                   │
       │ smo-node init                     │
       │ generate keypair                  │
       │                                   │
       │ ┌──────────────────────┐          │
       │ │ JOIN REQUEST         │          │
       │ │ Mesh: SOC            │          │
       │ │ FP: A3:F9:...       │          │
       │ │ QR: ███████         │          │
       │ │ SMOPUB:eyJ...       │          │
       │ └──────────────────────┘          │
       │                                   │
       │──── (QR on screen) ────────────── │
       │                                   │
       │                             smo-admin enroll
       │                             scan QR
       │                                   │
       │                             review request
       │                             sign certificate
       │                                   │
       │                             ┌─────┴──────────┐
       │                             │ JOIN RESPONSE  │
       │                             │ Cert: signed   │
       │                             │ QR: ███████   │
       │                             └─────┬──────────┘
       │                                   │
       │──── (QR on screen) ────────────── │
       │                                   │
       │ scan QR                           │
       │ import certificate                │
       │                                   │
       │ ✓ Node is now a mesh member       │
       │                                   │
```

**This entire flow:**
- Requires zero network connectivity
- Takes ~10 seconds
- Private key NEVER leaves the node
- QR carries only PublicKey (not sensitive) and JoinToken (short-lived)

---

### 11.4 Public Key Export Format

**Problem:** The public key must be representable in a human-friendly format for clipboard, file, and display.

**Decision:** ASCII Armor format, similar to SSH public keys and WireGuard:

```
-----BEGIN SMO PUBLIC KEY-----
SMO_KEY_V1:
Mesh: SOC-Production
Node: server-01
FP: A3F9...
Algorithm: Ed25519
PublicKey: MCowBQYDK2VwAyEA...
-----END SMO PUBLIC KEY-----
```

And a compact JSON variant for API use:

```json
{
  "version": 1,
  "mesh_id": "SOC-Production",
  "node_name": "server-01",
  "algorithm": "Ed25519",
  "public_key": "MCowBQYDK2VwAyEA...",
  "fingerprint": "A3F9..."
}
```

---

### 11.5 Enrollment via API (Server-Automated)

**Problem:** Some deployments have network connectivity and want automated enrollment (DevOps, CI/CD, cloud).

**Decision:** REST API endpoint for enrollment:

```
POST /api/v1/enroll

Request:
  Content-Type: application/json
  Body: (same ENROLL_REQUEST payload)

Response 200:
  Content-Type: application/json
  Body: (same ENROLL_RESPONSE payload)
  Certificate embedded as JSON
```

**No authentication required on this endpoint.** Authentication IS the enrollment — the node proves itself by:
1. Presenting a valid Join Token (out-of-band)
2. Signing a nonce with its private key (proves key possession)

This is intentionally similar to Let's Encrypt / ACME, but designed for mesh enrollment rather than web PKI.

---

### 11.6 Summary: Enrollment Design Principles

1. **Enrollment is a protocol, not a function.** Define ENROLL_REQUEST and ENROLL_RESPONSE. Everything else is a carrier.

2. **Public key is ~32 bytes.** It can travel via any medium. SMO does not restrict how.

3. **Certificate is ~200-500 bytes.** It fits in a QR code, a clipboard paste, or an API response.

4. **No private key ever travels.** Not in QR. Not in API. Not in clipboard. Not in USB.

5. **Carrier independence.** QR, USB, REST, clipboard, NFC, Bluetooth, Email, Discord — all are valid. SMO defines the what, not the how.

6. **QR-to-QR is the reference flow.** It works with zero infrastructure. Other carriers are valid but optional.

---

## 12. Updated Action Items

### SPEC.md new chapter:
- [ ] New chapter: **Enrollment Protocol** — ENROLL_REQUEST, ENROLL_RESPONSE, carrier independence principle

### Code modules:
- [ ] `core/enroll/` — EnrollRequest, EnrollResponse, carrier-agnostic types
- [ ] `protocol/enroll/` — Enrollment protocol messages over Control channel
- [ ] `transport/enrollment/` — QR code generation/scanning, file import/export, clipboard
- [ ] `cmd/smo-admin/` — `enroll` command (scan QR, sign, return)
- [ ] `cmd/smo-cli/` — `init` command (generate keypair, display request)
- [ ] `cmd/smo-node/` — `init` entry point (first-run keypair generation)
- [ ] `transport/certificate/` — Unified ImportCertificate() with format auto-detection

### RFC:
- [ ] RFC 0006: Mesh Identity and Certificate Model (expand to include Enrollment Protocol)
- [ ] RFC 0007: Enrollment Transport Carriers (QR, API, clipboard, file, NFC, Bluetooth — non-normative)

---

## 13. Enrollment Modes & File Format — Recorded Decisions (15 July 2026)

This section records decisions about the concrete enrollment file format, CLI workflow, and carrier modes.

**Core principle:** SMO defines exactly one Enrollment Request format (.smor) and exactly one Certificate format (.smoc). All carriers (QR, clipboard, file, API, USB, NFC, Bluetooth) are export/import views of the same underlying artifact.

---

### 13.1 File Format: .smor and .smoc

**Problem:** What is the concrete format of an enrollment request and a certificate?

**Decision:**

| Artifact | Extension | Content | Signed by |
|---|---|---|---|
| Enrollment Request | `.smor` | PublicKey + metadata + nonce + timestamp | Node's private key (proves possession) |
| Node Certificate | `.smoc` | MeshID + Role + Capabilities + Epoch + PublicKey | Authority's private key |

**.smor (Enrollment Request):**

```json
{
  "version": 1,
  "mesh_id": "SOC-Production",
  "node_name": "server-01",
  "os": "Linux 6.8.0-amd64",
  "smo_version": "3.0.0",
  "public_key": "MCowBQYDK2VwAyEA...",
  "fingerprint": "A3F9...",
  "requested_role": "CONTRIBUTOR",
  "requested_capabilities": ["CAP_FS_READ", "CAP_FS_WRITE", "CAP_EXEC_BASIC"],
  "nonce": "7b8a9c1d2e3f4a5b",
  "timestamp": "2026-07-15T12:00:00Z",
  "signature": "base64..."   // signed by node's private key
}
```

**.smoc (Node Certificate):**

```json
{
  "version": 1,
  "mesh_id": "SOC-Production",
  "node_public_key": "MCowBQYDK2VwAyEA...",
  "node_fingerprint": "A3F9...",
  "role": "CONTRIBUTOR",
  "capabilities": ["CAP_FS_READ", "CAP_FS_WRITE", "CAP_EXEC_BASIC"],
  "epoch": 1,
  "issued_by": "Authority-A",
  "issued_at": "2026-07-15T12:01:00Z",
  "expires_at": "2030-07-15T12:01:00Z",
  "signature": "base64..."   // signed by Authority's private key
}
```

**The .smor contains the full enrollment context**, not just a bare public key. This prevents:
- Reusing a public key in a different mesh context (mesh_id is embedded)
- Replaying old enrollment requests (nonce + timestamp)
- Ambiguity about what role the node is requesting

---

### 13.2 CLI Workflow (SSH-like)

**Problem:** The most common enrollment scenario is CLI↔CLI (two servers, both with SSH). The workflow must be as simple as `ssh-copy-id`.

**Decision:**

```
# On the new node:
smo-node init
  → generates node.key, node.pub
  → outputs: call smo-admin sign <this file>

# Export enrollment request:
smo export --format text > join_request.smor
  or
smo export --format qr          (shows QR on terminal)
  or
smo export --format json        (for API submission)

# Transfer to Authority (any carrier):
scp join_request.smor admin@authority:/tmp/
  or
cat join_request.smor            (copy via clipboard)
  or
API POST /api/v1/enroll

# On the Authority machine:
smo-admin sign join_request.smor
  → validates request
  → signs certificate
  → outputs node.smoc

# Transfer certificate back to node:
scp node.smoc admin@node:/tmp/
  or
cat node.smoc                    (copy via clipboard)
  or
API response

# On the node:
smo-node import node.smoc
  → installs certificate
  → node is now a mesh member
  → begin heartbeat, contracts, etc.
```

**This exactly mirrors SSH:**
```
ssh-keygen    → smo-node init
ssh-copy-id   → smo-admin sign
(login)       → smo-node import
```

First-time users already understand this pattern.

---

### 13.3 Five Enrollment Modes

**Decision:** SMO defines 5 enrollment modes. All modes use the same .smor and .smoc formats. Only the carrier differs.

| Mode | Medium | Use Case | UX |
|---|---|---|---|
| **Interactive (CLI↔CLI)** ⭐ | File transfer (scp, rsync, curl) | DevOps, server-to-server | `smo-admin sign request.smor` |
| **Clipboard** | Copy-paste (text, email, chat) | Remote teams, Discord, Signal | `cat .smor` → paste → `cat > .smor` |
| **QR** | Phone camera, KVM camera | Air-gap, on-prem, demos | `smo export --qr` → scan → `smo import` |
| **USB** | Removable media | Isolated networks, compliance | Copy file to USB, sign, copy back |
| **API** | REST endpoint | Enterprise, CI/CD, cloud | `POST /api/v1/enroll` |

**Key rule:** Every mode is optional. A deployment may implement only the modes it needs. The .smor/.smoc format is the one thing that is mandatory.

---

### 13.4 Export/Import Abstraction

**Problem:** How to avoid hardcoding each carrier into the enrollment logic?

**Decision:** Single export/import interface. Mode is a parameter, not a different function.

```cpp
// Export an enrollment request in any format
std::error_code ExportEnrollmentRequest(
    const EnrollRequest& request,
    ExportFormat format,       // TEXT | JSON | QR | BINARY
    std::vector<uint8_t>& out
);

// Import from any format (auto-detect)
std::error_code ImportCertificate(
    std::span<const uint8_t> data,
    NodeCertificate& cert
);
```

```bash
# CLI mirrors the API:
smo export --format text     # ASCII Armor (.smor)
smo export --format json     # JSON (.smor.json)
smo export --format qr       # QR on terminal (.smor → terminal QR)
smo export --format binary   # Raw CBOR (.smor.cbor)
```

**Export only changes presentation. The underlying EnrollRequest is identical.**

---

### 13.5 Summary: Enrollment Pipeline

```
smo-node init
    │
    │ 1. Generate Ed25519 keypair
    │ 2. node.key stays on node (NEVER leaves)
    │ 3. node.pub ready for enrollment
    ▼

EnrollRequest {
    mesh_id, node_name, public_key,
    nonce, timestamp, signature
}
    │
    │ export as .smor (text, json, qr, binary)
    │ carrier: file, scp, clipboard, QR, API, USB, NFC...
    ▼

Authority receives .smor
    │
    │ 1. Verify node's signature (proves key possession)
    │ 2. Verify nonce freshness
    │ 3. Verify mesh_id matches
    │ 4. Apply policy (is this node allowed? what role?)
    │ 5. Sign NodeCertificate
    ▼

NodeCertificate (.smoc)
    │
    │ carrier: file, scp, clipboard, QR, API, USB, NFC...
    ▼

smo-node import node.smoc
    │
    │ 1. Verify Authority's signature
    │ 2. Verify certificate chain (Authority → Root)
    │ 3. Install certificate
    │ 4. Node is now a member of Mesh <mesh_id>
    ▼

Node is ACTIVE. Begin Discovery → Control → Execution.
```

---

## 14. Final Action Items

### SPEC.md:
- [ ] New chapter: **Enrollment Protocol** — .smor, .smoc, CSR, 5 enrollment modes, carrier independence
- [ ] New chapter: **Mesh Identity & Trust Infrastructure (MITI)** — Root Key, Authority, certificate chain, epoch, recovery
- [ ] Update §X (Capability System) — add Epoch, expand presets
- [ ] Update §XVIII.2 (Opcodes) — add REVOKE_CERT, EPOCH_INCREMENT
- [ ] Update §IV (System Layers) — add Identity Layer, Membership Layer, Enrollment Layer

### Code modules:
- [ ] `core/identity/` — NodeIdentity, Ed25519 keypair generation, nonce signing
- [ ] `core/mesh/` — MeshID, MeshGenesis, Epoch type
- [ ] `core/enroll/` — EnrollRequest, EnrollResponse, NodeCertificate, ExportFormat
- [ ] `protocol/discovery/` — Heartbeat, membership, gossip (SWIM-inspired)
- [ ] `protocol/control/` — CONTRACT_PROPOSAL, CSR, REVOKE_CERT, EPOCH_INCREMENT
- [ ] `protocol/execution/` — EXEC_START, EXEC_PROGRESS, EXEC_RESULT, EXEC_CANCEL
- [ ] `protocol/data/` — CHANNEL_OPEN, CHUNK, ACK, FIN
- [ ] `transport/tcp/` — TCP transport implementation
- [ ] `transport/stun/` — STUN client (RFC 8489)
- [ ] `transport/ice/` — ICE candidate gathering (RFC 8445)
- [ ] `transport/nat/` — UDP hole punch
- [ ] `transport/relay/` — TURN relay (RFC 8656)
- [ ] `transport/framing/` — FrameHeader, zero-copy frame read/write
- [ ] `transport/serialization/` — CBOR, JSON, ASCII Armor, binary auto-detect
- [ ] `transport/certificate/` — Unified ImportCertificate()
- [ ] `transport/enrollment/` — QR generation, format export/import
- [ ] `cmd/smo-admin/` — `mesh create`, `authority issue`, `authority revoke`, `sign`, `enroll`
- [ ] `cmd/smo-cli/` — `ctx use`, `export`, `node join`
- [ ] `cmd/smo-node/` — `init`, `import`, daemon mode

### Architecture documents:
- [ ] Update ARCHITECTURE.md — 4-layer architecture: Connectivity → Session → Protocol → Runtime
- [ ] Update ARCHITECTURE.md — Identity → Membership → Capability → Session
- [ ] Update ARCHITECTURE.md — Certificate chain: Root → Authority → Contributor → Reader
- [ ] Update ARCHITECTURE.md — Enrollment pipeline diagram

### RFC:
- [ ] RFC 0001: Contract Model
- [ ] RFC 0002: Capability System
- [ ] RFC 0003: Witness Protocol
- [ ] RFC 0004: Trust and Reputation
- [ ] RFC 0005: Execution DAG
- [ ] RFC 0006: Mesh Identity and Certificate Model
- [ ] RFC 0007: Enrollment Protocol and Carriers
- [ ] RFC 0008: Networking Architecture (4 protocol layers, Connectivity vs Transport)
