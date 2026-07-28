# DISCUSSION 0043 — v0.0.2 Execution Plan: Dependency-Based Sprint Order

**Status:** Active  
**Target:** v0.0.2 (production-ready)  
**Parent:** DISCUSSION_0041 (roadmap), DISCUSSION_0040 (limitations)

---

## 1. Why Not Top-Down

The DISCUSSION_0041 epic list (P1 → P11) is a feature catalog, not an execution order. Implementing in that order creates **dependency inversions**:

```
Naive order:
  P1 AntiEntropy
    ├── needs Storage       → P5 not done → mock
    ├── needs Metrics       → P10 not done → blind
    └── needs Gossip FSM    → P2 not done → wrong state

Correct order:
  P5 Storage
  P2 FSM
  P10 Metrics
  P1 AntiEntropy → clean
```

After each epic, the project MUST:
- Build without errors
- Pass all existing tests
- Require zero refactoring of completed work

---

## 2. Sprint Plan — 4 Sprints, 11 Epics

### Sprint A — Core Runtime

| Order | Epic | Effort | Why First |
|-------|------|--------|-----------|
| ⭐ 1 | **P5 Policy Store** | 3d | Foundation for Sync, Gossip, AntiEntropy. Without storage, every upstream service is a stub. |
| ⭐ 2 | **P6 Nonce Dedup** | 1d | Small, isolated, security-critical. Freezes JoinProtocol early. |
| ⭐ 3 | **P2 Gossip Readiness** | 2d | FSM must be correct before writing AntiEntropy. Debugging a wrong FSM later is painful. |

**Goal after Sprint A:**
```
Join ──→ FSM ──→ Storage ──→ all production-ready
```

### Sprint B — Distributed Runtime

| Order | Epic | Effort | Why First |
|-------|------|--------|-----------|
| ⭐ 4 | **P10 Metrics & Observability** | 3d | Instrument before building large services. Debug with data, not printf. |
| ⭐ 5 | **P1 AntiEntropy Service** | 6d | Gossip + Storage + Metrics exist → clean implementation. |
| ⭐ 6 | **P11 Fault Injection / Chaos** | 2d | Test AntiEntropy immediately after writing it. |

**Key design decision:** AntiEntropy should NOT depend on Storage directly. Define a `SyncBackend` interface:

```cpp
class SyncBackend {
public:
    virtual ~SyncBackend() = default;
    virtual Delta getMembershipDelta(const VersionVector&) = 0;
    virtual Delta getPolicyDelta(const VersionVector&) = 0;
    virtual Delta getCRLDelta(const VersionVector&) = 0;
    virtual Delta getContractDelta(const VersionVector&) = 0;
    virtual Snapshot getFullSnapshot(const TreeID&) = 0;
};
```

`GossipEngine` → `SyncBackend` → `AntiEntropyService`. Storage can be swapped without touching AntiEntropy.

**Goal after Sprint B:** The mesh truly "lives" — converges, observable, chaos-tested.

### Sprint C — Production

| Order | Epic | Effort | Why First |
|-------|------|--------|-----------|
| ⭐ 7 | **P8 Hardening** | 4d | HA, graceful shutdown, cleanup. Needs stable runtime. |
| ⭐ 8 | **P3 CI/CD Pipeline** | 4d | Build pipeline once features stabilize. Avoid rewriting workflows. |
| ⭐ 9 | **P4 Packaging** | 2d | Package only when build is stable. |

### Sprint D — Release

| Order | Epic | Effort |
|-------|------|--------|
| ⭐ 10 | **P12 Docs Sync** | 2d |
| ⭐ 11 | **P9 Release v0.0.2** | 1d |

---

## 3. Current Status

Updated after each completed task.

### Sprint A

```
P5 Policy Store  [   ] — 0/6 tasks
P6 Nonce Dedup   [   ] — 0/4 tasks
P2 Gossip FSM    [   ] — 0/6 tasks
```

### Sprint B

```
P10 Metrics      [   ] — 0/9 tasks
P1 AntiEntropy   [   ] — 0/6 tasks
P11 Chaos        [   ] — 0/3 tasks
```

### Sprint C

```
P8 Hardening     [   ] — 0/4 tasks
P3 CI/CD         [   ] — 0/9 tasks
P4 Packaging     [   ] — 0/6 tasks
```

### Sprint D

```
P12 Docs         [   ] — 0/3 tasks
P9 Release       [   ] — 0/5 tasks
```

---

## 4. References

- [DISCUSSION_0041](DISCUSSION_0041_v0.0.2_Plan.md) — Full feature catalog
- [DISCUSSION_0040 §12](DISCUSSION_0040_Release_0.0.1_Plan.md#12-known-limitations-in-001) — Known limitations