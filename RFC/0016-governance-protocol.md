# RFC 0016 — Governance Protocol

## Status
ACCEPTED — AMENDED 2026-08-14 (§AMEND-6 atomic transition + base_epoch/state_hash anti-split-brain; §AMEND-7 liveness ≠ revocation). 5-tier governance model frozen. Fail-closed conflict resolution confirmed.

## Problem
Mesh-wide decisions (capability grant/revoke, policy changes, authority addition/removal, epoch increment, emergency lockdown) require a mechanism for Authorities to propose, sign, and commit actions. Governance must be tiered by impact, configurable per mesh, and fully independent of contract execution.

## Decisions

### 1. Governance does NOT govern execution (§33.1)
Governance manages the mesh — not individual contracts. An Authority cannot use governance to force a Responder to execute a contract. Execution decisions remain local to the Responder.

### 2. Five governance levels with configurable thresholds (§33.2)

| Level | Example Actions | Default Threshold | Scope |
|---|---|---|---|
| L0 — Local | Node-local policy, plugin enable | 1-of-1 (self) | Single node |
| L1 — Authority | Issue/revoke cert, grant capability | 1-of-N Authorities | Authority action |
| L2 — Policy | Change trust thresholds, protocol config | 2-of-N Authorities | Mesh-wide |
| L3 — Critical | Root rotate, mesh destroy, emergency lockdown | M-of-N (e.g., 3-of-5) | Mesh-wide |
| L4 — Genesis | Create mesh | 1-of-1 (Root Key) | Once only |

Thresholds are defined in the Mesh Manifest (`governance.policy_threshold`, `governance.critical_threshold`). Changing a threshold requires a Level 2 (or higher) proposal.

### 3. Proposal lifecycle
```
DRAFT → SIGNING → COMMITTED (threshold met)
   ↓        ↓
EXPIRED  REJECTED (conflicting proposal reached threshold first)
```
- Any Authority creates a `GovernanceProposal`.
- Other Authorities sign it.
- When signature count reaches the threshold for the proposal's level, any observing node may `commit()`.
- The commit action appends the proposal to `governance_store` and applies the effect (e.g., revokes a certificate, increments epoch).
- Proposals that do not reach threshold within `max_ttl` (default 24 hours) transition to EXPIRED.

> **AMEND-6 (2026-08-14) — Atomic state transition + anti-split-brain:**
> - Revoke + elect (authority replacement) MUST be a single atomic `GovernanceTransition`, NOT two independent transactions. Intermediate states (e.g., "A revoked, no replacement" or "old epoch still active") are forbidden.
> - Every transition carries `base_epoch + base_state_hash + new_epoch + new_state_hash`.
> - Commit rule: `proposal.base_epoch == mesh.current_epoch` AND `proposal.base_state_hash == mesh.current_state_hash`. Otherwise → **REJECT: stale governance base**.
> - Race example: B/C propose `revoke(A)+elect(B)` at base 41 while D/E propose `elect(D)` at base 41 → only the first commit (state_hash_42) wins; the second sees base epoch 41 stale and is rejected. NO split-brain double-commit.
> - Governance state is hash-chained: `state_hash_N = H(prev_state_hash, authority_set_N, revocation_set_N, epoch_N, sequence)`.

### 4. Conflict resolution: first-past-the-post
If two proposals conflict (e.g., Authority A grants a capability, Authority B revokes it), the first proposal to reach threshold wins. The losing proposal is REJECTED. This creates a **fail-closed** default: if split-brain occurs, conflicting proposals both remain uncommitted, and no change is applied until mesh connectivity is restored. Combined with AMEND-6 base_epoch/state_hash binding, stale proposals are rejected deterministically.

### 5. Compromised Authority recovery
A compromised Authority is removed by an explicit governance decision (revoke + elect in ONE atomic transition, AMEND-6). The transition bumps `epoch` and updates the **Revocation Set**: `A` is removed from `active_authorities` and its key_id/cert serials are added to the Revocation Set.

> **AMEND-7 (2026-08-14) — Liveness ≠ revocation:**
> - **Offline / DEAD ≠ COMPROMISED.** A node that merely misses heartbeats is NOT auto-revoked. If offline nodes were auto-revoked, a transient network partition (A ─X─ B/C/D) would revoke A, then the mesh heals and A returns → governance split-brain.
> - **Liveness** (heartbeat, failure detector, offline status) and **authority revocation** (explicit governance decision) are SEPARATE mechanisms and MUST NOT be merged.
> - **Signature validity ≠ governance authority.** A valid signature proves "A signed this"; it does NOT prove "A still has voting rights." Every governance action verifies: signature → authority identity → authority status → current capability epoch → proposal ID → current governance state → vote uniqueness → quorum → commit.

### 6. Mesh split handling
If a mesh splits into two partitions, each partition continues operating with its own epoch counter. When connectivity is restored, the runtime detects a governance history fork (divergent `governance_store` hashes). No automatic merge. Operators must manually reconcile and issue a Level 3 proposal accepting one history as canonical. AMEND-6 base_state_hash makes the divergent histories objectively detectible (different state hashes).

### 7. Root Key usage is strictly limited
The Root Key is used exactly once (mesh creation). It may be used again only for:
- Emergency recovery (reconstructing M-of-N shares).
- Signing the first Authority certificate after genesis.
- Authorizing a Level 4 (Genesis-level) decision after the original Root is lost (requires M-of-N recovery).

Any attempt to use the Root Key for Level 1-3 decisions is rejected by the governance engine.

### 8. Revocation model: Capability Epoch + Revocation Set (aligns RFC 0006 AMEND-2)
- **Capability Epoch** = coarse-grained global capability invalidation. `epoch++` invalidates ALL credentials authorized under older epochs.
- **Revocation Set** = fine-grained per-identity/per-key/per-cert-serial invalidation.
- A revoked/replaced authority fails BOTH: `capability_epoch < current_epoch` AND explicitly listed in the Revocation Set.
- Recovery ≠ resurrection: reconstructing shares decrypts material offline but a live authority identity requires a governance-authorized rekey/election + new epoch (RFC 0006 AMEND-3).

## Interfaces

```cpp
enum class GovernanceLevel : uint8_t {
    Local = 0, Authority = 1, Policy = 2, Critical = 3, Genesis = 4
};

enum class ProposalState : uint8_t {
    Draft, Signing, Committed, Rejected, Expired
};

struct AuthorityRecord {
    KeyId        key_id;
    SuiteId      suite_id;
    AuthorityStatus status;        // Active / Suspended / Revoked
    uint64_t     capability_epoch; // joined epoch; stale if < current
    uint64_t     joined_epoch;
    uint64_t     revoked_epoch;    // 0 if never revoked
};

struct RevocationSet {
    std::vector<KeyId>   revoked_key_ids;
    std::vector<uint64_t> revoked_cert_serials;
    std::vector<NodeID>  revoked_authorities;
};

struct GovernanceState {
    uint64_t epoch;
    Hash     state_hash;             // H(prev_hash, authority_set, revocation_set, epoch, seq)
    std::vector<AuthorityId> active_authorities;
    RevocationSet revocations;
    uint32_t quorum;
    uint64_t governance_sequence;
};

struct GovernanceProposal {
    ProposalID       id;
    GovernanceLevel  level;
    std::string      action;      // "revoke_and_elect", "grant_capability", "increment_epoch", etc.
    std::vector<uint8_t> payload; // action-specific data
    uint64_t base_epoch;          // AMEND-6 anti-split-brain
    Hash     base_state_hash;     // AMEND-6 anti-split-brain
    Hash     prev_state_hash;
    TimePoint        created_at;
    TimePoint        expires_at;
    std::vector<Signature> signatures;

    static Result<GovernanceProposal> create(
        GovernanceLevel level,
        std::string_view action,
        std::span<const uint8_t> payload,
        uint64_t base_epoch,
        const Hash& base_state_hash,
        TimePoint ttl);
    Result<void> sign(const Keypair& authority_key);
    Result<bool> threshold_met(const MeshManifest& manifest) const;
    Result<void> commit(GovernanceStore& store); // verify base_epoch+state_hash then apply
};

struct GovernanceTransition {   // AMEND-6 atomic: revoke + elect in ONE step
    std::vector<NodeID> revoke;
    std::vector<NodeID> elect_add;
    std::vector<NodeID> new_authority_set;
    uint64_t new_epoch;
    Hash     prev_state_hash;
    Hash     new_state_hash;
};

class GovernanceEngine {
    Result<void> submit_proposal(GovernanceProposal proposal);
    Result<void> sign_proposal(ProposalID id, const Keypair& authority_key);
    Result<void> commit_proposal(ProposalID id);
    Result<GovernanceProposal> get_proposal(ProposalID id) const;
    Result<std::vector<GovernanceProposal>> pending_proposals() const;
    Result<void> tick();  // expire stale proposals
    Result<void> detect_fork(const GovernanceStore& local,
                             const GovernanceStore& remote);  // compare state hashes
    Result<GovernanceState> current_state() const;
    Result<void> apply_transition(const GovernanceTransition& t); // verify then commit
};
```

## Consequences
- Governance actions are fully auditable (append-only `governance_store`).
- Configurable thresholds let small meshes (1 Authority) and large meshes (7+ Authorities) use the same engine with different manifests.
- Fail-closed conflict resolution prevents runtime ambiguity: if Authorities disagree, the default is "no change."
- Root Key isolation limits blast radius: Root compromise requires a targeted attack on the recovery package, not a runtime exploit.
- Mesh split detection + manual merge is a deliberate tradeoff: automatic merge of governance histories is intractable when policies diverge.
- AMEND-6: revoke+elect is atomic; stale proposals rejected by base_epoch/state_hash binding; no half-states.
- AMEND-7: offline nodes are never auto-revoked; revocation requires an explicit governance decision; a valid signature does not confer governance authority.
