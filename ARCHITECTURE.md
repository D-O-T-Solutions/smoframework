# SMO Architecture — Rationale and Design Decisions

This document explains **why** SMO is built the way it is.
It is not a specification. For precise definitions, see [SPEC.md](./SPEC.md).

---

## Why Contract?

Most distributed systems communicate via RPC or message passing.
SMO communicates via **contracts**.

A contract is a signed, metadata-only document that describes **what** should happen,
not **how**. The receiving node evaluates the contract against its own policy,
capabilities, and trust observations before deciding whether to execute.

This shifts the model from "tell a node what to do" to "propose to a node what could be done."
The node remains sovereign — it always has the final say.

Contracts also create a natural audit trail. Every execution is backed by a signed
document that all participants store independently. This is non-repudiation without
blockchain.

---

## Why Witness?

Broadcasting every operation to every node does not scale.
Asking a single trusted third party for an attestation is cheap and sufficient for most decisions.

The witness is not a consensus participant. It does not vote. It does not decide.
It simply says: "I know these two nodes, and I have no reason to believe anything is wrong."

This gives the Responder an independent signal without requiring a global broadcast.
If no witness is available, the Responder falls back to its local judgment
— the system degrades gracefully instead of halting.

---

## Why Capability (not Role)?

Roles (reader, writer, admin) are coarse and implicit.
A role-based system says: "you are an admin, so you can do everything."

A capability-based system says: "you have been granted CAP_FS_WRITE on /shared for this session."
The grant is explicit, scoped to a session, and must be presented at execution time.

This makes every permission visible, auditable, and bounded.
There is no implicit escalation. There is no "admin" key that unlocks everything.
Every opcode carries the capability set it needs, and the runtime verifies it.

R/W/X still exist — but only as convenience presets that map to capability sets.
The runtime itself does not know what "reader" means. It only knows capability bits.

---

## Why No Global State?

Global state is the single biggest source of complexity in distributed systems.
It requires consensus, replication, conflict resolution, and recovery protocols —
all before you have shipped a single feature.

SMO rejects global state by design.

Every node maintains its own session store, trust store, audit store, and DAG store.
The only thing shared between nodes is evidence: signed contracts, trust digests,
and attestations. There is no global ledger. There is no "cluster state."

This means SMO is eventually consistent by construction.
Two nodes may disagree about a trust score — and that is fine.
The Responder uses its local view to decide. If the view is wrong, the evidence
exists to correct it later.

---

## Why DAG (Directed Acyclic Graph)?

A linear execution queue is simple but wasteful.
Tasks that do not depend on each other should run in parallel.
A FIFO queue cannot express this.

A DAG captures dependencies explicitly. Task B depends on Task A; Task C depends on nothing.
The scheduler reads the graph and runs C immediately, A next, and B only after A finishes.

The DAG is produced once by the compiler and **never modified**.
This guarantees that all nodes involved in an execution see the same plan.
Replaying the execution against the original DAG always produces the same result.

---

## Why Trust Is Local (and Not Absolute)?

If trust were global and absolute, every node would need to agree on every other node's
reputation before making any decision. That is consensus — and consensus is slow, brittle,
and requires a global view that SMO explicitly does not have.

SMO treats trust as a local estimate. Every node computes scores based on its own
observations: heartbeat success, contract outcomes, witness feedback, and consistency checks.

These scores are gossiped as digests, but no node is required to accept another node's
score as truth. The Responder blends its local score with the witness's signal
and makes its own decision.

This design is more resilient. A compromised node can lie about its own trust score,
but it cannot force other nodes to believe that lie.

---

## Why Node Sovereignty?

In SMO, the Responder always has the final decision.
No contract is executed unless the executing node agrees.

This is not a bug. It is a feature.

In incident response, you want every node to be able to say "no" if the contract
violates local policy, even if the requester has the highest authority.
In fleet operations, you want each machine to validate an update against its own
OS version, patch level, and health status before applying it.

Sovereignty also limits blast radius. A compromised Authority node can send malicious
contracts, but every other node independently evaluates them. One bad actor cannot
force a fleet-wide compromise.

---

## Why These Seven Layers?

```
CLI / SDK
Intent Language
Execution Compiler
DAG Scheduler
Node Execution FSM
Consensus + Trust Engine
Transport Abstraction
```

Each layer has exactly one responsibility. No layer bypasses the layer below it.

- **CLI/SDK** is the user's entry point. It speaks in intents.
- **Intent Language** is the contract format (JSON/YAML today, .seme tomorrow).
- **Compiler** turns intent into a DAG.
- **Scheduler** walks the DAG and dispatches tasks.
- **FSM** governs the lifecycle of each execution on each node.
- **Trust engine** provides decision support (not decision authority).
- **Transport** is a pluggable abstraction (TCP today, QUIC tomorrow).

The layering guarantees that you can replace any layer without affecting the others.
Swap TCP for QUIC? The FSM does not change.
Swap JSON for FlatBuffers? The scheduler does not change.
Swap the trust formula? The contract format does not change.

---

## Key Architectural Properties

| Property | How SMO Achieves It |
|---|---|
| Non-repudiation | Three-party contract records (Requester, Responder, Witness) |
| No single point of failure | No global state; witness fallback to local decision |
| Graceful degradation | Fewer witnesses → local decision. No quorum required |
| Deterministic execution | Immutable DAG + auditable FSM transitions |
| Composable permissions | Capability bitsets; opcodes declare requirements |
| Pluggable transport | Transport interface abstracted from runtime |
| Local autonomy | Responder always has final execution authority |

---

## What SMO Is Not

SMO is not a blockchain. There is no global ledger, no consensus protocol,
no miners, no gas, no on-chain state.

SMO is not a message queue. Contracts are not events. They are executable intents
with authorization, policy, and audit baked in.

SMO is not a remote shell. SSH executes what you tell it. SMO evaluates what you propose.

SMO is not Kubernetes. It does not schedule containers. It schedules execution intents
across a trust-scoped mesh.
