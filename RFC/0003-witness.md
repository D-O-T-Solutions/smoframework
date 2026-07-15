# RFC 0003 — Witness Protocol

## Status
ACCEPTED — incorporated into SPEC.md §VIII.

## Problem
How does a Responder gain confidence about a Requester's identity and intent without broadcasting to the entire mesh?

## Decisions
1. **Witness is not an arbiter.** It does not vote, decide, or execute.
2. **Witness is an independent attester.** It confirms: "I know both nodes. I have no adverse evidence."
3. **Selected by Responder**, not by Requester or by algorithm.
4. **Optional with fallback:** if no witness is available, the Responder decides locally.

## Rationale
- Broadcasting to all nodes does not scale and leaks operational context.
- A single trusted witness provides enough signal for most decisions.
- Responder sovereignty is preserved: the witness informs, the Responder decides.

## Consequences
- Witness discovery is part of the heartbeat protocol (nodes advertise witness availability).
- A witness timeout does not block execution — it degrades to local decision.
- Contract records from all three parties provide strong non-repudiation.
