# RFC 0004 — Trust and Reputation

## Status
ACCEPTED — incorporated into SPEC.md §XI.

## Problem
How should a node decide whether to trust another node it has never directly interacted with?

## Decisions
1. **Four independent components:** Citizen, Execution, Witness, Consistency.
2. **Composite formula:** Citizen×0.2 + Execution×0.5 + Witness×0.2 + Consistency×0.1.
3. **Decay over sliding window.** Scores never grow unbounded.
4. **Trust is local.** Each node computes its own scores. Trust digests are gossiped, not enforced.
5. **Trust is one input among many.** A high trust score does not bypass capability or policy checks.

## Rationale
- Decomposing trust into independent axes prevents gaming (e.g., pinging 24/7 to inflate a single score).
- Decay ensures recent behavior matters more than ancient history.
- Local computation preserves node sovereignty. Gossiped digests provide signal, not truth.
- Placing trust below capability and policy in the decision chain prevents trust-based privilege escalation.

## Consequences
- Trust engine is not needed for MVP. Stage 1–4 can use a simple binary trust (known vs unknown).
- Full scoring and gossip arrive in Stage 5–6.
