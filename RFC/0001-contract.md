# RFC 0001 — Contract Model

## Status
ACCEPTED — incorporated into SPEC.md §VII.

## Problem
How should two or more nodes express intent and reach agreement on execution?

## Decisions
1. **Contract ≠ Data.** A contract describes intent, never carries payload.
2. **Three-party model:** Requester proposes, Responder executes, Witness attests.
3. **Contract is JSON/YAML** in MVP; a DSL (`.seme`) may follow.
4. **Record stored by all three participants** for non-repudiation.

## Rationale
- Keeping data out of contracts keeps contracts small, signable, and auditable.
- Three-party model avoids broadcast overhead while providing independent evidence.
- JSON/YAML lowers the barrier for MVP; DSL adds safety later.

## Consequences
- Large data transfers need a separate channel referenced by hash.
- Contract validation is stateless (just check fields and signatures).
