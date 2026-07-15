# RFC 0002 — Capability System

## Status
ACCEPTED — incorporated into SPEC.md §X.

## Problem
How to control what operations a node may request or execute?

## Decisions
1. **Capabilities, not roles.** The runtime knows only capability identifiers. R/W/X are presets.
2. **Ephemeral and session-scoped.** Capabilities are granted within a session and validated at runtime.
3. **Origin-sourced.** Only the Authority node can grant and revoke capabilities.
4. **Capability set is a bitset** — fast to check, small to transmit.

## Rationale
- Hardcoded roles (R/W/X) are inflexible and create implicit privilege escalation paths.
- Session scoping limits blast radius: a compromised session does not leak permanent capabilities.
- Origin sourcing creates a clear trust chain back to a single administrative root.

## Consequences
- Every opcode must declare its required capability mask.
- Policy evaluation is a simple subset check: intent capabilities ⊆ session capabilities.
