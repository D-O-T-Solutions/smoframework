# core/

Pure contracts and interfaces only. Zero business logic.

This layer defines the type system that the entire SMO runtime depends on.
Every invariant in the specification is reflected in these type definitions.

Modules:
- `intent/`      — Intent type definitions (§VII)
- `opcode/`      — Opcode enumeration and registry (§XVIII)
- `capability/`  — Capability type definitions (§X)
- `session/`     — Session type definitions
- `state/`       — State type definitions (§XIII)
- `errors/`      — Error type definitions

Rule: This directory MUST remain stable. No runtime logic, no dependencies
on transport, storage, or protocol.
