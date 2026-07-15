# transport/

Abstract communication layer. SMF NEVER depends on TCP directly.

## Design Rule (§IV Layer 7)
Transport is interchangeable. The runtime references only the `Transport` interface.

## Modules
- `tcp/`          — TCP transport implementation
- `quic/`         — QUIC transport (future)
- `relay/`        — Relay/proxy transport (future)
- `framing/`      — Message framing over stream transports (§VI)
- `serialization/`— Wire serialization/deserialization
