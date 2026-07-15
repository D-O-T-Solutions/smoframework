# Secure Mesh Operation (SMO)

Capability-scoped distributed execution runtime for untrusted mesh environments.
Designed for incident response, fleet operations, and intent-based orchestration.

## Current Status — Sprint 2.5

| Area | Status |
|---|---|
| **Crypto Suite Freeze** (RFC 0024) | ✅ 3 frozen suites: Classical (SHA-256 + Ed25519 + X25519), Modern (BLAKE3 + Ed25519 + X25519), PurePQC (BLAKE3 + ML-DSA-65 + ML-KEM-768) |
| **Contract Architecture** (RFC 0023) | ✅ OpcodeRegistry, ContractID, ContractDefinition, ContractFactory, native contracts |
| **Storage** | ✅ SQLite-backed: session, node, DAG, audit, trust stores |
| **Protocol** | ✅ Packet v1 (37-byte header), signing, encryption, replay protection |
| **Identity & Certificate** | ✅ Ed25519 keys, MembershipCertificate, enrollment flow (.smor/.smoc) |
| **Transport** | ✅ Abstract transport layer, TCP implementation, framing |
| **Platform** | 🔶 Linux Tier 1; Windows Tier 2 in progress |
| **31/31 tests passing** | 17 crypto + 14 contract (PQC=ON); 27/27 (PQC=OFF) |

## Documents

| Document | For |
|---|---|
| [SPEC.md](./SPEC.md) | Implementation — precise definitions, invariants, protocols |
| [ARCHITECTURE.md](./ARCHITECTURE.md) | Humans — rationale behind every design decision |
| [RFC/](./RFC/) | History — design change proposals (RFC 0006–0024) |
| [docs/STABILITY.md](./docs/STABILITY.md) | Frozen API/ABI registry |

## Repo Structure

```
cmd/          CLI entry points (smo-cli, smo-node, smo-admin, smo-debug)
core/         Type system — crypto, intents, opcodes, identity, sessions, contracts, FSM
compiler/     Intent → DAG compiler (graph, parser, planner, validator, optimizer)
runtime/      Execution engine, FSM, scheduler, sandbox, worker pool
protocol/     Wire format, packet, signing, encryption, replay, schema
providers/    Suite providers — Suite 1 Classical, Suite 2 Modern, Suite 3 PurePQC
transport/    Pluggable transport (TCP, QUIC, relay, serialization)
storage/      Per-node isolated stores (session, trust, audit, DAG, node)
trust/        Local trust scoring, decay, exchange, store
acl/          Capability policy engine, presets, revocation
sdk/          Client library and plugin interface
tooling/      Tracing, metrics, profiling, audit viewer
tests/        Unit, integration, mesh, chaos, replay, adversarial
third_party/  Bundled deps: Monocypher 4.0.2 (CC0)
```

## Build

Requires: CMake 3.20+, C++20 compiler, OpenSSL dev headers.

```sh
make configure  # cmake -B build -DWITH_PQC=ON
make build      # cmake --build build -j$(nproc)
make test       # ctest --test-dir build
```

| Flag | Default | Description |
|---|---|---|
| `-DWITH_PQC=ON/OFF` | ON | Build Suite 3 (PQC) with liboqs. Suites 1–2 still work when OFF. |

## Crypto Suites

| # | Name | Hash | Sign | KEM | AEAD |
|---|---|---|---|---|---|
| 1 | Classical | SHA-256 | Ed25519 (Monocypher) | X25519 (Monocypher) | XChaCha20-Poly1305 |
| 2 | Modern | BLAKE3 | Ed25519 (Monocypher) | X25519 (Monocypher) | XChaCha20-Poly1305 |
| 3 | PurePQC | BLAKE3 | ML-DSA-65 (liboqs) | ML-KEM-768 (liboqs) | XChaCha20-Poly1305 |

## License

Apache 2.0 — see [LICENSE](./LICENSE).
Copyright (c) 2026 Nguyen Duc Canh / Distributed Offensive Technology Solutions Co., Ltd.
