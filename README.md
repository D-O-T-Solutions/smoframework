# Secure Mesh Operation

Capability-scoped distributed execution runtime for untrusted mesh environments.

SMO is an open-source distributed runtime designed for incident response,
fleet operations, and intent-based orchestration.

## Documents

| Document | For |
|---|---|
| [SPEC.md](./SPEC.md) | Implementation — precise definitions, invariants, protocols |
| [ARCHITECTURE.md](./ARCHITECTURE.md) | Humans — rationale behind every design decision |
| [RFC/](./RFC/) | History — design change proposals and their resolution |

## Repo Structure

```
cmd/         CLI entry points (smo-cli, smo-node, smo-admin, smo-debug)
core/        Type system — intents, opcodes, capabilities, sessions, state
compiler/    Intent → DAG compiler
runtime/     Execution engine, FSM, scheduler, sandbox
protocol/    Wire format, packet, signing, encryption
transport/   Pluggable transport (TCP, QUIC, relay)
storage/     Per-node isolated stores (session, trust, audit, DAG, node)
trust/       Local trust scoring and gossip exchange
acl/         Capability policy engine and presets
sdk/         Client library and plugin interface
tooling/     Tracing, metrics, profiling, audit viewer
tests/       Unit, integration, mesh, chaos, replay, adversarial
reference/   Legacy OLD_SHELLMAP (consult for implementation patterns only)
```

## Build

```sh
make configure
make build
make test
```

Requires: CMake 3.20+, C++20 compiler, OpenSSL dev headers.

## License

Apache 2.0 — see [LICENSE](./LICENSE).
Copyright (c) 2026 Nguyen Duc Canh / Distributed Offensive Technology Solutions Co., Ltd.
