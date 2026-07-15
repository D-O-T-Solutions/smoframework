# RFC 0025 — Contract Runtime Architecture

| Field | Value |
|---|---|
| Status | Accepted |
| Author | SMO Architecture |
| Date | 2026-07-16 |
| Supersedes | RFC 0023 (Contract Architecture) |

## Summary

This RFC defines the complete **Contract Runtime Layer**: the compiler pipeline,
executor, kernel contracts, and the single `Runtime::execute()` interface that
unifies all contract categories.

## Motivation

Sprint 2.5 delivered the contract data model (ContractID, ContractDefinition,
Registry, Factory) and a compiler skeleton. What remains is the actual runtime
pipeline that compiles and executes contracts. This RFC fills that gap.

Without this layer, every new feature requires modifying the runtime core.
With it, new features are just new contracts registered in the registry.

## Architecture

### Contract Categories

```
┌─────────────────────────────────────┐
│         Kernel Contracts            │  0x00–0x0F
│  ping, whoami, session_open, ...    │  Trusted, bypass sandbox
├─────────────────────────────────────┤
│        Native Contracts             │  0x10–0x7F
│  ls, put, get, exec, quarantine, ...│  Built-in, capability-gated
├─────────────────────────────────────┤
│     Mesh / Private Contracts        │  0x80+
│  User-defined, plugin, community    │  Sandboxed, signed, audited
└─────────────────────────────────────┘
```

The runtime does NOT distinguish between these categories at dispatch time.
Category affects **sandbox policy** only.

### Single Runtime Interface

```cpp
// The ONLY entry point for contract execution
ExecutionResult Runtime::execute(
    const ContractID& id,
    const ExecutionContext& ctx
);
```

The runtime:
1. Resolves `ContractID` via `ContractRegistry`
2. Checks DAG cache (keyed by `ContractID + env_fingerprint`)
3. On cache miss: calls `Compiler::compile(intent, definition)` → caches DAG
4. Dispatches each DAG task node through `Executor`
5. Returns `ExecutionResult`

### Compiler Pipeline

```
Contract JSON / DSL / YAML / AI-gen
          ↓
     ┌──────────┐
     │  Parser   │  ContractDefinition → AST
     └──────────┘
          ↓
     ┌──────────┐
     │    AST    │  Opcodes, operands, edges, conditions
     └──────────┘
          ↓
     ┌──────────┐
     │   SMIR    │  SMO Intermediate Representation — canonical IR
     └──────────┘
          ↓
     ┌──────────┐
     │ Semantic  │  ABI hash match, capability check, dep check
     │ Validator │  (Pass 1 — source validation)
     └──────────┘
          ↓
     ┌──────────┐
     │  Planner  │  Target node selection, shard mapping
     └──────────┘
          ↓
     ┌──────────┐
     │  Builder  │  SMIR → ExecutionGraph (DAG)
     └──────────┘
          ↓
     ┌──────────┐
     │ Optimizer │  Prune, merge reads, fold constants
     └──────────┘
          ↓
     ┌──────────┐
     │  Final    │  Acyclic, max depth, reachability
     │ Validator │  (Pass 2 — structural validation)
     └──────────┘
          ↓
     ExecutionGraph (DAG)
```

**Why SMIR?** SMIR is the canonical IR that decouples input formats (JSON,
DSL, YAML, AI-generated) from the DAG. Any frontend that produces SMIR can
use the same downstream pipeline. This is the LLVM/MLIR philosophy.

### Executor

The executor is **ignorant** of contract category:

```cpp
struct Executor {
    // Resolve contract, check cache, execute DAG
    Result<ExecutionResult> dispatch(
        const ContractID& id,
        const Session& session
    );

    // Execute a compiled DAG (no resolution)
    Result<ExecutionResult> execute(
        const ExecutionGraph& dag,
        const Session& session
    );
};
```

Each DAG task node is dispatched through:
- **Kernel**: inline (trusted, no sandbox)
- **Native**: capability gate → sandbox → execute
- **Mesh/Private**: capability gate → sandbox → audit → execute

The dispatch table is a simple function pointer map, not an if-else chain.

### Kernel Contracts

Registered polymorphically, not hardcoded:

```cpp
registry.register_kernel("ping",             KernelPingContract{});
registry.register_kernel("whoami",           KernelWhoamiContract{});
registry.register_kernel("session_open",     KernelSessionOpenContract{});
registry.register_kernel("session_close",    KernelSessionCloseContract{});
registry.register_kernel("discover",         KernelDiscoverContract{});
registry.register_kernel("node.info",        KernelNodeInfoContract{});
registry.register_kernel("identity.rotate",  KernelIdentityRotateContract{});
```

All implement a unified `Contract` interface:

```cpp
struct Contract {
    virtual ~Contract() = default;
    virtual ContractID id() const = 0;
    virtual ContractCategory category() const = 0;
    virtual ContractABI abi() const = 0;
    virtual Result<ExecutionResult> execute(
        const ExecutionGraph& dag,
        const Session& session
    ) = 0;
};
```

### Sandbox

| Category | Sandbox | Notes |
|----------|---------|-------|
| Kernel | None | Runs in executor trusted context |
| Native | Capability gate | Pre-execution capability check |
| Mesh/Private | Seccomp + namespace | Full isolation, audit trail |

### Worker Pool

- Thread pool for parallel DAG task execution
- Tasks scheduled based on dependency edges
- Configurable max concurrency per session

## Key Design Decisions

### Why not compile JSON directly?

Because JSON is not an IR. JSON → AST → SMIR → DAG decouples the input
format from the compilation pipeline. Future frontends (DSL, YAML, visual
workflow, AI generator) all lower to SMIR and reuse the same optimizer,
planner, and executor.

### Why 2-pass validation?

LLVM has two verifier passes: one for the IR (module verification) and one
during codegen. SMIR follows the same pattern:
- **Pass 1 (Semantic)**: validate against Contract ABI before planning
- **Pass 2 (Final)**: validate the completed DAG before execution

### Why polymorphic kernel registration?

Traditional runtimes hardcode opcodes as if-else chains. SMO uses
polymorphic dispatch via `Contract` interface. Adding a new kernel contract
requires:
1. Implement `Contract` for the new kernel
2. Register it with a name
3. Done — zero changes to executor or runtime

## Dependencies

```
contract/ (registry, factory, native)
    ↓
compiler/ (parser, AST, SMIR, validator, planner, builder, optimizer)
    ↓
runtime/  (executor, sandbox, worker pool)
```

Compiler does NOT depend on Runtime. Executor does NOT depend on contract
category definitions.

## Files Changed

| File | Change |
|------|--------|
| `compiler/ast/ast.hpp/.cpp` | New — AST node types |
| `compiler/smir/smir.hpp/.cpp` | New — SMIR opcodes, IR lowering |
| `compiler/parser/parser.hpp/.cpp` | New — JSON → AST (replace stub) |
| `compiler/validator/semantic.hpp/.cpp` | New — Pass 1 validator |
| `compiler/validator/final.hpp/.cpp` | New — Pass 2 validator |
| `compiler/planner/planner.hpp/.cpp` | New — Target selection (replace stub) |
| `compiler/graph/builder.hpp/.cpp` | New — SMIR → DAG |
| `compiler/optimizer/optimizer.hpp/.cpp` | New — DAG optimization passes |
| `compiler/compiler.cpp` | New — Concrete Compiler class |
| `runtime/executor/executor.hpp/.cpp` | New — Executor implementation |
| `runtime/sandbox/sandbox.hpp/.cpp` | New — Sandbox isolation |
| `runtime/workerpool/workerpool.hpp/.cpp` | New — Thread pool |
| `runtime/runtime.hpp/.cpp` | New — Runtime::execute() |
| `contract/registry/contract_registry.hpp/.cpp` | Add register_kernel(), category support |
| `core/contract/contract_definition.hpp` | Add ContractCategory enum (Kernel/Native/Mesh/Private) |
| `core/contract/contract_abi.hpp/.cpp` | New — Contract ABI struct + ABI Hash |
| `core/contract/contract_interface.hpp` | New — Abstract Contract interface |

## Migration

No breaking changes. Existing Native contracts continue to work.
The old `Compiler` abstract class is replaced by the concrete pipeline.
Old stubs in `compiler/parser/`, `compiler/planner/`, etc. are deleted.
