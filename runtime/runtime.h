#pragma once

#include <memory>
#include <system_error>
#include "core/intent/intent.h"
#include "compiler/graph/graph.h"

namespace smo {

// §IV Layer 5 — Node Execution FSM
//
// The runtime is the heart of the system.
// It owns the scheduler, executor, sandbox, FSM, audit, and recovery subsystems.

class Runtime {
public:
    virtual ~Runtime() = default;

    // Submit an intent for execution.
    virtual std::error_code submit(const Intent& intent) = 0;

    // Execute a pre-compiled DAG.
    virtual std::error_code execute(const ExecutionGraph& dag) = 0;

    // Start the runtime event loop.
    virtual std::error_code run() = 0;

    // Graceful shutdown.
    virtual void shutdown() noexcept = 0;
};

} // namespace smo
