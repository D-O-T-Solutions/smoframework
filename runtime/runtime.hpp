#pragma once

#include "core/contract/contract_interface.hpp"
#include "core/errors/error.hpp"
#include "runtime/executor/executor.hpp"
#include "runtime/sandbox/sandbox.hpp"
#include "runtime/workerpool/workerpool.hpp"

namespace smo {

class Runtime {
public:
    Runtime();
    ~Runtime();

    Result<void> initialise();

    ExecutionResult execute(
        const ContractID& id,
        const ExecutionContext& ctx);

    Executor& executor() { return executor_; }
    Sandbox& sandbox() { return sandbox_; }
    WorkerPool& worker_pool() { return worker_pool_; }

private:
    Executor   executor_;
    Sandbox    sandbox_;
    WorkerPool worker_pool_;
};

} // namespace smo
