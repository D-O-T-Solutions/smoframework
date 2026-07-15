#pragma once

#include "compiler/graph/graph.h"
#include "core/contract/contract_interface.hpp"
#include "core/errors/error.hpp"

namespace smo {

class Executor {
public:
    Result<ExecutionResult> dispatch(
        const ContractID& id,
        const ExecutionContext& ctx);

    Result<ExecutionResult> execute(
        const ExecutionGraph& dag,
        const ExecutionContext& ctx);
};

} // namespace smo
