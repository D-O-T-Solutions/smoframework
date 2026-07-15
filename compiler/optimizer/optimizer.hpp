#pragma once

#include "compiler/graph/graph.h"
#include "core/errors/error.hpp"

namespace smo {

class Optimizer {
public:
    Result<ExecutionGraph> optimize(const ExecutionGraph& graph);
};

} // namespace smo
