#pragma once

#include "compiler/graph/graph.h"
#include "compiler/planner/planner.hpp"
#include "core/errors/error.hpp"

namespace smo {

class GraphBuilder {
public:
    Result<ExecutionGraph> build(const ExecutionPlan& plan);
};

} // namespace smo
