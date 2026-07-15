#pragma once

#include "compiler/graph/graph.h"
#include "core/errors/error.hpp"

namespace smo {

class FinalValidator {
public:
    struct Config {
        uint32_t max_depth{64};
        uint32_t max_width{256};
        uint32_t max_nodes{1024};
        bool     reject_cycles{true};
    };

    Result<ExecutionGraph> validate(const ExecutionGraph& graph, const Config& cfg);
};

} // namespace smo
