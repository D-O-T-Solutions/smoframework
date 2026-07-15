#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include "core/opcode/opcode.h"

namespace smo {

// §XII.1 — Execution DAG Format
//
// Internal immutable graph produced by the compiler.
// Invariant I-03: NEVER modified after compilation.

struct TaskNode {
    std::string       task_id;
    Opcode            opcode;
    std::vector<std::string> depends_on;   // task_id references
    std::string       parameters_json;
};

struct ExecutionGraph {
    std::string            graph_id;
    std::string            intent_id;
    std::vector<TaskNode>  nodes;
    int64_t                compiled_at{0};
};

} // namespace smo
