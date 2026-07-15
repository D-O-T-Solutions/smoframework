#pragma once

#include <memory>
#include <system_error>
#include "core/intent/intent.h"
#include "compiler/graph/graph.h"

namespace smo {

// §XII.2 — Compiler Pipeline
//
// JSON/AST → SMIR → Semantic Validator → Planner → Builder → Optimizer → Final Validator → DAG

class Compiler {
public:
    virtual ~Compiler() = default;

    struct Result {
        ExecutionGraph graph;
        std::string    graph_hash;   // Blake3 of the serialized graph
    };

    virtual Result compile(const Intent& intent, std::error_code& ec) = 0;

    static std::unique_ptr<Compiler> create();
};

} // namespace smo
