#pragma once

#include <system_error>
#include "core/intent/intent.h"
#include "compiler/graph/graph.h"

namespace smo {

// §XII.2 — Compiler Pipeline
//
// INTENT → Parse → Capability Resolution → Node Planning
//        → DAG Generation → Optimization → Execution DAG
//
// Output DAG is immutable (Invariant I-03).

class Compiler {
public:
    virtual ~Compiler() = default;

    struct Result {
        ExecutionGraph graph;
        std::string    graph_hash;   // Blake3 of the serialized graph
    };

    virtual Result compile(const Intent& intent, std::error_code& ec) = 0;
};

} // namespace smo
