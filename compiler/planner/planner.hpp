#pragma once

#include <string>
#include <vector>
#include "compiler/smir/smir.hpp"
#include "core/errors/error.hpp"

namespace smo {

struct ExecutionPlan {
    std::string              contract_id;
    std::vector<std::string> target_nodes;
    std::vector<std::string> shard_keys;
    SmirModule               smir;
};

class Planner {
public:
    Result<ExecutionPlan> plan(const SmirModule& module, const std::string& contract_id);
};

} // namespace smo
