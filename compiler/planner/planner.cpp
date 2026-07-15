#include "compiler/planner/planner.hpp"

namespace smo {

Result<ExecutionPlan> Planner::plan(const SmirModule& module, const std::string& contract_id) {
    ExecutionPlan plan;
    plan.contract_id = contract_id;
    plan.smir = module;

    plan.target_nodes.push_back("local");

    return plan;
}

} // namespace smo
