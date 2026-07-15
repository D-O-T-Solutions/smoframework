#include "compiler/optimizer/optimizer.hpp"
#include <unordered_set>

namespace smo {

Result<ExecutionGraph> Optimizer::optimize(const ExecutionGraph& graph) {
    ExecutionGraph result = graph;

    std::unordered_set<std::string> referenced;
    for (auto& node : result.nodes) {
        for (auto& dep : node.depends_on) {
            referenced.insert(dep);
        }
    }

    std::vector<TaskNode> pruned;
    for (auto& node : result.nodes) {
        if (node.task_id.empty()) continue;
        pruned.push_back(std::move(node));
    }
    result.nodes = std::move(pruned);

    return result;
}

} // namespace smo
