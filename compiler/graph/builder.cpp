#include "compiler/graph/builder.hpp"
#include "core/crypto/hash_provider.hpp"
#include <ctime>
#include <sstream>

namespace smo {

Result<ExecutionGraph> GraphBuilder::build(const ExecutionPlan& plan) {
    ExecutionGraph graph;
    graph.intent_id = plan.contract_id;

    auto& hp = HashProvider::default_provider();
    graph.graph_id = hp.hash_hex(plan.contract_id + std::to_string(std::time(nullptr)));

    int task_counter = 0;
    for (auto& block : plan.smir.blocks) {
        for (auto& inst : block.instructions) {
            if (inst.opcode == SmirOpcode::Call || inst.opcode == SmirOpcode::Seq) {
                TaskNode node;
                node.task_id = "t" + std::to_string(++task_counter);
                node.opcode = Opcode::CUSTOM;
                node.parameters_json = inst.annotation.empty() ? "{}" : inst.annotation;
                if (inst.opcode == SmirOpcode::Seq && task_counter > 1) {
                    node.depends_on.push_back("t" + std::to_string(task_counter - 1));
                }
                graph.nodes.push_back(std::move(node));
            }
        }
    }

    graph.compiled_at = std::time(nullptr);
    return graph;
}

} // namespace smo
