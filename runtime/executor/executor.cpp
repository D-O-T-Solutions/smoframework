#include <ctime>
#include "runtime/executor/executor.hpp"
#include "contract/registry/contract_registry.hpp"
#include "core/contract/contract_abi.hpp"
#include "core/crypto/hash_provider.hpp"

namespace smo {

Result<ExecutionResult> Executor::dispatch(
    const ContractID& id,
    const ExecutionContext& ctx)
{
    auto abi = AbiRegistry::instance().get_abi(id);
    if (!abi) {
        return SMO_ERR_RUNTIME(14, Error, NoRetry, None,
            "no ABI registered for contract");
    }

    if (!AbiRegistry::instance().verify_compatibility(id, "3.0.0")) {
        return SMO_ERR_RUNTIME(15, Error, NoRetry, None,
            "runtime version incompatible with contract ABI");
    }

    ExecutionResult result;
    result.contract_id = id;
    result.success = true;
    result.output_json = "{}";
    result.started_at = static_cast<uint64_t>(std::time(nullptr));
    result.completed_at = result.started_at;
    return result;
}

Result<ExecutionResult> Executor::execute(
    const ExecutionGraph& dag,
    const ExecutionContext& ctx)
{
    (void)ctx;

    ExecutionResult result;
    result.contract_id = ContractID::compute(
        dag.graph_id + std::to_string(dag.nodes.size()));
    result.success = true;
    result.started_at = static_cast<uint64_t>(std::time(nullptr));

    for (auto& node : dag.nodes) {
        (void)node;
    }

    result.completed_at = static_cast<uint64_t>(std::time(nullptr));
    return result;
}

} // namespace smo
