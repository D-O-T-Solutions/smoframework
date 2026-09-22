#include <ctime>
#include <chrono>
#include "runtime/executor/executor.hpp"
#include "contract/registry/contract_registry.hpp"
#include "core/contract/contract_abi.hpp"
#include "core/crypto/hash_provider.hpp"
#include "core/runtime/telemetry.hpp"

namespace smo {

    Result<ExecutionResult> Executor::dispatch(const ContractID& id, const ExecutionContext& ctx)
    {
        auto& telemetry = runtime::global_telemetry();
        auto start_ns = std::chrono::steady_clock::now().time_since_epoch().count();

        auto abi = AbiRegistry::instance().get_abi(id);
        if (!abi)
        {
            telemetry.increment_counter("smo_contract_exec_total", "contract=" + id.to_hex() + ",result=abi_not_found");
            return SMO_ERR_RUNTIME(14, Error, NoRetry, None, "no ABI registered for contract");
        }

        if (!AbiRegistry::instance().verify_compatibility(id, "3.0.0"))
        {
            telemetry.increment_counter("smo_contract_exec_total", "contract=" + id.to_hex() + ",result=version_mismatch");
            return SMO_ERR_RUNTIME(15, Error, NoRetry, None, "runtime version incompatible with contract ABI");
        }

        ExecutionResult result;
        result.contract_id = id;
        result.success = true;
        result.output_json = "{}";
        result.started_at = static_cast<uint64_t>(std::time(nullptr));
        result.completed_at = result.started_at;

        auto end_ns = std::chrono::steady_clock::now().time_since_epoch().count();
        telemetry.increment_counter("smo_contract_exec_total", "contract=" + id.to_hex() + ",result=success");
        telemetry.record_histogram("smo_contract_exec_duration_ns", static_cast<double>(end_ns - start_ns), "contract=" + id.to_hex());

        return result;
    }

    Result<ExecutionResult> Executor::execute(const ExecutionGraph& dag, const ExecutionContext& ctx)
    {
        (void)ctx;
        auto& telemetry = runtime::global_telemetry();
        auto start_ns = std::chrono::steady_clock::now().time_since_epoch().count();

        ExecutionResult result;
        result.contract_id = ContractID::compute(dag.graph_id + std::to_string(dag.nodes.size()));
        result.success = true;
        result.started_at = static_cast<uint64_t>(std::time(nullptr));

        for (auto& node : dag.nodes)
        {
            (void)node;
        }

        result.completed_at = static_cast<uint64_t>(std::time(nullptr));

        auto end_ns = std::chrono::steady_clock::now().time_since_epoch().count();
        telemetry.increment_counter("smo_contract_dag_exec_total", "result=success");
        telemetry.record_histogram("smo_contract_dag_exec_duration_ns", static_cast<double>(end_ns - start_ns), "");

        return result;
    }

} // namespace smo
