#include "runtime/runtime.hpp"
#include "contract/registry/contract_registry.hpp"
#include "core/contract/contract_abi.hpp"
#include "compiler/compiler.h"

namespace smo {

Runtime::Runtime() : worker_pool_(4) {}

Runtime::~Runtime() = default;

Result<void> Runtime::initialise() {
    Sandbox::Config sbox_cfg;
    auto result = sandbox_.initialise(sbox_cfg);
    if (!result) return result.error();
    return {};
}

ExecutionResult Runtime::execute(
    const ContractID& id,
    const ExecutionContext& ctx)
{
    auto abi_opt = AbiRegistry::instance().get_abi(id);
    if (!abi_opt) {
        ExecutionResult err;
        err.success = false;
        err.contract_id = id;
        err.errors.push_back(
            SMO_ERR_RUNTIME(14, Error, NoRetry, None,
                "no ABI registered for contract"));
        return err;
    }

    auto exec_result = executor_.dispatch(id, ctx);
    if (!exec_result) {
        ExecutionResult fail;
        fail.success = false;
        fail.contract_id = id;
        fail.errors.push_back(std::move(exec_result.error()));
        return fail;
    }

    return std::move(*exec_result);
}

} // namespace smo
