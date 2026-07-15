#include "contract/kernel/kernel_contracts.hpp"
#include "contract/registry/contract_registry.hpp"
#include "core/crypto/hash_provider.hpp"
#include <ctime>
#include <sstream>

namespace smo {

static ContractID make_kernel_id(const std::string& name) {
    auto& hp = HashProvider::default_provider();
    return ContractID::compute(hp.hash_hex("kernel:" + name));
}

static ContractABI make_kernel_abi(const std::string& name) {
    ContractABI abi;
    abi.abi_version = 1;
    abi.contract_name = name;
    abi.category = "kernel";
    abi.capability_mask = "00000000";
    abi.min_runtime_version = "3.0.0";
    abi.max_runtime_version = "99.99.99";
    abi.abi_hash = abi.compute_abi_hash();
    return abi;
}

static std::string make_kernel_json(const std::string& opcode, const std::string& name) {
    std::ostringstream os;
    os << R"({)";
    os << R"("contract_version":"1.0",)";
    os << R"("category":"kernel",)";
    os << R"("opcode":")" << opcode << R"(",)";
    os << R"("name":")" << name << R"(",)";
    os << R"("publisher":"00000000-0000-0000-0000-000000000000",)";
    os << R"("semver":"1.0.0",)";
    os << R"("parameters":[],)";
    os << R"("capabilities_required":{},)";
    os << R"("compiler_hints":{"max_parallelism":1,"timeout_sec":5,"idempotent":true},)";
    os << R"("signature":null)";
    os << R"(})";
    return os.str();
}

static ExecutionResult make_result(const ContractID& cid, const std::string& output) {
    ExecutionResult r;
    r.success = true;
    r.contract_id = cid;
    r.output_json = output;
    r.started_at = static_cast<uint64_t>(std::time(nullptr));
    r.completed_at = r.started_at;
    return r;
}

ContractID KernelPingContract::id() const { return make_kernel_id("ping"); }
ContractABI KernelPingContract::abi() const { return make_kernel_abi("ping"); }
Result<ExecutionResult> KernelPingContract::execute(
    const std::string& dag_json, const ExecutionContext& ctx)
{
    (void)dag_json;
    (void)ctx;
    return make_result(id(), "{\"status\":\"pong\",\"timestamp\":" +
        std::to_string(std::time(nullptr)) + "}");
}

ContractID KernelWhoamiContract::id() const { return make_kernel_id("whoami"); }
ContractABI KernelWhoamiContract::abi() const { return make_kernel_abi("whoami"); }
Result<ExecutionResult> KernelWhoamiContract::execute(
    const std::string& dag_json, const ExecutionContext& ctx)
{
    (void)dag_json;
    return make_result(id(),
        "{\"node_id\":\"" + ctx.requester_node_id + "\"}");
}

ContractID KernelSessionOpenContract::id() const { return make_kernel_id("session_open"); }
ContractABI KernelSessionOpenContract::abi() const { return make_kernel_abi("session_open"); }
Result<ExecutionResult> KernelSessionOpenContract::execute(
    const std::string& dag_json, const ExecutionContext& ctx)
{
    (void)dag_json;
    (void)ctx;
    return make_result(id(), "{\"session_id\":\"new-session\"}");
}

ContractID KernelSessionCloseContract::id() const { return make_kernel_id("session_close"); }
ContractABI KernelSessionCloseContract::abi() const { return make_kernel_abi("session_close"); }
Result<ExecutionResult> KernelSessionCloseContract::execute(
    const std::string& dag_json, const ExecutionContext& ctx)
{
    (void)dag_json;
    (void)ctx;
    return make_result(id(), "{\"closed\":true}");
}

ContractID KernelDiscoverContract::id() const { return make_kernel_id("discover"); }
ContractABI KernelDiscoverContract::abi() const { return make_kernel_abi("discover"); }
Result<ExecutionResult> KernelDiscoverContract::execute(
    const std::string& dag_json, const ExecutionContext& ctx)
{
    (void)dag_json;
    (void)ctx;
    return make_result(id(), "{\"peers\":[]}");
}

ContractID KernelNodeInfoContract::id() const { return make_kernel_id("node.info"); }
ContractABI KernelNodeInfoContract::abi() const { return make_kernel_abi("node.info"); }
Result<ExecutionResult> KernelNodeInfoContract::execute(
    const std::string& dag_json, const ExecutionContext& ctx)
{
    (void)dag_json;
    (void)ctx;
    return make_result(id(),
        "{\"version\":\"3.0.0\",\"uptime\":0,\"load\":0}");
}

ContractID KernelIdentityRotateContract::id() const { return make_kernel_id("identity.rotate"); }
ContractABI KernelIdentityRotateContract::abi() const { return make_kernel_abi("identity.rotate"); }
Result<ExecutionResult> KernelIdentityRotateContract::execute(
    const std::string& dag_json, const ExecutionContext& ctx)
{
    (void)dag_json;
    (void)ctx;
    return make_result(id(), "{\"rotated\":true,\"new_key\":\"pending\"}");
}

Result<void> register_kernel_contracts(ContractRegistry& registry) {
    registry.register_native(make_kernel_json("ping", "Ping"));
    registry.register_native(make_kernel_json("whoami", "Whoami"));
    registry.register_native(make_kernel_json("session_open", "Session Open"));
    registry.register_native(make_kernel_json("session_close", "Session Close"));
    registry.register_native(make_kernel_json("discover", "Discover"));
    registry.register_native(make_kernel_json("node.info", "Node Info"));
    registry.register_native(make_kernel_json("identity.rotate", "Identity Rotate"));
    return {};
}

} // namespace smo
