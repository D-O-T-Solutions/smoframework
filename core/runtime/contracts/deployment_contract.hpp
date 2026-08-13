#pragma once

#include "../contract_interface.hpp"
#include "../runtime_context.hpp"

#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

namespace smo::runtime {

    // DeploymentContract (RFC 0040 §4): deploy / undeploy / status / trace
    //
    // Manages the deployment lifecycle of contracts installed on a node.
    // Unlike the stateless native contracts (file/process), this contract
    // owns a persisted registry of deployed contract instances and their
    // lifecycle + execution trace events.
    //
    // Methods (method in payload):
    //   "deploy"    args { name, version, publisher?, description?, entry_point? }
    //   "undeploy"  args { contract_id, force? }
    //   "status"    args { contract_id }
    //   "list"      args {}
    //   "trace"     args { contract_id }
    class DeploymentContract final : public NativeContract
    {
    public:
        explicit DeploymentContract(std::string data_dir);

        Result<ContractResult> execute(const ContractInput& input, const RuntimeContext& ctx) override;

        ContractCapabilities required_capabilities() const override;

        static ContractMetadata default_metadata();

    private:
        struct DeployedContract
        {
            std::string contract_id;
            std::string name;
            std::string version;
            std::string publisher;
            std::string description;
            std::string entry_point;
            ContractLifecycleState state = ContractLifecycleState::Registered;
            int64_t registered_at_ns = 0;
            int64_t last_execution_at_ns = 0;
            std::vector<std::pair<int64_t, std::string>> events; // (ts_ns, label)
        };

        Result<ContractResult> handle_deploy(const ContractInput& input);
        Result<ContractResult> handle_undeploy(const ContractInput& input);
        Result<ContractResult> handle_status(const ContractInput& input);
        Result<ContractResult> handle_list(const ContractInput& input);
        Result<ContractResult> handle_trace(const ContractInput& input);

        void load_state();
        void persist_state();
        static std::string json_escape(const std::string& s);
        static std::string describe_state(ContractLifecycleState s);

        std::string data_dir_;
        std::unordered_map<std::string, DeployedContract> deployed_;
        std::vector<std::string> order_; // insertion order for stable listing
    };

} // namespace smo::runtime