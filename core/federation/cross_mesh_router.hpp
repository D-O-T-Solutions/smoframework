#pragma once

#include <core/errors/error.hpp>
#include <core/types.hpp>
#include <core/runtime/runtime_types.hpp>
#include <core/runtime/contract_interface.hpp>
#include <core/session/session.hpp>

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <functional>
#include <memory>

namespace smo::federation {

struct CrossMeshExecutionRequest
{
    std::string source_mesh_id;
    std::string destination_mesh_id;
    std::string contract_id;
    runtime::ContractInput input;
    std::string session_id;
    std::vector<std::string> capabilities;
    int64_t timeout_ns = 30'000'000'000LL; // 30s
};

struct CrossMeshExecutionResponse
{
    bool success = false;
    runtime::ContractResult result;
    std::string error_message;
    int64_t execution_time_ns = 0;
};

struct CrossMeshRouteEntry
{
    std::string destination_mesh;
    std::string gateway_session_id;
    std::string next_hop_gateway;
    uint32_t metric = 1;
    int64_t last_used = 0;
    bool healthy = true;
};

class CrossMeshRouter
{
public:
    struct Config
    {
        std::string local_mesh_id;
        std::string local_gateway_node_id;
        int64_t default_timeout_ns = 30'000'000'000LL;
        size_t max_pending_requests = 1000;
    };

    using ExecuteLocalFn = std::function<smo::Result<runtime::ContractResult>(const std::string& contract_id,
                                                                               const runtime::ContractInput& input,
                                                                               const runtime::RuntimeContext& ctx)>;
    using SendRemoteFn = std::function<smo::Result<void>(const std::string& destination_mesh,
                                                          const std::string& session_id,
                                                          smo::BytesView payload)>;
    using OnResponseFn = std::function<void(const std::string& request_id, const CrossMeshExecutionResponse& response)>;

    CrossMeshRouter(const Config& config, ExecuteLocalFn execute_local, SendRemoteFn send_remote, OnResponseFn on_response);
    ~CrossMeshRouter() = default;

    smo::Result<void> add_route(const CrossMeshRouteEntry& route);
    smo::Result<void> remove_route(const std::string& destination_mesh);
    smo::Result<CrossMeshRouteEntry> find_route(const std::string& destination_mesh) const;

    smo::Result<std::string> execute_cross_mesh(const CrossMeshExecutionRequest& request);
    smo::Result<void> handle_incoming_request(const std::string& request_id, const CrossMeshExecutionRequest& request);
    smo::Result<void> handle_response(const std::string& request_id, const CrossMeshExecutionResponse& response);

    void tick(int64_t now_ns);

private:
    struct PendingRequest
    {
        std::string request_id;
        CrossMeshExecutionRequest request;
        CrossMeshRouteEntry route;
        int64_t sent_at = 0;
        int64_t timeout_ns = 0;
        bool response_received = false;
    };

    Config config_;
    ExecuteLocalFn execute_local_;
    SendRemoteFn send_remote_;
    OnResponseFn on_response_;

    std::unordered_map<std::string, CrossMeshRouteEntry> routes_;
    std::unordered_map<std::string, PendingRequest> pending_requests_;
    uint64_t next_request_id_ = 1;

    smo::Result<void> forward_request(const PendingRequest& pending);
    smo::Result<void> execute_local_and_respond(const std::string& request_id, const CrossMeshExecutionRequest& request);
    std::string generate_request_id();
};

} // namespace smo::federation