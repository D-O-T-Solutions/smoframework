#include "cross_mesh_router.hpp"

#include <core/runtime/telemetry.hpp>
#include <core/crypto/registry.hpp>

#include <chrono>
#include <random>
#include <sstream>

namespace smo::federation {

static int64_t now_ns()
{
    return static_cast<int64_t>(std::chrono::system_clock::now().time_since_epoch().count());
}

// ============================================================================
// CrossMeshRouter
// ============================================================================

CrossMeshRouter::CrossMeshRouter(const Config& config, ExecuteLocalFn execute_local, SendRemoteFn send_remote, OnResponseFn on_response)
    : config_(config), execute_local_(std::move(execute_local)), send_remote_(std::move(send_remote)), on_response_(std::move(on_response))
{
}

Result<void> CrossMeshRouter::add_route(const CrossMeshRouteEntry& route)
{
    if (route.destination_mesh == config_.local_mesh_id)
    {
        return Error(ErrorCode(ErrorCategory::Federation, 1, Severity::Error,
                               RetryClass::NoRetry, Recovery::None),
                     "Cannot add route to local mesh", __FILE__, __LINE__);
    }

    routes_[route.destination_mesh] = route;
    return {};
}

Result<void> CrossMeshRouter::remove_route(const std::string& destination_mesh)
{
    auto it = routes_.find(destination_mesh);
    if (it == routes_.end())
    {
        return Error(ErrorCode(ErrorCategory::Federation, 2, Severity::Warn,
                               RetryClass::NoRetry, Recovery::None),
                     "Route not found: " + destination_mesh, __FILE__, __LINE__);
    }
    routes_.erase(it);
    return {};
}

Result<CrossMeshRouteEntry> CrossMeshRouter::find_route(const std::string& destination_mesh) const
{
    auto it = routes_.find(destination_mesh);
    if (it == routes_.end())
    {
        return Error(ErrorCode(ErrorCategory::Federation, 3, Severity::Warn,
                               RetryClass::NoRetry, Recovery::None),
                     "No route to mesh: " + destination_mesh, __FILE__, __LINE__);
    }

    if (!it->second.healthy)
    {
        return Error(ErrorCode(ErrorCategory::Federation, 4, Severity::Warn,
                               RetryClass::RetryBackoff, Recovery::None),
                     "Route unhealthy: " + destination_mesh, __FILE__, __LINE__);
    }

    return it->second;
}

Result<std::string> CrossMeshRouter::execute_cross_mesh(const CrossMeshExecutionRequest& request)
{
    if (request.destination_mesh_id == config_.local_mesh_id)
    {
        return Error(ErrorCode(ErrorCategory::Federation, 5, Severity::Error,
                               RetryClass::NoRetry, Recovery::None),
                     "Cannot execute cross-mesh to local mesh", __FILE__, __LINE__);
    }

    auto route_result = find_route(request.destination_mesh_id);
    if (!route_result)
    {
        return route_result.error();
    }

    const auto& route = route_result.value();

    std::string request_id = generate_request_id();

    PendingRequest pending;
    pending.request_id = request_id;
    pending.request = request;
    pending.route = route;
    pending.sent_at = now_ns();
    pending.timeout_ns = request.timeout_ns;
    pending.response_received = false;

    if (pending_requests_.size() >= config_.max_pending_requests)
    {
        return Error(ErrorCode(ErrorCategory::Federation, 6, Severity::Error,
                               RetryClass::RetryBackoff, Recovery::None),
                     "Max pending requests reached", __FILE__, __LINE__);
    }

    pending_requests_[request_id] = std::move(pending);

    auto forward_result = forward_request(pending_requests_[request_id]);
    if (!forward_result)
    {
        pending_requests_.erase(request_id);
        return forward_result.error();
    }

    return request_id;
}

Result<void> CrossMeshRouter::handle_incoming_request(const std::string& request_id, const CrossMeshExecutionRequest& request)
{
    if (request.destination_mesh_id != config_.local_mesh_id)
    {
        auto route_result = find_route(request.destination_mesh_id);
        if (!route_result)
        {
            CrossMeshExecutionResponse response;
            response.success = false;
            response.error_message = "No route to destination mesh: " + request.destination_mesh_id;
            on_response_(request_id, response);
            return Error(ErrorCode(ErrorCategory::Federation, 7, Severity::Error,
                                  RetryClass::NoRetry, Recovery::None), "Failed to send response", __FILE__, __LINE__);
        }

        return forward_request(PendingRequest{request_id, request, route_result.value(), now_ns(), request.timeout_ns, false});
    }

    return execute_local_and_respond(request_id, request);
}

Result<void> CrossMeshRouter::handle_response(const std::string& request_id, const CrossMeshExecutionResponse& response)
{
    auto it = pending_requests_.find(request_id);
    if (it == pending_requests_.end())
    {
        return Error(ErrorCode(ErrorCategory::Federation, 8, Severity::Warn,
                               RetryClass::NoRetry, Recovery::None),
                     "No pending request: " + request_id, __FILE__, __LINE__);
    }

    it->second.response_received = true;
    on_response_(request_id, response);
    pending_requests_.erase(it);

    return Result<void>{};
}

void CrossMeshRouter::tick(int64_t now_ns)
{
    std::vector<std::string> timed_out;

    for (const auto& [id, pending] : pending_requests_)
    {
        if (!pending.response_received && (now_ns - pending.sent_at) > pending.timeout_ns)
        {
            timed_out.push_back(id);
        }
    }

    for (const auto& id : timed_out)
    {
        auto it = pending_requests_.find(id);
        if (it != pending_requests_.end())
        {
            CrossMeshExecutionResponse response;
            response.success = false;
            response.error_message = "Request timed out";
            on_response_(id, response);
            pending_requests_.erase(it);
        }
    }
}

Result<void> CrossMeshRouter::forward_request(const PendingRequest& pending)
{
    runtime::RuntimeContext ctx;
    ctx.info.mesh_id = pending.request.destination_mesh_id;
    ctx.vars.set("session_id", runtime::ContextValue(pending.request.session_id));

    // Serialize the request
    Bytes payload;
    // Simplified serialization - in practice would use CBOR
    return send_remote_(pending.request.destination_mesh_id, pending.route.gateway_session_id, payload);
}

Result<void> CrossMeshRouter::execute_local_and_respond(const std::string& request_id, const CrossMeshExecutionRequest& request)
{
    runtime::RuntimeContext ctx;
    ctx.info.mesh_id = config_.local_mesh_id;
    ctx.vars.set("session_id", runtime::ContextValue(request.session_id));

    auto result = execute_local_(request.contract_id, request.input, ctx);

    CrossMeshExecutionResponse response;
    response.execution_time_ns = now_ns();

    if (result)
    {
        response.success = true;
        response.result = result.value();
    }
    else
    {
        response.success = false;
        response.error_message = result.error().message;
    }

    on_response_(request_id, response);
    return Result<void>{};
}

std::string CrossMeshRouter::generate_request_id()
{
    std::ostringstream oss;
    oss << "xmesh-" << config_.local_mesh_id << "-" << next_request_id_++ << "-"
        << std::chrono::duration_cast<std::chrono::nanoseconds>(
               std::chrono::system_clock::now().time_since_epoch()).count();
    return oss.str();
}

} // namespace smo::federation