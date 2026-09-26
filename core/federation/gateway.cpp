#include "gateway.hpp"
#include "policy_federation.hpp"

#include <core/crypto/impl.hpp>
#include <core/certificate/certificate.hpp>
#include <core/runtime/telemetry.hpp>
#include <core/identity/identity.hpp>

#include <chrono>
#include <fstream>
#include <iostream>
#include <sstream>

namespace smo::federation {

static int64_t now_ns()
{
    return static_cast<int64_t>(std::chrono::system_clock::now().time_since_epoch().count());
}

static std::string make_policy_key(const std::string& source, const std::string& dest)
{
    return source + "->" + dest;
}

// ============================================================================
// CrossMeshRoutingTable
// ============================================================================

CrossMeshRoutingTable::CrossMeshRoutingTable(const Config& config) : config_(config) {}

smo::Result<void> CrossMeshRoutingTable::add_mesh(const MeshInfo& mesh)
{
    if (mesh.mesh_id == config_.local_mesh_id)
    {
        return smo::Error(smo::ErrorCode(smo::ErrorCategory::Federation, 1, smo::Severity::Error,
                               smo::RetryClass::NoRetry, smo::Recovery::None),
                     "Cannot add local mesh as remote mesh", __FILE__, __LINE__);
    }
    if (meshes_.find(mesh.mesh_id) != meshes_.end())
    {
        return smo::Error(smo::ErrorCode(smo::ErrorCategory::Federation, 2, smo::Severity::Error,
                               smo::RetryClass::NoRetry, smo::Recovery::None),
                     "Mesh already exists: " + mesh.mesh_id, __FILE__, __LINE__);
    }
    meshes_[mesh.mesh_id] = mesh;
    return {};
}

smo::Result<void> CrossMeshRoutingTable::remove_mesh(const std::string& mesh_id)
{
    auto it = meshes_.find(mesh_id);
    if (it == meshes_.end())
    {
        return smo::Error(smo::ErrorCode(smo::ErrorCategory::Federation, 2, smo::Severity::Warn,
                               smo::RetryClass::NoRetry, smo::Recovery::None),
                     "Mesh not found: " + mesh_id, __FILE__, __LINE__);
    }
    meshes_.erase(it);
    routes_.erase(mesh_id);
    return {};
}

smo::Result<MeshInfo> CrossMeshRoutingTable::get_mesh(const std::string& mesh_id) const
{
    auto it = meshes_.find(mesh_id);
    if (it == meshes_.end())
    {
        return smo::Error(smo::ErrorCode(smo::ErrorCategory::Federation, 3, smo::Severity::Warn,
                               smo::RetryClass::NoRetry, smo::Recovery::None),
                     "Mesh not found: " + mesh_id, __FILE__, __LINE__);
    }
    return it->second;
}

std::vector<MeshInfo> CrossMeshRoutingTable::list_meshes() const
{
    std::vector<MeshInfo> result;
    result.reserve(meshes_.size());
    for (const auto& [id, mesh] : meshes_)
    {
        result.push_back(mesh);
    }
    return result;
}

smo::Result<void> CrossMeshRoutingTable::add_route(const CrossMeshRoute& route)
{
    if (route.destination_mesh_id == config_.local_mesh_id)
    {
        return smo::Error(smo::ErrorCode(smo::ErrorCategory::Federation, 4, smo::Severity::Error,
                               smo::RetryClass::NoRetry, smo::Recovery::None),
                     "Cannot add route to local mesh", __FILE__, __LINE__);
    }

    auto mesh_it = meshes_.find(route.destination_mesh_id);
    if (mesh_it == meshes_.end())
    {
        return smo::Error(smo::ErrorCode(smo::ErrorCategory::Federation, 5, smo::Severity::Error,
                               smo::RetryClass::NoRetry, smo::Recovery::None),
                     "Destination mesh not registered: " + route.destination_mesh_id, __FILE__, __LINE__);
    }

    routes_[route.destination_mesh_id] = route;
    return {};
}

smo::Result<void> CrossMeshRoutingTable::remove_route(const std::string& destination_mesh)
{
    auto it = routes_.find(destination_mesh);
    if (it == routes_.end())
    {
        return smo::Error(smo::ErrorCode(smo::ErrorCategory::Federation, 6, smo::Severity::Warn,
                               smo::RetryClass::NoRetry, smo::Recovery::None),
                     "Route not found: " + destination_mesh, __FILE__, __LINE__);
    }
    routes_.erase(it);
    return {};
}

smo::Result<CrossMeshRoute> CrossMeshRoutingTable::find_route(const std::string& destination_mesh) const
{
    auto it = routes_.find(destination_mesh);
    if (it == routes_.end())
    {
        return smo::Error(smo::ErrorCode(smo::ErrorCategory::Federation, 7, smo::Severity::Warn,
                               smo::RetryClass::NoRetry, smo::Recovery::None),
                     "No route to mesh: " + destination_mesh, __FILE__, __LINE__);
    }
    return it->second;
}

std::vector<CrossMeshRoute> CrossMeshRoutingTable::list_routes() const
{
    std::vector<CrossMeshRoute> result;
    result.reserve(routes_.size());
    for (const auto& [id, route] : routes_)
    {
        result.push_back(route);
    }
    return result;
}

smo::Result<void> CrossMeshRoutingTable::update_mesh_health(const std::string& mesh_id, bool healthy)
{
    auto it = meshes_.find(mesh_id);
    if (it == meshes_.end())
    {
        return smo::Error(smo::ErrorCode(smo::ErrorCategory::Federation, 8, smo::Severity::Warn,
                               smo::RetryClass::NoRetry, smo::Recovery::None),
                     "Mesh not found: " + mesh_id, __FILE__, __LINE__);
    }
    it->second.healthy = healthy;
    return {};
}

smo::Result<void> CrossMeshRoutingTable::update_mesh_sync_time(const std::string& mesh_id, int64_t now)
{
    auto it = meshes_.find(mesh_id);
    if (it == meshes_.end())
    {
        return smo::Error(smo::ErrorCode(smo::ErrorCategory::Federation, 9, smo::Severity::Warn,
                               smo::RetryClass::NoRetry, smo::Recovery::None),
                     "Mesh not found: " + mesh_id, __FILE__, __LINE__);
    }
    it->second.last_sync = now;
    return {};
}

void CrossMeshRoutingTable::set_gateway_policy(const GatewayPolicy& policy)
{
    policies_[make_policy_key(policy.source_mesh, policy.destination_mesh)] = policy;
}

smo::Result<GatewayPolicy> CrossMeshRoutingTable::get_gateway_policy(const std::string& source_mesh, const std::string& dest_mesh) const
{
    auto it = policies_.find(make_policy_key(source_mesh, dest_mesh));
    if (it == policies_.end())
    {
        GatewayPolicy default_policy;
        default_policy.name = "default";
        default_policy.source_mesh = source_mesh;
        default_policy.destination_mesh = dest_mesh;
        default_policy.default_decision = acl::PolicyDecision::Allow;
        return default_policy;
    }
    return it->second;
}

std::vector<GatewayPolicy> CrossMeshRoutingTable::list_gateway_policies() const
{
    std::vector<GatewayPolicy> result;
    result.reserve(policies_.size());
    for (const auto& [key, policy] : policies_)
    {
        result.push_back(policy);
    }
    return result;
}

smo::Result<bool> CrossMeshRoutingTable::check_route_policy(const std::string& source_mesh, const std::string& dest_mesh,
                                                        const std::string& contract_id, const std::vector<std::string>& capabilities) const
{
    auto policy_result = get_gateway_policy(source_mesh, dest_mesh);
    if (!policy_result)
    {
        return false;
    }

    const auto& policy = policy_result.value();

    if (!policy.enabled)
    {
        return policy.default_decision == acl::PolicyDecision::Allow;
    }

    // Explicit deny takes precedence
    if (!policy.denied_contracts.empty())
    {
        for (const auto& denied : policy.denied_contracts)
        {
            if (denied == contract_id)
            {
                return false;
            }
        }
    }

    // Explicit allow with capability check
    if (!policy.allowed_contracts.empty())
    {
        bool allowed = false;
        for (const auto& allowed_contract : policy.allowed_contracts)
        {
            if (allowed_contract == contract_id)
            {
                allowed = true;
                break;
            }
        }
        if (!allowed)
        {
            return false;
        }
        // Check required capabilities for explicitly allowed contracts
        for (const auto& required_cap : policy.required_capabilities)
        {
            bool has_cap = false;
            for (const auto& cap : capabilities)
            {
                if (cap == required_cap)
                {
                    has_cap = true;
                    break;
                }
            }
            if (!has_cap)
            {
                return false;
            }
        }
        // Explicitly allowed and all capabilities met
        return true;
    }

    // No explicit allow rule, use default decision
    return policy.default_decision == acl::PolicyDecision::Allow;
}

// ============================================================================
// GatewayNode
// ============================================================================

GatewayNode::GatewayNode(const Config& config, const Dependencies& deps)
    : config_(config)
    , deps_(deps)
    , routing_table_({config.local_mesh_id, config.gateway_node_id})
    , policy_federation_({config.local_mesh_id, config.data_dir}, *deps.policy_engine)
{
}

GatewayNode::~GatewayNode()
{
    shutdown();
}

smo::Result<void> GatewayNode::initialize()
{
    return policy_federation_.initialize();
}

void GatewayNode::shutdown()
{
    for (const auto& [mesh_id, session_id] : mesh_sessions_)
    {
        deps_.session_mgr->close(session_id, smo::federation::now_ns());
    }
    mesh_sessions_.clear();
}

smo::Result<void> GatewayNode::connect_to_mesh(const std::string& remote_mesh_id, const std::vector<smo::Endpoint>& gateway_endpoints)
{
    if (gateway_endpoints.empty())
    {
        return smo::Error(smo::ErrorCode(smo::ErrorCategory::Federation, 10, smo::Severity::Error,
                               smo::RetryClass::NoRetry, smo::Recovery::None),
                      "No gateway endpoints provided", __FILE__, __LINE__);
    }

    for (const auto& endpoint : gateway_endpoints)
    {
        auto handshake_result = perform_federation_handshake(remote_mesh_id, endpoint);
        if (handshake_result)
        {
            return handshake_result;
        }
    }

    return smo::Error(smo::ErrorCode(smo::ErrorCategory::Federation, 11, smo::Severity::Error,
                               smo::RetryClass::RetryBackoff, smo::Recovery::ManualIntervention),
                  "Failed to connect to any gateway endpoint for mesh: " + remote_mesh_id, __FILE__, __LINE__);
}

smo::Result<void> GatewayNode::disconnect_mesh(const std::string& remote_mesh_id)
{
    auto session_it = mesh_sessions_.find(remote_mesh_id);
    if (session_it != mesh_sessions_.end())
    {
        deps_.session_mgr->close(session_it->second, smo::federation::now_ns());
        mesh_sessions_.erase(session_it);
    }

    routing_table_.update_mesh_health(remote_mesh_id, false);
    return {};
}

smo::Result<smo::Session*> GatewayNode::get_mesh_session(const std::string& remote_mesh_id)
{
    auto session_it = mesh_sessions_.find(remote_mesh_id);
    if (session_it == mesh_sessions_.end())
    {
        return smo::Error(smo::ErrorCode(smo::ErrorCategory::Federation, 12, smo::Severity::Warn,
                               smo::RetryClass::NoRetry, smo::Recovery::None),
                     "No active session to mesh: " + remote_mesh_id, __FILE__, __LINE__);
    }

    auto* session = deps_.session_mgr->lookup(session_it->second);
    if (!session || session->state() != smo::SessionState::Established)
    {
return smo::Error(smo::ErrorCode(smo::ErrorCategory::Federation, 13, smo::Severity::Warn,
                               smo::RetryClass::RetrySafe, smo::Recovery::Reconnect),
                      "Session not established to mesh: " + remote_mesh_id, __FILE__, __LINE__);
    }

    return session;
}

smo::Result<void> GatewayNode::sync_policy(const std::string& remote_mesh_id)
{
    return policy_federation_.sync_policy_to_mesh(remote_mesh_id);
}

smo::Result<void> GatewayNode::sync_trust_anchors(const std::string& remote_mesh_id)
{
    return policy_federation_.sync_trust_anchors_to_mesh(remote_mesh_id);
}

void GatewayNode::tick(int64_t now_ns)
{
    last_tick_ = now_ns;

    for (const auto& [mesh_id, session_id] : mesh_sessions_)
    {
        auto* session = deps_.session_mgr->lookup(session_id);
        if (session && session->is_valid_at(now_ns))
        {
            routing_table_.update_mesh_sync_time(mesh_id, now_ns);
            routing_table_.update_mesh_health(mesh_id, true);
        }
        else
        {
            routing_table_.update_mesh_health(mesh_id, false);
        }
    }

    policy_federation_.tick(now_ns);
}

smo::Result<void> GatewayNode::perform_federation_handshake(const std::string& remote_mesh_id, const smo::Endpoint& gateway_endpoint)
{
    (void)remote_mesh_id;
    (void)gateway_endpoint;
    return smo::Error(smo::ErrorCode(smo::ErrorCategory::Federation, 14, smo::Severity::Error,
                               smo::RetryClass::NoRetry, smo::Recovery::ManualIntervention),
                      "Federation handshake not fully implemented", __FILE__, __LINE__);
}

smo::Result<void> GatewayNode::verify_remote_mesh_identity(const std::string& remote_mesh_id, const smo::Certificate& cert)
{
    (void)remote_mesh_id;
    (void)cert;
    return {};
}

smo::Result<void> GatewayNode::exchange_trust_anchors(const std::string& remote_mesh_id)
{
    (void)remote_mesh_id;
    return {};
}

} // namespace smo::federation