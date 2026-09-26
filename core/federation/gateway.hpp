#pragma once

#include <core/errors/error.hpp>
#include <core/types.hpp>
#include <core/crypto/suite.hpp>
#include <core/acl/policy_engine.hpp>
#include <core/session/session.hpp>
#include <core/discovery/discovery.hpp>
#include <core/mesh/mesh_manager.hpp>
#include <core/authority/authority.hpp>
#include <core/trust/trust.hpp>
#include "policy_federation.hpp"

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <memory>
#include <chrono>

namespace smo::federation {

enum class MeshRole : uint8_t
{
    Local = 0,
    Gateway = 1,
    Remote = 2,
};

struct MeshInfo
{
    std::string mesh_id;
    std::string display_name;
    std::string authority_pubkey;
    std::string root_pubkey;
    CryptoSuiteID cipher_suite = kSuitePurePQC;
    int64_t epoch = 1;
    MeshRole role = MeshRole::Remote;
    std::string gateway_node_id;
    std::vector<std::string> advertise_endpoints;
    int64_t last_sync = 0;
    bool healthy = true;
};

struct CrossMeshRoute
{
    std::string destination_mesh_id;
    std::string next_hop_mesh_id;
    std::string gateway_node_id;
    uint32_t metric = 1;
    int64_t last_updated = 0;
    bool active = true;
};

struct GatewayPolicy
{
    std::string name;
    std::string source_mesh;
    std::string destination_mesh;
    std::vector<std::string> allowed_contracts;
    std::vector<std::string> denied_contracts;
    std::vector<std::string> required_capabilities;
    acl::PolicyDecision default_decision = acl::PolicyDecision::Allow;
    int32_t priority = 0;
    bool enabled = true;
};

class CrossMeshRoutingTable
{
public:
    struct Config
    {
        std::string local_mesh_id;
        std::string local_gateway_node_id;
    };

    explicit CrossMeshRoutingTable(const Config& config);

    smo::Result<void> add_mesh(const MeshInfo& mesh);
    smo::Result<void> remove_mesh(const std::string& mesh_id);
    smo::Result<MeshInfo> get_mesh(const std::string& mesh_id) const;
    std::vector<MeshInfo> list_meshes() const;

    smo::Result<void> add_route(const CrossMeshRoute& route);
    smo::Result<void> remove_route(const std::string& destination_mesh);
    smo::Result<CrossMeshRoute> find_route(const std::string& destination_mesh) const;
    std::vector<CrossMeshRoute> list_routes() const;

    smo::Result<void> update_mesh_health(const std::string& mesh_id, bool healthy);
    smo::Result<void> update_mesh_sync_time(const std::string& mesh_id, int64_t now);

    void set_gateway_policy(const GatewayPolicy& policy);
    smo::Result<GatewayPolicy> get_gateway_policy(const std::string& source_mesh, const std::string& dest_mesh) const;
    std::vector<GatewayPolicy> list_gateway_policies() const;

    smo::Result<bool> check_route_policy(const std::string& source_mesh, const std::string& dest_mesh,
                                          const std::string& contract_id, const std::vector<std::string>& capabilities) const;

private:
    Config config_;
    std::unordered_map<std::string, MeshInfo> meshes_;
    std::unordered_map<std::string, CrossMeshRoute> routes_;
    std::unordered_map<std::string, GatewayPolicy> policies_;
};

class GatewayNode
{
public:
    struct Config
    {
        std::string local_mesh_id;
        std::string gateway_node_id;
        std::string data_dir;
        int64_t federation_handshake_timeout_ns = 30'000'000'000LL; // 30s
        int64_t session_ttl_ns = 3600'000'000'000LL; // 1h
    };

    struct Dependencies
    {
        const smo::CryptoProvider* crypto = nullptr;
        smo::RngRef* rng = nullptr;
        smo::SessionManager* session_mgr = nullptr;
        smo::DiscoveryEngine* discovery = nullptr;
        smo::MeshManager* mesh_manager = nullptr;
        smo::authority::MeshAuthority* authority = nullptr;
        smo::acl::PolicyEngine* policy_engine = nullptr;
        smo::TrustManager* trust_mgr = nullptr;
    };

    GatewayNode(const Config& config, const Dependencies& deps);
    ~GatewayNode();

    smo::Result<void> initialize();
    void shutdown();

    smo::Result<void> connect_to_mesh(const std::string& remote_mesh_id, const std::vector<smo::Endpoint>& gateway_endpoints);
    smo::Result<void> disconnect_mesh(const std::string& remote_mesh_id);
    smo::Result<smo::Session*> get_mesh_session(const std::string& remote_mesh_id);
    smo::Result<void> sync_policy(const std::string& remote_mesh_id);
    smo::Result<void> sync_trust_anchors(const std::string& remote_mesh_id);

    void tick(int64_t now_ns);

    const CrossMeshRoutingTable& routing_table() const { return routing_table_; }
    CrossMeshRoutingTable& routing_table() { return routing_table_; }

private:
    Config config_;
    Dependencies deps_;
    CrossMeshRoutingTable routing_table_;
    PolicyFederation policy_federation_;
    std::unordered_map<std::string, smo::SessionId> mesh_sessions_;
    int64_t last_tick_ = 0;

    smo::Result<void> perform_federation_handshake(const std::string& remote_mesh_id, const smo::Endpoint& gateway_endpoint);
    smo::Result<void> verify_remote_mesh_identity(const std::string& remote_mesh_id, const smo::Certificate& cert);
    smo::Result<void> exchange_trust_anchors(const std::string& remote_mesh_id);
};

} // namespace smo::federation