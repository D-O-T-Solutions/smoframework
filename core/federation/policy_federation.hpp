#pragma once

#include <core/errors/error.hpp>
#include <core/types.hpp>
#include <core/acl/policy_engine.hpp>
#include <core/certificate/certificate.hpp>

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <functional>
#include <memory>

namespace smo::federation {

struct PolicyDelta
{
    std::string mesh_id;
    uint64_t version = 0;
    std::vector<acl::PolicySet> added_policies;
    std::vector<std::string> removed_policies;
    std::vector<acl::PolicySet> updated_policies;
    int64_t timestamp = 0;

    smo::Bytes serialize() const;
    static smo::Result<PolicyDelta> deserialize(smo::BytesView data);
};

struct TrustAnchorDelta
{
    std::string mesh_id;
    uint64_t version = 0;
    std::vector<smo::Certificate> added_anchors;
    std::vector<std::string> removed_anchor_fingerprints;
    int64_t timestamp = 0;

    smo::Bytes serialize() const;
    static smo::Result<TrustAnchorDelta> deserialize(smo::BytesView data);
};

class PolicyFederation
{
public:
    struct Config
    {
        std::string local_mesh_id;
        std::string data_dir;
        int64_t sync_interval_ns = 60'000'000'000LL; // 60s
        int64_t delta_retention_ns = 3600'000'000'000LL; // 1h
    };

    using SendDeltaFn = std::function<smo::Result<void>(const std::string& remote_mesh_id, smo::BytesView delta)>;
    using OnPolicyChangeFn = std::function<void(const std::string& mesh_id, const acl::PolicySet& policy, bool added)>;
    using OnTrustAnchorChangeFn = std::function<void(const std::string& mesh_id, const smo::Certificate& anchor, bool added)>;

    PolicyFederation(const Config& config, acl::PolicyEngine& local_policy_engine);
    ~PolicyFederation() = default;

    smo::Result<void> initialize();
    void shutdown();

    smo::Result<void> register_remote_mesh(const std::string& mesh_id, SendDeltaFn send_fn);
    smo::Result<void> unregister_remote_mesh(const std::string& mesh_id);

    smo::Result<void> sync_policy_to_mesh(const std::string& remote_mesh_id);
    smo::Result<void> sync_trust_anchors_to_mesh(const std::string& remote_mesh_id);

    smo::Result<void> handle_policy_delta(const std::string& from_mesh_id, smo::BytesView delta_data);
    smo::Result<void> handle_trust_anchor_delta(const std::string& from_mesh_id, smo::BytesView delta_data);

    void set_on_policy_change(OnPolicyChangeFn fn) { on_policy_change_ = std::move(fn); }
    void set_on_trust_anchor_change(OnTrustAnchorChangeFn fn) { on_trust_anchor_change_ = std::move(fn); }

    void tick(int64_t now_ns);

    uint64_t local_policy_version() const;
    uint64_t local_trust_anchor_version() const;

private:
    struct RemoteMeshState
    {
        std::string mesh_id;
        SendDeltaFn send_fn;
        uint64_t last_policy_version = 0;
        uint64_t last_trust_anchor_version = 0;
        int64_t last_sync = 0;
    };

    Config config_;
    acl::PolicyEngine& local_policy_engine_;
    std::unordered_map<std::string, RemoteMeshState> remote_meshes_;
    int64_t last_tick_ = 0;
    OnPolicyChangeFn on_policy_change_;
    OnTrustAnchorChangeFn on_trust_anchor_change_;

    smo::Result<void> send_policy_delta(const std::string& remote_mesh_id, const PolicyDelta& delta);
    smo::Result<void> send_trust_anchor_delta(const std::string& remote_mesh_id, const TrustAnchorDelta& delta);
    smo::Result<void> apply_policy_delta(const PolicyDelta& delta);
    smo::Result<void> apply_trust_anchor_delta(const TrustAnchorDelta& delta);
    std::vector<smo::Certificate> load_local_trust_anchors();
};

} // namespace smo::federation