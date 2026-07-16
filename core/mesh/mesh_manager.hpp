#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <memory>
#include <chrono>
#include <unordered_map>
#include "core/types.hpp"
#include "core/errors/error.hpp"
#include "core/contract/contract.hpp"
#include "core/acl/policy_engine.hpp"

namespace smo {

struct MeshConfig {
    std::string mesh_id;
    std::string display_name;
    std::string authority_pubkey;
    std::string root_pubkey;
    int64_t epoch = 1;
    int64_t created_at = 0;
};

struct MeshPaths {
    std::string mesh_dir;
    std::string mesh_json;
    std::string cert_path;
    std::string identity_json;
    std::string peers_db;
    std::string audit_db;
    std::string contract_db;
    std::string policy_dir;
    std::string contracts_dir;
    std::string cache_dir;
    std::string dumps_dir;
    std::string workflow_dir;
};

struct MeshContext {
    MeshConfig config;
    std::string display_name;
    MeshPaths paths;
};

class MeshManager {
public:
    struct Config {
        std::string base_data_dir;
        std::string default_mesh_name = "default";
    };

    explicit MeshManager(const Config& config = {});
    ~MeshManager();

    MeshManager(const MeshManager&) = delete;
    MeshManager& operator=(const MeshManager&) = delete;
    MeshManager(MeshManager&&) = default;
    MeshManager& operator=(MeshManager&&) = default;

    // Lifecycle
    Result<void> initialize();
    Result<void> create_mesh(const MeshConfig& config, const std::string& name);
    Result<void> delete_mesh(const std::string& mesh_id);
    Result<void> join_mesh(const std::string& mesh_id, const std::string& seed_address);
    Result<void> leave_mesh(const std::string& mesh_id);
    Result<void> switch_mesh(const std::string& mesh_id_or_name);

    // Access
    Result<std::shared_ptr<MeshContext>> get_mesh(const std::string& mesh_id);
    Result<std::shared_ptr<MeshContext>> get_current_mesh() const;
    std::vector<std::string> list_meshes() const;
    std::string get_current_mesh_id() const;
    std::string get_current_mesh_name() const;

    // Services
    struct MeshHandle {
        std::shared_ptr<MeshContext> context;
        ~MeshHandle();
    };
    Result<MeshHandle> open_mesh(const std::string& mesh_id);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace smo