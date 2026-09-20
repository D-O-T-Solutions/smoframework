#pragma once

#include <core/mesh/mesh_manager.hpp>
#include <core/authority/authority.hpp>
#include <core/crypto/impl.hpp>
#include <core/errors/error.hpp>
#include <core/types.hpp>

#include <string>
#include <memory>

namespace smo::runtime {

// AuthorityMeshService: owns MeshAuthority init, MeshManager init, mesh opening/switching
class AuthorityMeshService
{
public:
    struct Config
    {
        std::string mesh_dir;
        std::string data_dir; // base data dir for MeshManager catalog
    };

    struct Dependencies
    {
        const CryptoProvider* crypto = nullptr;
        MeshManager& mesh_manager;
        authority::MeshAuthority& authority;
    };

    explicit AuthorityMeshService(const Config& config, const Dependencies& deps);
    ~AuthorityMeshService() = default;

    AuthorityMeshService(const AuthorityMeshService&) = delete;
    AuthorityMeshService& operator=(const AuthorityMeshService&) = delete;
    AuthorityMeshService(AuthorityMeshService&&) = default;
    AuthorityMeshService& operator=(AuthorityMeshService&&) = default;

    // Initialize Authority and MeshManager, open/switch to the configured mesh
    Result<void> initialize();

private:
    Config config_;
    Dependencies deps_;
};

} // namespace smo::runtime