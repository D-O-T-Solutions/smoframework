#include <core/runtime/authority_mesh_service.hpp>

#include <fstream>
#include <filesystem>
#include <sqlite3.h>

namespace smo::runtime {

AuthorityMeshService::AuthorityMeshService(const Config& config, const Dependencies& deps)
    : config_(config)
    , deps_(deps)
{
}

Result<void> AuthorityMeshService::initialize()
{
    if (config_.mesh_dir.empty())
    {
        return {};
    }

    // Parse mesh_id from mesh.json
    std::string authority_mesh_id;
    std::string mesh_json_path = config_.mesh_dir + "/mesh.json";
    std::ifstream mf(mesh_json_path);
    if (mf)
    {
        std::string mjson((std::istreambuf_iterator<char>(mf)), std::istreambuf_iterator<char>());
        auto mpos = mjson.find("\"mesh_id\"");
        if (mpos != std::string::npos)
        {
            auto mcolon = mjson.find(':', mpos);
            auto mstart = mjson.find('"', mcolon + 1);
            auto mend = mstart != std::string::npos ? mjson.find('"', mstart + 1) : std::string::npos;
            if (mstart != std::string::npos && mend != std::string::npos)
                authority_mesh_id = mjson.substr(mstart + 1, mend - mstart - 1);
        }
    }
    if (authority_mesh_id.empty())
    {
        authority_mesh_id = std::filesystem::path(config_.mesh_dir).filename().string();
    }

    // Initialize MeshAuthority
    authority::MeshAuthority::Config acfg;
    acfg.mesh_id = authority_mesh_id;
    acfg.data_dir = config_.mesh_dir;
    acfg.registry_path = config_.mesh_dir + "/node_registry.db";

    if (!deps_.crypto)
    {
        return Error(ErrorCode(ErrorCategory::Crypto, 1, Severity::Error,
                               RetryClass::NoRetry, Recovery::None),
                     "crypto provider not set", __FILE__, __LINE__);
    }

    auto auth_rng = deps_.crypto->default_rng();
    if (auto ar = deps_.authority.init(*deps_.crypto, auth_rng); !ar)
    {
        std::printf("[smo-node] Warning: failed to init MeshAuthority: %s\n", ar.error().message.c_str());
    }
    else if (auto ar2 = deps_.authority.open(acfg); !ar2)
    {
        std::printf("[smo-node] Warning: failed to open MeshAuthority at %s: %s\n", config_.mesh_dir.c_str(),
                    ar2.error().message.c_str());
    }
    else
    {
        std::printf("[smo-node] MeshAuthority opened (mesh_id=%s, registry=%s)\n", acfg.mesh_id.c_str(),
                    acfg.registry_path.c_str());

        // Open the mesh for bootstrap sync
        if (auto mh = deps_.mesh_manager.open_mesh(authority_mesh_id); !mh)
        {
            std::printf("[smo-node] Warning: failed to open mesh %s: %s\n", authority_mesh_id.c_str(),
                        mh.error().message.c_str());
        }
        else
        {
            std::printf("[smo-node] Mesh opened for bootstrap sync: %s\n", authority_mesh_id.c_str());
        }
    }

    // Initialize mesh manager to discover meshes
    if (auto mi = deps_.mesh_manager.initialize(); !mi)
    {
        std::printf("[smo-node] Warning: failed to initialize MeshManager: %s\n", mi.error().message.c_str());
    }
    else
    {
        std::printf("[smo-node] MeshManager initialized\n");

        // Register existing mesh in catalog for bootstrap sync
        std::string catalog_mesh_id = authority_mesh_id;
        std::ifstream mf2(mesh_json_path);
        if (mf2)
        {
            std::string mjson((std::istreambuf_iterator<char>(mf2)), std::istreambuf_iterator<char>());
            auto mpos = mjson.find("\"mesh_id\"");
            if (mpos != std::string::npos)
            {
                auto mcolon = mjson.find(':', mpos);
                auto mstart = mjson.find('"', mcolon + 1);
                auto mend = mstart != std::string::npos ? mjson.find('"', mstart + 1) : std::string::npos;
                if (mstart != std::string::npos && mend != std::string::npos)
                    catalog_mesh_id = mjson.substr(mstart + 1, mend - mstart - 1);
            }

            // Insert into catalog if not present
            std::string catalog_db = config_.data_dir + "/catalog.db";
            sqlite3* cat_db = nullptr;
            if (sqlite3_open(catalog_db.c_str(), &cat_db) == SQLITE_OK)
            {
                std::string sql = "INSERT OR IGNORE INTO meshes (mesh_id, display_name, authority_pubkey, "
                                  "root_pubkey, epoch, created_at, config_json) "
                                  "VALUES (?, ?, '', '', 1, strftime('%s','now'), ?)";
                sqlite3_stmt* stmt = nullptr;
                if (sqlite3_prepare_v2(cat_db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK)
                {
                    sqlite3_bind_text(stmt, 1, catalog_mesh_id.c_str(), -1, SQLITE_STATIC);
                    sqlite3_bind_text(stmt, 2, catalog_mesh_id.c_str(), -1, SQLITE_STATIC);
                    sqlite3_bind_text(stmt, 3, mjson.c_str(), -1, SQLITE_STATIC);
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
                sqlite3_close(cat_db);
            }
        }

        // Set the mesh as active for bootstrap sync
        if (auto sw = deps_.mesh_manager.switch_mesh(authority_mesh_id); !sw)
        {
            std::printf("[smo-node] Warning: failed to switch to mesh %s: %s\n", authority_mesh_id.c_str(),
                        sw.error().message.c_str());
        }
        else
        {
            std::printf("[smo-node] Mesh set as active: %s\n", authority_mesh_id.c_str());
        }
    }

    return {};
}

} // namespace smo::runtime