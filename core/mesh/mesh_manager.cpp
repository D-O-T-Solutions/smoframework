#include "mesh_manager.hpp"

#include <filesystem>
#include <sqlite3.h>
#include <chrono>
#include <random>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <fstream>

namespace smo {

static const char kMeshSchema[] = R"(
    CREATE TABLE IF NOT EXISTS meshes (
        mesh_id TEXT PRIMARY KEY,
        display_name TEXT NOT NULL,
        authority_pubkey TEXT NOT NULL,
        root_pubkey TEXT NOT NULL,
        epoch INTEGER NOT NULL DEFAULT 1,
        created_at INTEGER NOT NULL,
        config_json TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_meshes_name ON meshes(display_name);
)";

static std::string generate_mesh_id(const MeshConfig& config) {
    std::string canonical = config.root_pubkey + "|" +
        std::to_string(config.created_at) + "|" + std::to_string(std::rand());
    std::array<uint8_t, 32> hash;
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, canonical.data(), canonical.size());
    blake3_hasher_finalize(&hasher, hash.data(), 32);
    std::ostringstream ss;
    for (uint8_t b : hash) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    }
    return ss.str();
}

static MeshPaths make_mesh_paths(const std::string& base_dir, const std::string& mesh_id) {
    MeshPaths p;
    p.mesh_dir = base_dir + "/meshes/" + mesh_id;
    p.mesh_json = p.mesh_dir + "/mesh.json";
    p.cert_path = p.mesh_dir + "/cert.smoc";
    p.identity_json = p.mesh_dir + "/identity.json";
    p.peers_db = p.mesh_dir + "/peers.db";
    p.audit_db = p.mesh_dir + "/audit.db";
    p.contract_db = p.mesh_dir + "/contract.db";
    p.policy_dir = p.mesh_dir + "/policies";
    p.contracts_dir = p.mesh_dir + "/contracts";
    p.cache_dir = p.mesh_dir + "/cache";
    p.dumps_dir = p.mesh_dir + "/dumps";
    p.workflow_dir = p.mesh_dir + "/workflows";
    return p;
}

static void ensure_dirs(const MeshPaths& p) {
    std::error_code ec;
    std::filesystem::create_directories(p.mesh_dir, ec);
    std::filesystem::create_directories(p.policy_dir, ec);
    std::filesystem::create_directories(p.contracts_dir, ec);
    std::filesystem::create_directories(p.cache_dir, ec);
    std::filesystem::create_directories(p.dumps_dir, ec);
    std::filesystem::create_directories(p.workflow_dir, ec);
}

static std::string serialize_config(const MeshConfig& config) {
    std::ostringstream oss;
    oss << "{";
    oss << "\"display_name\":\"" << config.display_name << "\",";
    oss << "\"authority_pubkey\":\"" << config.authority_pubkey << "\",";
    oss << "\"root_pubkey\":\"" << config.root_pubkey << "\",";
    oss << "\"epoch\":" << config.epoch << ",";
    oss << "\"created_at\":" << config.created_at;
    oss << "}";
    return oss.str();
}

class MeshManager::Impl {
public:
    Config config_;
    sqlite3* db_ = nullptr;
    std::string current_mesh_id_;
    std::unordered_map<std::string, std::shared_ptr<MeshContext>> cache_;

    Impl(const Config& config) : config_(config) {}

    ~Impl() { close(); }

    Result<void> open() {
        std::error_code ec;
        std::filesystem::create_directories(config_.base_data_dir, ec);
        if (ec) {
            return SMO_ERR_STORAGE(900, Critical, NoRetry, RebootNode,
                                   "Failed to create base directory: " + ec.message());
        }
        std::string db_path = config_.base_data_dir + "/catalog.db";
        int rc = sqlite3_open_v2(db_path.c_str(), &db_,
                                 SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                                 nullptr);
        if (rc != SQLITE_OK) {
            return SMO_ERR_STORAGE(900, Critical, NoRetry, RebootNode,
                                   "Failed to open catalog DB: " + std::string(sqlite3_errmsg(db_)));
        }
        char* err = nullptr;
        rc = sqlite3_exec(db_, "PRAGMA journal_mode = WAL;", nullptr, nullptr, &err);
        if (rc != SQLITE_OK) {
            std::string msg = err ? err : "unknown";
            sqlite3_free(err);
            sqlite3_close(db_); db_ = nullptr;
            return SMO_ERR_STORAGE(900, Critical, NoRetry, RebootNode, msg);
        }
        rc = sqlite3_exec(db_, kMeshSchema, nullptr, nullptr, &err);
        if (rc != SQLITE_OK) {
            std::string msg = err ? err : "unknown";
            sqlite3_free(err);
            sqlite3_close(db_); db_ = nullptr;
            return SMO_ERR_STORAGE(900, Critical, NoRetry, RebootNode, msg);
        }
        ensure_default_mesh();
        return {};
    }

    void close() {
        if (db_) { sqlite3_close(db_); db_ = nullptr; }
    }

    Result<void> create_mesh(const MeshConfig& config, const std::string& name) {
        std::string mesh_id = config.mesh_id.empty() ? generate_mesh_id(config) : config.mesh_id;
        auto exists = find_mesh(mesh_id, name);
        if (exists) {
            return SMO_ERR_STORAGE(902, Warn, NoRetry, None, "Mesh already exists");
        }
        // Create on-disk structure with MeshID as folder name
        MeshPaths paths = make_mesh_paths(config_.base_data_dir, mesh_id);
        ensure_dirs(paths);
        // Write mesh.json
        std::ofstream mf(paths.mesh_json);
        mf << serialize_config(config);
        mf.close();
        // Insert into catalog
        std::string sql = "INSERT INTO meshes (mesh_id, display_name, authority_pubkey, "
                          "root_pubkey, epoch, created_at, config_json) "
                          "VALUES (?, ?, ?, ?, ?, ?, ?)";
        sqlite3_stmt* stmt = nullptr;
        int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            return SMO_ERR_STORAGE(904, Error, RetrySafe, RetryOperation, "Failed to prepare insert");
        }
        sqlite3_bind_text(stmt, 1, mesh_id.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, name.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, config.authority_pubkey.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 4, config.root_pubkey.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 5, config.epoch);
        sqlite3_bind_int64(stmt, 6, std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
        sqlite3_bind_text(stmt, 7, serialize_config(config).c_str(), -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) {
            return SMO_ERR_STORAGE(904, Error, RetrySafe, RetryOperation, "Failed to insert mesh");
        }
        return {};
    }

    Result<void> switch_mesh(const std::string& id_or_name) {
        auto found = find_mesh(id_or_name, id_or_name);
        if (!found) {
            return SMO_ERR_STORAGE(404, Info, NoRetry, None, "Mesh not found: " + id_or_name);
        }
        current_mesh_id_ = found.value();
        return {};
    }

    std::vector<std::string> list_meshes() const {
        std::vector<std::string> meshes;
        std::string sql = "SELECT display_name, mesh_id FROM meshes ORDER BY display_name";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) return {};
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            std::string name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            std::string id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            meshes.push_back(name + " (" + id.substr(0, 8) + "...)");
        }
        sqlite3_finalize(stmt);
        return meshes;
    }

    std::string get_current_mesh_id() const { return current_mesh_id_; }

    std::string get_current_mesh_name() const {
        if (current_mesh_id_.empty()) return "";
        auto ctx = load_mesh_context(current_mesh_id_);
        return ctx ? ctx->display_name : "";
    }

    Result<std::shared_ptr<MeshContext>> get_mesh(const std::string& mesh_id) {
        auto it = cache_.find(mesh_id);
        if (it != cache_.end()) return it->second;
        auto ctx = load_mesh_context(mesh_id);
        if (!ctx) {
            return SMO_ERR_STORAGE(404, Info, NoRetry, None, "Mesh not found: " + mesh_id);
        }
        cache_[mesh_id] = ctx;
        return ctx;
    }

    std::shared_ptr<MeshContext> load_mesh_context(const std::string& mesh_id) {
        std::string sql = "SELECT display_name, config_json FROM meshes WHERE mesh_id = ?";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) return nullptr;
        sqlite3_bind_text(stmt, 1, mesh_id.c_str(), -1, SQLITE_STATIC);
        std::shared_ptr<MeshContext> ctx;
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            ctx = std::make_shared<MeshContext>();
            ctx->config.mesh_id = mesh_id;
            ctx->display_name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            ctx->paths = make_mesh_paths(config_.base_data_dir, mesh_id);
        }
        sqlite3_finalize(stmt);
        return ctx;
    }

private:
    std::optional<std::string> find_mesh(const std::string& id, const std::string& name) const {
        std::string sql = "SELECT mesh_id FROM meshes WHERE mesh_id = ? OR display_name = ?";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) return std::nullopt;
        sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, name.c_str(), -1, SQLITE_STATIC);
        std::optional<std::string> result;
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            result = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        }
        sqlite3_finalize(stmt);
        return result;
    }

    void ensure_default_mesh() {
        std::string sql = "SELECT COUNT(*) FROM meshes WHERE display_name = 'default'";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) return;
        bool exists = false;
        if (sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_int(stmt, 0) > 0) exists = true;
        sqlite3_finalize(stmt);
        if (exists) return;
        MeshConfig cfg;
        cfg.display_name = "default";
        cfg.authority_pubkey = "placeholder";
        cfg.root_pubkey = cfg.authority_pubkey;
        cfg.epoch = 1;
        cfg.created_at = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        create_mesh(cfg, "default");
    }
};

MeshManager::MeshManager(const Config& config)
    : impl_(std::make_unique<Impl>(config)) {}

MeshManager::~MeshManager() = default;

Result<void> MeshManager::initialize() { return impl_->open(); }

Result<void> MeshManager::create_mesh(const MeshConfig& config, const std::string& name) {
    return impl_->create_mesh(config, name);
}

Result<void> MeshManager::delete_mesh(const std::string& mesh_id) {
    (void)mesh_id;
    return SMO_ERR_STORAGE(905, Error, NoRetry, None, "Not implemented");
}

Result<void> MeshManager::join_mesh(const std::string& mesh_id, const std::string& seed_address) {
    (void)mesh_id; (void)seed_address;
    return SMO_ERR_STORAGE(905, Error, NoRetry, None, "Not implemented");
}

Result<void> MeshManager::leave_mesh(const std::string& mesh_id) {
    (void)mesh_id;
    return SMO_ERR_STORAGE(905, Error, NoRetry, None, "Not implemented");
}

Result<void> MeshManager::switch_mesh(const std::string& id_or_name) {
    return impl_->switch_mesh(id_or_name);
}

Result<std::shared_ptr<MeshContext>> MeshManager::get_mesh(const std::string& mesh_id) {
    return impl_->get_mesh(mesh_id);
}

Result<std::shared_ptr<MeshContext>> MeshManager::get_current_mesh() const {
    if (impl_->get_current_mesh_id().empty()) {
        return SMO_ERR_STORAGE(404, Info, NoRetry, None, "No current mesh");
    }
    return impl_->get_mesh(impl_->get_current_mesh_id());
}

std::vector<std::string> MeshManager::list_meshes() const {
    return impl_->list_meshes();
}

std::string MeshManager::get_current_mesh_id() const {
    return impl_->get_current_mesh_id();
}

std::string MeshManager::get_current_mesh_name() const {
    return impl_->get_current_mesh_name();
}

Result<MeshManager::MeshHandle> MeshManager::open_mesh(const std::string& mesh_id) {
    MeshHandle handle;
    auto ctx = impl_->get_mesh(mesh_id);
    if (ctx) handle.context = ctx.value();
    return handle;
}

MeshManager::MeshHandle::~MeshHandle() = default;

} // namespace smo