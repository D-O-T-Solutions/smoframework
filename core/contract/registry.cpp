#include "registry.hpp"

#include <sqlite3.h>
#include <blake3.h>
#include <chrono>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#include <stdexcept>
#include <algorithm>
#include <iostream>

namespace smo {

static const char kContractSchema[] =
    "CREATE TABLE IF NOT EXISTS contracts ("
    "  contract_id       BLOB PRIMARY KEY,"
    "  name              TEXT NOT NULL,"
    "  version           TEXT NOT NULL,"
    "  publisher         TEXT NOT NULL,"
    "  description       TEXT,"
    "  abi_hash          TEXT NOT NULL,"
    "  semantic_hash     TEXT NOT NULL,"
    "  required_caps     TEXT NOT NULL DEFAULT '[]',"
    "  max_cpu_millis    INTEGER NOT NULL DEFAULT 0,"
    "  max_memory_bytes  INTEGER NOT NULL DEFAULT 0,"
    "  max_disk_bytes    INTEGER NOT NULL DEFAULT 0,"
    "  timeout_ns        INTEGER NOT NULL DEFAULT 30000000000,"
    "  publisher_id      TEXT NOT NULL,"
    "  published_at      INTEGER NOT NULL,"
    "  signature         TEXT NOT NULL,"
    "  registered_at     INTEGER NOT NULL,"
    "  registered_by     TEXT NOT NULL,"
    "  signature         TEXT NOT NULL"
    ");";

static const char kContractIndexSchema[] =
    "CREATE INDEX IF NOT EXISTS idx_contracts_name ON contracts(name);"
    "CREATE INDEX IF NOT EXISTS idx_contracts_publisher ON contracts(publisher);"
    "CREATE INDEX IF NOT EXISTS idx_contracts_published ON contracts(published_at);";

namespace smo {

class ContractRegistry::Impl {
public:
    Impl(const Config& config) : config_(config) {}

    Result<void> open() {
        namespace fs = std::filesystem;
        fs::path dir(config_.db_path);
        fs::path dir_path = dir.parent_path();
        if (!dir_path.empty()) {
            std::error_code ec;
            fs::create_directories(dir_path, ec);
        }

        int rc = sqlite3_open(config_.db_path.c_str(), &db_);
        if (rc != SQLITE_OK) {
            return SMO_ERR_STORAGE(900, Critical, NoRetry, RebootNode,
                                   "Failed to open contract registry: " + std::string(sqlite3_errmsg(db_)));
        }

        // Enable WAL mode
        char* err = nullptr;
        int rc = sqlite3_exec(db_, "PRAGMA journal_mode = WAL;", nullptr, nullptr, &err);
        if (rc != SQLITE_OK) {
            std::string msg = err ? err : "unknown";
            sqlite3_free(err);
            return SMO_ERR_STORAGE(900, Critical, NoRetry, RebootNode, msg);
        }

        // Create schema
        rc = sqlite3_exec(db_, kContractSchema, nullptr, nullptr, &err);
        if (rc != SQLITE_OK) {
            std::string msg = err ? err : "unknown";
            sqlite3_free(err);
            return SMO_ERR_STORAGE(900, Critical, NoRetry, RebootNode, msg);
        }

        rc = sqlite3_exec(db_, kContractIndexSchema, nullptr, nullptr, &err);
        if (rc != SQLITE_OK) {
            std::string msg = err ? err : "unknown";
            sqlite3_free(err);
            return SMO_ERR_STORAGE(900, Critical, NoRetry, RebootNode, msg);
        }

        return {};
    }

    void close() {
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
    }

    sqlite3* db() { return db_; }

private:
    Config config_;
    sqlite3* db_ = nullptr;
};

ContractRegistry::ContractRegistry(const Config& config) : impl_(std::make_unique<Impl>(config)) {}

ContractRegistry::~ContractRegistry() {
    close();
}

Result<void> ContractRegistry::open() {
    return impl_->open();
}

void ContractRegistry::close() {
    impl_->close();
}

Result<void> ContractRegistry::register_contract(const ContractDefinition& def, const std::string& registered_by, const HashImpl& hash) {
    // Compute contract ID
    auto cid_result = compute_contract_id(def, hash);
    if (!cid_result) return cid_result.error();
    ContractID id = cid_result.value();

    // Check if already exists
    auto existing = get_contract(id);
    if (existing) {
        return SMO_ERR_STORAGE(902, Warn, NoRetry, None, "Contract already registered");
    }

    // Serialize required capabilities as JSON
    std::string caps_json = "[";
    for (size_t i = 0; i < def.required_capabilities.size(); ++i) {
        if (i > 0) caps_json += ",";
        caps_json += "\"" + def.required_capabilities[i] + "\"";
    }
    caps_json += "]";

    std::string def_json = "{"
        "\"name\":\"" + def.name + "\","
        "\"version\":\"" + def.version + "\","
        "\"publisher\":\"" + def.publisher + "\","
        "\"description\":\"" + def.description + "\","
        "\"abi_hash\":\"" + def.abi_hash + "\","
        "\"semantic_hash\":\"" + def.semantic_hash + "\","
        "\"required_caps\":" + caps_json + ","
        "\"max_cpu_millis\":" + std::to_string(def.resources.max_cpu_millis) + ","
        "\"max_memory_bytes\":" + std::to_string(def.resources.max_memory_bytes) + ","
        "\"max_disk_bytes\":" + std::to_string(def.resources.max_disk_bytes) + ","
        "\"timeout_ns\":" + std::to_string(def.resources.timeout_ns) + ","
        "\"publisher_id\":\"" + def.publisher_id + "\","
        "\"published_at\":" + std::to_string(def.published_at) + ","
        "\"signature\":\"" + def.signature + "\""
        "}";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, 
        "INSERT INTO contracts "
        "(contract_id, name, version, publisher, description, abi_hash, semantic_hash, "
        "required_caps, max_cpu_millis, max_memory_bytes, max_disk_bytes, timeout_ns, "
        "publisher_id, published_at, signature, registered_at, registered_by, signature) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        -1, &stmt, nullptr);
    
    if (rc != SQLITE_OK) {
        return SMO_ERR_STORAGE(904, Error, RetrySafe, RetryOperation, "Failed to prepare statement");
    }

    sqlite3_bind_blob(stmt, 1, id.value.data(), 32, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, def.name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, def.version.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, def.publisher.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, def.description.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, def.abi_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, def.semantic_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 8, "[\"cap1\",\"cap2\"]", -1, SQLITE_TRANSIENT); // Simplified
    sqlite3_bind_int64(stmt, 9, 0);
    sqlite3_bind_int64(stmt, 10, 0);
    sqlite3_bind_int64(stmt, 11, 0);
    sqlite3_bind_int64(stmt, 12, 30000000000);
    sqlite3_bind_text(stmt, 13, def.publisher_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 13, std::chrono::system_clock::now().time_since_epoch().count());
    sqlite3_bind_text(stmt, 14, "sig", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 14, std::chrono::system_clock::now().time_since_epoch().count());
    sqlite3_bind_text(stmt, 15, "system", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 15, "sig", -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        return SMO_ERR_STORAGE(904, Error, RetrySafe, RetryOperation, "Failed to insert contract");
    }

    return {};
}

Result<ContractEntry> ContractRegistry::get_contract(const ContractID& id) const {
    // Implementation would query the database
    return SMO_ERR_STORAGE(404, Info, RetrySafe, None, "Not implemented");
}

Result<std::vector<ContractEntry>> ContractRegistry::list_contracts() const {
    return {};
}

Result<void> ContractRegistry::unregister_contract(const ContractID& id, const std::string& unregistered_by) {
    return SMO_ERR_STORAGE(905, Error, NoRetry, None, "Not implemented");
}

} // namespace smo