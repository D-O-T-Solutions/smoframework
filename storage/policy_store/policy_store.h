#pragma once

#include <memory>
#include <optional>
#include <string>
#include <vector>
#include "storage/storage.h"
#include "core/acl/policy_engine.hpp"

namespace smo {

// PolicyStore — SQLite-backed persistence for policy rule sets.
// Used by PolicyEngine to load/store policies across restarts.
// Governance contract updates policies via this store.
class PolicyStore : public Store {
public:
    struct Record {
        std::string name;
        std::string description;
        std::string version;
        std::string yaml_content;   // raw YAML policy definition
        int64_t     created_at = 0;
        std::string created_by;
        int64_t     updated_at = 0;
    };

    explicit PolicyStore(std::string base_path) : base_path_(std::move(base_path)) {}

    std::error_code open() noexcept override;
    void close() noexcept override;
    std::error_code flush() noexcept override;

    // CRUD
    std::error_code put(const Record& rec);
    std::optional<Record> get(const std::string& name);
    std::error_code remove(const std::string& name);
    std::vector<std::string> list();

    // Load all policies into a PolicyEngine
    std::error_code load_into(acl::PolicyEngine& engine);
    // Save all policies from a PolicyEngine
    std::error_code save_from(acl::PolicyEngine& engine);

    // Version for hot-reload detection
    int64_t store_version() const { return store_version_; }

private:
    std::string base_path_;
    std::unique_ptr<class SqliteStore> store_;
    int64_t store_version_ = 0;
};

} // namespace smo