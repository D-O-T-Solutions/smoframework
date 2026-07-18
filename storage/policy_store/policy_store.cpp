#include "policy_store.h"

#include "../../core/storage/sqlite_store.hpp"
#include "../../core/types.hpp"
#include <sstream>

namespace smo {

static Bytes to_bytes(const std::string& s) {
    return Bytes(s.begin(), s.end());
}

static std::string to_str(const Bytes& b) {
    return std::string(b.begin(), b.end());
}

static std::string policy_key(const std::string& name) {
    return "pol:" + name;
}

static std::string record_serialize(const PolicyStore::Record& r) {
    std::ostringstream os;
    os << r.name << '\0'
       << r.description << '\0'
       << r.version << '\0'
       << r.yaml_content << '\0'
       << r.created_at << '\0'
       << r.created_by << '\0'
       << r.updated_at;
    return os.str();
}

static bool record_deserialize(const std::string& data, PolicyStore::Record& r) {
    std::istringstream is(data);
    std::string field;
    if (!std::getline(is, r.name, '\0')) return false;
    if (!std::getline(is, r.description, '\0')) return false;
    if (!std::getline(is, r.version, '\0')) return false;
    if (!std::getline(is, r.yaml_content, '\0')) return false;
    if (!std::getline(is, field, '\0')) return false;
    r.created_at = std::stoll(field);
    if (!std::getline(is, r.created_by, '\0')) return false;
    std::getline(is, field);
    r.updated_at = std::stoll(field);
    return true;
}

std::error_code PolicyStore::open() noexcept {
    store_ = std::make_unique<SqliteStore>(StoreID::Trust, base_path_);
    auto res = store_->open();
    if (!res) return std::error_code(Errc::STORE_UNAVAILABLE);
    return {};
}

void PolicyStore::close() noexcept { if (store_) store_->close(); }
std::error_code PolicyStore::flush() noexcept { return {}; }

std::error_code PolicyStore::put(const Record& rec) {
    if (!store_) return std::error_code(Errc::STORE_UNAVAILABLE);
    auto res = store_->put(to_bytes(policy_key(rec.name)),
                            to_bytes(record_serialize(rec)));
    if (!res) return std::error_code(Errc::STORE_CORRUPTION);
    store_version_++;
    return {};
}

std::optional<PolicyStore::Record> PolicyStore::get(const std::string& name) {
    if (!store_) return std::nullopt;
    auto res = store_->get(to_bytes(policy_key(name)));
    if (!res) return std::nullopt;
    Record r;
    if (!record_deserialize(to_str(res.value()), r)) return std::nullopt;
    return r;
}

std::error_code PolicyStore::remove(const std::string& name) {
    if (!store_) return std::error_code(Errc::STORE_UNAVAILABLE);
    bool ok = store_->remove(to_bytes(policy_key(name)));
    if (!ok) return std::error_code(Errc::STORE_CORRUPTION);
    store_version_++;
    return {};
}

std::vector<std::string> PolicyStore::list() {
    if (!store_) return {};
    auto keys = store_->list_by_prefix(to_bytes("pol:"));
    std::vector<std::string> names;
    for (auto& k : keys) {
        auto s = to_str(k);
        if (s.size() > 4) names.push_back(s.substr(4));
    }
    return names;
}

std::error_code PolicyStore::load_into(acl::PolicyEngine& engine) {
    auto names = list();
    for (auto& name : names) {
        auto rec = get(name);
        if (!rec) continue;
        // Parse YAML content and load into engine
        auto res = engine.load_policies(rec->yaml_content);
        if (!res) return std::error_code(Errc::STORE_CORRUPTION);
    }
    return {};
}

std::error_code PolicyStore::save_from(acl::PolicyEngine& engine) {
    auto policies = engine.list_policies();
    if (!policies) return std::error_code(Errc::STORE_CORRUPTION);
    for (auto& name : policies.value()) {
        auto ps = engine.get_policy(name);
        if (!ps) continue;
        // Serialize policy to YAML and store
        Record rec;
        rec.name = ps.value().name;
        rec.description = ps.value().description;
        rec.version = ps.value().version;
        rec.created_at = ps.value().created_at;
        rec.created_by = ps.value().created_by;
        rec.updated_at = ps.value().created_at;
        rec.yaml_content = "name: " + rec.name;
        auto err = put(rec);
        if (err) return err;
    }
    return {};
}

} // namespace smo