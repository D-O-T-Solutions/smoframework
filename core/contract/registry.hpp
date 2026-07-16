#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <chrono>
#include "core/types.hpp"
#include "core/errors/error.hpp"
#include "core/crypto/impl.hpp"
#include "core/contract/contract_id.hpp"

namespace smo {

// ===========================================================================
// Contract Definition
// ===========================================================================

struct ContractDefinition {
    std::string name;
    std::string version;          // semantic version
    std::string publisher;        // publisher identity
    std::string description;
    
    // ABI
    std::string abi_hash;         // hash of ABI definition
    std::string semantic_hash;    // hash of semantic definition
    
    // Capabilities required
    std::vector<std::string> required_capabilities;
    
    // Resource requirements
    struct ResourceRequirements {
        int64_t max_cpu_millis = 0;
        int64_t max_memory_bytes = 0;
        int64_t max_disk_bytes = 0;
        int64_t timeout_ns = 30'000'000'000;  // 30s default
    } resources;
    
    // Metadata
    std::string publisher_id;      // NodeID of publisher
    int64_t published_at = 0;
    std::string signature;         // Publisher signature
};

Result<ContractID> compute_contract_id(const ContractDefinition& def, const HashImpl& hash) {
    // Canonical serialization
    std::string canonical = "CONTRACT|"
        + def.publisher + "|" + def.name + "|" 
        + def.version + "|" + def.abi_hash + "|" + def.semantic_hash;
    
    auto hash_result = hash.hash(std::string_view(
        reinterpret_cast<const char*>(canonical.data()), canonical.size()));
    if (!hash_result) return hash_result.error();

    ContractID id;
    if (hash_result.value().size() >= 32) {
        std::copy(hash_result.value().begin(), hash_result.value().begin() + 32, id.value.begin());
    }
    return id;
}

// ===========================================================================
// Contract Registry
// ===========================================================================

struct ContractEntry {
    ContractDefinition definition;
    ContractID id;
    int64_t registered_at = 0;
    std::string registered_by;
    std::string signature;
};

class ContractRegistry {
public:
    struct Config {
        std::string db_path;
        size_t max_contracts = 10000;
    };

    explicit ContractRegistry(const Config& config = {});
    ~ContractRegistry();

    ContractRegistry(const ContractRegistry&) = delete;
    ContractRegistry& operator=(const ContractRegistry&) = delete;
    ContractRegistry(ContractRegistry&&) = default;
    ContractRegistry& operator=(ContractRegistry&&) = default;

    Result<void> open();
    void close();

    Result<void> register_contract(const ContractDefinition& def, const std::string& registered_by, const HashImpl& hash);
    Result<ContractEntry> get_contract(const ContractID& id) const;
    Result<std::vector<ContractEntry>> list_contracts() const;
    Result<void> unregister_contract(const ContractID& id, const std::string& unregistered_by);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace smo