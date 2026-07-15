#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>
#include "core/contract/contract_id.hpp"
#include "core/errors/error.hpp"
#include "core/types.hpp"

namespace smo {

using Hash256 = std::string;

struct SchemaProperty {
    std::string name;
    std::string type;
    bool        required{false};
    std::optional<std::string> default_value;
    std::string description;
};

struct Schema {
    std::string                   type{"object"};
    std::vector<SchemaProperty>   properties;
};

struct ContractABI {
    uint32_t                abi_version{1};
    std::string             contract_name;
    std::string             category;
    Schema                  input_schema;
    Schema                  output_schema;
    std::string             capability_mask;
    std::vector<std::string> opcode_dependencies;
    Hash256                 abi_hash;
    Hash256                 semantic_hash;
    std::string             min_runtime_version{"3.0.0"};
    std::string             max_runtime_version{"99.99.99"};

    Hash256 compute_abi_hash() const;
    Hash256 compute_semantic_hash(std::string_view contract_body) const;
    std::string to_canonical_json() const;
    static Result<ContractABI> from_canonical_json(std::string_view json);
};

class AbiRegistry {
public:
    void register_abi(const ContractABI& abi);
    std::optional<ContractABI> get_abi(const ContractID& id) const;
    bool verify_compatibility(
        const ContractID& id,
        const std::string& runtime_version) const;
    bool abi_hash_matches(const ContractID& id, const Hash256& expected) const;

    static AbiRegistry& instance();

private:
    std::map<ContractID, ContractABI> registry_;
};

} // namespace smo
