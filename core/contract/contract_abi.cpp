#include "core/contract/contract_abi.hpp"
#include "core/crypto/hash_provider.hpp"
#include <cstring>
#include <sstream>

namespace smo {

static std::string escape_json(std::string_view s) {
    std::string out;
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\t': out += "\\t"; break;
            default: out += c;
        }
    }
    return out;
}

Hash256 ContractABI::compute_abi_hash() const {
    auto json = to_canonical_json();
    auto& hp = HashProvider::default_provider();
    return hp.hash_hex(json);
}

Hash256 ContractABI::compute_semantic_hash(std::string_view contract_body) const {
    auto& hp = HashProvider::default_provider();
    std::string input(abi_hash);
    input.append(contract_body);
    return hp.hash_hex(input);
}

std::string ContractABI::to_canonical_json() const {
    std::ostringstream os;
    os << "{";
    os << "\"abi_version\":" << abi_version << ",";
    os << "\"contract_name\":\"" << escape_json(contract_name) << "\",";
    os << "\"category\":\"" << escape_json(category) << "\",";
    os << "\"input_schema\":{\"type\":\"" << escape_json(input_schema.type) << "\",\"properties\":[";
    bool first = true;
    for (auto& p : input_schema.properties) {
        if (!first) os << ",";
        first = false;
        os << "{\"name\":\"" << escape_json(p.name) << "\","
           << "\"type\":\"" << escape_json(p.type) << "\","
           << "\"required\":" << (p.required ? "true" : "false");
        if (p.default_value) os << ",\"default\":\"" << escape_json(*p.default_value) << "\"";
        os << "}";
    }
    os << "]},";
    os << "\"output_schema\":{\"type\":\"" << escape_json(output_schema.type) << "\",\"properties\":[";
    first = true;
    for (auto& p : output_schema.properties) {
        if (!first) os << ",";
        first = false;
        os << "{\"name\":\"" << escape_json(p.name) << "\","
           << "\"type\":\"" << escape_json(p.type) << "\","
           << "\"required\":" << (p.required ? "true" : "false");
        if (p.default_value) os << ",\"default\":\"" << escape_json(*p.default_value) << "\"";
        os << "}";
    }
    os << "]},";
    os << "\"capability_mask\":\"" << escape_json(capability_mask) << "\",";
    os << "\"opcode_dependencies\":[";
    first = true;
    for (auto& dep : opcode_dependencies) {
        if (!first) os << ",";
        first = false;
        os << "\"" << escape_json(dep) << "\"";
    }
    os << "],";
    os << "\"min_runtime_version\":\"" << escape_json(min_runtime_version) << "\",";
    os << "\"max_runtime_version\":\"" << escape_json(max_runtime_version) << "\"";
    os << "}";
    return os.str();
}

Result<ContractABI> ContractABI::from_canonical_json(std::string_view json) {
    ContractABI abi;
    auto pos = json.find("\"abi_version\"");
    if (pos != std::string_view::npos) {
        auto vpos = json.find(':', pos);
        if (vpos != std::string_view::npos) {
            auto end = json.find_first_of(",}", vpos + 1);
            if (end != std::string_view::npos) {
                auto val = json.substr(vpos + 1, end - vpos - 1);
                while (!val.empty() && val.front() == ' ') val.remove_prefix(1);
                abi.abi_version = static_cast<uint32_t>(std::stoul(std::string(val)));
            }
        }
    }

    auto extract_str = [&](const char* key, std::string& out) {
        auto kpos = json.find(key);
        if (kpos == std::string_view::npos) return false;
        auto vpos = json.find('"', kpos + strlen(key));
        if (vpos == std::string_view::npos) return false;
        auto vend = json.find('"', vpos + 1);
        if (vend == std::string_view::npos) return false;
        out = json.substr(vpos + 1, vend - vpos - 1);
        return true;
    };

    extract_str("\"contract_name\"", abi.contract_name);
    extract_str("\"category\"", abi.category);
    extract_str("\"capability_mask\"", abi.capability_mask);
    extract_str("\"abi_hash\"", abi.abi_hash);
    extract_str("\"semantic_hash\"", abi.semantic_hash);
    extract_str("\"min_runtime_version\"", abi.min_runtime_version);
    extract_str("\"max_runtime_version\"", abi.max_runtime_version);

    return abi;
}

void AbiRegistry::register_abi(const ContractABI& abi) {
    ContractID cid = ContractID::compute(abi.to_canonical_json());
    registry_[cid] = abi;
}

std::optional<ContractABI> AbiRegistry::get_abi(const ContractID& id) const {
    auto it = registry_.find(id);
    if (it != registry_.end()) return it->second;
    return std::nullopt;
}

bool AbiRegistry::verify_compatibility(
    const ContractID& id, const std::string& runtime_version) const
{
    auto abi = get_abi(id);
    if (!abi) return false;
    return abi->min_runtime_version <= runtime_version
        && runtime_version <= abi->max_runtime_version;
}

bool AbiRegistry::abi_hash_matches(const ContractID& id, const Hash256& expected) const {
    auto abi = get_abi(id);
    if (!abi) return false;
    return abi->abi_hash == expected;
}

AbiRegistry& AbiRegistry::instance() {
    static AbiRegistry inst;
    return inst;
}

} // namespace smo
