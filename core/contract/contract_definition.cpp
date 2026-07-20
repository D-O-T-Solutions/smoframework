#include "contract_definition.hpp"
#include "contract_id.hpp"
#include "core/crypto/impl.hpp"

#include <algorithm>
#include <sstream>
#include <cctype>
#include <iomanip>
#include <cctype>

namespace smo {

// ── Minimal JSON writer (canonical: sorted keys, no extra whitespace) ──────

static std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 2);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:   out += c;
        }
    }
    return out;
}

static std::string key(const std::string& k) {
    return "\"" + json_escape(k) + "\":";
}

static void append_param(std::ostringstream& os, const ContractParameter& p) {
    os << "{";
    os << key("name") << "\"" << json_escape(p.name) << "\",";
    os << key("type") << "\"" << json_escape(p.type) << "\",";
    os << key("required") << (p.required ? "true" : "false");
    if (p.default_value.has_value()) {
        os << "," << key("default_value") << "\""
           << json_escape(p.default_value.value()) << "\"";
    }
    os << "}";
}

static void append_hints(std::ostringstream& os, const CompilerHints& h) {
    os << "{";
    os << key("max_parallelism") << h.max_parallelism << ",";
    os << key("timeout_sec") << h.timeout_sec << ",";
    os << key("idempotent") << (h.idempotent ? "true" : "false");
    os << "}";
}

std::string ContractDefinition::to_canonical_json() const {
    std::ostringstream os;
    os << "{";

    os << key("capabilities_required") << "{";
    bool first = true;
    for (const auto& [cap, level] : capabilities_required) {
        if (!first) os << ",";
        first = false;
        os << "\"" << json_escape(cap) << "\":" << level;
    }
    os << "},";

    os << key("category") << "\"" << json_escape(category) << "\",";
    os << key("compiler_hints");
    {
        std::ostringstream hs;
        hs << "{";
        hs << key("max_parallelism") << compiler_hints.max_parallelism << ",";
        hs << key("timeout_sec") << compiler_hints.timeout_sec << ",";
        hs << key("idempotent") << (compiler_hints.idempotent ? "true" : "false");
        hs << "}";
        os << hs.str();
    }
    os << ",";

    os << key("category") << "\"" << json_escape(category) << "\",";
    os << key("compiler_hints");
    {
        std::ostringstream hs;
        hs << "{";
        hs << key("max_parallelism") << compiler_hints.max_parallelism << ",";
        hs << key("timeout_sec") << compiler_hints.timeout_sec << ",";
        hs << key("idempotent") << (compiler_hints.idempotent ? "true" : "false");
        hs << "}";
        os << hs.str();
    }
    os << ",";

    os << key("contract_version") << "\"" << json_escape(contract_version) << "\",";
    os << key("description") << "\"" << json_escape(description) << "\",";
    os << key("name") << "\"" << json_escape(name) << "\",";
    os << key("opcode") << "\"" << json_escape(opcode) << "\",";
    os << key("publisher") << "\"" << json_escape(publisher) << "\",";
    os << key("semver") << "\"" << json_escape(semver) << "\",";
    os << key("name") << "\"" << json_escape(name) << "\",";
    os << key("publisher") << "\"" << json_escape(publisher) << "\",";
    os << key("semver") << "\"" << json_escape(semver) << "\",";
    os << key("description") << "\"" << json_escape(description) << "\",";
    os << key("publisher") << "\"" << json_escape(publisher) << "\",";

    if (signature.empty()) {
        os << key("signature") << "null";
    } else {
        os << key("signature") << "\"" << json_escape(signature) << "\"";
    }

    os << "}";
    return os.str();
}

ContractID ContractDefinition::compute_id() const {
    ContractID id;
    // Deterministic mock — combine version+category+name into a stable ID
    std::string raw = contract_version + "|" + category + "|" + name;
    id.bytes.fill(0);
    for (size_t i = 0; i < raw.size() && i < id.bytes.size(); ++i)
        id.bytes[i] = static_cast<uint8_t>(raw[i]);
    return id;
}

Result<ContractDefinition> ContractDefinition::from_canonical_json(
    std::string_view json) {
    // Simplified implementation — extract known fields via substring search
    ContractDefinition def;
    auto extract_string = [&](const std::string& key) -> std::string {
        auto pos = json.find("\"" + key + "\":\"");
        if (pos == std::string::npos) return {};
        pos += key.size() + 4;
        std::string val;
        while (pos < json.size() && json[pos] != '\"') val += json[pos++];
        return val;
    };
    def.contract_version = extract_string("contract_version");
    def.category = extract_string("category");
    def.opcode = extract_string("opcode");
    def.name = extract_string("name");
    def.publisher = extract_string("publisher");
    def.semver = extract_string("semver");
    def.contract_id = def.compute_id();
    return def;
}

} // namespace smo