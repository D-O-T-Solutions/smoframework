#include "opcode_registry.hpp"
#include "core/capability/capability.h"

namespace smo {

// RFC 0020: Compile-time constexpr wire table
// Format: {code, ns, message_id, name, functional_group, capability_mask, idempotent}
// 3-byte namespace allocation: namespace(1) + message_id(2)
// Sequential message IDs per functional group

constexpr WireOpcodeEntry kWireTable[] = {
    // Discovery namespace (0x01) - Functional group: "discovery"
    {Opcode::LS,       kNamespaceDiscovery, 0x0101, "ls",        "discovery", 0x01, true},
    {Opcode::PUT,      kNamespaceDiscovery, 0x0102, "put",       "discovery", 0x01, true},
    {Opcode::GET,      kNamespaceDiscovery, 0x0103, "get",       "discovery", 0x01, true},
    {Opcode::ECHO,     kNamespaceDiscovery, 0x0104, "echo",      "discovery", 0x01, true},

    // Control namespace (0x02) - Functional group: "session"
    {Opcode::SESSION_OPEN,  kNamespaceControl, 0x0010, "session_open", "session", 0x01, false},
    {Opcode::SESSION_CLOSE, kNamespaceControl, 0x0011, "session_close", "session", 0x01, true},
    {Opcode::SESSION_RENEW, kNamespaceControl, 0x0012, "session_renew", "session", 0x01, false},

    // Control namespace (0x02) - Functional group: "governance"
    {Opcode::GOV_PROPOSE,   kNamespaceControl, 0x0020, "gov_propose", "governance", 0x01, false},
    {Opcode::GOV_VOTE,      kNamespaceControl, 0x0021, "gov_vote",    "governance", 0x01, false},
    {Opcode::GOV_COMMIT,    kNamespaceControl, 0x0022, "gov_commit",  "governance", 0x01, true},
    {Opcode::GOV_LIST,      kNamespaceControl, 0x0023, "gov_list",    "governance", 0x01, true},
    {Opcode::GOV_STATUS,    kNamespaceControl, 0x0024, "gov_status",  "governance", 0x01, true},
    {Opcode::GOV_INFO,      kNamespaceControl, 0x0025, "gov_info",    "governance", 0x01, true},

    // Control namespace (0x02) - Functional group: "certificate"
    {Opcode::REVOKE_CERT,    kNamespaceControl, 0x0030, "revoke_cert",    "certificate", 0x01, false},
    {Opcode::EPOCH_INCREMENT, kNamespaceControl, 0x0031, "epoch_increment", "certificate", 0x01, false},
    {Opcode::CRL_SYNC,       kNamespaceControl, 0x0032, "crl_sync",      "certificate", 0x01, true},

    // Control namespace (0x02) - Functional group: "recovery"
    {Opcode::RECOVERY_SESSION, kNamespaceControl, 0x0040, "recovery_session", "recovery", 0x01, false},
    {Opcode::RECOVERY,         kNamespaceControl, 0x0041, "recovery",         "recovery", 0x01, false},

    // Control namespace (0x02) - Functional group: "contract_mgmt"
    {Opcode::CONTRACT_MGMT, kNamespaceControl, 0x0050, "contract_mgmt", "contract_mgmt", 0x01, false},
    {Opcode::WITNESS,       kNamespaceControl, 0x0051, "witness",       "contract_mgmt", 0x01, false},

    // Execution namespace (0x03) - Functional group: "execution"
    {Opcode::EXEC,     kNamespaceExecution, 0x0201, "exec",      "execution", 0x01, false},
    {Opcode::QUARANTINE, kNamespaceExecution, 0x0202, "quarantine","execution", 0x01, false},
    {Opcode::MKDIR,    kNamespaceExecution, 0x0203, "mkdir",     "execution", 0x01, true},
    {Opcode::RM,       kNamespaceExecution, 0x0204, "rm",        "execution", 0x01, false},
    {Opcode::CP,       kNamespaceExecution, 0x0205, "cp",        "execution", 0x01, true},
    {Opcode::FILE_OP,  kNamespaceExecution, 0x0206, "file_op",   "execution", 0x01, false},
    {Opcode::PROCESS,  kNamespaceExecution, 0x0207, "process",   "execution", 0x01, false},
    {Opcode::CUSTOM,   kNamespaceExecution, 0x02FF, "custom",    "execution", 0x01, false},

    // Data namespace (0x04) - Functional group: "data"
    // Note: BOOTSTRAP_*, JOIN_* are non-packet (use HTTP/other transport), ns=0, message_id=0
};

constexpr const WireOpcodeEntry* OpcodeRegistry::wire_table() noexcept { return kWireTable; }
constexpr size_t OpcodeRegistry::wire_table_size() noexcept { return sizeof(kWireTable) / sizeof(kWireTable[0]); }

OpcodeRegistry::OpcodeRegistry()
{
    for (const auto& entry : kWireTable)
    {
        OpcodeEntry oe;
        oe.id = entry.code;
        oe.name = entry.name;
        oe.semver = "1.0.0";
        oe.capability_mask = entry.capability_mask;
        oe.idempotent = entry.idempotent;
        oe.ns = entry.ns;
        oe.message_id = entry.message_id;
        oe.functional_group = entry.functional_group;
        oe.supported_arches = {"x86_64", "aarch64"};

        by_code_[entry.code] = oe;
        by_name_[entry.name] = entry.code;

        if (entry.ns != 0 && entry.message_id != 0)
        {
            uint32_t wire_key = (static_cast<uint32_t>(entry.ns) << 16) | entry.message_id;
            by_wire_[wire_key] = oe;
        }

        // Initialize next message_id per functional group
        auto it = next_msg_id_.find(entry.functional_group);
        if (it == next_msg_id_.end() || it->second <= entry.message_id)
        {
            next_msg_id_[entry.functional_group] = entry.message_id + 1;
        }
    }

    // Register non-packet opcodes (ns=0, message_id=0)
    register_builtin(Opcode::BOOTSTRAP_SNAPSHOT, "bootstrap_snapshot", 0x01, true);
    register_builtin(Opcode::BOOTSTRAP_INFO, "bootstrap_info", 0x01, true);
    register_builtin(Opcode::JOIN, "join", 0x01, false);
    register_builtin(Opcode::LEAVE, "leave", 0x01, true);
    register_builtin(Opcode::JOIN_INFO, "join_info", 0x01, true);
}

OpcodeRegistry& OpcodeRegistry::instance()
{
    static OpcodeRegistry reg;
    return reg;
}

void OpcodeRegistry::register_builtin(Opcode code, std::string_view name, uint32_t capability_mask, bool idempotent)
{
    OpcodeEntry entry;
    entry.id = code;
    entry.name = std::string(name);
    entry.semver = "1.0.0";
    entry.capability_mask = capability_mask;
    entry.idempotent = idempotent;
    entry.supported_arches = {"x86_64", "aarch64"};

    // Look up wire info from constexpr table
    for (const auto& we : kWireTable)
    {
        if (we.code == code)
        {
            entry.ns = we.ns;
            entry.message_id = we.message_id;
            entry.functional_group = we.functional_group;
            break;
        }
    }

    by_code_[code] = entry;
    by_name_[entry.name] = code;

    uint32_t wire_key = (static_cast<uint32_t>(entry.ns) << 16) | entry.message_id;
    by_wire_[wire_key] = entry;

    auto it = next_msg_id_.find(entry.functional_group);
    if (it == next_msg_id_.end() || it->second <= entry.message_id)
    {
        next_msg_id_[entry.functional_group] = entry.message_id + 1;
    }
}

Result<void> OpcodeRegistry::register_plugin_opcode(const OpcodeEntry& entry)
{
    if (entry.id < Opcode(0xFB) || entry.id > Opcode(0xFE))
    {
        return SMO_ERR_CRYPTO(8, Error, NoRetry, None, "plugin opcode out of range (0xFB-0xFE)");
    }
    if (by_code_.count(entry.id))
    {
        return SMO_ERR_CRYPTO(8, Error, NoRetry, None, "duplicate opcode registration");
    }
    if (by_name_.count(entry.name))
    {
        return SMO_ERR_CRYPTO(8, Error, NoRetry, None, "duplicate opcode name");
    }

    by_code_[entry.id] = entry;
    by_name_[entry.name] = entry.id;

    if (entry.ns != 0 && entry.message_id != 0)
    {
        uint32_t wire_key = (static_cast<uint32_t>(entry.ns) << 16) | entry.message_id;
        if (by_wire_.count(wire_key))
        {
            return SMO_ERR_CRYPTO(8, Error, NoRetry, None, "duplicate wire opcode (ns, message_id)");
        }
        by_wire_[wire_key] = entry;

        auto it = next_msg_id_.find(entry.functional_group);
        if (it == next_msg_id_.end() || it->second <= entry.message_id)
        {
            next_msg_id_[entry.functional_group] = entry.message_id + 1;
        }
    }

    return {};
}

Result<OpcodeEntry> OpcodeRegistry::resolve(Opcode code) const
{
    auto it = by_code_.find(code);
    if (it == by_code_.end())
    {
        return SMO_ERR_CRYPTO(8, Error, NoRetry, None, "unknown opcode");
    }
    return it->second;
}

Result<OpcodeEntry> OpcodeRegistry::resolve_by_name(std::string_view name) const
{
    auto it = by_name_.find(std::string(name));
    if (it == by_name_.end())
    {
        return SMO_ERR_CRYPTO(8, Error, NoRetry, None, "unknown opcode name");
    }
    return by_code_.at(it->second);
}

Result<OpcodeEntry> OpcodeRegistry::resolve_by_wire(uint8_t ns, uint16_t message_id) const
{
    uint32_t wire_key = (static_cast<uint32_t>(ns) << 16) | message_id;
    auto it = by_wire_.find(wire_key);
    if (it == by_wire_.end())
    {
        return SMO_ERR_CRYPTO(8, Error, NoRetry, None, "unknown wire opcode (ns=" + std::to_string(ns) + ", msg_id=0x" + std::to_string(message_id) + ")");
    }
    return it->second;
}

Result<void> OpcodeRegistry::validate_packet_opcode(uint8_t ns, uint16_t message_id) const
{
    // RFC 0020: validate that the wire opcode exists in registry
    auto res = resolve_by_wire(ns, message_id);
    if (!res)
    {
        return res.error();
    }

    // Additional validation: namespace must be one of the 4 frozen namespaces
    if (ns != kNamespaceDiscovery && ns != kNamespaceControl &&
        ns != kNamespaceExecution && ns != kNamespaceData)
    {
        return SMO_ERR_PROTOCOL(604, Error, NoRetry, None, "unsupported namespace for packet (RFC 0020)");
    }

    return {};
}

uint16_t OpcodeRegistry::next_message_id(std::string_view functional_group) const
{
    auto it = next_msg_id_.find(std::string(functional_group));
    if (it == next_msg_id_.end())
    {
        return 0x0100; // Start at 0x0100 for new functional groups
    }
    return it->second++;
}

std::vector<OpcodeEntry> OpcodeRegistry::all() const
{
    std::vector<OpcodeEntry> entries;
    entries.reserve(by_code_.size());
    for (const auto& [_, entry] : by_code_)
        entries.push_back(entry);
    return entries;
}

} // namespace smo