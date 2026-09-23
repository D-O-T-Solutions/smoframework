#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include "core/errors/error.hpp"
#include "core/opcode/opcode.h"

namespace smo {

// RFC 0020 — 3-byte namespace allocation (namespace(1) + message_id(2))
// Four frozen namespaces: Discovery(0x01), Control(0x02), Execution(0x03), Data(0x04)

inline constexpr uint8_t kNamespaceDiscovery = 0x01;
inline constexpr uint8_t kNamespaceControl = 0x02;
inline constexpr uint8_t kNamespaceExecution = 0x03;
inline constexpr uint8_t kNamespaceData = 0x04;

struct OpcodeEntry
{
    Opcode id;
    std::string name;
    std::string semver;
    uint32_t capability_mask{0};
    bool idempotent{false};
    std::string contract_id;
    std::string plugin_id;
    std::vector<std::string> supported_arches;

    // RFC 0020: wire namespace and message_id
    uint8_t ns{0};
    uint16_t message_id{0};

    // RFC 0020: functional group for sequential message ID allocation
    std::string functional_group;
};

struct WireOpcodeEntry
{
    Opcode code;
    uint8_t ns;
    uint16_t message_id;
    const char* name;
    const char* functional_group;
    uint32_t capability_mask;
    bool idempotent;
};

class OpcodeRegistry
{
public:
    OpcodeRegistry();

    void register_builtin(Opcode code, std::string_view name, uint32_t capability_mask, bool idempotent);

    Result<void> register_plugin_opcode(const OpcodeEntry& entry);

    Result<OpcodeEntry> resolve(Opcode code) const;
    Result<OpcodeEntry> resolve_by_name(std::string_view name) const;

    // RFC 0020: resolve by wire namespace + message_id
    Result<OpcodeEntry> resolve_by_wire(uint8_t ns, uint16_t message_id) const;

    // RFC 0020: packet validation via registry
    Result<void> validate_packet_opcode(uint8_t ns, uint16_t message_id) const;

    // RFC 0020: get next message_id for a functional group
    uint16_t next_message_id(std::string_view functional_group) const;

    std::vector<OpcodeEntry> all() const;

    // Compile-time constexpr access
    static constexpr const WireOpcodeEntry* wire_table() noexcept;
    static constexpr size_t wire_table_size() noexcept;

    static OpcodeRegistry& instance();

private:
    std::unordered_map<Opcode, OpcodeEntry> by_code_;
    std::unordered_map<std::string, Opcode> by_name_;

    // RFC 0020: wire lookup (ns, message_id) -> OpcodeEntry
    std::unordered_map<uint32_t, OpcodeEntry> by_wire_;

    // RFC 0020: functional group -> next message_id
    mutable std::unordered_map<std::string, uint16_t> next_msg_id_;
};

} // namespace smo