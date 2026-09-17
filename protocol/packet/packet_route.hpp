#pragma once

#include <cstdint>
#include <optional>

#include "../../core/opcode/opcode.h"

namespace smo::packet_route {

// RFC 0019 §wire — frozen namespaces (0x01..0x04). Không tạo namespace mới.
inline constexpr uint8_t kNamespaceDiscovery = 0x01;
inline constexpr uint8_t kNamespaceControl   = 0x02;
inline constexpr uint8_t kNamespaceExecution = 0x03;
inline constexpr uint8_t kNamespaceData      = 0x04;

struct PacketRoute {
    uint8_t  ns;
    uint16_t message_id;

    bool operator==(const PacketRoute&) const = default;
};

// Implementation adapter: internal Opcode -> RFC 0019 {namespace, message_id}.
// `message_id` = byte value của Opcode (implementation mapping, không phải RFC registration).
// Returns nullopt cho non-Packet opcodes (BOOTSTRAP_*, JOIN_*, LEAVE).
std::optional<PacketRoute> to_packet_route(Opcode op) noexcept;
std::optional<PacketRoute> to_packet_route(uint32_t opcode_id) noexcept;

// Reverse adapter. Returns nullopt nếu (ns, message_id) không map về Packet opcode nào.
std::optional<Opcode> from_packet_route(uint8_t ns, uint16_t message_id) noexcept;

// True nếu opcode có Packet route trong G3.
bool is_packet_capable(Opcode op) noexcept;

} // namespace smo::packet_route
