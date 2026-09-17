#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "../../core/errors/error.hpp"
#include "../../core/opcode/opcode.h"

namespace smo {

// RFC 0019 (AMEND-4) — Packet wire format, canonical 39B big-endian header:
//   protocol_version(1) | suite_id(1) | namespace(1) | message_id(2)
//   | session_id(16) | timestamp(8, ns) | nonce(8, seq) | payload_length(2)
//   | payload(N) | auth(V)
//
// NOTE: `packet_to_buffer`/`packet_from_buffer` write/read multi-byte fields
// explicitly big-endian, so the in-memory struct below is NOT a raw memcpy
// target and is intentionally NOT `packed` (packed fields cannot bind to
// references, which the canonical accessors rely on).

inline constexpr uint8_t kPacketProtocolVersion = 0x03;

// Wire header luôn 39B (RFC 0019). In-memory struct có padding, nên kích thước
// wire được assert bằng công thức field widths, không phải sizeof().
inline constexpr size_t kPacketHeaderWireSize = 1 + 1 + 1 + 2 + 16 + 8 + 8 + 2;
static_assert(kPacketHeaderWireSize == 39, "RFC 0019 wire header must be exactly 39 bytes");

struct PacketHeader {
    uint8_t  protocol_version{kPacketProtocolVersion};
    uint8_t  suite_id{0};
    uint8_t  ns{0};                          // RFC 0019 namespace (0x01..0x04)
    uint16_t message_id{0};
    std::array<uint8_t, 16> session_id{};
    int64_t  timestamp{0};                   // Unix nanoseconds
    uint64_t nonce{0};                       // monotonic sequence; 0 rejected
    uint16_t payload_length{0};
};

// Auth/signature length suy từ (namespace, suite_id) — KHÔNG lên wire.
// Trả 0 nghĩa là namespace không hỗ trợ Packet ở G3.
size_t expected_auth_length(uint8_t ns, uint8_t suite_id) noexcept;

// Serialize the canonical 39B big-endian header (RFC 0019). This is the single
// source of truth for the wire header AND for the AEAD AAD, so the AAD is
// byte-identical to what `packet_to_buffer` emits.
std::array<uint8_t, kPacketHeaderWireSize> serialize_packet_header(const PacketHeader& header) noexcept;

struct Packet {
    PacketHeader header{};
    std::vector<uint8_t> payload;
    std::vector<uint8_t> auth;

    // Canonical convenience accessors — map thẳng vào header, không duplicate storage.
    std::array<uint8_t, 16>& session_id() noexcept { return header.session_id; }
    const std::array<uint8_t, 16>& session_id() const noexcept { return header.session_id; }
    int64_t& timestamp() noexcept { return header.timestamp; }
    const int64_t& timestamp() const noexcept { return header.timestamp; }

    // ── Legacy in-memory compatibility adapters (KHÔNG phải wire fields, xóa ở P5) ──
    // Không tham gia serialization / AAD / equality / packet-size.
    uint32_t opcode_id{0};
    std::array<uint8_t, 16> intent_id{};
};

// Parse a wire buffer into a Packet. Rejects: version != 0x03, too short,
// zero nonce, zero session_id, unsupported namespace, bad payload/auth length.
Result<Packet> packet_from_buffer(std::span<const uint8_t> wire);

// Serialize a Packet to `out`. If header.ns/message_id are unset (message_id==0)
// the route is derived from `opcode_id`; non-Packet opcodes are rejected.
Result<void> packet_to_buffer(const Packet& pkt, std::vector<uint8_t>& out);

} // namespace smo
