#include "packet.h"
#include "packet_route.hpp"
#include "../../core/opcode/opcode_registry.hpp"

#include <cstring>

namespace smo {

    namespace {

        constexpr size_t kHeaderSize = kPacketHeaderWireSize; // 39
        constexpr size_t kAeadTagLen = 16;
        constexpr size_t kEd25519SigLen = 64;
        constexpr size_t kMlDsa65SigLen = 3309;

        uint16_t get_u16(std::span<const uint8_t> data, size_t off)
        {
            return static_cast<uint16_t>((static_cast<uint16_t>(data[off]) << 8) | data[off + 1]);
        }

        uint64_t get_u64(std::span<const uint8_t> data, size_t off)
        {
            uint64_t v = 0;
            for (int i = 0; i < 8; ++i)
                v = (v << 8) | data[off + static_cast<size_t>(i)];
            return v;
        }

    } // anonymous namespace

    size_t expected_auth_length(uint8_t ns, uint8_t suite_id) noexcept
    {
        if (ns == packet_route::kNamespaceDiscovery || ns == packet_route::kNamespaceExecution || ns == packet_route::kNamespaceData)
            return kAeadTagLen;

        if (ns == packet_route::kNamespaceControl)
        {
            if (suite_id == 1 || suite_id == 2)
                return kEd25519SigLen;
            if (suite_id == 3)
                return kMlDsa65SigLen;
            return 0;
        }

        return 0;
    }

    std::array<uint8_t, kPacketHeaderWireSize> serialize_packet_header(const PacketHeader& header) noexcept
    {
        std::array<uint8_t, kPacketHeaderWireSize> out{};
        out[0] = header.protocol_version;
        out[1] = header.suite_id;
        out[2] = header.ns;
        out[3] = static_cast<uint8_t>(header.message_id >> 8);
        out[4] = static_cast<uint8_t>(header.message_id & 0xFF);
        std::memcpy(out.data() + 5, header.session_id.data(), header.session_id.size());

        const uint64_t ts = static_cast<uint64_t>(header.timestamp);
        for (int i = 0; i < 8; ++i)
            out[21 + static_cast<size_t>(i)] = static_cast<uint8_t>(ts >> ((7 - i) * 8));
        for (int i = 0; i < 8; ++i)
            out[29 + static_cast<size_t>(i)] = static_cast<uint8_t>(header.nonce >> ((7 - i) * 8));

        out[37] = static_cast<uint8_t>(header.payload_length >> 8);
        out[38] = static_cast<uint8_t>(header.payload_length & 0xFF);
        return out;
    }

    Result<Packet> packet_from_buffer(std::span<const uint8_t> wire)
    {
        if (wire.size() < kHeaderSize)
        {
            return SMO_ERR_PROTOCOL(600, Error, NoRetry, None, "wire buffer too short for packet header");
        }

        if (wire[0] != kPacketProtocolVersion)
        {
            return SMO_ERR_PROTOCOL(601, Error, NoRetry, None, "unsupported packet version");
        }

        Packet pkt{};
        pkt.header.protocol_version = wire[0];
        pkt.header.suite_id = wire[1];
        pkt.header.ns = wire[2];
        pkt.header.message_id = get_u16(wire, 3);
        std::memcpy(pkt.header.session_id.data(), wire.data() + 5, 16);
        pkt.header.timestamp = static_cast<int64_t>(get_u64(wire, 21));
        pkt.header.nonce = get_u64(wire, 29);
        pkt.header.payload_length = get_u16(wire, 37);

        if (pkt.header.nonce == 0)
        {
            return SMO_ERR_PROTOCOL(602, Error, NoRetry, None, "zero nonce rejected (RFC 0019 rule 1)");
        }

        bool zero_session = true;
        for (const auto b : pkt.header.session_id)
            zero_session = zero_session && (b == 0);
        if (zero_session)
        {
            return SMO_ERR_PROTOCOL(603, Error, NoRetry, None, "zero session_id rejected");
        }

        const size_t auth_len = expected_auth_length(pkt.header.ns, pkt.header.suite_id);
        if (auth_len == 0)
        {
            return SMO_ERR_PROTOCOL(604, Error, NoRetry, None, "unsupported namespace for packet G3");
        }

        // RFC 0020: validate opcode via registry
        auto reg_res = OpcodeRegistry::instance().validate_packet_opcode(pkt.header.ns, pkt.header.message_id);
        if (!reg_res)
        {
            return reg_res.error();
        }

        if (kHeaderSize + pkt.header.payload_length > wire.size())
        {
            return SMO_ERR_PROTOCOL(605, Error, NoRetry, None, "payload length exceeds wire buffer");
        }
        if (kHeaderSize + pkt.header.payload_length + auth_len != wire.size())
        {
            return SMO_ERR_PROTOCOL(606, Error, NoRetry, None, "auth length mismatch");
        }

        pkt.payload.assign(wire.begin() + static_cast<ptrdiff_t>(kHeaderSize),
                           wire.begin() + static_cast<ptrdiff_t>(kHeaderSize + pkt.header.payload_length));
        pkt.auth.assign(wire.begin() + static_cast<ptrdiff_t>(kHeaderSize + pkt.header.payload_length),
                        wire.end());

        const auto route = packet_route::from_packet_route(pkt.header.ns, pkt.header.message_id);
        pkt.opcode_id = route ? static_cast<uint32_t>(*route) : 0;

        return pkt;
    }

    Result<void> packet_to_buffer(const Packet& pkt, std::vector<uint8_t>& out)
    {
        out.clear();

        if (pkt.header.protocol_version != kPacketProtocolVersion)
        {
            return SMO_ERR_PROTOCOL(601, Error, NoRetry, None, "unsupported packet version to serialize");
        }
        if (pkt.payload.size() > 65535)
        {
            return SMO_ERR_PROTOCOL(602, Error, NoRetry, None, "payload too large");
        }

        uint8_t ns = pkt.header.ns;
        uint16_t message_id = pkt.header.message_id;
        if (message_id == 0)
        {
            const auto route = packet_route::to_packet_route(pkt.opcode_id);
            if (!route)
            {
                return SMO_ERR_PROTOCOL(603, Error, NoRetry, None, "no packet route for opcode");
            }
            ns = route->ns;
            message_id = route->message_id;
        }

        // RFC 0020: validate opcode via registry before serialization
        auto reg_res = OpcodeRegistry::instance().validate_packet_opcode(ns, message_id);
        if (!reg_res)
        {
            return reg_res.error();
        }

        PacketHeader wire_header = pkt.header;
        wire_header.protocol_version = kPacketProtocolVersion;
        wire_header.ns = ns;
        wire_header.message_id = message_id;
        wire_header.payload_length = static_cast<uint16_t>(pkt.payload.size());
        const auto header_bytes = serialize_packet_header(wire_header);

        out.reserve(kHeaderSize + pkt.payload.size() + pkt.auth.size());
        out.insert(out.end(), header_bytes.begin(), header_bytes.end());
        out.insert(out.end(), pkt.payload.begin(), pkt.payload.end());
        out.insert(out.end(), pkt.auth.begin(), pkt.auth.end());

        return {};
    }

} // namespace smo
