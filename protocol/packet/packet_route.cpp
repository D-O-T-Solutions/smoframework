#include "packet_route.hpp"
#include "../../core/opcode/opcode_registry.hpp"

namespace smo::packet_route {

    std::optional<PacketRoute> to_packet_route(Opcode op) noexcept
    {
        const auto& registry = OpcodeRegistry::instance();
        auto res = registry.resolve(op);
        if (!res)
            return std::nullopt;

        const auto& entry = res.value();
        if (entry.ns == 0 || entry.message_id == 0)
            return std::nullopt;

        return PacketRoute{entry.ns, entry.message_id};
    }

    std::optional<PacketRoute> to_packet_route(uint32_t opcode_id) noexcept
    {
        if (opcode_id > 0xFF)
            return std::nullopt;
        return to_packet_route(static_cast<Opcode>(opcode_id));
    }

    std::optional<Opcode> from_packet_route(uint8_t ns, uint16_t message_id) noexcept
    {
        const auto& registry = OpcodeRegistry::instance();
        auto res = registry.resolve_by_wire(ns, message_id);
        if (!res)
            return std::nullopt;

        return res.value().id;
    }

    bool is_packet_capable(Opcode op) noexcept
    {
        const auto& registry = OpcodeRegistry::instance();
        auto res = registry.resolve(op);
        if (!res)
            return false;
        return res.value().ns != 0 && res.value().message_id != 0;
    }

} // namespace smo::packet_route