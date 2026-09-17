#include "packet_route.hpp"

namespace smo::packet_route {

    namespace {

        // Namespace của từng opcode được Packet hóa ở G3. Trả 0 nếu non-Packet.
        constexpr uint8_t ns_for(Opcode op) noexcept
        {
            switch (op)
            {
                // ── EXECUTION (0x03) ─────────────────────────────────────
                case Opcode::LS:
                case Opcode::PUT:
                case Opcode::GET:
                case Opcode::EXEC:
                case Opcode::QUARANTINE:
                case Opcode::ECHO:
                case Opcode::MKDIR:
                case Opcode::RM:
                case Opcode::CP:
                case Opcode::FILE_OP:
                case Opcode::PROCESS:
                case Opcode::CUSTOM:
                    return kNamespaceExecution;

                // ── CONTROL (0x02) ───────────────────────────────────────
                case Opcode::CONTRACT_MGMT:
                case Opcode::WITNESS:
                case Opcode::REVOKE_CERT:
                case Opcode::EPOCH_INCREMENT:
                case Opcode::RECOVERY_SESSION:
                case Opcode::CRL_SYNC:
                case Opcode::RECOVERY:
                case Opcode::GOV_PROPOSE:
                case Opcode::GOV_VOTE:
                case Opcode::GOV_COMMIT:
                case Opcode::GOV_LIST:
                case Opcode::GOV_STATUS:
                case Opcode::GOV_INFO:
                    return kNamespaceControl;

                // ── Non-Packet (không có route) ──────────────────────────
                case Opcode::BOOTSTRAP_SNAPSHOT:
                case Opcode::BOOTSTRAP_INFO:
                case Opcode::JOIN:
                case Opcode::LEAVE:
                case Opcode::JOIN_INFO:
                default:
                    return 0;
            }
        }

    } // anonymous namespace

    std::optional<PacketRoute> to_packet_route(Opcode op) noexcept
    {
        const uint8_t ns = ns_for(op);
        if (ns == 0)
            return std::nullopt;
        return PacketRoute{ns, static_cast<uint16_t>(op)};
    }

    std::optional<PacketRoute> to_packet_route(uint32_t opcode_id) noexcept
    {
        if (opcode_id > 0xFF)
            return std::nullopt;
        return to_packet_route(static_cast<Opcode>(opcode_id));
    }

    std::optional<Opcode> from_packet_route(uint8_t ns, uint16_t message_id) noexcept
    {
        if (message_id > 0xFF)
            return std::nullopt;

        const auto op = static_cast<Opcode>(message_id);
        if (ns_for(op) != ns)
            return std::nullopt;

        return op;
    }

    bool is_packet_capable(Opcode op) noexcept { return ns_for(op) != 0; }

} // namespace smo::packet_route
