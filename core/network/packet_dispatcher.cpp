#include "packet_dispatcher.hpp"
#include "core/discovery/gossip.hpp"
#include "core/transport/framing.hpp"
#include "protocol/packet/packet.h"
#include "protocol/packet/packet_crypto.hpp"
#include "protocol/packet/packet_route.hpp"
#include "core/session/session.hpp"
#include <cstring>

namespace smo::network {

    // ── PacketSessionTransport — wraps SecureSession as hl::Transport for packet path ─
    // Uses send_framed/recv_framed + packet AEAD (no inner FrameHeader, B5)
    class PacketSessionTransport final : public hl::Transport
    {
    public:
        PacketSessionTransport(SecureSession& sec, const hl::Endpoint& remote) : sec_(&sec), remote_(remote) {}

        std::error_code listen(const hl::Endpoint&, hl::Transport::PacketHandler, hl::Transport::ErrorHandler) override
        {
            return {};
        }

        std::error_code connect(const hl::Endpoint&) override { return {}; }

        std::error_code send(Packet&& pkt, const hl::Endpoint&) override
        {
            // Packet path: seal with AEAD, send framed
            auto route_opt = smo::packet_route::to_packet_route(pkt.opcode_id);
            if (!route_opt)
            {
                return std::make_error_code(std::errc::invalid_argument);
            }

            // Ensure header has required fields
            bool session_id_zero = true;
            for (uint8_t b : pkt.header.session_id)
            {
                if (b != 0) { session_id_zero = false; break; }
            }
            if (session_id_zero || pkt.header.nonce == 0)
            {
                return std::make_error_code(std::errc::invalid_argument);
            }

            // Seal the packet
            auto seal_res = packet_seal_data(pkt, sec_->crypto_context().packet_tx_key(), pkt.header.nonce);
            if (!seal_res)
            {
                return std::make_error_code(std::errc::invalid_argument);
            }

            // Serialize sealed packet
            std::vector<uint8_t> buf;
            auto pack_res = packet_to_buffer(pkt, buf);
            if (!pack_res)
            {
                return std::make_error_code(std::errc::invalid_argument);
            }

            // Send framed (no inner FrameHeader per B5)
            auto send_res = sec_->send_framed(BytesView(buf.data(), buf.size()));
            if (!send_res)
            {
                return std::make_error_code(std::errc::io_error);
            }
            return {};
        }

        void close() noexcept override {}

    private:
        SecureSession* sec_;
        hl::Endpoint remote_;
    };

    // ── SessionTransport — wraps a single TransportSession as hl::Transport ─

    class SessionTransport final : public hl::Transport
    {
    public:
        SessionTransport(TransportSession& session, const hl::Endpoint& remote) : session_(&session), remote_(remote) {}

        std::error_code listen(const hl::Endpoint&, hl::Transport::PacketHandler, hl::Transport::ErrorHandler) override
        {
            return {};
        } // not used

        std::error_code connect(const hl::Endpoint&) override { return {}; } // not used

        std::error_code send(Packet&& pkt, const hl::Endpoint&) override
        {
            // P5: Packet path — seal with AEAD, send framed (no inner FrameHeader, B5)
            // Determine if this is a packet-capable opcode
            auto route_opt = smo::packet_route::to_packet_route(pkt.opcode_id);
            if (route_opt)
            {
                // Build header fields for packet path
                // Note: session_id, sequence, timestamp should be set by caller before calling send
                // For now, we assume they're already set in the packet
                bool session_id_zero = true;
                for (uint8_t b : pkt.header.session_id)
                {
                    if (b != 0) { session_id_zero = false; break; }
                }
                if (session_id_zero)
                {
                    return std::make_error_code(std::errc::invalid_argument);
                }
                if (pkt.header.nonce == 0)
                {
                    return std::make_error_code(std::errc::invalid_argument);
                }

                // Seal the packet (AEAD)
                // The caller must ensure the transport session has access to PacketTxKey
                // This requires the underlying session to be a SecureSession
                // For now, fall back to legacy framing if we can't access the key
                std::vector<uint8_t> buf;
                auto pack_res = packet_to_buffer(pkt, buf);
                if (!pack_res)
                {
                    return std::make_error_code(std::errc::invalid_argument);
                }

                // Frame the data (legacy path for non-packet or when key unavailable)
                Bytes framed;
                frame_write(BytesView(buf.data(), buf.size()), kFrameFlagNone, framed);

                // Send
                auto send_res = session_->send(framed);
                if (!send_res)
                {
                    return std::make_error_code(std::errc::io_error);
                }
                return {};
            }

            // Legacy path for non-packet opcodes
            std::vector<uint8_t> buf;
            auto pack_res = packet_to_buffer(pkt, buf);
            if (!pack_res)
            {
                return std::make_error_code(std::errc::invalid_argument);
            }

            Bytes framed;
            frame_write(BytesView(buf.data(), buf.size()), kFrameFlagNone, framed);

            auto send_res = session_->send(framed);
            if (!send_res)
            {
                return std::make_error_code(std::errc::io_error);
            }
            return {};
        }

        void close() noexcept override {}

    private:
        TransportSession* session_;
        hl::Endpoint remote_;
    };

    // ── PacketDispatcher ──────────────────────────────────────────────────

    void PacketDispatcher::register_handler(uint32_t opcode_id, HandlerFunc handler)
    {
        handlers_[opcode_id] = std::move(handler);
    }

    void PacketDispatcher::unregister_handler(uint32_t opcode_id)
    {
        handlers_.erase(opcode_id);
    }

    bool PacketDispatcher::has_handler(uint32_t opcode_id) const
    {
        return handlers_.find(opcode_id) != handlers_.end();
    }

    void PacketDispatcher::register_raw_handler(RawHandler handler)
    {
        raw_handler_ = std::move(handler);
    }

    Result<void> PacketDispatcher::dispatch(Packet&& pkt, const hl::Endpoint& remote, hl::Transport& transport)
    {
        // Node lifecycle state check
        if (lifecycle_fsm_)
        {
            auto state_check = lifecycle_fsm_->check_opcode_allowed(pkt.opcode_id);
            if (!state_check)
                return state_check;
        }

        auto it = handlers_.find(pkt.opcode_id);
        if (it == handlers_.end())
        {
            return SMO_ERR_PROTOCOL(604, Error, NoRetry, None,
                                    "No handler registered for opcode 0x" + std::to_string(pkt.opcode_id));
        }
        return it->second(std::move(pkt), remote, transport);
    }

    Result<void> PacketDispatcher::dispatch_session(TransportSession& session, const hl::Endpoint& remote)
    {
        // 1. Read raw framed data
        auto data = session.recv(65536);
        if (!data)
        {
            return SMO_ERR_TRANSPORT(304, Error, RetrySafe, None,
                                     "Failed to read from session: " + data.error().message);
        }
        Bytes raw = std::move(data.value());

        // 2. Try framed Packet format first
        FrameHeader fh;
        BytesView payload;
        size_t frame_sz = frame_read(raw, fh, payload);
        if (frame_sz > 0)
        {
            // 2a. Check for gossip frame (starts with "GOSP" magic)
            if (payload.size() >= 4)
            {
                uint32_t gossip_magic = 0;
                gossip_magic |= (static_cast<uint32_t>(payload[0]) << 24);
                gossip_magic |= (static_cast<uint32_t>(payload[1]) << 16);
                gossip_magic |= (static_cast<uint32_t>(payload[2]) << 8);
                gossip_magic |= static_cast<uint32_t>(payload[3]);
                if (gossip_magic == kGossipFrameMagic && gossip_engine_)
                {
                    auto gossip_data = payload.subspan(4);
                    return gossip_engine_->apply_gossip(gossip_data);
                }
            }

            // 3. Parse as Packet
            auto pkt = packet_from_buffer(payload);
            if (pkt)
            {
                // 3a. Node lifecycle state check
                if (lifecycle_fsm_)
                {
                    auto state_check = lifecycle_fsm_->check_opcode_allowed(pkt.value().opcode_id);
                    if (!state_check)
                        return state_check;
                }
                // 4. Look up handler
                auto it = handlers_.find(pkt.value().opcode_id);
                if (it == handlers_.end())
                {
                    return SMO_ERR_PROTOCOL(604, Error, NoRetry, None,
                                            "No handler for opcode 0x" + std::to_string(pkt.value().opcode_id));
                }
                // 5. Create transport adapter and dispatch
                SessionTransport transport_adapter(session, remote);
                return it->second(std::move(pkt.value()), remote, transport_adapter);
            }
            // framed but not a valid Packet — fall through to raw handler
        }

        // 6. Fallback: raw (non-Packet) protocol handler
        if (raw_handler_)
        {
            return raw_handler_(raw, session, remote);
        }

        if (frame_sz == 0)
        {
            return SMO_ERR_TRANSPORT(309, Error, RetrySafe, None, "Failed to unframe data");
        }
        return SMO_ERR_PROTOCOL(600, Error, NoRetry, None, "Failed to parse packet");
    }

    Result<void> PacketDispatcher::dispatch_packet_session(SecureSession& sec, SessionManager& session_mgr,
                                                           const hl::Endpoint& remote)
    {
        // 1. Receive framed packet (no AEAD at transport layer)
        auto framed_res = sec.recv_framed();
        if (!framed_res)
        {
            return SMO_ERR_TRANSPORT(304, Error, RetrySafe, None,
                                     "Failed to read framed packet: " + framed_res.error().message);
        }
        Bytes sealed = std::move(framed_res.value());

        // 2. Parse packet
        auto pkt_res = packet_from_buffer(sealed);
        if (!pkt_res)
        {
            return SMO_ERR_PROTOCOL(600, Error, NoRetry, None, "Failed to parse packet: " + pkt_res.error().message);
        }
        Packet pkt = std::move(pkt_res.value());

        // 3. Verify this is a packet-capable opcode (has namespace+message_id mapping)
        auto route_opt = smo::packet_route::from_packet_route(pkt.header.ns, pkt.header.message_id);
        if (!route_opt)
        {
            return SMO_ERR_PROTOCOL(604, Error, NoRetry, None,
                                    "Opcode not packet-capable: ns=" + std::to_string(pkt.header.ns) +
                                    " mid=" + std::to_string(pkt.header.message_id));
        }

        // 4. Look up session by session_id from packet header
        smo::SessionId sid;
        std::memcpy(sid.bytes.data(), pkt.header.session_id.data(), 16);
        auto* session = session_mgr.lookup(sid);
        if (!session)
        {
            return SMO_ERR_SESSION(501, Error, NoRetry, Reconnect, "Session not found for packet");
        }

        // 5. Replay window precheck (sequence = header.nonce)
        uint64_t sequence = pkt.header.nonce;
        if (!session->security_state().rx_window.is_acceptable(sequence))
        {
            return SMO_ERR_PROTOCOL(606, Error, NoRetry, None, "Replay window check failed for sequence " + std::to_string(sequence));
        }

        // 6. Open packet with AEAD (PacketRxKey)
        auto open_res = packet_open_data(pkt, sec.crypto_context().packet_rx_key());
        if (!open_res)
        {
            return SMO_ERR_PROTOCOL(607, Error, NoRetry, None, "Packet AEAD open failed: " + open_res.error().message);
        }

        // 7. Replay commit ONLY after AEAD success
        if (!session->security_state().rx_window.commit(sequence))
        {
            return SMO_ERR_PROTOCOL(606, Error, NoRetry, None, "Replay commit failed for sequence " + std::to_string(sequence));
        }

        // 8. Node lifecycle state check (using mapped opcode)
        if (lifecycle_fsm_)
        {
            auto state_check = lifecycle_fsm_->check_opcode_allowed(static_cast<uint32_t>(route_opt.value()));
            if (!state_check)
                return state_check;
        }

        // 10. Look up handler by opcode_id (internal opcode)
        uint32_t opcode_id = static_cast<uint32_t>(route_opt.value());
        auto it = handlers_.find(opcode_id);
        if (it == handlers_.end())
        {
            return SMO_ERR_PROTOCOL(604, Error, NoRetry, None,
                                    "No handler for opcode 0x" + std::to_string(opcode_id));
        }

        // 11. Create transport adapter for response (uses packet path)
        PacketSessionTransport transport_adapter(sec, remote);
        return it->second(std::move(pkt), remote, transport_adapter);
    }

} // namespace smo::network
