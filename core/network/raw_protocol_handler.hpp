#pragma once

#include <core/discovery/discovery.hpp>
#include <core/mesh/mesh_manager.hpp>
#include <core/authority/authority.hpp>
#include <core/recovery/crl.hpp>
#include <core/join/join_protocol.hpp>
#include <core/transport/transport.hpp>

namespace smo {

    // Handles raw (non-packet) protocol messages for discovery and join
    struct RawProtocolHandler {
        DiscoveryEngine& discovery_engine;
        NodeID local_id;
        PeerRecord self_record;
        MeshManager& mesh_manager;
        authority::MeshAuthority& authority;
        recovery::CRL& crl;

        RawProtocolHandler(DiscoveryEngine& de, NodeID lid, const PeerRecord& sr,
                          MeshManager& mm, authority::MeshAuthority& auth, recovery::CRL& c)
            : discovery_engine(de), local_id(lid), self_record(sr),
              mesh_manager(mm), authority(auth), crl(c) {}

        Result<void> operator()(BytesView raw, TransportSession& session, const Endpoint& remote) const {
            int64_t now_ns = static_cast<int64_t>(std::chrono::system_clock::now().time_since_epoch().count());

            Endpoint ep;
            ep.scheme = "tcp";
            ep.host = remote.host;
            ep.port = remote.port;

            auto try_join_protocol = [this, &raw, &session, &remote]() -> bool {
                BytesView cbor_data = raw;

                auto send_cbor_resp = [&](const Bytes& cbor) -> bool {
                    auto send_res = session.send(BytesView(cbor));
                    return static_cast<bool>(send_res);
                };

                auto join_req = join::JoinRequest::decode_cbor(cbor_data);
                if (join_req) {
                    std::printf("[smo-node] Raw handler: JoinRequest from %s\n", remote.host.c_str());
                    auto join_resp = join::process_join_request(join_req.value(), mesh_manager, authority);
                    if (join_resp) {
                        auto cbor = join_resp.value().encode_cbor();
                        send_cbor_resp(cbor);
                        return true;
                    }
                    std::printf("[smo-node] JoinRequest failed: %s\n", join_resp.error().message.c_str());
                    return false;
                }

                auto sync_req = join::BootstrapSyncRequest::decode_cbor(cbor_data);
                if (sync_req) {
                    std::printf("[smo-node] Raw handler: BootstrapSyncRequest from %s\n", remote.host.c_str());
                    auto sync_resp = join::process_bootstrap_sync(sync_req.value(), mesh_manager, authority, &crl);
                    if (sync_resp) {
                        auto cbor = sync_resp.value().encode_cbor();
                        send_cbor_resp(cbor);
                        return true;
                    }
                    std::printf("[smo-node] BootstrapSync failed: %s\n", sync_resp.error().message.c_str());
                    return false;
                }

                return false;
            };

            if (try_join_protocol()) {
                std::printf("[smo-node] Join protocol handled successfully\n");
                return {};
            }

            auto hello = HelloMsg::deserialize(raw);
            if (hello) {
                std::printf("[smo-node] Raw handler: HelloMsg from %s\n", remote.host.c_str());
                auto handle_res = discovery_engine.handle_hello(hello.value(), ep, now_ns);
                if (!handle_res) return handle_res.error();

                WelcomeMsg welcome;
                welcome.node_id = local_id;
                welcome.peer_record = self_record;
                auto welcome_data = welcome.serialize();
                auto send_res = session.send(welcome_data);
                if (!send_res) {
                    std::printf("[smo-node] Failed to send WelcomeMsg\n");
                }
                return {};
            }

            auto ping = PingMsg::deserialize(raw);
            if (ping) {
                PongMsg pong;
                pong.timestamp = ping.value().timestamp;
                auto pong_data = pong.serialize();
                session.send(pong_data);
                return {};
            }

            return Error(ErrorCode(ErrorCategory::Transport, 309, Severity::Warn,
                                   RetryClass::RetrySafe, Recovery::None),
                         "Unknown raw protocol", __FILE__, __LINE__);
        }
    };

} // namespace smo