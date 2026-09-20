#include "protocol_service.hpp"

#include <core/join/join_protocol.hpp>
#include <core/discovery/discovery.hpp>
#include <core/runtime/structured_logger.hpp>

#include <chrono>

namespace smo::runtime {

    namespace {
        auto& LOG = smo::runtime::global_logger();

        inline int64_t now_ns_since_epoch() {
            return static_cast<int64_t>(std::chrono::system_clock::now().time_since_epoch().count());
        }
    }

    ProtocolService::ProtocolService(
        Config config,
        smo::DiscoveryEngine& discovery,
        smo::MeshManager& mesh_manager,
        smo::authority::MeshAuthority& authority,
        smo::recovery::CRL& crl,
        const smo::NodeID& local_id,
        const smo::PeerRecord& self_record)
        : config_(std::move(config)),
          discovery_(discovery),
          mesh_manager_(mesh_manager),
          authority_(authority),
          crl_(crl),
          local_id_(local_id),
          self_record_(self_record) {}

    ProtocolService::~ProtocolService() = default;

    ProtocolService::ProtocolService(ProtocolService&& other) noexcept
        : config_(std::move(other.config_)),
          discovery_(other.discovery_),
          mesh_manager_(other.mesh_manager_),
          authority_(other.authority_),
          crl_(other.crl_),
          local_id_(other.local_id_),
          self_record_(other.self_record_) {}

    void ProtocolService::register_raw_handler(smo::network::PacketDispatcher& dispatcher)
    {
        dispatcher.register_raw_handler([this](smo::BytesView raw, smo::TransportSession& session,
                                                const smo::Endpoint& remote) -> smo::Result<void> {
            return this->handle_raw(raw, session, remote);
        });
    }

    smo::Result<void> ProtocolService::handle_raw(smo::BytesView raw, smo::TransportSession& session,
                                                   const smo::Endpoint& remote) {
        int64_t now_ns = now_ns_since_epoch();

        // Use remote directly as smo::Endpoint
        smo::Endpoint ep = remote;

        // Try join protocol FIRST (raw CBOR)
        auto try_join_protocol = [&]() -> bool {
            smo::BytesView cbor_data = raw;

            // Send raw CBOR (client decodes without a length prefix)
            auto send_cbor_resp = [&](const smo::Bytes& cbor) -> bool {
                auto send_res = session.send(smo::BytesView(cbor));
                return static_cast<bool>(send_res);
            };

            // Try JoinRequest (opcode 0x0601)
            auto join_req = smo::join::JoinRequest::decode_cbor(cbor_data);
            if (join_req)
            {
                LOG.info("Raw handler: JoinRequest from " + remote.host);
                auto join_resp = smo::join::process_join_request(join_req.value(), mesh_manager_, authority_);
                if (join_resp)
                {
                    auto cbor = join_resp.value().encode_cbor();
                    send_cbor_resp(cbor);
                    return true;
                }
                LOG.warn("JoinRequest failed: " + join_resp.error().message);
                return false;
            }

            // Try BootstrapSyncRequest (opcode 0x0603)
            auto sync_req = smo::join::BootstrapSyncRequest::decode_cbor(cbor_data);
            if (sync_req)
            {
                LOG.info("Raw handler: BootstrapSyncRequest from " + remote.host);
                auto sync_resp = smo::join::process_bootstrap_sync(sync_req.value(), mesh_manager_, authority_, &crl_);
                if (sync_resp)
                {
                    auto cbor = sync_resp.value().encode_cbor();
                    send_cbor_resp(cbor);
                    return true;
                }
                LOG.warn("BootstrapSync failed: " + sync_resp.error().message);
                return false;
            }

            return false;
        };

        if (try_join_protocol())
        {
            LOG.info("Join protocol handled successfully");
            return {};
        }

        // Try HelloMsg
        auto hello = smo::HelloMsg::deserialize(raw);
        if (hello)
        {
            LOG.info("Raw handler: HelloMsg from " + remote.host);
            auto handle_res = discovery_.handle_hello(hello.value(), ep, now_ns);
            if (!handle_res)
            {
                return handle_res.error();
            }

            // Send WelcomeMsg back with our own record so the requester
            // learns who the seed is (its node_id + reachable endpoint).
            smo::WelcomeMsg welcome;
            welcome.node_id = local_id_;
            welcome.peer_record = self_record_;
            auto welcome_data = welcome.serialize();
            auto send_res = session.send(smo::BytesView(welcome_data));
            if (!send_res)
            {
                LOG.warn("Failed to send WelcomeMsg");
            }
            return {};
        }

        // Try PingMsg
        auto ping = smo::PingMsg::deserialize(raw);
        if (ping)
        {
            smo::PongMsg pong;
            pong.timestamp = ping.value().timestamp;
            auto pong_data = pong.serialize();
            session.send(smo::BytesView(pong_data));
            return {};
        }

        // Unknown raw protocol
        return smo::Error(smo::ErrorCode(smo::ErrorCategory::Transport, 309, smo::Severity::Warn,
                                         smo::RetryClass::RetrySafe, smo::Recovery::None),
                          "Unknown raw protocol", __FILE__, __LINE__);
    }

} // namespace smo::runtime
