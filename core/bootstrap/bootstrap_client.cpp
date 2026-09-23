#include "bootstrap_client.hpp"

#include <core/transport/secure_session.hpp>
#include <core/transport/tcp_transport.hpp>
#include <core/transport/transport.hpp>
#include <core/discovery/discovery.hpp>
#include <core/identity/identity.hpp>
#include <core/runtime/structured_logger.hpp>

namespace smo::bootstrap {

    namespace {
        auto& LOG = smo::runtime::global_logger();
    }

BootstrapClient::Result BootstrapClient::bootstrap(const Endpoint& seed_ep,
                                                         const CryptoProvider& crypto,
                                                         const Identity& local_identity,
                                                         const PeerRecord& self_record,
                                                         DiscoveryEngine& discovery_engine,
                                                         const Bytes& server_cert_blob,
                                                         const Bytes& server_signing_key,
                                                         const Bytes& root_public_key,
                                                         const std::string& mesh_id,
                                                         uint64_t current_epoch) {
        // 1. Raw TCP connect + version handshake (Sync connection type)
        auto raw_session = TransportRegistry::instance().get("tcp")->connect(seed_ep, ConnectionType::Sync);
        if (!raw_session) {
            LOG.warn("Seed connection failed: connection failed");
            return {PeerRecord{}, false};
        }

        auto* tcp_ses = static_cast<TcpSession*>(raw_session.value().get());
        int fd = tcp_ses->release_fd();

        // 2. PQ handshake (client) - authority requires it when certed
        SecureSession::Config sec_cfg;
        sec_cfg.role = SecureSession::Role::Client;
        sec_cfg.client_cert = server_cert_blob;
        sec_cfg.client_signing_secret_key = server_signing_key;
        sec_cfg.root_public_key = root_public_key;
        sec_cfg.mesh_id = mesh_id;
        sec_cfg.current_epoch = current_epoch; // C1.3: Capability Epoch

        SecureSession sec(fd, sec_cfg, crypto);
        auto hs = sec.handshake();
        if (!hs) {
            LOG.warn("Seed PQ handshake failed: " + hs.error().message);
            return {PeerRecord{}, false};
        }

        // 3. Send HELLO inside the secure session
        HelloMsg hello;
        hello.node_id = local_identity.node_id();
        hello.endpoint = self_record.endpoint;
        auto hello_data = hello.serialize();
        auto send_res = sec.send(BytesView(hello_data));
        if (!send_res) {
            LOG.warn("Seed HELLO send failed: " + send_res.error().message);
            return {PeerRecord{}, false};
        }

        // 4. Read WELCOME (encrypted)
        auto welcome_data = sec.recv();
        if (!welcome_data) {
            LOG.warn("Seed WELCOME read failed: recv failed");
            return {PeerRecord{}, false};
        }
        auto welcome = WelcomeMsg::deserialize(BytesView(welcome_data.value()));
        if (!welcome) {
            LOG.warn("Seed WELCOME parse failed: parse failed");
            return {PeerRecord{}, false};
        }

        auto& rec = welcome.value().peer_record;
        LOG.info("Seed responded: " + rec.display_name + " (" + rec.endpoint.to_string() + ")");

        // 5. Wire into discovery engine
        discovery_engine.handle_welcome(WelcomeMsg{local_identity.node_id(), rec}, 0);

        return {rec, true};
    }

} // namespace smo::bootstrap