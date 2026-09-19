#include "bootstrap_client.hpp"

#include <core/transport/secure_session.hpp>
#include <core/transport/tcp_transport.hpp>
#include <core/transport/transport.hpp>
#include <core/discovery/discovery.hpp>
#include <core/identity/identity.hpp>

#include <cstdio>
#include <fstream>

namespace smo::bootstrap {

    // Helper to load binary file
    static smo::Bytes load_file_binary(const std::string& path) {
        std::ifstream f(path, std::ios::binary | std::ios::ate);
        if (!f) return {};
        size_t size = f.tellg();
        f.seekg(0);
        Bytes data(size);
        f.read(reinterpret_cast<char*>(data.data()), size);
        return data;
    }

    BootstrapClient::Result BootstrapClient::bootstrap(const Endpoint& seed_ep,
                                                        const CryptoProvider& crypto,
                                                        const Identity& local_identity,
                                                        const PeerRecord& self_record,
                                                        DiscoveryEngine& discovery_engine,
                                                        const std::string& data_dir,
                                                        const std::string& mesh_id) {
        // 1. Raw TCP connect + version handshake (Sync connection type)
        auto raw_session = TransportRegistry::instance().get("tcp")->connect(seed_ep, ConnectionType::Sync);
        if (!raw_session) {
            std::printf("[smo-node] Seed connection failed: %s\n", "connection failed");
            return {PeerRecord{}, false};
        }

        auto* tcp_ses = static_cast<TcpSession*>(raw_session.value().get());
        int fd = tcp_ses->release_fd();

        // 2. PQ handshake (client) - authority requires it when certed
        SecureSession::Config sec_cfg;
        sec_cfg.role = SecureSession::Role::Client;

        // Load client certificate and secret key for mutual auth
        std::string cert_path = data_dir + "/node.cert.smoc";
        smo::Bytes client_cert_blob = load_file_binary(cert_path);
        if (client_cert_blob.empty()) {
            std::fprintf(stderr, "[smo-node] Warning: client certificate not found at %s, PQ handshake may fail\n", cert_path.c_str());
        } else {
            sec_cfg.client_cert = client_cert_blob;
        }

        std::string id_path = data_dir + "/identity.json";
        auto id_res = Identity::load_from_file(id_path, crypto);
        if (!id_res) {
            std::fprintf(stderr, "[smo-node] Warning: identity not found at %s, PQ handshake may fail\n", id_path.c_str());
        } else {
            sec_cfg.client_signing_secret_key = Bytes(id_res.value().secret_key().begin(), id_res.value().secret_key().end());
        }

        sec_cfg.mesh_id = mesh_id;

        SecureSession sec(fd, sec_cfg, crypto);
        auto hs = sec.handshake();
        if (!hs) {
            std::printf("[smo-node] Seed PQ handshake failed: %s\n", hs.error().message.c_str());
            return {PeerRecord{}, false};
        }

        // 3. Send HELLO inside the secure session
        HelloMsg hello;
        hello.node_id = local_identity.node_id();
        hello.endpoint = self_record.endpoint;
        auto hello_data = hello.serialize();
        auto send_res = sec.send(BytesView(hello_data));
        if (!send_res) {
            std::printf("[smo-node] Seed HELLO send failed: %s\n", send_res.error().message.c_str());
            return {PeerRecord{}, false};
        }

        // 4. Read WELCOME (encrypted)
        auto welcome_data = sec.recv();
        if (!welcome_data) {
            std::printf("[smo-node] Seed WELCOME read failed: %s\n", "recv failed");
            return {PeerRecord{}, false};
        }
        auto welcome = WelcomeMsg::deserialize(BytesView(welcome_data.value()));
        if (!welcome) {
            std::fprintf(stderr, "[smo-node] Seed WELCOME parse failed: %s\n", "parse failed");
            return {PeerRecord{}, false};
        }

        auto& rec = welcome.value().peer_record;
        std::printf("[smo-node] Seed responded: %s (%s)\n", rec.display_name.c_str(), rec.endpoint.to_string().c_str());

        return {rec, true};
    }

} // namespace smo::bootstrap