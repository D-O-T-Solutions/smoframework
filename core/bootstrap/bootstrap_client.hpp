#pragma once

#include <core/transport/transport.hpp>
#include <core/transport/tcp_transport.hpp>
#include <core/transport/secure_session.hpp>
#include <core/crypto/suite.hpp>
#include <core/discovery/discovery.hpp>
#include <core/types.hpp>
#include <core/identity/identity.hpp>

#include <string>
#include <memory>

namespace smo::bootstrap {

    // BootstrapClient handles the client-side seed bootstrap protocol:
    // 1. Connect to seed (TCP + version handshake with Sync connection type)
    // 2. PQ handshake (SecureSession)
    // 3. Send HELLO with local identity and endpoint
    // 4. Receive WELCOME with seed's peer record
    // 5. Update discovery engine with seed's peer record
    struct BootstrapClient {
        struct Result {
            PeerRecord seed_record;
            bool success;
        };

        // Perform bootstrap with seed
        static Result bootstrap(const Endpoint& seed_ep,
                                const CryptoProvider& crypto,
                                const Identity& local_identity,
                                const PeerRecord& self_record,
                                DiscoveryEngine& discovery_engine,
                                const std::string& data_dir,
                                const std::string& mesh_id);

    private:
        static Result perform_handshake(int fd,
                                        const CryptoProvider& crypto,
                                        const Identity& local_identity,
                                        const std::string& data_dir,
                                        const std::string& mesh_id);
    };

} // namespace smo::bootstrap