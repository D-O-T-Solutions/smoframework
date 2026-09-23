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
    // 5. Return seed's peer record for discovery engine wiring
    struct BootstrapClient {
        struct Result {
            PeerRecord seed_record;
            bool success;
        };

        // Perform bootstrap with seed using provided PQ material
        // (avoids re-loading from disk when already available in memory)
static Result bootstrap(const Endpoint& seed_ep,
                                 const CryptoProvider& crypto,
                                 const Identity& local_identity,
                                 const PeerRecord& self_record,
                                 DiscoveryEngine& discovery_engine,
                                 const Bytes& server_cert_blob,
                                 const Bytes& server_signing_key,
                                 const Bytes& root_public_key,
                                 const std::string& mesh_id,
                                 uint64_t current_epoch);

    private:
        static Result perform_handshake(int fd,
                                        const CryptoProvider& crypto,
                                        const Bytes& server_cert_blob,
                                        const Bytes& server_signing_key,
                                        const Bytes& root_public_key,
                                        const std::string& mesh_id,
                                        uint64_t current_epoch);
    };

} // namespace smo::bootstrap