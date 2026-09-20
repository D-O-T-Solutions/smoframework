#pragma once

#include <core/errors/error.hpp>
#include <core/transport/transport.hpp>
#include <core/types.hpp>
#include <core/authority/authority.hpp>
#include <core/recovery/crl.hpp>
#include <core/network/packet_dispatcher.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace smo {

    class DiscoveryEngine;
    class MeshManager;
    namespace join {
        struct JoinRequest;
        struct BootstrapSyncRequest;
        struct JoinResponse;
        struct BootstrapSyncResponse;
        Result<JoinResponse> process_join_request(const JoinRequest&, class MeshManager&, authority::MeshAuthority&);
        Result<BootstrapSyncResponse> process_bootstrap_sync(const BootstrapSyncRequest&, class MeshManager&, authority::MeshAuthority&, recovery::CRL*);
    }
    struct HelloMsg;
    struct WelcomeMsg;
    struct PingMsg;
    struct PongMsg;
    struct PeerRecord;
    class NodeID;

} // namespace smo

namespace smo::runtime {

    // =========================================================================
    // ProtocolService — raw protocol dispatch service (Phase 5)
    // -------------------------------------------------------------------------
    // Owns the raw CBOR/discovery protocol dispatch that previously lived inline
    // in NodeRuntime::wire_runtime(). The composition root injects dependencies
    // (DiscoveryEngine, MeshManager, Authority, CRL, local identity) and the
    // service registers itself with the PacketDispatcher as the raw handler.
    // =========================================================================
    class ProtocolService
    {
    public:
        struct Config
        {
            // No config needed for now; all deps injected via ctor
        };

        using SendFn = std::function<smo::Result<void>(smo::BytesView)>;

        ProtocolService(
            Config config,
            smo::DiscoveryEngine& discovery,
            smo::MeshManager& mesh_manager,
            smo::authority::MeshAuthority& authority,
            smo::recovery::CRL& crl,
            const smo::NodeID& local_id,
            const smo::PeerRecord& self_record);

        ~ProtocolService();

        // Non-copyable, movable
        ProtocolService(const ProtocolService&) = delete;
        ProtocolService& operator=(const ProtocolService&) = delete;
        ProtocolService(ProtocolService&&) noexcept;
        ProtocolService& operator=(ProtocolService&&) noexcept = delete;

        // Register this service's raw handler with the given PacketDispatcher
        void register_raw_handler(smo::network::PacketDispatcher& dispatcher);

    private:
        Config config_;
        smo::DiscoveryEngine& discovery_;
        smo::MeshManager& mesh_manager_;
        smo::authority::MeshAuthority& authority_;
        smo::recovery::CRL& crl_;
        const smo::NodeID& local_id_;
        const smo::PeerRecord& self_record_;

        // Raw handler implementation (matching PacketDispatcher::RawHandler signature)
        smo::Result<void> handle_raw(smo::BytesView raw, smo::TransportSession& session, const smo::Endpoint& remote);
    };

} // namespace smo::runtime
