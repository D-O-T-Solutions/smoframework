#pragma once

#include "core/runtime/event_bus.hpp"
#include "core/runtime/service_registry.hpp"
#include "core/runtime/telemetry.hpp"
#include "core/runtime/output_manager.hpp"
#include "core/session/session.hpp"
#include "core/discovery/peer_store.hpp"
#include "core/mesh/mesh_manager.hpp"
#include "core/authority/authority.hpp"
#include "core/governance/governance.hpp"
#include "core/recovery/crl.hpp"
#include "core/discovery/discovery.hpp"
#include "core/discovery/gossip.hpp"
#include "core/network/sync/sync_backend.hpp"
#include "core/network/sync/anti_entropy.hpp"
#include "core/trust/trust.hpp"
#include "core/network/transport/address_resolver.hpp"
#include "core/network/udp/heartbeat_service.hpp"

#include <memory>

namespace smo::runtime {

class EventRegistryService
{
public:
    struct Dependencies
    {
        EventBus& event_bus;
        SessionManager& session_mgr;
        PeerStore& peer_store;
        MeshManager& mesh_manager;
        authority::MeshAuthority& authority;
        recovery::CRL& crl;
        DiscoveryEngine& discovery;
        GossipEngine& gossip;
        Telemetry& telemetry;
        OutputManager& output_mgr;
        TrustManager& trust_mgr;
        GovernanceEngine& governance_engine;
        network::transport::AddressResolver& address_resolver;
        network::udp::HeartbeatService& heartbeat;
        MembershipTable& membership;
    };

    explicit EventRegistryService(const Dependencies& deps);
    ~EventRegistryService() = default;

    EventRegistryService(const EventRegistryService&) = delete;
    EventRegistryService& operator=(const EventRegistryService&) = delete;
    EventRegistryService(EventRegistryService&&) = delete;
    EventRegistryService& operator=(EventRegistryService&&) = delete;

    void register_all();
    void start_anti_entropy(sync::SyncBackend& backend);

    std::unique_ptr<smo::sync::AntiEntropyService>& anti_entropy() { return anti_entropy_; }

private:
    Dependencies deps_;
    sync::SyncBackend* sync_backend_ = nullptr;
    std::unique_ptr<smo::sync::AntiEntropyService> anti_entropy_;
};

} // namespace smo::runtime