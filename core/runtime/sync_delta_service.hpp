#pragma once

#include <core/errors/error.hpp>
#include <core/network/sync/sync_service.hpp>
#include <core/discovery/gossip.hpp>
#include <core/recovery/crl.hpp>
#include <core/storage/manifest_store.hpp>
#include <storage/policy_store/policy_store.h>

#include <string>
#include <functional>

namespace smo::runtime {

    // =========================================================================
    // SyncDeltaService — SyncService delta handlers (Phase 6)
    // -------------------------------------------------------------------------
    // Encapsulates all SyncService delta callbacks (CRL, Policy, Manifest,
    // Routing, Contracts) and GossipEngine delta handlers that previously
    // lived inline in NodeRuntime::_wire_sync_services(). The composition root
    // injects the SyncService, GossipEngine, CRL, ManifestStore, PolicyStore.
    // =========================================================================
    class SyncDeltaService
    {
    public:
        struct Config
        {
            std::string data_dir;
        };

        using EpochGetter = std::function<uint64_t()>;
        using EpochSetter = std::function<void(uint64_t)>;

        SyncDeltaService(
            Config config,
            smo::sync::SyncService& sync_service,
            smo::GossipEngine& gossip,
            smo::recovery::CRL& crl,
            smo::ManifestStore& manifest_store,
            smo::PolicyStore& policy_store);

        ~SyncDeltaService();

        SyncDeltaService(const SyncDeltaService&) = delete;
        SyncDeltaService& operator=(const SyncDeltaService&) = delete;
        SyncDeltaService(SyncDeltaService&&) noexcept;
        SyncDeltaService& operator=(SyncDeltaService&&) = delete;

        // Register all delta callbacks with SyncService and GossipEngine
        void register_delta_handlers();

    private:
        Config config_;
        smo::sync::SyncService& sync_service_;
        smo::GossipEngine& gossip_;
        smo::recovery::CRL& crl_;
        smo::ManifestStore& manifest_store_;
        smo::PolicyStore& policy_store_;

        uint64_t last_crl_epoch_ = 0;
        uint64_t last_policy_version_ = 0;
        uint64_t last_manifest_epoch_ = 0;
    };

} // namespace smo::runtime