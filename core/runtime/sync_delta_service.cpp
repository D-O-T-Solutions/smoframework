#include "sync_delta_service.hpp"

#include <core/runtime/structured_logger.hpp>
#include <storage/policy_store/policy_store.h>
#include <core/storage/manifest_store.hpp>

namespace smo::runtime {

    namespace {
        auto& LOG = smo::runtime::global_logger();
    }

    SyncDeltaService::SyncDeltaService(
        Config config,
        smo::sync::SyncService& sync_service,
        smo::GossipEngine& gossip,
        smo::recovery::CRL& crl,
        smo::ManifestStore& manifest_store,
        smo::PolicyStore& policy_store)
        : config_(std::move(config)),
          sync_service_(sync_service),
          gossip_(gossip),
          crl_(crl),
          manifest_store_(manifest_store),
          policy_store_(policy_store),
          last_crl_epoch_(0),
          last_policy_version_(0),
          last_manifest_epoch_(0) {}

    SyncDeltaService::~SyncDeltaService() = default;

    SyncDeltaService::SyncDeltaService(SyncDeltaService&&) noexcept = default;
    

    void SyncDeltaService::register_delta_handlers()
    {
        // CRL delta: serialize entries since last known epoch
        sync_service_.on_delta("crl", [&](const std::string&) -> smo::Result<void> {
            auto entries = crl_.entries_since(last_crl_epoch_);
            if (entries.empty())
                return {};
            for (const auto& e : entries)
            {
                if (e.epoch > last_crl_epoch_)
                    last_crl_epoch_ = e.epoch;
            }
            // Serialize only new entries
            smo::Bytes buf;
            uint32_t count = static_cast<uint32_t>(entries.size());
            for (int i = 3; i >= 0; --i)
                buf.push_back(static_cast<uint8_t>((count >> (i * 8)) & 0xFF));
            for (auto& e : entries)
            {
                auto ser = e.serialize();
                uint32_t len = static_cast<uint32_t>(ser.size());
                for (int i = 3; i >= 0; --i)
                    buf.push_back(static_cast<uint8_t>((len >> (i * 8)) & 0xFF));
                buf.insert(buf.end(), ser.begin(), ser.end());
            }
            if (!buf.empty())
            {
                gossip_.queue_delta(smo::DeltaType::CRL, std::move(buf));
            }
            return {};
        });

        // PolicyStore for policy rule persistence
        // Policy delta: send policy records since last known version
        sync_service_.on_delta("policy", [&](const std::string&) -> smo::Result<void> {
            auto current = policy_store_.store_version();
            if (current <= last_policy_version_)
                return {};
            last_policy_version_ = current;
            auto names = policy_store_.list();
            if (names.empty())
                return {};
            // Serialize each record with length prefix
            smo::Bytes buf;
            uint32_t count = static_cast<uint32_t>(names.size());
            for (int i = 3; i >= 0; --i)
                buf.push_back(static_cast<uint8_t>((count >> (i * 8)) & 0xFF));
            for (auto& name : names)
            {
                auto rec = policy_store_.get(name);
                if (!rec)
                    continue;
                auto ser = smo::PolicyStore::serialize_record(rec.value());
                uint32_t len = static_cast<uint32_t>(ser.size());
                for (int i = 3; i >= 0; --i)
                    buf.push_back(static_cast<uint8_t>((len >> (i * 8)) & 0xFF));
                buf.insert(buf.end(), ser.begin(), ser.end());
            }
            if (!buf.empty())
            {
                gossip_.queue_delta(smo::DeltaType::Policy, std::move(buf));
            }
            return {};
        });

        // Manifest delta: send new epoch list since last sync
        sync_service_.on_delta("manifest", [&](const std::string&) -> smo::Result<void> {
            if (!manifest_store_.is_open())
                return {};
            auto latest = manifest_store_.latest_epoch();
            if (!latest || latest.value() <= last_manifest_epoch_)
                return {};
            auto epochs = manifest_store_.list_epochs();
            if (!epochs)
                return {};
            std::vector<uint64_t> new_epochs;
            for (auto e : epochs.value())
            {
                if (e > last_manifest_epoch_)
                    new_epochs.push_back(e);
            }
            if (new_epochs.empty())
                return {};
            last_manifest_epoch_ = latest.value();
            // Serialize epoch list
            smo::Bytes buf;
            uint32_t count = static_cast<uint32_t>(new_epochs.size());
            for (int i = 3; i >= 0; --i)
                buf.push_back(static_cast<uint8_t>((count >> (i * 8)) & 0xFF));
            for (auto e : new_epochs)
            {
                for (int i = 7; i >= 0; --i)
                    buf.push_back(static_cast<uint8_t>((e >> (i * 8)) & 0xFF));
            }
            gossip_.queue_delta(smo::DeltaType::Manifest, std::move(buf));
            return {};
        });

        // Routing delta: stub (routing table not yet implemented)
        sync_service_.on_delta("routing", [](const std::string&) -> smo::Result<void> {
            return {};
        });

        // Contracts delta: stub (contracts store not yet implemented)
        sync_service_.on_delta("contracts", [](const std::string&) -> smo::Result<void> {
            return {};
        });

        // Register receive-side delta handlers in GossipEngine
        gossip_.set_delta_handler(smo::DeltaType::Manifest, [&](smo::BytesView payload) -> smo::Result<void> {
            if (payload.size() < 4)
                return {};
            uint32_t count = 0;
            for (int i = 0; i < 4; ++i)
                count = (count << 8) | payload[i];
            LOG.info("Gossip: received manifest delta with " + std::to_string(count) + " epochs");
            return {};
        });

        gossip_.set_delta_handler(smo::DeltaType::Policy, [&](smo::BytesView payload) -> smo::Result<void> {
            if (payload.size() < 4)
                return {};
            uint32_t count = 0;
            for (int i = 0; i < 4; ++i)
                count = (count << 8) | payload[i];
            size_t off = 4;
            for (uint32_t j = 0; j < count && off < payload.size(); ++j)
            {
                if (off + 4 > payload.size())
                    break;
                uint32_t len = 0;
                for (int i = 0; i < 4; ++i)
                    len = (len << 8) | payload[off++];
                if (off + len > payload.size())
                    break;
                std::string data(payload.begin() + off, payload.begin() + off + len);
                off += len;
                auto rec = smo::PolicyStore::deserialize_record(data);
                if (rec)
                {
                    policy_store_.put(rec.value());
                }
            }
            return {};
        });
    }

} // namespace smo::runtime