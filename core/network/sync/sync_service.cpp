#include "sync_service.hpp"

#include "../../discovery/gossip.hpp"
#include "../../recovery/crl.hpp"

#include <cstring>
#include <unordered_map>

namespace smo::sync {

struct SyncService::Impl {
    GossipEngine& gossip;
    recovery::CRL* crl;
    SyncSchedule schedule;

    int64_t last_membership_sync = 0;
    int64_t last_policy_sync = 0;
    int64_t last_crl_sync = 0;
    int64_t last_routing_sync = 0;
    int64_t last_manifest_sync = 0;
    int64_t last_contracts_sync = 0;

    std::unordered_map<std::string, DeltaCallback> delta_callbacks;

    Impl(GossipEngine& g, recovery::CRL* c, SyncSchedule s)
        : gossip(g), crl(c), schedule(s) {}

    uint32_t tick(int64_t now_ns) {
        uint32_t flags = 0;
        uint32_t flag = 1;

        auto check = [&](int64_t& last, uint64_t interval, const char* name) {
            bool due = false;
            if (interval == 0) {
                // on-change: fire every tick; callback gates on actual changes
                due = true;
                last = now_ns;
            } else if (last == 0 || now_ns - last >= interval) {
                due = true;
                last = now_ns;
            }
            if (due) {
                flags |= flag;
                auto it = delta_callbacks.find(name);
                if (it != delta_callbacks.end()) {
                    (void)it->second(name);
                }
            }
            flag <<= 1;
        };

        // Fire all delta callbacks first (they may queue data into GossipEngine)
        check(last_routing_sync, schedule.routing_interval_ns, "routing");
        check(last_policy_sync, schedule.policy_interval_ns, "policy");
        check(last_crl_sync, schedule.crl_interval_ns, "crl");
        check(last_manifest_sync, schedule.manifest_interval_ns, "manifest");
        check(last_contracts_sync, schedule.contracts_interval_ns, "contracts");
        check(last_membership_sync, schedule.membership_interval_ns, "membership");

        // Trigger gossip fanout after all deltas queued (sends everything together)
        if (flags & (1 << 5)) { // membership bit = flag 32
            gossip.tick(now_ns);
        }

        return flags;
    }
};

SyncService::SyncService(GossipEngine& gossip,
                         recovery::CRL* crl,
                         SyncSchedule schedule)
    : impl_(std::make_unique<Impl>(gossip, crl, schedule))
{}

SyncService::~SyncService() = default;

void SyncService::start() { running_ = true; }
void SyncService::stop() { running_ = false; }

uint32_t SyncService::tick(int64_t now_ns) {
    if (!running_) return 0;
    return impl_->tick(now_ns);
}

void SyncService::on_delta(const std::string& delta_type, DeltaCallback cb) {
    impl_->delta_callbacks[delta_type] = std::move(cb);
}

Result<void> SyncService::sync_now(const std::string& delta_type) {
    auto it = impl_->delta_callbacks.find(delta_type);
    if (it != impl_->delta_callbacks.end()) {
        return it->second(delta_type);
    }
    return {};
}

} // namespace smo::sync
