#pragma once

#include "../../errors/error.hpp"
#include "../../types.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace smo {
class GossipEngine;
namespace recovery { class CRL; }
}

namespace smo::sync {

// Per DISCUSSION_0039 §5.19: SyncScheduler with policy-driven intervals.
// Defaults can be overridden via mesh policy (governance ChangePolicy action).
//   heartbeat     (every 20s) — node health / liveness
//   membership    (every 45s) — membership delta sync
//   policy        (every 60s) — policy delta sync
//   crl           (every 10min) — CRL delta sync
//   manifest      (on change) — manifest delta sync
//   routing       (every 15s) — routing table sync
//   contracts     (on change) — contract registry sync
struct SyncSchedule {
    // Named intervals matching mesh policy keys
    uint64_t heartbeat_ns     = 20'000'000'000ULL;   // 20s
    uint64_t membership_ns    = 45'000'000'000ULL;   // 45s
    uint64_t policy_ns        = 60'000'000'000ULL;   // 60s
    uint64_t crl_ns           = 600'000'000'000ULL;  // 10min
    uint64_t manifest_ns      = 0;                   // on change (tick resets timer)
    uint64_t routing_ns       = 15'000'000'000ULL;   // 15s
    uint64_t contracts_ns     = 0;                   // on change

    // Apply policy overrides from a CBOR map.
    // Expected keys: "heartbeat", "membership", "policy", "crl", "manifest", "routing", "contracts"
    // Each value is interval in seconds (uint).
    void apply_policy(const std::string& policy_cbor);
};

class SyncService {
public:
    using DeltaCallback = std::function<Result<void>(const std::string& delta_type)>;

    SyncService(GossipEngine& gossip,
                recovery::CRL* crl = nullptr,
                SyncSchedule schedule = {});

    ~SyncService();
    SyncService(SyncService&&) = default;
    SyncService& operator=(SyncService&&) = default;
    SyncService(const SyncService&) = delete;
    SyncService& operator=(const SyncService&) = delete;

    void start();
    void stop();
    bool is_running() const { return running_; }

    // Periodic tick — called by daemon main loop
    // Returns bitmap of triggered delta types
    uint32_t tick(int64_t now_ns);

    // Register external callback for specific delta type
    void on_delta(const std::string& delta_type, DeltaCallback cb);

    // Force a specific delta sync immediately
    Result<void> sync_now(const std::string& delta_type);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    bool running_ = false;
};

} // namespace smo::sync
