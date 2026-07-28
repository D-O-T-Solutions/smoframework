#pragma once

#include "merkle_tree.hpp"
#include "sync_backend.hpp"
#include <core/discovery/gossip.hpp>
#include <cstdint>
#include <memory>
#include <random>

namespace smo {

class MembershipTable;

namespace sync {

class AntiEntropyService {
public:
    struct Config {
        uint64_t interval_ns;
        uint32_t fanout;
    };

    static Config default_config() {
        return Config{1800'000'000'000ULL, 3};
    }

    AntiEntropyService(MembershipTable& table,
                       GossipEngine& gossip,
                       SyncBackend& backend,
                       Config cfg = default_config());
    ~AntiEntropyService();

    void start();
    void stop();
    void tick(int64_t now_ns);

    uint64_t repairs_done() const noexcept { return repairs_done_; }
    void clear_repairs() noexcept { repairs_done_ = 0; }

    static constexpr uint32_t kRequestOpcode = 0x0108;
    static constexpr uint32_t kResponseOpcode = 0x0109;
    static constexpr uint32_t kMaxDeltaEntries = 500;

private:
    int64_t next_exchange_ns_ = 0;
    MembershipTable& table_;
    GossipEngine& gossip_;
    SyncBackend& backend_;
    Config config_;
    std::mt19937_64 rng_;
    std::atomic<uint64_t> repairs_done_{0};
};

} // namespace sync
} // namespace smo