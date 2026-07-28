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
        uint32_t max_delta_entries;

        static Config defaults() {
            return Config{1800'000'000'000ULL, 3, 500};
        }
    };

    AntiEntropyService(MembershipTable& table,
                       GossipEngine& gossip,
                       SyncBackend& backend,
                       Config cfg = Config::defaults());
    ~AntiEntropyService();

    void start();
    void stop();
    void tick(int64_t now_ns);

    uint64_t repairs_done() const noexcept { return repairs_done_; }
    void clear_repairs() noexcept { repairs_done_ = 0; }

    uint32_t max_delta_entries() const noexcept { return config_.max_delta_entries; }

    static constexpr uint32_t kRequestOpcode = 0x0108;
    static constexpr uint32_t kResponseOpcode = 0x0109;

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