#pragma once

#include <cstdint>
#include <array>
#include <chrono>
#include <unordered_set>

namespace smo {

// §VI.2 — Replay protection via nonce + timestamp window.
//
// Every packet carries a nonce and a timestamp.
// Receivers maintain a sliding bloom filter / set of recently seen nonces.

struct ReplayConfig {
    int64_t  max_time_delta_ms{5'000};   // 5 second window
    size_t   max_nonce_cache{10'000};    // LRU eviction
};

class ReplayProtector {
public:
    explicit ReplayProtector(ReplayConfig cfg) noexcept;

    // Returns true if the packet is fresh (valid time window + unseen nonce).
    bool accept(std::array<uint8_t, 8> nonce, int64_t timestamp) noexcept;

    void clear() noexcept;

private:
    ReplayConfig cfg_;
    // nonce cache: sliding window of seen nonces
    // (concrete implementation uses a ring buffer + hash set)
};

} // namespace smo
