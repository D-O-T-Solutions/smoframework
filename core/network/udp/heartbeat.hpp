#pragma once

#include <core/discovery/discovery.hpp>
#include <core/errors/error.hpp>
#include <core/transport/transport.hpp>
#include <core/types.hpp>

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace smo::network::udp {

struct HeartbeatConfig {
    uint32_t ping_interval_ms = 5000;
    uint32_t ping_timeout_ms  = 3000;
    uint32_t max_misses       = 3;
    uint32_t fanout           = 3;
};

class HeartbeatService {
public:
    explicit HeartbeatService(Transport& udp,
                               MembershipTable& membership,
                               HealthMonitor& health,
                               const HeartbeatConfig& cfg = {});

    ~HeartbeatService();

    HeartbeatService(const HeartbeatService&) = delete;
    HeartbeatService& operator=(const HeartbeatService&) = delete;

    void start();
    void stop();

    // Call periodically from main loop (or run in background thread)
    void tick(int64_t now_ns);

    // Handle incoming PONG response
    void handle_pong(const Endpoint& from, const PongMsg& msg, int64_t now_ns);

    // Set callback for when peer state changes
    using StateChangeCallback = std::function<void(const NodeID&, PeerState, int)>;
    void set_state_change_callback(StateChangeCallback cb) { on_state_change_ = std::move(cb); }

private:
    void send_ping_all(int64_t now_ns);
    void check_health(int64_t now_ns);
    void mark_suspect(const NodeID& id, int misses);
    void mark_offline(const NodeID& id);

    HeartbeatConfig config_;
    Transport& udp_;
    MembershipTable& membership_;
    HealthMonitor& health_;

    std::atomic<bool> running_{false};
    int64_t last_ping_ns_ = 0;
    uint64_t sequence_ = 0;

    std::function<void(const NodeID&, PeerState, int)> on_state_change_;
};

} // namespace smo::network::udp