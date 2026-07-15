#pragma once

#include "../core/discovery/discovery.hpp"
#include "../core/discovery/gossip.hpp"
#include "../core/transport/transport.hpp"

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <random>
#include <string>
#include <vector>

namespace smo::network::gossip {

class GossipEngine {
public:
    struct Config {
        uint32_t interval_ms     = 5000;  // gossip interval
        uint32_t fanout          = 3;     // peers per round
        uint32_t max_payload     = 4096;  // max gossip payload
    };

    explicit GossipEngine(MembershipTable& table, Config cfg = {})
        : table_(table), config_(cfg), rng_(std::random_device{}()) {}

    ~GossipEngine() { stop(); }

    // Start gossip with given UDP transport
    void start(UdpTransport& udp);

    void stop();

    // Call periodically from main loop
    void tick(int64_t now_ns);

    // Handle incoming gossip message from peer
    Result<void> handle_gossip(const Bytes& payload, const Endpoint& from);

    // Broadcast local membership changes
    void broadcast_change(const MembershipEvent& event);

    // Subscribe to received gossip updates
    using Callback = std::function<void(const NodeID&, const Bytes&)>;
    void on_gossip_received(std::function<void(const NodeID&, const Bytes&)> cb) {
        on_gossip_ = std::move(cb);
    }

private:
    struct GossipMessage {
        uint64_t incarnation;
        uint64_t sequence;
        Bytes payload;
    };

    void send_gossip_to_peer(const Endpoint& target);
    std::vector<Endpoint> select_fanout_peers();

    MembershipTable& table_;
    Config config_;
    std::mt19937_64 rng_;
    uint64_t incarnation_ = 1;
    uint64_t local_sequence_ = 0;
    std::atomic<bool> running_{false};
    std::function<void(const NodeID&, const Bytes&)> on_gossip_;

    UdpTransport* udp_ = nullptr;
};

} // namespace smo::network::gossip