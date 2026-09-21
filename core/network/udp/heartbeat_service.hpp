#pragma once

#include "../../core/discovery/discovery.hpp"
#include "../../core/transport/transport.hpp"
#include "../../types.hpp"
#include "../udp/udp_transport.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <chrono>
#include <thread>
#include <atomic>

namespace smo::network::udp {

    class HeartbeatService
    {
    public:
        struct Config
        {
            uint32_t ping_interval_ms = 5000;
            uint32_t ping_timeout_ms = 3000;
            int max_misses = 3;
            uint16_t local_port = 0; // 0 = auto
        };
        explicit HeartbeatService(const Config& cfg);

        HeartbeatService();

        static Config default_config();

        ~HeartbeatService() { stop(); }

        // Set this node's own NodeID (used in PingMsg.sender_id / PongMsg.sender_id).
        void set_local_node_id(const NodeID& id) noexcept { local_id_ = id; }

        // Start heartbeat service on the daemon's already-bound UDP listener.
        // The service does NOT bind its own socket — it sends PING/PONG datagrams
        // through the shared bound listener (single socket per daemon, NAT-punching).
        Result<void> start(UdpListener& udp_listener, smo::MembershipTable& membership, smo::HealthMonitor& health);

        void stop();

        // Call periodically (e.g., from main loop) to send PINGs and check timeouts
        void tick(int64_t now_ns);

        // Handle incoming PONG from a peer (matches by sender NodeID)
        Result<void> handle_pong(const smo::PongMsg& msg, int64_t now_ns, const smo::Endpoint& from);

        // Handle incoming PING from a peer (respond with PONG via bound socket)
        Result<void> handle_ping(const smo::PingMsg& msg, int64_t now_ns, const smo::Endpoint& from);

    private:
        Config config_;
        UdpListener* udp_ = nullptr;
        smo::MembershipTable* membership_ = nullptr;
        smo::HealthMonitor* health_ = nullptr;
        NodeID local_id_;

        std::atomic<bool> running_{false};
        int64_t last_ping_ns_ = 0;
        uint64_t ping_sequence_ = 0;

        void send_ping_to_all(int64_t now_ns);
        void check_peer_health(int64_t now_ns);
    };

} // namespace smo::network::udp