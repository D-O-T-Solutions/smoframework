#pragma once

#include "../../core/discovery/discovery.hpp"
#include "../../core/transport/transport.hpp"
#include "../../types.hpp"
#include "../udp/udp_transport.hpp"
#include "../../runtime/telemetry.hpp"
#include "../../network/relay/relay_service.hpp"

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
            bool enable_hole_punch = true; // N2: enable UDP hole punching
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
        Result<void> start(UdpListener& udp_listener, smo::MembershipTable& membership, smo::HealthMonitor& health,
                           smo::network::relay::RelayService* relay_service = nullptr);

        void stop();

        // Call periodically (e.g., from main loop) to send PINGs and check timeouts
        void tick(int64_t now_ns);

        // Handle incoming PONG from a peer (matches by sender NodeID)
        Result<void> handle_pong(const smo::PongMsg& msg, int64_t now_ns, const smo::Endpoint& from);

        // Handle incoming PING from a peer (respond with PONG via bound socket)
        Result<void> handle_ping(const smo::PingMsg& msg, int64_t now_ns, const smo::Endpoint& from);

        // N2: Hole punch result callback
        using HolePunchCallback = std::function<void(const NodeID&, bool success, const std::string& path)>;
        void set_hole_punch_callback(HolePunchCallback cb) { hole_punch_cb_ = std::move(cb); }

        // N5: NAT test status callback (0=unknown, 1=direct, 2=relay, 3=blocked)
        using NatTestStatusCallback = std::function<void(const NodeID&, uint8_t status)>;
        void set_nat_test_status_callback(NatTestStatusCallback cb) { nat_test_status_cb_ = std::move(cb); }

        // N2: Hole punch state for testing/inspection
        struct HolePunchState
        {
            int64_t started_at = 0;
            int attempts = 0;
            bool succeeded = false;
            std::string path; // "direct", "relay", "failed"
        };

        // N5: NAT Test Status metric values
        enum class NatTestStatus : uint8_t
        {
            Unknown = 0,
            Direct = 1,
            Relay = 2,
            Blocked = 3
        };

        // N5: Get config for inspection
        const Config& config() const noexcept { return config_; }

        // N5: Get NAT test status for a peer (for metrics export)
        NatTestStatus get_nat_test_status(const NodeID& id) const;

    private:
        Config config_;
        UdpListener* udp_ = nullptr;
        smo::MembershipTable* membership_ = nullptr;
        smo::HealthMonitor* health_ = nullptr;
        NodeID local_id_;
        smo::network::relay::RelayService* relay_service_ = nullptr;

        std::atomic<bool> running_{false};
        int64_t last_ping_ns_ = 0;
        uint64_t ping_sequence_ = 0;

        // N2: Hole punch tracking
        std::unordered_map<uint64_t, HolePunchState> hole_punch_states_;
        HolePunchCallback hole_punch_cb_;

        // N5: NAT test status callback
        NatTestStatusCallback nat_test_status_cb_;

        void send_ping_to_all(int64_t now_ns);
        void check_peer_health(int64_t now_ns);

        // N2: Hole punch methods
        Result<void> try_direct_hole_punch(const smo::PeerRecord& rec, int64_t now_ns);
        Result<void> try_relay_fallback(const smo::PeerRecord& rec, int64_t now_ns);
        void record_hole_punch_result(const NodeID& id, bool success, const std::string& path);
        uint64_t peer_key(const NodeID& id) const;
    };

} // namespace smo::network::udp