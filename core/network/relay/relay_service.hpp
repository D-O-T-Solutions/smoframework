#pragma once

#include <core/discovery/discovery.hpp>
#include <core/errors/error.hpp>
#include <core/types.hpp>
#include <core/transport/transport.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace smo::network::relay {

    // Relay session state for a single peer
    struct RelaySession
    {
        NodeID peer_id;               // Target peer
        NodeID relay_node_id;         // Relay node (with relay:true capability)
        Endpoint relay_endpoint;      // Relay node's endpoint (TCP)
        int64_t created_at_ns = 0;
        int64_t last_activity_ns = 0;
        uint64_t bytes_forwarded = 0;
        bool active = false;
    };

    class RelayService
    {
    public:
        struct Config
        {
            uint64_t bandwidth_bps_per_peer = 1'000'000; // 1 Mbps default
            uint32_t session_timeout_ms = 300000;         // 5 min default
            uint32_t max_sessions = 100;
        };

        // Metrics callback interface (implemented by runtime layer)
        struct MetricsCallback
        {
            virtual ~MetricsCallback() = default;
            virtual void increment_counter(const std::string& name, const std::string& labels, int64_t delta) = 0;
            virtual void set_gauge(const std::string& name, double value, const std::string& labels) = 0;
        };

        explicit RelayService(const Config& cfg = default_config());
        ~RelayService() = default;

        RelayService(const RelayService&) = delete;
        RelayService& operator=(const RelayService&) = delete;

        static Config default_config();

        // Start the relay service with references to membership and transport
        Result<void> start(MembershipTable& membership, Transport& transport, MetricsCallback* metrics = nullptr);

        void stop();

        // Periodic tick: cleanup expired sessions, enforce bandwidth
        void tick(int64_t now_ns);

        // Allocate or get existing relay session for a peer
        // Returns relay node endpoint if a relay-capable node is available
        Result<Endpoint> allocate_relay_session(const NodeID& peer_id);

        // Forward an encrypted frame through relay (no decrypt, preserve AEAD)
        // frame: complete encrypted frame including headers
        Result<void> forward_frame(const NodeID& peer_id, BytesView frame);

        // Called when we receive a relayed frame from a relay node
        Result<void> handle_relayed_frame(const NodeID& from_relay, BytesView frame);

        // Check if a peer has an active relay session
        bool has_active_session(const NodeID& peer_id) const;

        // Get relay session info for metrics/inspection
        std::vector<RelaySession> get_active_sessions() const;

        // Metrics
        uint64_t total_bytes_forwarded() const noexcept { return total_bytes_forwarded_; }
        uint32_t active_peer_count() const noexcept;

        // Callback for when a new relay session is established
        using SessionCallback = std::function<void(const NodeID& peer_id, const Endpoint& relay_ep)>;
        void set_session_callback(SessionCallback cb) { session_cb_ = std::move(cb); }

    private:
        Config config_;
        MembershipTable* membership_ = nullptr;
        Transport* transport_ = nullptr;
        MetricsCallback* metrics_ = nullptr;
        std::atomic<bool> running_{false};

        mutable std::mutex sessions_mutex_;
        std::unordered_map<uint64_t, RelaySession> sessions_; // key = peer_id hash

        std::atomic<uint64_t> total_bytes_forwarded_{0};

        SessionCallback session_cb_;

        uint64_t peer_key(const NodeID& id) const;

        // Find a relay-capable peer (relay:true in capabilities)
        Result<NodeID> find_relay_candidate(const NodeID& exclude_peer = {}) const;

        // Enforce bandwidth budget per peer
        bool check_budget(const RelaySession& session, size_t frame_size) const;

        // Cleanup expired sessions
        void cleanup_expired_sessions(int64_t now_ns);
    };

} // namespace smo::network::relay