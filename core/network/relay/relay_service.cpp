#include "core/network/relay/relay_service.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <random>

namespace smo::network::relay {

    namespace {
        uint64_t hash_node_id(const NodeID& id)
        {
            uint64_t key = 0;
            for (size_t i = 0; i < id.value.size() && i < 8; ++i)
            {
                key = (key << 8) | id.value[i];
            }
            return key;
        }
    }

    RelayService::Config RelayService::default_config()
    {
        return Config{};
    }

    RelayService::RelayService(const Config& cfg) : config_(cfg) {}

    Result<void> RelayService::start(MembershipTable& membership, Transport& transport, MetricsCallback* metrics)
    {
        membership_ = &membership;
        transport_ = &transport;
        metrics_ = metrics;
        running_ = true;
        return {};
    }

    void RelayService::stop()
    {
        running_ = false;
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        sessions_.clear();
    }

    void RelayService::tick(int64_t now_ns)
    {
        if (!running_)
            return;
        cleanup_expired_sessions(now_ns);
    }

    Result<Endpoint> RelayService::allocate_relay_session(const NodeID& peer_id)
    {
        if (!membership_ || !transport_)
        {
            return SMO_ERR_DISCOVERY(500, Error, RetrySafe, None, "RelayService not started");
        }

        uint64_t key = peer_key(peer_id);

        {
            std::lock_guard<std::mutex> lock(sessions_mutex_);
            auto it = sessions_.find(key);
            if (it != sessions_.end() && it->second.active)
            {
                // Session exists and active, return relay endpoint
                it->second.last_activity_ns = std::chrono::system_clock::now().time_since_epoch().count();
                return it->second.relay_endpoint;
            }
        }

        // Find a relay-capable peer
        auto relay_candidate = find_relay_candidate(peer_id);
        if (!relay_candidate)
        {
            return relay_candidate.error();
        }

        auto relay_id = relay_candidate.value();
        auto relay_rec_opt = membership_->lookup(relay_id);
        if (!relay_rec_opt)
        {
            return SMO_ERR_DISCOVERY(501, Error, RetrySafe, None, "Relay candidate not found in membership");
        }

        auto& relay_rec = relay_rec_opt.value();
        Endpoint relay_ep = relay_rec.endpoint;
        if (relay_ep.port == 0)
        {
            return SMO_ERR_DISCOVERY(502, Error, RetrySafe, None, "Relay candidate has no valid endpoint");
        }

        // Create new session
        RelaySession session;
        session.peer_id = peer_id;
        session.relay_node_id = relay_id;
        session.relay_endpoint = relay_ep;
        session.created_at_ns = std::chrono::system_clock::now().time_since_epoch().count();
        session.last_activity_ns = session.created_at_ns;
        session.active = true;

        {
            std::lock_guard<std::mutex> lock(sessions_mutex_);
            sessions_[key] = std::move(session);
        }

        std::printf("[smo-relay] Allocated relay session for %s via %s (%s:%u)\n",
                    peer_id.to_string().c_str(),
                    relay_id.to_string().c_str(),
                    relay_ep.host.c_str(),
                    static_cast<unsigned>(relay_ep.port));

        // Update metrics
        if (metrics_)
        {
            metrics_->set_gauge("smo_relay_active_peers", static_cast<double>(active_peer_count()), "");
        }

        if (session_cb_)
        {
            session_cb_(peer_id, relay_ep);
        }

        return relay_ep;
    }

    Result<void> RelayService::forward_frame(const NodeID& peer_id, BytesView frame)
    {
        if (!running_)
        {
            return SMO_ERR_DISCOVERY(503, Error, RetrySafe, None, "RelayService not running");
        }

        uint64_t key = peer_key(peer_id);
        RelaySession* session = nullptr;

        {
            std::lock_guard<std::mutex> lock(sessions_mutex_);
            auto it = sessions_.find(key);
            if (it == sessions_.end() || !it->second.active)
            {
                return SMO_ERR_DISCOVERY(504, Error, RetrySafe, None, "No active relay session for peer");
            }
            session = &it->second;
        }

        // Check bandwidth budget
        if (!check_budget(*session, frame.size()))
        {
            return SMO_ERR_DISCOVERY(505, Warn, RetryBackoff, None, "Relay bandwidth budget exceeded");
        }

        // Connect to relay node and forward frame
        // We use a simple TCP connection for relay forwarding
        auto fd_result = transport_->connect(session->relay_endpoint);
        if (!fd_result)
        {
            return fd_result.error();
        }

        auto session_ptr = std::move(fd_result.value());

        // Send the frame as-is (preserving AEAD encryption)
        // The frame already includes SMO framing headers
        auto send_result = session_ptr->send(frame);
        session_ptr->close();

        if (send_result)
        {
            session->bytes_forwarded += frame.size();
            session->last_activity_ns = std::chrono::system_clock::now().time_since_epoch().count();
            total_bytes_forwarded_.fetch_add(frame.size(), std::memory_order_relaxed);

            // Update metrics
            if (metrics_)
            {
                metrics_->increment_counter("smo_relay_bytes_total", "direction=out,peer=" + peer_id.to_string(), frame.size());
            }

            std::printf("[smo-relay] Forwarded %zu bytes to %s via %s\n",
                        frame.size(),
                        peer_id.to_string().c_str(),
                        session->relay_node_id.to_string().c_str());
        }

        return send_result;
    }

    Result<void> RelayService::handle_relayed_frame(const NodeID& from_relay, BytesView frame)
    {
        // This is called when we receive a frame FROM a relay node
        // The frame is already encrypted end-to-end (AEAD preserved)
        // We just need to dispatch it to the local protocol handler

        // Update metrics
        total_bytes_forwarded_.fetch_add(frame.size(), std::memory_order_relaxed);
        if (metrics_)
        {
            metrics_->increment_counter("smo_relay_bytes_total", "direction=in,relay=" + from_relay.to_string(), frame.size());
        }

        std::printf("[smo-relay] Received relayed frame from %s (%zu bytes)\n",
                    from_relay.to_string().c_str(), frame.size());

        // Frame dispatch is handled by the caller (PacketDispatcher)
        return {};
    }

    bool RelayService::has_active_session(const NodeID& peer_id) const
    {
        uint64_t key = peer_key(peer_id);
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        auto it = sessions_.find(key);
        return it != sessions_.end() && it->second.active;
    }

    std::vector<RelaySession> RelayService::get_active_sessions() const
    {
        std::vector<RelaySession> result;
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        for (const auto& kv : sessions_)
        {
            if (kv.second.active)
            {
                result.push_back(kv.second);
            }
        }
        return result;
    }

    uint32_t RelayService::active_peer_count() const noexcept
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        uint32_t count = 0;
        for (const auto& kv : sessions_)
        {
            if (kv.second.active)
                count++;
        }
        return count;
    }

    uint64_t RelayService::peer_key(const NodeID& id) const
    {
        return hash_node_id(id);
    }

    Result<NodeID> RelayService::find_relay_candidate(const NodeID& exclude_peer) const
    {
        if (!membership_)
        {
            return SMO_ERR_DISCOVERY(506, Error, RetrySafe, None, "No membership table");
        }

        auto peers = membership_->peers_with_state(PeerState::Online);
        if (peers.empty())
        {
            return SMO_ERR_DISCOVERY(507, Warn, RetrySafe, None, "No online peers for relay");
        }

        // First pass: prefer peers with relay capability (relay:true)
        std::vector<NodeID> relay_candidates;
        std::vector<NodeID> fallback_candidates;
        for (const auto& rec : peers)
        {
            if (rec.node_id == exclude_peer)
                continue;
            if (rec.endpoint.port != 0 && !rec.endpoint.host.empty())
            {
                if (rec.relay_capable)
                {
                    relay_candidates.push_back(rec.node_id);
                }
                else
                {
                    fallback_candidates.push_back(rec.node_id);
                }
            }
        }

        const std::vector<NodeID>* candidates = &relay_candidates;
        if (relay_candidates.empty())
        {
            candidates = &fallback_candidates;
        }

        if (candidates->empty())
        {
            return SMO_ERR_DISCOVERY(508, Warn, RetrySafe, None, "No suitable relay candidates");
        }

        // Simple round-robin / random selection
        static std::mt19937_64 rng(std::random_device{}());
        std::uniform_int_distribution<size_t> dist(0, candidates->size() - 1);
        return (*candidates)[dist(rng)];
    }

    bool RelayService::check_budget(const RelaySession& session, size_t frame_size) const
    {
        // Simple token bucket: 1 Mbps = 125 KB/s
        // Allow burst up to 2x budget
        auto now = std::chrono::system_clock::now().time_since_epoch().count();
        auto elapsed_ns = now - session.last_activity_ns;
        if (elapsed_ns <= 0)
            return true;

        double elapsed_sec = static_cast<double>(elapsed_ns) / 1'000'000'000.0;
        double budget_bytes = static_cast<double>(config_.bandwidth_bps_per_peer) / 8.0 * elapsed_sec;
        double allowed_bytes = budget_bytes * 2.0; // 2x burst allowance

        return static_cast<double>(session.bytes_forwarded + frame_size) <= allowed_bytes;
    }

    void RelayService::cleanup_expired_sessions(int64_t now_ns)
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        auto timeout_ns = static_cast<int64_t>(config_.session_timeout_ms) * 1'000'000;

        for (auto it = sessions_.begin(); it != sessions_.end();)
        {
            if (!it->second.active)
            {
                it = sessions_.erase(it);
                continue;
            }

            if (now_ns - it->second.last_activity_ns > timeout_ns)
            {
                std::printf("[smo-relay] Session expired for peer %s (timeout)\n",
                            it->second.peer_id.to_string().c_str());
                it->second.active = false;
                it = sessions_.erase(it);

                // Update metrics
                if (metrics_)
                {
                    metrics_->set_gauge("smo_relay_active_peers", static_cast<double>(active_peer_count()), "");
                }
            }
            else
            {
                ++it;
            }
        }
    }

} // namespace smo::network::relay