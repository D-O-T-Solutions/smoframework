#include "heartbeat_service.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <unordered_map>

namespace smo::network::udp {

    namespace {

        std::string node_id_hex(const smo::NodeID& id)
        {
            return id.to_string();
        }

    } // namespace

    HeartbeatService::Config HeartbeatService::default_config()
    {
        return Config{};
    }

    HeartbeatService::HeartbeatService(const Config& cfg) : config_(cfg) {}

    HeartbeatService::HeartbeatService() : config_(default_config()) {}

    Result<void> HeartbeatService::start(UdpListener& udp_listener, smo::MembershipTable& membership,
                                         smo::HealthMonitor& health,
                                         smo::network::relay::RelayService* relay_service)
    {
        // No bind: reuse the daemon's single UDP socket (bound by the main listener).
        udp_ = &udp_listener;
        membership_ = &membership;
        health_ = &health;
        relay_service_ = relay_service;

        running_ = true;
        last_ping_ns_ = std::chrono::system_clock::now().time_since_epoch().count();

        return {};
    }

    void HeartbeatService::stop()
    {
        running_ = false;
    }

    void HeartbeatService::tick(int64_t now_ns)
    {
        if (!running_)
            return;

        // Send periodic PINGs
        if (now_ns - last_ping_ns_ >= static_cast<int64_t>(config_.ping_interval_ms) * 1'000'000)
        {
            send_ping_to_all(now_ns);
            last_ping_ns_ = now_ns;
        }

        // Check peer health (timeout detection)
        check_peer_health(now_ns);
    }

    Result<void> HeartbeatService::handle_pong(const smo::PongMsg& msg, int64_t now_ns, const smo::Endpoint& from)
    {
        auto peers = membership_->peers();
        const smo::PeerRecord* matched = nullptr;
        for (const auto& rec : peers)
        {
            if (rec.node_id == msg.sender_id)
            {
                matched = &rec;
                break;
            }
        }
        if (!matched)
        {
            // Fallback: match by source endpoint (only useful for legacy senders
            // that do not populate sender_id).
            for (const auto& rec : peers)
            {
                if (rec.endpoint.host == from.host && rec.endpoint.port == from.port)
                {
                    matched = &rec;
                    break;
                }
            }
        }
        if (!matched)
        {
            return SMO_ERR_DISCOVERY(400, Info, RetrySafe, None, "unknown peer sent PONG");
        }

        // Record PONG, calculate RTT, refresh liveness so the peer flips back Online.
        int64_t rtt_ns = now_ns - msg.timestamp;
        health_->record_pong(matched->node_id, now_ns);

        auto rec_opt = membership_->lookup(matched->node_id);
        if (rec_opt)
        {
            auto updated = rec_opt.value();
            updated.rtt_ms = static_cast<double>(rtt_ns) / 1'000'000.0;
            updated.last_seen = now_ns;
            updated.ping_misses = 0;
            updated.state = smo::PeerState::Online;
            membership_->upsert(std::move(updated));
        }

        // N2: If we were attempting hole punch to this peer, mark success via callback
        if (config_.enable_hole_punch)
        {
            record_hole_punch_result(matched->node_id, true, "direct");
        }

        std::printf("[smo-node] heartbeat: PONG from %s (rtt=%.2fms, last_seen updated, state=Online)\n",
                    node_id_hex(matched->node_id).c_str(), static_cast<double>(rtt_ns) / 1'000'000.0);
        return {};
    }

    Result<void> HeartbeatService::handle_ping(const smo::PingMsg& msg, int64_t now_ns, const smo::Endpoint& from)
    {
        (void)now_ns;
        if (!udp_)
            return {};

        // Respond with PONG echoing the timestamp, from the shared bound socket.
        smo::PongMsg pong;
        pong.timestamp = msg.timestamp;
        pong.sender_id = local_id_;

        auto pong_data = pong.serialize();
        auto framed = wrap_discovery_msg(smo::DiscoveryMsgType::Pong, pong_data);

        auto res = udp_->send_to(from, framed);
        if (res)
        {
            std::printf("[smo-node] heartbeat: PING from %s -> PONG reply\n", node_id_hex(msg.sender_id).c_str());
        }
        return res;
    }

    void HeartbeatService::send_ping_to_all(int64_t now_ns)
    {
        if (!udp_ || !membership_)
            return;

        auto peers = membership_->peers();
        for (auto& rec : peers)
        {
            // Skip self
            if (rec.node_id == local_id_)
                continue;
            if (rec.endpoint.port == 0)
                continue;

            // N2: Try direct UDP hole punch first (to mapped address if available)
            if (config_.enable_hole_punch && !rec.mapped_address.empty())
            {
                auto hp_result = try_direct_hole_punch(rec, now_ns);
                if (hp_result)
                {
                    // Hole punch succeeded, continue to next peer
                    health_->record_ping(rec.node_id, now_ns);
                    continue;
                }
                // Fall through to relay fallback
            }

            // N3: Try relay fallback if hole punch failed or not enabled
            if (relay_service_)
            {
                auto relay_result = try_relay_fallback(rec, now_ns);
                if (relay_result)
                {
                    // Relay ping sent successfully
                    health_->record_ping(rec.node_id, now_ns);
                    continue;
                }
            }

            // Final fallback: send to physical endpoint via UDP
            smo::PingMsg ping;
            ping.timestamp = now_ns;
            ping.sender_id = local_id_;
            ++ping_sequence_;
            ping.sequence = ping_sequence_;

            auto ping_data = ping.serialize();
            auto framed = wrap_discovery_msg(smo::DiscoveryMsgType::Ping, ping_data);

            smo::Endpoint target;
            target.scheme = "udp";
            target.host = rec.endpoint.host;
            target.port = rec.endpoint.port;

            auto res = udp_->send_to(target, framed);
            if (res)
            {
                std::printf("[smo-node] heartbeat: PING -> %s:%u (physical)\n", target.host.c_str(),
                            static_cast<unsigned>(target.port));
            }
            else
            {
                // N2: Record hole punch failure if we tried
                if (config_.enable_hole_punch && !rec.mapped_address.empty())
                {
                    record_hole_punch_result(rec.node_id, false, "failed");
                }
            }

            // Record ping sent
            health_->record_ping(rec.node_id, now_ns);
        }
    }

    void HeartbeatService::check_peer_health(int64_t now_ns)
    {
        if (!membership_ || !health_)
            return;

        health_->tick(*membership_, now_ns, static_cast<int64_t>(config_.ping_timeout_ms) * 1'000'000,
                      config_.max_misses);
    }

    // N2: Hole punch implementation

    uint64_t HeartbeatService::peer_key(const NodeID& id) const
    {
        // Simple hash of node_id for unordered_map key
        uint64_t key = 0;
        for (size_t i = 0; i < id.value.size() && i < 8; ++i)
        {
            key = (key << 8) | id.value[i];
        }
        return key;
    }

    Result<void> HeartbeatService::try_direct_hole_punch(const smo::PeerRecord& rec, int64_t now_ns)
    {
        if (!udp_ || rec.mapped_address.empty())
        {
            return SMO_ERR_DISCOVERY(400, Info, RetrySafe, None, "no mapped address for hole punch");
        }

        uint64_t key = peer_key(rec.node_id);
        auto& state = hole_punch_states_[key];

        // Initialize hole punch state on first attempt
        if (state.attempts == 0)
        {
            state.started_at = now_ns;
            state.path = "direct";
        }
        state.attempts++;

        // Predictable port pair: both sides use the same local port for hole punching
        // The mapped_address.port is the port as seen by STUN server
        // We send to the mapped address using our bound socket (same local port)
        smo::PingMsg ping;
        ping.timestamp = now_ns;
        ping.sender_id = local_id_;
        ++ping_sequence_;
        ping.sequence = ping_sequence_;

        auto ping_data = ping.serialize();
        auto framed = wrap_discovery_msg(smo::DiscoveryMsgType::Ping, ping_data);

        smo::Endpoint target;
        target.scheme = "udp";
        target.host = rec.mapped_address.ip;
        target.port = rec.mapped_address.port;

        auto res = udp_->send_to(target, framed);
        if (res)
        {
            std::printf("[smo-node] heartbeat: HOLE PUNCH attempt %d -> %s:%u (mapped)\n",
                        state.attempts, target.host.c_str(), static_cast<unsigned>(target.port));
        }

        // Record ping sent for health tracking
        health_->record_ping(rec.node_id, now_ns);

        // Note: Actual success is determined when we receive PONG in handle_pong
        // For now, we consider the send attempt as "in progress"
        return res;
    }

    void HeartbeatService::record_hole_punch_result(const NodeID& id, bool success, const std::string& path)
    {
        uint64_t key = peer_key(id);
        auto it = hole_punch_states_.find(key);
        if (it != hole_punch_states_.end())
        {
            it->second.succeeded = success;
            it->second.path = path;
        }

        // N5: Determine NAT test status
        NatTestStatus nat_status = NatTestStatus::Unknown;
        if (success)
        {
            if (path == "direct")
                nat_status = NatTestStatus::Direct;
            else if (path == "relay")
                nat_status = NatTestStatus::Relay;
        }
        else
        {
            if (path == "relay_unavailable" || path == "relay_failed" || path == "failed")
                nat_status = NatTestStatus::Blocked;
        }

        // Emit NAT test status via callback (runtime layer handles metric)
        if (nat_test_status_cb_)
        {
            nat_test_status_cb_(id, static_cast<uint8_t>(nat_status));
        }

        // Emit metrics via callback (telemetry is in runtime layer)
        if (hole_punch_cb_)
        {
            hole_punch_cb_(id, success, path);
        }

        std::printf("[smo-node] heartbeat: hole punch %s for %s via %s (nat_status=%u)\n",
                    success ? "SUCCESS" : "FAILURE", node_id_hex(id).c_str(), path.c_str(),
                    static_cast<uint8_t>(nat_status));
    }

    HeartbeatService::NatTestStatus HeartbeatService::get_nat_test_status(const NodeID& id) const
    {
        uint64_t key = peer_key(id);
        auto it = hole_punch_states_.find(key);
        if (it != hole_punch_states_.end())
        {
            if (it->second.succeeded)
            {
                if (it->second.path == "direct")
                    return NatTestStatus::Direct;
                else if (it->second.path == "relay")
                    return NatTestStatus::Relay;
            }
            else
            {
                if (it->second.path == "relay_unavailable" || it->second.path == "relay_failed" || it->second.path == "failed")
                    return NatTestStatus::Blocked;
            }
        }
        return NatTestStatus::Unknown;
    }

    // N3: Relay fallback - send ping through relay service
    Result<void> HeartbeatService::try_relay_fallback(const smo::PeerRecord& rec, int64_t now_ns)
    {
        if (!relay_service_)
        {
            return SMO_ERR_DISCOVERY(500, Info, RetrySafe, None, "RelayService not available");
        }

        // Allocate relay session for this peer
        auto relay_ep_result = relay_service_->allocate_relay_session(rec.node_id);
        if (!relay_ep_result)
        {
            std::printf("[smo-node] heartbeat: No relay available for %s\n", rec.node_id.to_string().c_str());
            record_hole_punch_result(rec.node_id, false, "relay_unavailable");
            return relay_ep_result.error();
        }
        auto relay_ep = relay_ep_result.value();

        // Create ping message
        smo::PingMsg ping;
        ping.timestamp = now_ns;
        ping.sender_id = local_id_;
        ++ping_sequence_;
        ping.sequence = ping_sequence_;

        auto ping_data = ping.serialize();
        auto framed = wrap_discovery_msg(smo::DiscoveryMsgType::Ping, ping_data);

        // Forward through relay service (preserves AEAD encryption)
        auto res = relay_service_->forward_frame(rec.node_id, framed);
        if (res)
        {
            std::printf("[smo-node] heartbeat: PING -> %s via relay (%s:%u)\n",
                        rec.node_id.to_string().c_str(),
                        relay_ep.host.c_str(),
                        static_cast<unsigned>(relay_ep.port));
            record_hole_punch_result(rec.node_id, true, "relay");
        }
        else
        {
            std::printf("[smo-node] heartbeat: Relay forward failed for %s: %s\n",
                        rec.node_id.to_string().c_str(), res.error().message.c_str());
            record_hole_punch_result(rec.node_id, false, "relay_failed");
        }

        return res;
    }

} // namespace smo::network::udp