#include "heartbeat_service.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>

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
                                         smo::HealthMonitor& health)
    {
        // No bind: reuse the daemon's single UDP socket (bound by the main listener).
        udp_ = &udp_listener;
        membership_ = &membership;
        health_ = &health;

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

            // Send PING framed as a discovery datagram so the receiver's dispatch
            // loop can route it to the receiver's heartbeat handler.
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
                std::printf("[smo-node] heartbeat: PING -> %s:%u\n", target.host.c_str(),
                            static_cast<unsigned>(target.port));
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

} // namespace smo::network::udp