#include "heartbeat.hpp"

#include <algorithm>
#include <chrono>

namespace smo::network::udp {

HeartbeatService::HeartbeatService(Transport& udp,
                                    MembershipTable& membership,
                                    HealthMonitor& health,
                                    const HeartbeatConfig& cfg)
    : udp_(udp), membership_(membership), health_(health), config_(cfg) {}

HeartbeatService::~HeartbeatService() {
    stop();
}

void HeartbeatService::start() {
    running_ = true;
}

void HeartbeatService::stop() {
    running_ = false;
}

void HeartbeatService::tick(int64_t now_ns) {
    if (!running_) return;

    // Periodic PING to all online peers
    if (now_ns - last_ping_ns_ >= static_cast<int64_t>(config_.ping_interval_ms) * 1'000'000) {
        send_ping_all(now_ns);
        last_ping_ns_ = now_ns;
    }

    // Check health / timeouts
    check_health(now_ns);
}

void HeartbeatService::send_ping_all(int64_t now_ns) {
    auto peers = membership_.peers_with_state(PeerState::Online);
    for (auto& rec : peers) {
        if (rec.endpoint.port == 0) continue;

        PingMsg ping;
        ping.timestamp = now_ns;
        ping.sequence = ++sequence_;

        auto ping_data = ping.serialize();

        // Send via UDP transport
        Endpoint target;
        target.scheme = "udp";
        target.host = rec.endpoint.host;
        target.port = rec.endpoint.port;

        // TODO: Use proper UDP session from transport
        // For now, just record the ping in health monitor
        health_.record_ping(rec.node_id, now_ns);

        // In real impl: udp_.connect(target).value()->send(ping_data);
    }
}

void HeartbeatService::check_health(int64_t now_ns) {
    health_.tick(membership_, now_ns,
                 static_cast<int64_t>(config_.ping_timeout_ms) * 1'000'000,
                 config_.max_misses);

    // Check for state changes
    auto peers = membership_.peers();
    for (auto& rec : peers) {
        auto state = health_.state(rec.node_id);
        if (state != rec.state) {
            if (on_state_change_) {
                on_state_change_(rec.node_id, state, health_.ping_misses(rec.node_id));
            }
        }
    }
}

void HeartbeatService::handle_pong(const Endpoint& from, const PongMsg& msg, int64_t now_ns) {
    (void)msg;
    // Find peer by endpoint
    auto peers = membership_.peers_with_state(PeerState::Online);
    for (auto& rec : peers) {
        if (rec.endpoint.host == from.host && rec.endpoint.port == from.port) {
            int64_t rtt_ns = now_ns - msg.timestamp;
            health_.record_pong(rec.node_id, now_ns);

            // Update RTT in membership
            auto rec_opt = membership_.lookup(rec.node_id);
            if (rec_opt) {
                auto updated = rec_opt.value();
                updated.rtt_ms = static_cast<double>(rtt_ns) / 1'000'000.0;
                membership_.upsert(std::move(updated));
            }
            return;
        }
    }
}

void HeartbeatService::mark_suspect(const NodeID& id, int misses) {
    auto rec_opt = membership_.lookup(id);
    if (!rec_opt) return;
    auto rec = rec_opt.value();
    if (rec.state != PeerState::Suspect) {
        rec.state = PeerState::Suspect;
        rec.ping_misses = misses;
        membership_.upsert(std::move(rec));
        if (on_state_change_) on_state_change_(id, PeerState::Suspect, misses);
    }
}

void HeartbeatService::mark_offline(const NodeID& id) {
    auto rec_opt = membership_.lookup(id);
    if (!rec_opt) return;
    auto rec = rec_opt.value();
    if (rec.state != PeerState::Offline) {
        rec.state = PeerState::Offline;
        membership_.upsert(std::move(rec));
        if (on_state_change_) on_state_change_(id, PeerState::Offline, 0);
    }
}

} // namespace smo::network::udp