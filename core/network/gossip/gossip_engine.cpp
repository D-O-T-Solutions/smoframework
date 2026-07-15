#include "gossip_engine.hpp"

#include <algorithm>
#include <chrono>

namespace smo::network::gossip {

void GossipEngine::start(UdpTransport& udp) {
    udp_ = &udp;
    running_ = true;
}

void GossipEngine::stop() {
    running_ = false;
}

void GossipEngine::tick(int64_t now_ns) {
    if (!running_ || !udp_) return;

    // Gossip interval check (simplified - would use interval tracking)
    // For now, just try to send to fanout peers periodically
    auto peers = select_fanout_peers();
    for (auto& ep : peers) {
        send_gossip_to_peer(ep);
    }
}

Result<void> GossipEngine::handle_gossip(const Bytes& payload, const Endpoint& from) {
    if (on_gossip_) {
        // Find peer by endpoint
        auto peers = table_.peers();
        for (auto& rec : peers) {
            if (rec.endpoint.host == from.host && rec.endpoint.port == from.port) {
                on_gossip_(rec.node_id, payload);
                break;
            }
        }
    }
    return {};
}

void GossipEngine::broadcast_change(const MembershipEvent& event) {
    // Serialize event and broadcast to fanout peers
    // For now just increment sequence
    ++local_sequence_;
}

std::vector<Endpoint> GossipEngine::select_fanout_peers() {
    std::vector<Endpoint> result;
    auto peers = table_.peers_with_state(PeerState::Online);

    if (peers.empty()) return result;

    // Shuffle and pick fanout
    std::shuffle(peers.begin(), peers.end(), rng_);
    size_t count = std::min<size_t>(config_.fanout, peers.size());

    for (size_t i = 0; i < count; ++i) {
        Endpoint ep;
        ep.scheme = "udp";
        ep.host = peers[i].endpoint.host;
        ep.port = peers[i].endpoint.port;
        result.push_back(ep);
    }
    return result;
}

void GossipEngine::send_gossip_to_peer(const Endpoint& target) {
    if (!udp_) return;

    // Create gossip message with current membership digest
    // Simplified: just send current sequence
    // Full impl would serialize membership digest

    // Connect via UDP and send
    auto session = udp_->connect(target);
    if (session) {
        // Send minimal payload
        Bytes msg(8);
        // Just send local sequence for now
        for (int i = 7; i >= 0; --i) {
            msg[i] = static_cast<uint8_t>(local_sequence_ >> ((7 - i) * 8));
        }
        session.value()->send(msg).ignore();
    }
}

} // namespace smo::network::gossip