#include "core/discovery/gossip.hpp"

#include <algorithm>
#include <chrono>
#include <sstream>
#include <string>

namespace smo {

GossipEngine::Config GossipEngine::default_config() {
    return Config{};
}

GossipEngine::GossipEngine(MembershipTable& table, const Config& cfg)
    : table_(table), config_(cfg), rng_(std::random_device{}()) {}

GossipEngine::~GossipEngine() = default;

void GossipEngine::tick(int64_t now_ns) {
    if (now_ns - last_gossip_ < gossip_interval_ns_) return;
    last_gossip_ = now_ns;
    incarnation_++;

    auto peers = select_fanout_peers();
    for (auto& ep : peers) {
        send_gossip_to_peer(ep);
    }
}

std::vector<GossipEngine::GossipMessage> GossipEngine::pending_updates(uint64_t since_sequence) const {
    std::vector<GossipMessage> updates;
    auto peers = table_.peers();
    for (auto& rec : peers) {
        if (rec.state == PeerState::Offline) continue;

        GossipMessage msg;
        msg.node_id = rec.node_id;
        msg.state = rec.state;
        msg.last_seen = rec.last_seen;
        msg.incarnation = incarnation_;
        updates.push_back(std::move(msg));
    }
    return updates;
}

void GossipEngine::apply_updates(const std::vector<GossipMessage>& updates) {
    for (auto& msg : updates) {
        auto existing = table_.lookup(msg.node_id);
        if (!existing) {
            PeerRecord rec;
            rec.node_id = msg.node_id;
            rec.state = msg.state;
            rec.last_seen = msg.last_seen;
            rec.ping_misses = 0;
            table_.upsert(std::move(rec));
        } else {
            auto rec = existing.value();
            if (msg.incarnation > incarnation_) {
                rec.state = msg.state;
                rec.last_seen = msg.last_seen;
                table_.upsert(std::move(rec));
            }
        }
    }
}

void GossipEngine::send_gossip_to_peer(const Endpoint& target) {
    // TODO: Implement UDP send via transport
}

std::vector<Endpoint> GossipEngine::select_fanout_peers() {
    std::vector<Endpoint> result;
    auto peers = table_.peers_with_state(PeerState::Online);

    if (peers.empty()) return result;

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

// EventBus listener for RecoveryApproved events
// Gossips CRL updates to peers
void GossipEngine::on_recovery_approved(const runtime::Event& ev) {
    // Parse JSON payload from event details
    // Expected: "CertificateRevocation proposal approved: {fingerprint, node_id_hex, reason, epoch}"
    std::string payload = ev.details;
    size_t brace_pos = payload.find('{');
    if (brace_pos == std::string::npos) return;

    std::string json_str = payload.substr(brace_pos);

    // Simple JSON parsing
    auto extract_field = [&](const std::string& json, const std::string& key) -> std::string {
        std::string search = "\"" + key + "\":\"";
        size_t pos = json.find(search);
        if (pos == std::string::npos) return "";
        pos += search.length();
        size_t end = json.find('"', pos);
        if (end == std::string::npos) return "";
        return json.substr(pos, end - pos);
    };
    auto extract_uint = [&](const std::string& json, const std::string& key) -> uint64_t {
        std::string search = "\"" + key + "\":";
        size_t pos = json.find(search);
        if (pos == std::string::npos) return 0;
        pos += search.length();
        size_t end = json.find_first_of(",}", pos);
        if (end == std::string::npos) return 0;
        return std::stoull(json.substr(pos, end - pos));
    };

    std::string fingerprint = extract_field(json_str, "fingerprint");
    std::string node_id_hex = extract_field(json_str, "node_id_hex");
    std::string reason = extract_field(json_str, "reason");
    uint64_t epoch = extract_uint(json_str, "epoch");

    if (fingerprint.empty() || node_id_hex.empty()) return;

    // Add to CRL if available
    if (crl_) {
        int64_t now = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        crl_->revoke(fingerprint, node_id_hex, reason, epoch, now);
    }

    // Increment incarnation to force full sync on next gossip cycle
    incarnation_++;

    std::printf("[smo-node] GossipEngine: CRL update gossiped for fingerprint=%s epoch=%llu\n",
                fingerprint.c_str(), (unsigned long long)epoch);
}

} // namespace smo