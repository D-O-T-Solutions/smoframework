#include "membership_sync.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>

namespace smo::network::sync {

MembershipSync::MembershipSync(MembershipTable& table, HealthMonitor& health)
    : membership_(table), health_(health) {}

uint64_t MembershipSync::subscribe(std::function<void(const MembershipEvent&)> cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    uint64_t id = next_sub_id_++;
    subscribers_.emplace_back(next_sub_id_, std::move(cb));
    return id;
}

void MembershipSync::unsubscribe(uint64_t id) {
    std::lock_guard<std::mutex> lock(mutex_);
    subscribers_.erase(
        std::remove_if(subscribers_.begin(), subscribers_.end(),
                       [id](const auto& p) { return p.first == id; }),
        subscribers_.end());
}

void MembershipSync::emit(MembershipEvent event) {
    event.timestamp_ns = std::chrono::system_clock::now().time_since_epoch().count();
    event.sequence = ++sequence_;

    // Keep event log bounded
    event_log_.push_back(event);
    if (event_log_.size() > max_event_log_) {
        event_log_.erase(event_log_.begin());
    }

    // Notify subscribers
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [id, cb] : subscribers_) {
        cb(event);
    }
}

void MembershipSync::emit_peer_added(const PeerRecord& rec) {
    MembershipEvent ev;
    ev.type = MembershipEventType::PeerAdded;
    ev.node_id = rec.node_id;
    emit(std::move(ev));
}

void MembershipSync::emit_peer_removed(const NodeID& id) {
    MembershipEvent ev;
    ev.type = MembershipEventType::PeerRemoved;
    ev.node_id = id;
    emit(std::move(ev));
}

void MembershipSync::emit_peer_updated(const PeerRecord& old_rec, const PeerRecord& new_rec) {
    MembershipEvent ev;
    ev.type = MembershipEventType::PeerUpdated;
    ev.node_id = new_rec.node_id;
    emit(std::move(ev));
}

void MembershipSync::emit_peer_renamed(const NodeID& id,
                                       const std::string& old_name,
                                       const std::string& new_name) {
    MembershipEvent ev;
    ev.type = MembershipEventType::PeerRenamed;
    ev.node_id = id;
    ev.old_display_name = old_name;
    ev.new_display_name = new_name;
    emit(std::move(ev));
}

void MembershipSync::emit_capability_changed(const NodeID& id, Role old_role, Role new_role,
                                             const std::vector<std::string>& added,
                                             const std::vector<std::string>& removed) {
    MembershipEvent ev;
    ev.type = MembershipEventType::CapabilityChange;
    ev.node_id = id;
    ev.new_role = new_role;
    ev.added_caps = added;
    ev.removed_caps = removed;
    emit(std::move(ev));
}

void MembershipSync::emit_certificate_rotated(const NodeID& id, const Certificate& new_cert) {
    MembershipEvent ev;
    ev.type = MembershipEventType::CertificateRotate;
    ev.node_id = id;
    // Certificate is serialized in apply_events
    emit(std::move(ev));
}

void MembershipSync::emit_state_changed(const NodeID& id, PeerState old_state,
                                         PeerState new_state, int misses) {
    MembershipEvent ev;
    ev.type = MembershipEventType::StateChange;
    ev.node_id = id;
    ev.new_state = new_state;
    // misses encoded in sequence for now
    emit(std::move(ev));
}

Bytes MembershipSync::serialize_events(const std::vector<MembershipEvent>& events) const {
    Bytes out;
    // Simple serialization: [count][event1][event2]...
    // Each event: [type][node_id(32)][seq][timestamp][payload...]
    // Payload varies by type - for simplicity, just store type+node_id+seq+timestamp
    // Real impl would use proper binary format
    return out;
}

Result<void> MembershipSync::apply_events(const Bytes& data) {
    (void)data;
    // Deserialize and apply
    // For each event: upsert/remove in MembershipTable
    return {};
}

std::vector<MembershipEvent> MembershipSync::pending_events(uint64_t since_sequence) const {
    std::vector<MembershipEvent> result;
    for (auto it = event_log_.rbegin(); it != event_log_.rend(); ++it) {
        if (it->sequence <= since_sequence) break;
        result.push_back(*it);
    }
    std::reverse(result.begin(), result.end());
    return result;
}

void MembershipSync::acknowledge(uint64_t sequence) {
    // For reliable gossip: mark events as acked
    // Could trim event_log_ up to this sequence
    (void)sequence;
}

} // namespace smo::network::sync