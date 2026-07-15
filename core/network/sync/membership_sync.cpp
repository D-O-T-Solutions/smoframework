#include "membership_sync.hpp"

#include <algorithm>
#include <sstream>

namespace smo::network::sync {

MembershipSync::MembershipSync(MembershipTable& table)
    : table_(table) {}

void MembershipSync::subscribe(EventCallback cb) {
    subscribers_.push_back(std::move(cb));
}

void MembershipSync::publish(const MembershipEvent& event) {
    for (auto& cb : subscribers_) {
        cb(event);
    }
}

void MembershipSync::on_peer_added(const PeerRecord& rec) {
    MembershipEvent ev;
    ev.type = MembershipEventType::PeerAdded;
    ev.node_id = rec.node_id;
    ev.timestamp = std::chrono::system_clock::now().time_since_epoch().count();
    ev.payload = "{\"display_name\":\"" + rec.display_name + "\"}";
    publish(ev);
}

void MembershipSync::on_peer_removed(const NodeID& id) {
    MembershipEvent ev;
    ev.type = MembershipEventType::PeerRemoved;
    ev.node_id = id;
    ev.timestamp = std::chrono::system_clock::now().time_since_epoch().count();
    publish(ev);
}

void MembershipSync::on_peer_updated(const PeerRecord& rec) {
    MembershipEvent ev;
    ev.type = MembershipEventType::PeerUpdated;
    ev.node_id = rec.node_id;
    ev.timestamp = std::chrono::system_clock::now().time_since_epoch().count();
    // Serialize key fields that changed
    std::ostringstream oss;
    oss << "{\"role\":" << static_cast<int>(rec.role)
        << ",\"state\":" << static_cast<int>(rec.state)
        << ",\"rtt_ms\":" << rec.rtt_ms << "}";
    ev.payload = oss.str();
    publish(ev);
}

void MembershipSync::on_peer_renamed(const NodeID& id, const std::string& new_name) {
    MembershipEvent ev;
    ev.type = MembershipEventType::PeerRenamed;
    ev.node_id = id;
    ev.timestamp = std::chrono::system_clock::now().time_since_epoch().count();
    ev.payload = "{\"new_name\":\"" + new_name + "\"}";
    publish(ev);
}

Bytes MembershipSync::snapshot() const {
    // Serialize entire membership table
    return table_.serialize();
}

Result<void> MembershipSync::apply_snapshot(BytesView data) {
    auto table = MembershipTable::deserialize(data);
    if (!table) return table.error();

    // For each peer in snapshot, upsert into local table
    for (auto& rec : table->peers()) {
        auto r = table_.upsert(std::move(rec));
        if (!r) return r;
    }
    return {};
}

std::vector<MembershipEvent> MembershipSync::pending_events(uint64_t since_seq) const {
    // In full impl, would maintain event log with sequence numbers
    // For now return empty
    return {};
}

} // namespace smo::network::sync