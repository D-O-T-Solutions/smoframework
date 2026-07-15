#pragma once

#include "../core/discovery/discovery.hpp"
#include "../core/errors/error.hpp"
#include "../core/identity/identity.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace smo::network::sync {

enum class MembershipEventType : uint8_t {
    PeerAdded   = 1,
    PeerRemoved = 2,
    PeerUpdated = 3,
    PeerRenamed = 4,
    CapChanged  = 5,
    CertRotated = 6,
};

struct MembershipEvent {
    MembershipEventType type;
    NodeID node_id;
    int64_t timestamp;       // unix ns
    std::string payload;     // JSON or custom
};

using EventCallback = std::function<void(const MembershipEvent&)>;

class MembershipSync {
public:
    explicit MembershipSync(MembershipTable& table);

    // Subscribe to membership events
    void subscribe(EventCallback cb);

    // Publish event to all subscribers
    void publish(const MembershipEvent& event);

    // Notify peer added (from bootstrap/hello)
    void on_peer_added(const PeerRecord& rec);

    // Notify peer removed (offline/leave)
    void on_peer_removed(const NodeID& id);

    // Notify peer updated (cap, role, endpoint change)
    void on_peer_updated(const PeerRecord& rec);

    // Notify peer renamed
    void on_peer_renamed(const NodeID& id, const std::string& new_name);

    // Notify capability changed
    void on_capability_changed(const NodeID& id, const std::string& cap);

    // Generate full membership snapshot for sync
    Bytes snapshot() const;

    // Apply incoming snapshot from peer
    Result<void> apply_snapshot(BytesView data);

    // Get pending events since given sequence
    std::vector<MembershipEvent> pending_events(uint64_t since_seq) const;

private:
    MembershipTable& table_;
    std::vector<EventCallback> subscribers_;
    uint64_t sequence_ = 0;

    uint64_t next_sequence() noexcept { return ++sequence_; }
};

} // namespace smo::network::sync