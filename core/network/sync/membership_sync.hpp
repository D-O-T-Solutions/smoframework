#pragma once

#include <core/discovery/discovery.hpp>
#include <core/errors/error.hpp>

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace smo::network::sync {

enum class MembershipEventType : uint8_t {
    PeerAdded        = 1,
    PeerRemoved      = 2,
    PeerUpdated      = 3,
    PeerRenamed      = 4,
    CapabilityChange = 5,
    CertificateRotate = 6,
    StateChange      = 7,
};

struct MembershipEvent {
    MembershipEventType type;
    NodeID              node_id;
    int64_t             timestamp_ns = 0;
    uint64_t            sequence = 0;

    // Event-specific payload
    std::string old_display_name;   // for Rename
    std::string new_display_name;   // for Rename
    Role        new_role = Role::Reader;          // for CapabilityChange
    std::vector<std::string> added_caps;          // for CapabilityChange
    std::vector<std::string> removed_caps;        // for CapabilityChange
    PeerState  new_state = PeerState::Unknown;    // for StateChange
    Certificate new_cert;                         // for CertificateRotate
};

class MembershipSync {
public:
    using Callback = std::function<void(const MembershipEvent&)>;

    explicit MembershipSync(MembershipTable& table, HealthMonitor& health);

    // Subscribe to membership events
    uint64_t subscribe(std::function<void(const MembershipEvent&)> cb);

    // Unsubscribe
    void unsubscribe(uint64_t subscription_id);

    // Emit events (called from DiscoveryEngine, HeartbeatService, etc.)
    void emit_peer_added(const PeerRecord& rec);
    void emit_peer_removed(const NodeID& id);
    void emit_peer_updated(const PeerRecord& old_rec, const PeerRecord& new_rec);
    void emit_peer_renamed(const NodeID& id, const std::string& old_name, const std::string& new_name);
    void emit_capability_changed(const NodeID& id, Role old_role, Role new_role,
                                  const std::vector<std::string>& added,
                                  const std::vector<std::string>& removed);
    void emit_certificate_rotated(const NodeID& id, const Certificate& new_cert);
    void emit_state_changed(const NodeID& id, PeerState old_state, PeerState new_state, int misses);

    // Serialize events for gossip transmission
    Bytes serialize_events(const std::vector<MembershipEvent>& events) const;

    // Deserialize and apply events received from gossip
    Result<void> apply_events(const Bytes& data);

    // Get pending events since a sequence number (for gossip push)
    std::vector<MembershipEvent> pending_events(uint64_t since_sequence) const;

    // Mark events as acknowledged (for reliable gossip)
    void acknowledge(uint64_t sequence);

    uint64_t current_sequence() const noexcept { return sequence_.load(); }

private:
    struct Subscription {
        uint64_t id;
        std::function<void(const MembershipEvent&)> callback;
    };

    void emit(MembershipEvent event);

    MembershipTable& membership_;
    HealthMonitor& health_;

    mutable std::mutex mutex_;
    std::vector<std::pair<uint64_t, std::function<void(const MembershipEvent&)>>> subscribers_;
    uint64_t next_sub_id_ = 1;

    std::atomic<uint64_t> sequence_{0};
    std::vector<MembershipEvent> event_log_;
    size_t max_event_log_ = 1000;
};

} // namespace smo::network::sync