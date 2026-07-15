#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>
#include "core/discovery/discovery.hpp"
#include "core/errors/error.hpp"
#include "core/identity/identity.hpp"

namespace smo {

class GossipEngine {
public:
    explicit GossipEngine(MembershipTable& table);

    struct GossipMessage {
        NodeID      node_id;
        PeerState   state;
        int64_t     last_seen;
        uint32_t    incarnation;
    };

    void tick(int64_t now);
    std::vector<GossipMessage> pending_updates() const;
    void apply_updates(const std::vector<GossipMessage>& updates);

    void set_gossip_interval(int64_t ns) { gossip_interval_ns_ = ns; }

private:
    MembershipTable& table_;
    int64_t gossip_interval_ns_{5'000'000'000};
    int64_t last_gossip_{0};
    uint32_t incarnation_{0};
};

} // namespace smo
