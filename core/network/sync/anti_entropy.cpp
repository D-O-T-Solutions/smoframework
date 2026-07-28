#include "anti_entropy.hpp"
#include <core/discovery/discovery.hpp>
#include <cstdio>

namespace smo::sync {

AntiEntropyService::AntiEntropyService(MembershipTable& table,
                                       GossipEngine& gossip,
                                       SyncBackend& backend,
                                       Config cfg)
    : table_(table), gossip_(gossip), backend_(backend), config_(cfg)
    , rng_(std::random_device{}())
{
    next_exchange_ns_ = 0;
}

AntiEntropyService::~AntiEntropyService() = default;

void AntiEntropyService::start() {
    next_exchange_ns_ = 0;
}

void AntiEntropyService::stop() {
    next_exchange_ns_ = -1;
}

void AntiEntropyService::tick(int64_t now_ns) {
    if (next_exchange_ns_ < 0) return;
    if (next_exchange_ns_ == 0) {
        next_exchange_ns_ = now_ns + config_.interval_ns;
        return;
    }
    if (now_ns < next_exchange_ns_) return;

    auto peers = table_.peers();
    if (peers.empty()) {
        next_exchange_ns_ = now_ns + config_.interval_ns;
        return;
    }

    // Compute Merkle trees for all 4 trees
    MerkleTree trees[4] = {
        backend_.compute_tree(TreeID::Membership),
        backend_.compute_tree(TreeID::CRL),
        backend_.compute_tree(TreeID::Policy),
        backend_.compute_tree(TreeID::Contract),
    };

    // Select random peers for exchange
    std::shuffle(peers.begin(), peers.end(), rng_);
    uint32_t n = std::min<uint32_t>(config_.fanout, peers.size());

    for (uint32_t i = 0; i < n; ++i) {
        const auto& peer = peers[i];
        if (peer.node_id.value.empty()) continue;

        // Build anti-entropy request payload: serialized Merkle trees
        Bytes payload;
        for (auto& tree : trees) {
            auto tbytes = tree.serialize();
            uint32_t tlen = static_cast<uint32_t>(tbytes.size());
            payload.insert(payload.end(),
                           reinterpret_cast<const uint8_t*>(&tlen),
                           reinterpret_cast<const uint8_t*>(&tlen) + 4);
            payload.insert(payload.end(), tbytes.begin(), tbytes.end());
        }

        // Queue the request as a gossip delta
        // In a full implementation, this would use a dedicated peer-to-peer
        // connection. For now, we log the exchange.
        std::printf("[anti-entropy] Exchange with %s: 4 trees\n",
                    peer.display_name.c_str());

        // Check each tree — if roots differ, request repair
        // (Peer response handling would be in a real implementation via
        //  PacketDispatcher or dedicated TCP connection)
    }

    repairs_done_ += n;
    next_exchange_ns_ = now_ns + config_.interval_ns;
}

} // namespace smo::sync