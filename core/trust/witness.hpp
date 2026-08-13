#pragma once

#include "../identity/identity.hpp"
#include "../types.hpp"
#include "trust.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace smo::trust {

    // ===========================================================================
    // WitnessSelector (RFC 0003 §3, RFC 0017 §3)
    //
    // Selects the witness node for a contract's execution outcome attestation.
    // Per RFC 0003 the witness is a non-arbiter third party that observed the
    // execution; it is selected by the Responder from the membership table.
    //
    // Selection policy (local, configurable):
    //   1. Never select the requester or the responder themselves.
    //   2. Prefer peers with the highest current trust score (non-anchor first
    //      so anchors are not overloaded; anchors are never witnesses).
    //   3. Prefer peers in the Online state over Offline/Unknown.
    //   4. Deterministic tie-break on NodeID so all parties agree.
    //   5. Fall back to "no witness" (local decision) when no eligible peer.
    // ===========================================================================
    class WitnessSelector
    {
    public:
        struct Candidate
        {
            NodeID node_id;
            bool online{false}; // from heartbeat/membership state
            double trust{0.0};  // from TrustManager (0.0 if unknown)
            bool anchor{false}; // trust anchors are never witnesses
        };

        // Returns the selected witness, or empty optional when none eligible
        // (RFC 0003 §3.4: fall back to local decision — never block).
        std::optional<NodeID> select(NodeID requester, NodeID responder,
                                     const std::vector<Candidate>& candidates) const noexcept;

        // Build Candidate vector from a TrustManager + membership peer set.
        static std::vector<Candidate> candidates_from(const TrustManager& tm, const std::vector<NodeID>& online,
                                                      const std::vector<NodeID>& all) noexcept;

        // User-facing description of the selection result.
        std::string describe(std::optional<NodeID> witness) const noexcept;

        void set_prefer_online(bool v) noexcept { prefer_online_ = v; }
        bool prefer_online() const noexcept { return prefer_online_; }

    private:
        bool prefer_online_ = true;
    };

} // namespace smo::trust
