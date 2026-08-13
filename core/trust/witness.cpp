#include "witness.hpp"

#include <algorithm>

namespace smo::trust {

    std::optional<NodeID> WitnessSelector::select(NodeID requester, NodeID responder,
                                                  const std::vector<Candidate>& candidates) const noexcept
    {
        // 1. Exclude requester, responder and anchors.
        std::vector<Candidate> eligible;
        eligible.reserve(candidates.size());
        for (const auto& c : candidates)
        {
            if (c.node_id == requester || c.node_id == responder)
                continue;
            if (c.anchor)
                continue;
            eligible.push_back(c);
        }
        if (eligible.empty())
        {
            return std::nullopt;
        }

        // 2. Deterministic total order: online status, then trust score (desc),
        //    then NodeID (asc) for a stable tie-break.
        const bool prefer_online = prefer_online_;
        std::sort(eligible.begin(), eligible.end(), [prefer_online](const Candidate& a, const Candidate& b) noexcept {
            if (prefer_online && a.online != b.online)
                return a.online;
            if (a.trust != b.trust)
                return a.trust > b.trust;
            return a.node_id < b.node_id;
        });

        return eligible.front().node_id;
    }

    std::vector<WitnessSelector::Candidate> WitnessSelector::candidates_from(const TrustManager& tm,
                                                                             const std::vector<NodeID>& online,
                                                                             const std::vector<NodeID>& all) noexcept
    {
        std::vector<Candidate> out;
        out.reserve(all.size());

        // Known peers from the membership table.
        for (const auto& id : all)
        {
            Candidate c;
            c.node_id = id;
            c.online = std::find(online.begin(), online.end(), id) != online.end();
            c.anchor = tm.is_trust_anchor(id);
            if (auto score = tm.get_score(id); score)
            {
                c.trust = score.value();
            }
            out.push_back(c);
        }

        // Peers observed online but not (yet) in the membership table.
        for (const auto& id : online)
        {
            bool present = std::any_of(out.begin(), out.end(), [&id](const Candidate& c) { return c.node_id == id; });
            if (!present)
            {
                Candidate c;
                c.node_id = id;
                c.online = true;
                c.anchor = tm.is_trust_anchor(id);
                if (auto score = tm.get_score(id); score)
                {
                    c.trust = score.value();
                }
                out.push_back(c);
            }
        }
        return out;
    }

    std::string WitnessSelector::describe(std::optional<NodeID> witness) const noexcept
    {
        if (!witness)
        {
            return "no eligible witness (fall back to local decision)";
        }
        return "selected witness " + witness->to_string();
    }

} // namespace smo::trust
