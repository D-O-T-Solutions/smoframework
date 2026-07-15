#pragma once

#include "../certificate/certificate.hpp"
#include "../discovery/discovery.hpp"
#include "../errors/error.hpp"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace smo {
namespace select {

// Selection errors use Discovery category (codes 450-459)

// ===========================================================================
// SelectMode — how to pick from the filtered set
// ===========================================================================
enum class SelectMode : uint8_t {
    ALL     = 0,   // return all matching nodes
    NEAREST = 1,   // single node with lowest RTT
    TOP_N   = 2,   // top N by composite score
    RANDOM  = 3,   // N random nodes
};

// ===========================================================================
// SelectQuery — user intent for node selection
// ===========================================================================
struct SelectQuery {
    std::optional<NodeID>             node_id;
    std::optional<std::string>        name;             // display name or alias
    std::optional<Role>               role;
    std::vector<std::string>          tags;             // all must match
    std::optional<std::string>        cap_mask;         // hex capability mask
    std::optional<double>             trust_min;
    std::optional<double>             trust_max;
    std::optional<std::string>        os;
    std::optional<std::string>        arch;
    std::optional<std::string>        version_constraint; // semver constraint
    std::optional<std::string>        mesh_name;
    std::optional<PeerState>          state;
    std::optional<std::string>        where_expr;       // expression string
    SelectMode                        mode = SelectMode::ALL;
    int                               limit = 0;        // for TOP_N / RANDOM
};

// ===========================================================================
// NodeSet — the result of a selection query
// ===========================================================================
struct NodeSet {
    struct Entry {
        NodeID                  id;
        std::string             display_name;
        Role                    role = Role::Reader;
        std::vector<std::string> tags;
        double                  trust_score = 0.0;
        double                  rtt_ms      = 0.0;
        std::string             os;
        std::string             arch;
        std::string             version;
    };

    std::vector<Entry> entries;

    bool empty() const noexcept { return entries.empty(); }
    size_t size() const noexcept { return entries.size(); }

    // Pick the single best candidate for scope=single.
    // Best = highest trust score, then lowest RTT.
    // Returns default-constructed NodeID if empty.
    NodeID pick_one() const noexcept;
};

// ===========================================================================
// Selector — stateless selection engine
//
// Reads from MembershipTable, never writes. Filters are applied
// conjunctively (AND). The result is always a NodeSet.
// ===========================================================================
class Selector {
public:
    explicit Selector(const MembershipTable& table) noexcept
        : table_(table) {}

    Result<NodeSet> select(const SelectQuery& query) const;

private:
    const MembershipTable& table_;
};

} // namespace select
} // namespace smo
