#pragma once

#include <cstdint>

namespace smo {

// §XI — Trust and Reputation System
//
// Four independent components, computed locally on each node.
// Invariant I-13: Trust is eventually consistent. NOT absolute truth.

struct TrustComponents {
    double citizen{0.0};       // online time, heartbeat stability
    double execution{0.0};     // contract success ratio
    double witness{0.0};       // witness participation and accuracy
    double consistency{0.0};   // result agreement with majority
};

// Composite: Citizen×0.2 + Execution×0.5 + Witness×0.2 + Consistency×0.1
// Weights are defaults; local policy MAY override.
double compute_composite(const TrustComponents& c) noexcept;

struct TrustConfig {
    double weight_citizen{0.2};
    double weight_execution{0.5};
    double weight_witness{0.2};
    double weight_consistency{0.1};
    double decay_half_life_days{30.0};     // sliding window decay
    double citizen_penalty_offline{0.001};  // per offline detection
    double requester_penalty_rejected{0.01};
    double requester_penalty_no_authority{0.05};
};

} // namespace smo
