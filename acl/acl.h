#pragma once

#include <cstdint>
#include <system_error>
#include "core/capability/capability.h"
#include "core/intent/intent.h"
#include "core/session/session.h"

namespace smo {

// §X — Capability System
//
// Capabilities are ephemeral, session-scoped, and runtime validated.
// The policy engine evaluates whether an intent can be executed.

struct PolicyResult {
    bool allowed{false};
    std::error_code reason;
    CapabilitySet granted;
};

class PolicyEngine {
public:
    virtual ~PolicyEngine() = default;

    // Evaluate whether the requester (via session) may perform the intent.
    virtual PolicyResult evaluate(const Intent& intent,
                                   const Session& session) = 0;
};

} // namespace smo
