#pragma once

#include "core/capability/capability.h"

namespace smo {
namespace acl {

// §X.3 — Capability Presets (Role Profiles)
//
// The runtime does NOT hardcode R/W/X. These are convenience presets.

inline CapabilitySet reader() noexcept {
    CapabilitySet s;
    s.set(Capability::HEARTBEAT);
    s.set(Capability::VERIFY);
    s.set(Capability::FS_READ);
    s.set(Capability::SESSION_CREATE);
    return s;
}

inline CapabilitySet contributor() noexcept {
    auto s = reader();
    s.set(Capability::FS_WRITE);
    s.set(Capability::CUSTOM_CONTRACT);
    return s;
}

inline CapabilitySet authority() noexcept {
    auto s = contributor();
    s.set(Capability::PROC_EXEC);
    s.set(Capability::GRANT);
    s.set(Capability::REVOKE);
    s.set(Capability::DISTRIBUTE);
    s.set(Capability::POLICY_CHANGE);
    s.set(Capability::NODE_BOOTSTRAP);
    return s;
}

} // namespace acl
} // namespace smo
