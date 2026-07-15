#pragma once

#include <cstdint>
#include <string_view>
#include <bitset>

namespace smo {

enum class Capability : uint8_t {
    // Filesystem
    FS_READ       = 0,
    FS_WRITE,

    // Process
    PROC_EXEC,

    // Network
    NET_BIND,

    // Session
    SESSION_CREATE,

    // Administration
    NODE_QUARANTINE,
    GRANT,
    REVOKE,
    DISTRIBUTE,
    POLICY_CHANGE,
    NODE_BOOTSTRAP,
    VERIFY,

    // Custom
    CUSTOM_CONTRACT,

    // Heartbeat
    HEARTBEAT,

    COUNT_,  // sentinel — must be last
};

using CapabilitySet = std::bitset<static_cast<size_t>(Capability::COUNT_)>;

// Predefined capability groupings (§X.3)
// The runtime does NOT hardcode R/W/X — these are presets only.
namespace presets {

CapabilitySet reader() noexcept;
CapabilitySet contributor() noexcept;
CapabilitySet authority() noexcept;

} // namespace presets

} // namespace smo
