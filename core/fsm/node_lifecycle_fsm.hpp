#pragma once

#include "fsm.hpp"
#include "../errors/error.hpp"
#include "../types.hpp"

#include <cstdint>
#include <string>
#include <unordered_set>

namespace smo {

// ===========================================================================
// Node Lifecycle States  (MASTER_SYSTEM_MAP.md §IX)
// ===========================================================================
enum class NodeLifecycleState : FsmState {
    NEW                = 0,
    IDENTITY_READY     = 1,
    CSR_PENDING        = 2,
    CERTIFIED          = 3,
    BOOTSTRAPPING      = 4,
    JOINING            = 5,
    SYNCHRONIZING      = 6,
    ACTIVE             = 7,
    SUSPENDED          = 8,
    RECOVERING         = 9,
    REVOKED            = 10,
    REMOVED            = 11,
};

// ===========================================================================
// Node Lifecycle Events  (MASTER_SYSTEM_MAP.md §IX event table)
// ===========================================================================
enum class NodeLifecycleEvent : FsmEvent {
    IDENTITY_CREATED    = 1,   // NEW → IDENTITY_READY
    CSR_EXPORTED        = 2,   // IDENTITY_READY → CSR_PENDING
    CERT_IMPORTED       = 3,   // CSR_PENDING → CERTIFIED
    BOOTSTRAP_START     = 4,   // CERTIFIED → BOOTSTRAPPING
    BOOTSTRAP_COMPLETE  = 5,   // BOOTSTRAPPING → JOINING
    JOIN_COMPLETE       = 6,   // JOINING → SYNCHRONIZING
    SYNC_COMPLETE       = 7,   // SYNCHRONIZING → ACTIVE
    HEARTBEAT_TIMEOUT   = 8,   // ACTIVE → SUSPENDED
    RECONNECT           = 9,   // SUSPENDED → ACTIVE
    RECOVERY_PROPOSED   = 10,  // ACTIVE/SUSPENDED → RECOVERING
    RECOVERY_COMPLETE   = 11,  // RECOVERING → ACTIVE
    CERT_REVOKED        = 12,  // any → REVOKED
    ADMIN_REMOVE        = 13,  // REVOKED → REMOVED
};

// ===========================================================================
// Bootstrap/join opcodes allowed during BOOTSTRAPPING/JOINING states
// ===========================================================================
struct BootstrapOpcode {
    uint32_t value;
    const char* name;
};

inline const BootstrapOpcode kAllowedDuringBootstrap[] = {
    {0x0105, "BootstrapRequest"},
    {0x0205, "BootstrapResponse"},
    {0x30,   "BOOTSTRAP_SNAPSHOT"},
    {0x31,   "BOOTSTRAP_INFO"},
    {0x33,   "JOIN"},
    {0x34,   "LEAVE"},
    {0x35,   "JOIN_INFO"},
};

inline bool is_opcode_allowed_during_bootstrap(uint32_t opcode) {
    for (auto& o : kAllowedDuringBootstrap) {
        if (o.value == opcode) return true;
    }
    return false;
}

// ===========================================================================
// NodeLifecycleFSM — wraps FsmInstance with node lifecycle semantics
// ===========================================================================
class NodeLifecycleFSM {
public:
    NodeLifecycleFSM();

    // Process a lifecycle event (MASTER doc event names)
    Result<void> on_event(NodeLifecycleEvent event);

    // Called when the current state's dwell time expires
    Result<void> on_timeout();

    // Get state of the local node (or a known peer, future extension)
    NodeLifecycleState get_state() const;
    std::string state_name() const;

    // Check if a given opcode is allowed in the current state
    // ACTIVE → all opcodes
    // BOOTSTRAPPING/JOINING/SYNCHRONIZING → only bootstrap/join opcodes
    // other → DENY all
    Result<void> check_opcode_allowed(uint32_t opcode) const;

    // Shortcut: true for ACTIVE
    bool is_active() const { return get_state() == NodeLifecycleState::ACTIVE; }

    // Reset to NEW
    void reset();

private:
    static std::vector<TransitionRule> build_transitions();
    static std::vector<StateTimeout> build_timeouts();
    FsmInstance fsm_;
};

// String conversion
std::string to_string(NodeLifecycleState state);
std::string to_string(NodeLifecycleEvent event);

} // namespace smo