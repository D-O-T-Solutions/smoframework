#include "node_lifecycle_fsm.hpp"

namespace smo {

// ===========================================================================
// Transition table  (MASTER_SYSTEM_MAP.md §IX event table)
// ===========================================================================
std::vector<TransitionRule> NodeLifecycleFSM::build_transitions() {
    using S = NodeLifecycleState;
    using E = NodeLifecycleEvent;
    return {
        // Standard forward path
        {static_cast<FsmState>(S::NEW),             static_cast<FsmEvent>(E::IDENTITY_CREATED),   static_cast<FsmState>(S::IDENTITY_READY)},
        {static_cast<FsmState>(S::IDENTITY_READY),   static_cast<FsmEvent>(E::CSR_EXPORTED),      static_cast<FsmState>(S::CSR_PENDING)},
        {static_cast<FsmState>(S::CSR_PENDING),      static_cast<FsmEvent>(E::CERT_IMPORTED),     static_cast<FsmState>(S::CERTIFIED)},
        {static_cast<FsmState>(S::CERTIFIED),         static_cast<FsmEvent>(E::BOOTSTRAP_START),   static_cast<FsmState>(S::BOOTSTRAPPING)},
        {static_cast<FsmState>(S::BOOTSTRAPPING),     static_cast<FsmEvent>(E::BOOTSTRAP_COMPLETE),static_cast<FsmState>(S::JOINING)},
        {static_cast<FsmState>(S::JOINING),           static_cast<FsmEvent>(E::JOIN_COMPLETE),    static_cast<FsmState>(S::SYNCHRONIZING)},
        {static_cast<FsmState>(S::SYNCHRONIZING),     static_cast<FsmEvent>(E::SYNC_COMPLETE),    static_cast<FsmState>(S::ACTIVE)},

        // Suspend / resume
        {static_cast<FsmState>(S::ACTIVE),            static_cast<FsmEvent>(E::HEARTBEAT_TIMEOUT), static_cast<FsmState>(S::SUSPENDED)},
        {static_cast<FsmState>(S::SUSPENDED),         static_cast<FsmEvent>(E::RECONNECT),        static_cast<FsmState>(S::ACTIVE)},

        // Recovery
        {static_cast<FsmState>(S::ACTIVE),            static_cast<FsmEvent>(E::RECOVERY_PROPOSED), static_cast<FsmState>(S::RECOVERING)},
        {static_cast<FsmState>(S::SUSPENDED),         static_cast<FsmEvent>(E::RECOVERY_PROPOSED), static_cast<FsmState>(S::RECOVERING)},
        {static_cast<FsmState>(S::RECOVERING),        static_cast<FsmEvent>(E::RECOVERY_COMPLETE),static_cast<FsmState>(S::ACTIVE)},

        // Revocation — any state to REVOKED
        {static_cast<FsmState>(S::NEW),               static_cast<FsmEvent>(E::CERT_REVOKED),     static_cast<FsmState>(S::REVOKED)},
        {static_cast<FsmState>(S::IDENTITY_READY),    static_cast<FsmEvent>(E::CERT_REVOKED),     static_cast<FsmState>(S::REVOKED)},
        {static_cast<FsmState>(S::CSR_PENDING),       static_cast<FsmEvent>(E::CERT_REVOKED),     static_cast<FsmState>(S::REVOKED)},
        {static_cast<FsmState>(S::CERTIFIED),          static_cast<FsmEvent>(E::CERT_REVOKED),     static_cast<FsmState>(S::REVOKED)},
        {static_cast<FsmState>(S::BOOTSTRAPPING),      static_cast<FsmEvent>(E::CERT_REVOKED),     static_cast<FsmState>(S::REVOKED)},
        {static_cast<FsmState>(S::JOINING),            static_cast<FsmEvent>(E::CERT_REVOKED),     static_cast<FsmState>(S::REVOKED)},
        {static_cast<FsmState>(S::SYNCHRONIZING),      static_cast<FsmEvent>(E::CERT_REVOKED),     static_cast<FsmState>(S::REVOKED)},
        {static_cast<FsmState>(S::ACTIVE),             static_cast<FsmEvent>(E::CERT_REVOKED),     static_cast<FsmState>(S::REVOKED)},
        {static_cast<FsmState>(S::SUSPENDED),          static_cast<FsmEvent>(E::CERT_REVOKED),     static_cast<FsmState>(S::REVOKED)},
        {static_cast<FsmState>(S::RECOVERING),         static_cast<FsmEvent>(E::CERT_REVOKED),     static_cast<FsmState>(S::REVOKED)},

        // REVOKED → REMOVED (admin cleanup)
        {static_cast<FsmState>(S::REVOKED),           static_cast<FsmEvent>(E::ADMIN_REMOVE),     static_cast<FsmState>(S::REMOVED)},
    };
}

// ===========================================================================
// Timeout configuration (BOOTSTRAPPING → fallback to CERTIFIED, etc.)
// ===========================================================================
std::vector<StateTimeout> NodeLifecycleFSM::build_timeouts() {
    using S = NodeLifecycleState;
    constexpr uint64_t SEC = 1'000'000'000ULL;
    return {
        {static_cast<FsmState>(S::BOOTSTRAPPING),  30 * SEC, static_cast<FsmState>(S::CERTIFIED)},
        {static_cast<FsmState>(S::JOINING),         30 * SEC, static_cast<FsmState>(S::CERTIFIED)},
        {static_cast<FsmState>(S::SYNCHRONIZING),   60 * SEC, static_cast<FsmState>(S::JOINING)},
        {static_cast<FsmState>(S::RECOVERING),     120 * SEC, static_cast<FsmState>(S::ACTIVE)},
    };
}

// ===========================================================================
// Constructor
// ===========================================================================
NodeLifecycleFSM::NodeLifecycleFSM() {
    auto transitions = build_transitions();
    auto timeouts = build_timeouts();
    fsm_.set_transitions(std::move(transitions));
    fsm_.set_timeouts(std::move(timeouts));
    fsm_.reset(static_cast<FsmState>(NodeLifecycleState::NEW));
}

Result<void> NodeLifecycleFSM::on_event(NodeLifecycleEvent event) {
    return fsm_.on_event(static_cast<FsmEvent>(event));
}

Result<void> NodeLifecycleFSM::on_timeout() {
    return fsm_.on_timeout();
}

NodeLifecycleState NodeLifecycleFSM::get_state() const {
    return static_cast<NodeLifecycleState>(fsm_.current_state());
}

std::string NodeLifecycleFSM::state_name() const {
    return to_string(get_state());
}

Result<void> NodeLifecycleFSM::check_opcode_allowed(uint32_t opcode) const {
    auto state = get_state();
    if (state == NodeLifecycleState::ACTIVE) {
        return {};
    }
    if (state == NodeLifecycleState::BOOTSTRAPPING
        || state == NodeLifecycleState::JOINING
        || state == NodeLifecycleState::SYNCHRONIZING) {
        if (is_opcode_allowed_during_bootstrap(opcode)) {
            return {};
        }
        return Error(
            ErrorCode(ErrorCategory::Session, 507,
                      Severity::Error, RetryClass::NoRetry,
                      Recovery::None),
            "opcode not allowed in state " + to_string(state)
            + " (only bootstrap/join opcodes permitted)",
            __FILE__, __LINE__);
    }
    return Error(
        ErrorCode(ErrorCategory::Session, 508,
                  Severity::Error, RetryClass::NoRetry,
                  Recovery::None),
        "node state " + to_string(state) + " cannot process packets",
        __FILE__, __LINE__);
}

void NodeLifecycleFSM::reset() {
    fsm_.reset(static_cast<FsmState>(NodeLifecycleState::NEW));
}

// ===========================================================================
// String conversion
// ===========================================================================
std::string to_string(NodeLifecycleState state) {
    switch (state) {
        case NodeLifecycleState::NEW:                return "NEW";
        case NodeLifecycleState::IDENTITY_READY:      return "IDENTITY_READY";
        case NodeLifecycleState::CSR_PENDING:         return "CSR_PENDING";
        case NodeLifecycleState::CERTIFIED:           return "CERTIFIED";
        case NodeLifecycleState::BOOTSTRAPPING:       return "BOOTSTRAPPING";
        case NodeLifecycleState::JOINING:             return "JOINING";
        case NodeLifecycleState::SYNCHRONIZING:       return "SYNCHRONIZING";
        case NodeLifecycleState::ACTIVE:              return "ACTIVE";
        case NodeLifecycleState::SUSPENDED:           return "SUSPENDED";
        case NodeLifecycleState::RECOVERING:          return "RECOVERING";
        case NodeLifecycleState::REVOKED:             return "REVOKED";
        case NodeLifecycleState::REMOVED:             return "REMOVED";
    }
    return "UNKNOWN(" + std::to_string(static_cast<int>(state)) + ")";
}

std::string to_string(NodeLifecycleEvent event) {
    switch (event) {
        case NodeLifecycleEvent::IDENTITY_CREATED:    return "identity_created";
        case NodeLifecycleEvent::CSR_EXPORTED:        return "csr_exported";
        case NodeLifecycleEvent::CERT_IMPORTED:       return "cert_imported";
        case NodeLifecycleEvent::BOOTSTRAP_START:     return "bootstrap_start";
        case NodeLifecycleEvent::BOOTSTRAP_COMPLETE:  return "bootstrap_complete";
        case NodeLifecycleEvent::JOIN_COMPLETE:       return "join_complete";
        case NodeLifecycleEvent::SYNC_COMPLETE:       return "sync_complete";
        case NodeLifecycleEvent::HEARTBEAT_TIMEOUT:   return "heartbeat_timeout";
        case NodeLifecycleEvent::RECONNECT:           return "reconnect";
        case NodeLifecycleEvent::RECOVERY_PROPOSED:   return "recovery_proposed";
        case NodeLifecycleEvent::RECOVERY_COMPLETE:   return "recovery_complete";
        case NodeLifecycleEvent::CERT_REVOKED:        return "cert_revoked";
        case NodeLifecycleEvent::ADMIN_REMOVE:        return "admin_remove";
    }
    return "UNKNOWN(" + std::to_string(static_cast<int>(event)) + ")";
}

} // namespace smo