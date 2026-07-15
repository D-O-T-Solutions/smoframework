#pragma once

#include <cstdint>

namespace smo {

enum class NodeState : uint8_t {
    BOOTSTRAP           = 0,
    KEY_GENERATION,
    DOMAIN_JOIN,
    CAPABILITY_NEGOTIATION,
    ACTIVE,
    DEGRADED,
    QUARANTINED,
    OFFLINE,
};

enum class ContractState : uint8_t {
    PENDING             = 0,
    VALIDATING_POLICY,
    VALIDATING_CAPABILITY,
    VALIDATING_SIGNATURE,
    VERIFYING_SESSION,
    CONSULTING_WITNESS,
    LOCAL_DECISION,
    EXECUTING,
    RECORDING_RESULT,
    NOTIFYING_PARTICIPANTS,
    FINALIZED,
    REJECTED,
    FAILED,
};

} // namespace smo
