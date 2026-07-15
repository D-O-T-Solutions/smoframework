#pragma once

#include <cstdint>
#include <system_error>
#include "core/state/state.h"

namespace smo {

// §XIII — Node Execution FSM
//
// Every transition MUST be:
//   - auditable   (I-04)
//   - deterministic (I-05)
//   - replayable  (I-06)
//   - serializable (I-07)

struct FsmEvent {
    uint64_t     sequence{0};
    std::string  contract_id;
    std::string  trigger;
    std::string  payload_json;
    int64_t      timestamp{0};
};

class Fsm {
public:
    virtual ~Fsm() = default;

    virtual NodeState current_state() const noexcept = 0;
    virtual std::error_code dispatch(const FsmEvent& event) = 0;
    virtual void reset() noexcept = 0;
};

} // namespace smo
