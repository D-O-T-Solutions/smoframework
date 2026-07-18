#pragma once

#include "runtime_types.hpp"
#include "runtime_kernel.hpp"
#include "contract_interface.hpp"
#include "dispatcher.hpp"

#include "core/session/session.hpp"
#include "protocol/packet/packet.h"

#include <string>
#include <unordered_map>
#include <cstdint>

namespace smo::runtime {

// OpcodeRoute: maps an opcode_id to a contract + method (RFC 0041 §2.2)
struct OpcodeRoute {
    std::string contract_id;
    std::string method;
};

// RuntimeBridge: network → runtime adapter (RFC 0041)
//
//   PacketDispatcher → SessionManager::lookup()
//                   → MiddlewarePipeline::process()
//                   → RuntimeBridge::convert(Packet → RuntimeRequest)
//                   → RuntimeKernel::execute()
//
// Bridge is THIN — it only converts Packet to RuntimeRequest.
// Session validation, authorization, policy are handled BEFORE bridge.
class RuntimeBridge {
public:
    RuntimeBridge(RuntimeKernel& kernel,
                  Dispatcher& dispatcher)
        : kernel_(kernel)
        , dispatcher_(dispatcher) {}

    // Register an opcode → contract_id + method mapping
    void register_route(uint32_t opcode_id,
                        std::string contract_id,
                        std::string method);

    // Resolve opcode to route
    const OpcodeRoute* resolve(uint32_t opcode_id) const;

    // Convert Packet → RuntimeRequest and execute via kernel.
    // No authorization — that must happen before calling bridge().
    Result<RuntimeResult> bridge(Packet&& pkt);

private:
    RuntimeKernel& kernel_;
    Dispatcher& dispatcher_;
    std::unordered_map<uint32_t, OpcodeRoute> routes_;
};

} // namespace smo::runtime