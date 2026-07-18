#pragma once

#include "runtime_types.hpp"
#include "runtime_kernel.hpp"
#include "contract_interface.hpp"
#include "dispatcher.hpp"
#include "authorization_manager.hpp"
#include "core/session/session.hpp"
#include "core/trust/trust.hpp"
#include "core/recovery/crl.hpp"
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
//   Packet → OpcodeRoute → RuntimeRequest → RuntimeKernel → RuntimeResult
//
// Bridge does NOT know Transport. It only converts between wire objects
// (Packet) and runtime objects (RuntimeRequest / RuntimeResult).
class RuntimeBridge {
public:
    RuntimeBridge(RuntimeKernel& kernel,
                  Dispatcher& dispatcher,
                  SessionManager& session_mgr,
                  smo::TrustManager* trust_mgr = nullptr,
                  smo::recovery::CRL* crl = nullptr)
        : kernel_(kernel)
        , dispatcher_(dispatcher)
        , session_mgr_(session_mgr)
        , auth_mgr_(session_mgr, trust_mgr, crl) {}

    // Set TrustManager for trust-based authorization
    void set_trust_manager(smo::TrustManager& tm) {
        auth_mgr_.set_trust_manager(tm);
    }

    // Set CRL for certificate revocation checking
    void set_crl(smo::recovery::CRL& crl) {
        auth_mgr_.set_crl(crl);
    }

    // Register an opcode → contract_id + method mapping
    void register_route(uint32_t opcode_id,
                        std::string contract_id,
                        std::string method);

    // Mark a contract as anonymous (no session/capability check)
    void set_anonymous(const std::string& contract_id, bool anonymous = true);

    // Resolve opcode to route
    const OpcodeRoute* resolve(uint32_t opcode_id) const;

    // Access to AuthorizationManager for external configuration
    AuthorizationManager& authorization() { return auth_mgr_; }

    // Bridge: Packet → RuntimeRequest → Kernel → RuntimeResult
    // Returns the runtime result and any NextActions produced.
    Result<RuntimeResult> bridge(Packet&& pkt);

private:
    RuntimeKernel& kernel_;
    Dispatcher& dispatcher_;
    SessionManager& session_mgr_;
    AuthorizationManager auth_mgr_;
    std::unordered_map<uint32_t, OpcodeRoute> routes_;
};

} // namespace smo::runtime
