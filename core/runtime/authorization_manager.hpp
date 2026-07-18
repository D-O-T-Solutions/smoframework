#pragma once

#include "runtime_types.hpp"
#include "contract_interface.hpp"
#include "core/session/session.hpp"
#include "core/capability/capability.h"
#include "core/trust/trust.hpp"
#include "core/recovery/crl.hpp"

#include <string>
#include <unordered_set>

namespace smo::runtime {

// AuthorizationManager: full authorization pipeline (Sprint 37)
//
//   bridge → authorize(session_id, contract_meta) → pass/fail
//
// Pipeline:
//   1. Anonymous? → skip all checks
//   2. Session exists and valid?
//   3. Certificate revoked? (CRL check)
//   4. Trust score sufficient? (TrustManager)
//   5. Capabilities: session.caps ⊇ contract.required_caps
//
class AuthorizationManager {
public:
    AuthorizationManager(smo::SessionManager& session_mgr,
                         smo::TrustManager* trust_mgr = nullptr,
                         smo::recovery::CRL* crl = nullptr)
        : session_mgr_(session_mgr)
        , trust_mgr_(trust_mgr)
        , crl_(crl) {}

    // Set TrustManager reference (nullable — trust check skipped if null)
    void set_trust_manager(smo::TrustManager& tm) { trust_mgr_ = &tm; }

    // Set CRL reference (nullable — CRL check skipped if null)
    void set_crl(smo::recovery::CRL& crl) { crl_ = &crl; }

    // Full authorization pipeline:
    //   1. Anonymous? → allow
    //   2. Session lookup
    //   3. Session valid?
    //   4. CRL check (if CRL available)
    //   5. Trust score check (if TrustManager available)
    //   6. Capability check
    Result<void> authorize(
        const SessionId& session_id,
        const ContractMetadata& contract_meta);

    // Quick capability-only check (for existing callers)
    Result<void> authorize_capabilities(
        const SessionId& session_id,
        const ContractMetadata& contract_meta);

    // Register a contract as "anonymous" — no session/capability check.
    void set_anonymous(const std::string& contract_id, bool anonymous = true);

    bool is_anonymous(const std::string& contract_id) const {
        return anonymous_contracts_.count(contract_id) > 0;
    }

    // Capability mapping utilities
    static bool check_capabilities(
        const CapabilitySet& session_caps,
        const ContractCapabilities& contract_caps);

    static CapabilitySet to_session_capabilities(
        const ContractCapabilities& contract_caps);

private:
    smo::SessionManager& session_mgr_;
    smo::TrustManager* trust_mgr_ = nullptr;
    smo::recovery::CRL* crl_ = nullptr;
    std::unordered_set<std::string> anonymous_contracts_;
};

} // namespace smo::runtime
