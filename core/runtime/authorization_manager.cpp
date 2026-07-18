#include "authorization_manager.hpp"

#include <cstdio>

namespace smo::runtime {

void AuthorizationManager::set_anonymous(const std::string& contract_id, bool anonymous) {
    if (anonymous) {
        anonymous_contracts_.insert(contract_id);
    } else {
        anonymous_contracts_.erase(contract_id);
    }
}

// ── Full authorization pipeline ──────────────────────────────────────
//
//   1. Anonymous contracts → allow unconditionally
//   2. Session must exist
//   3. Session must be valid (not closed/expired)
//   4. CRL: session's certificate must not be revoked (if CRL available)
//   5. Trust: peer's trust score must meet minimum threshold (if TrustManager available)
//   6. Capabilities: session.capabilities ⊇ contract.required_capabilities
//
Result<void> AuthorizationManager::authorize(
    const SessionId& session_id,
    const ContractMetadata& contract_meta)
{
    // 1. Anonymous contracts skip all checks
    if (anonymous_contracts_.count(contract_meta.id)) {
        return {};
    }

    // 2. Look up session
    auto* session = session_mgr_.lookup(session_id);
    if (!session) {
        return Error(
            ErrorCode(ErrorCategory::Session, 503,
                      Severity::Error, RetryClass::NoRetry,
                      Recovery::Reconnect),
            "session not found",
            __FILE__, __LINE__);
    }

    // 3. Session must be valid
    if (session->state() == SessionState::Closed) {
        return Error(
            ErrorCode(ErrorCategory::Session, 501,
                      Severity::Error, RetryClass::RetrySafe,
                      Recovery::Reconnect),
            "session is closed",
            __FILE__, __LINE__);
    }

    // 4. CRL check: is the session's certificate revoked?
    if (crl_) {
        // Compute certificate fingerprint from serialized cert bytes
        // Using first 32 bytes hex as unique identifier
        auto cert_full = session->peer_cert().serialize_full();
        std::string fp;
        for (size_t i = 0; i < cert_full.size() && i < 32; ++i) {
            char buf[3];
            std::snprintf(buf, sizeof(buf), "%02x", cert_full[i]);
            fp += buf;
        }
        if (fp.empty()) fp = "unknown";
        auto revoked = crl_->is_revoked(fp);
        if (revoked && revoked.value()) {
            return Error(
                ErrorCode(ErrorCategory::Trust, 207,
                          Severity::Error, RetryClass::NoRetry,
                          Recovery::None),
                "certificate revoked: " + fp,
                __FILE__, __LINE__);
        }
    }

    // 5. Trust score check
    if (trust_mgr_) {
        auto score_res = trust_mgr_->get_score(session->peer_id());
        if (!score_res) {
            // No trust data — use trust anchor (score = 1.0) if applicable
            // TrustManager already returns 1.0 for trust anchors
            if (!trust_mgr_->is_trust_anchor(session->peer_id())) {
                return Error(
                    ErrorCode(ErrorCategory::Trust, 200,
                              Severity::Info, RetryClass::RetrySafe,
                              Recovery::None),
                    "no trust data for peer",
                    __FILE__, __LINE__);
            }
        } else {
            double score = score_res.value();
            // Minimum trust threshold: 0.2 (Low trust level)
            // Contracts can specify higher thresholds via policy
            constexpr double kMinTrustThreshold = 0.2;
            if (score < kMinTrustThreshold) {
                return Error(
                    ErrorCode(ErrorCategory::Trust, 201,
                              Severity::Info, RetryClass::NoRetry,
                              Recovery::None),
                    "trust score below minimum threshold",
                    __FILE__, __LINE__);
            }
            std::printf("[auth] trust score %.2f for peer\n", score);
        }
    }

    // 6. Capability check: session.caps ⊇ contract.required_caps
    if (!check_capabilities(session->capabilities(), contract_meta.required_capabilities)) {
        return Error(
            ErrorCode(ErrorCategory::Session, 507,
                      Severity::Error, RetryClass::NoRetry,
                      Recovery::None),
            "insufficient capabilities for: " + contract_meta.id,
            __FILE__, __LINE__);
    }

    return {};
}

// ── Capability-only check (backwards compatible) ─────────────────────
Result<void> AuthorizationManager::authorize_capabilities(
    const SessionId& session_id,
    const ContractMetadata& contract_meta)
{
    if (anonymous_contracts_.count(contract_meta.id)) {
        return {};
    }

    auto* session = session_mgr_.lookup(session_id);
    if (!session) {
        return Error(
            ErrorCode(ErrorCategory::Session, 503,
                      Severity::Error, RetryClass::NoRetry,
                      Recovery::Reconnect),
            "session not found",
            __FILE__, __LINE__);
    }

    if (!check_capabilities(session->capabilities(), contract_meta.required_capabilities)) {
        return Error(
            ErrorCode(ErrorCategory::Session, 507,
                      Severity::Error, RetryClass::NoRetry,
                      Recovery::None),
            "insufficient capabilities for: " + contract_meta.id,
            __FILE__, __LINE__);
    }

    return {};
}

// ── Static capability mapping ───────────────────────────────────────

bool AuthorizationManager::check_capabilities(
    const CapabilitySet& session_caps,
    const ContractCapabilities& contract_caps)
{
    auto required = to_session_capabilities(contract_caps);
    if (required.none()) return true;
    return (session_caps & required) == required;
}

CapabilitySet AuthorizationManager::to_session_capabilities(
    const ContractCapabilities& contract_caps)
{
    CapabilitySet caps;

    if (contract_caps.test(static_cast<size_t>(ContractCapability::Filesystem))) {
        caps.set(static_cast<size_t>(Capability::FS_READ));
        caps.set(static_cast<size_t>(Capability::FS_WRITE));
    }

    if (contract_caps.test(static_cast<size_t>(ContractCapability::Scheduler))) {
        caps.set(static_cast<size_t>(Capability::PROC_EXEC));
    }

    if (contract_caps.test(static_cast<size_t>(ContractCapability::Governance))) {
        caps.set(static_cast<size_t>(Capability::GRANT));
        caps.set(static_cast<size_t>(Capability::REVOKE));
        caps.set(static_cast<size_t>(Capability::POLICY_CHANGE));
    }

    if (contract_caps.test(static_cast<size_t>(ContractCapability::Recovery))) {
        caps.set(static_cast<size_t>(Capability::GRANT));
        caps.set(static_cast<size_t>(Capability::VERIFY));
    }

    if (contract_caps.test(static_cast<size_t>(ContractCapability::Identity))) {
        caps.set(static_cast<size_t>(Capability::VERIFY));
    }

    if (contract_caps.test(static_cast<size_t>(ContractCapability::Storage))) {
        caps.set(static_cast<size_t>(Capability::FS_READ));
        caps.set(static_cast<size_t>(Capability::FS_WRITE));
    }

    if (contract_caps.test(static_cast<size_t>(ContractCapability::Audit))) {
        caps.set(static_cast<size_t>(Capability::VERIFY));
    }

    if (contract_caps.test(static_cast<size_t>(ContractCapability::Network))) {
        caps.set(static_cast<size_t>(Capability::HEARTBEAT));
    }

    return caps;
}

} // namespace smo::runtime
