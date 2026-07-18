#include "policy_middleware.hpp"
#include "dispatcher.hpp"
#include "core/session/session.hpp"

#include <cstdio>

namespace smo::runtime {

PolicyMiddleware::PolicyMiddleware(smo::TrustManager* trust_mgr,
                                     smo::acl::PolicyEngine* policy_engine,
                                     NodeLifecycleFSM* lifecycle_fsm)
    : trust_mgr_(trust_mgr)
    , policy_engine_(policy_engine)
    , lifecycle_fsm_(lifecycle_fsm) {}

void PolicyMiddleware::set_anonymous(const std::string& contract_id, bool anonymous) {
    if (anonymous) {
        anonymous_contracts_.insert(contract_id);
    } else {
        anonymous_contracts_.erase(contract_id);
    }
}

bool PolicyMiddleware::is_anonymous(const std::string& contract_id) const {
    return anonymous_contracts_.count(contract_id) > 0;
}

Result<void> PolicyMiddleware::process(PacketContext& ctx) {
    // 1. Anonymous contracts skip all checks
    if (anonymous_contracts_.count(ctx.contract_id)) {
        return {};
    }

    // 2. Session must exist
    if (!ctx.session) {
        ctx.denied = true;
        ctx.deny_reason = "session required for: " + ctx.contract_id;
        return {};
    }

    // 3. Session must be valid
    auto* session = ctx.session;
    if (session->state() == SessionState::Closed) {
        ctx.denied = true;
        ctx.deny_reason = "session is closed";
        return {};
    }

    // 4. Build PolicyEngine context
    double trust_score = 0.0;
    if (trust_mgr_) {
        auto score_res = trust_mgr_->get_score(session->peer_id());
        if (score_res) {
            trust_score = score_res.value();
        }
    }

    acl::PolicyEvaluationContext pe_ctx;
    pe_ctx.session_id = session->id().to_hex();
    pe_ctx.session_trust_score = trust_score;
    pe_ctx.session_created_at = session->created_at();
    pe_ctx.request_contract_id = ctx.contract_id;
    pe_ctx.request_method = ctx.method;

    // Get node lifecycle state
    if (lifecycle_fsm_) {
        pe_ctx.node_state = lifecycle_fsm_->state_name();
    } else {
        pe_ctx.node_state = "UNKNOWN";
    }

    // 5. Evaluate PolicyEngine rules (if engine is wired)
    if (policy_engine_) {
        auto result = policy_engine_->evaluate(pe_ctx);
        if (!result) {
            ctx.denied = true;
            ctx.deny_reason = "policy evaluation error: " + result.error().message;
            return {};
        }

        auto& decision = result.value();
        if (decision.decision == acl::PolicyDecision::Deny) {
            ctx.denied = true;
            ctx.deny_reason = decision.reason;
            return {};
        }

        // Plugin effects
        if (decision.decision == acl::PolicyDecision::Audit) {
            ctx.audit = true;
        }
        if (decision.decision == acl::PolicyDecision::Sandbox) {
            ctx.sandbox = true;
        }
        if (decision.decision == acl::PolicyDecision::RateLimit) {
            ctx.ratelimit = true;
        }
        if (decision.decision == acl::PolicyDecision::ReadOnly) {
            // ReadOnly is handled by deeper layers (kernel)
        }

        // All non-deny decisions pass through
        return {};
    }

    // 6. Fallback: inline checks (no PolicyEngine wired)
    // Trust score check
    if (trust_mgr_ && trust_score < 0.2) {
        ctx.denied = true;
        ctx.deny_reason = "trust score below threshold";
        return {};
    }

    return {};
}

} // namespace smo::runtime