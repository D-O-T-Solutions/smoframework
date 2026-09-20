#include "core/runtime/governance_middleware_service.hpp"

namespace smo::runtime {

GovernanceMiddlewareService::GovernanceMiddlewareService(MiddlewarePipeline& pipeline, Dependencies deps)
    : pipeline_(pipeline)
    , governance_engine_(deps.governance_engine)
{
    policy_middleware_ = std::make_unique<PolicyMiddleware>(deps.trust_mgr, deps.policy_engine, deps.lifecycle_fsm);
    pipeline_.push(std::move(policy_middleware_));
}

Result<void> GovernanceMiddlewareService::initialize()
{
    return {};
}

void GovernanceMiddlewareService::tick(int64_t now_ns)
{
    if (governance_engine_)
    {
        governance_engine_->tick(now_ns);
    }
}

void GovernanceMiddlewareService::shutdown()
{
    // Nothing to do for now
}

} // namespace smo::runtime