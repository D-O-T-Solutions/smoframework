#pragma once

#include "core/governance/governance.hpp"
#include "core/runtime/middleware_pipeline.hpp"
#include "core/runtime/policy_middleware.hpp"
#include "core/acl/policy_engine.hpp"
#include "core/fsm/node_lifecycle_fsm.hpp"
#include "core/errors/error.hpp"

#include <memory>

namespace smo::runtime {

class GovernanceMiddlewareService
{
public:
    struct Dependencies
    {
        GovernanceEngine* governance_engine = nullptr;
        TrustManager* trust_mgr = nullptr;
        acl::PolicyEngine* policy_engine = nullptr;
        NodeLifecycleFSM* lifecycle_fsm = nullptr;
    };

    GovernanceMiddlewareService(MiddlewarePipeline& pipeline, Dependencies deps);

    Result<void> initialize();
    void tick(int64_t now_ns);
    void shutdown();

private:
    MiddlewarePipeline& pipeline_;
    std::unique_ptr<PolicyMiddleware> policy_middleware_;
    GovernanceEngine* governance_engine_ = nullptr;
};

} // namespace smo::runtime