#pragma once

#include "middleware_pipeline.hpp"
#include "contract_interface.hpp"
#include "core/acl/policy_engine.hpp"
#include "core/capability/capability.h"
#include "core/trust/trust.hpp"
#include "core/session/session.hpp"
#include "core/fsm/node_lifecycle_fsm.hpp"

#include <string>
#include <unordered_set>

namespace smo::runtime {

// PolicyMiddleware: check session validity + evaluate PolicyEngine rules.
//
// This replaces the old AuthorizationManager.
// It is ONE middleware in the pipeline — policies can be added
// as additional middleware (AuditMiddleware, QuotaMiddleware, etc.).
class PolicyMiddleware : public Middleware {
public:
    PolicyMiddleware(smo::TrustManager* trust_mgr = nullptr,
                     smo::acl::PolicyEngine* policy_engine = nullptr,
                     NodeLifecycleFSM* lifecycle_fsm = nullptr);

    void set_trust_manager(smo::TrustManager& tm) { trust_mgr_ = &tm; }
    void set_policy_engine(smo::acl::PolicyEngine& pe) { policy_engine_ = &pe; }
    void set_lifecycle_fsm(NodeLifecycleFSM* fsm) { lifecycle_fsm_ = fsm; }
    void set_anonymous(const std::string& contract_id, bool anonymous = true);
    bool is_anonymous(const std::string& contract_id) const;

    std::string name() const override { return "PolicyMiddleware"; }

    Result<void> process(PacketContext& ctx) override;

private:
    smo::TrustManager* trust_mgr_ = nullptr;
    smo::acl::PolicyEngine* policy_engine_ = nullptr;
    NodeLifecycleFSM* lifecycle_fsm_ = nullptr;
    std::unordered_set<std::string> anonymous_contracts_;
};

} // namespace smo::runtime