#include "core/runtime/recovery_trust_service.hpp"

namespace smo::runtime {

RecoveryTrustService::RecoveryTrustService(TrustManager& trust_mgr, recovery::RecoveryEngine& recovery_engine)
    : trust_mgr_(trust_mgr)
    , recovery_engine_(recovery_engine)
{
}

Result<void> RecoveryTrustService::initialize()
{
    return {};
}

void RecoveryTrustService::tick(int64_t now_ns)
{
    trust_mgr_.tick(now_ns);
}

void RecoveryTrustService::shutdown()
{
    // Nothing to do for now
}

} // namespace smo::runtime