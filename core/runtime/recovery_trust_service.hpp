#pragma once

#include "core/recovery/recovery_engine.hpp"
#include "core/trust/trust.hpp"
#include "core/errors/error.hpp"

namespace smo::runtime {

class RecoveryTrustService
{
public:
    RecoveryTrustService(TrustManager& trust_mgr, recovery::RecoveryEngine& recovery_engine);

    Result<void> initialize();
    void tick(int64_t now_ns);
    void shutdown();

private:
    TrustManager& trust_mgr_;
    recovery::RecoveryEngine& recovery_engine_;
};

} // namespace smo::runtime