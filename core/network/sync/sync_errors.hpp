#pragma once

#include <core/errors/error.hpp>

namespace smo::sync {

namespace SyncErrc {
    inline constexpr ErrorCode
    Truncated(ErrorCategory::Sync, 1, Severity::Error, RetryClass::NoRetry, Recovery::None);
    inline constexpr ErrorCode
    Inconsistent(ErrorCategory::Sync, 2, Severity::Warn, RetryClass::RetrySafe, Recovery::RestartFSM);
} // namespace SyncErrc

} // namespace smo::sync