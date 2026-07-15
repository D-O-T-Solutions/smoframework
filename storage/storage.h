#pragma once

#include <cstdint>
#include <memory>
#include <system_error>
#include "core/errors/errors.h"

namespace smo {

// §IX — Storage Model
//
// All storage is per-node isolated.
// Invariant I-08: Never store mutable shared execution state globally.

class Store {
public:
    virtual ~Store() = default;

    virtual std::error_code open() noexcept = 0;
    virtual void close() noexcept = 0;
    virtual std::error_code flush() noexcept = 0;
};

} // namespace smo
