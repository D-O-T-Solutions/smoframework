#pragma once

#include <cstdint>
#include <string>
#include <array>
#include "core/capability/capability.h"
#include "core/session/session_id.hpp"

namespace smo {

struct Session {
    SessionId     id;
    std::string   requester;
    std::string   responder;
    CapabilitySet capabilities;
    int64_t       created_at{0};
    int64_t       expires_at{0};
    bool          active{false};
};

} // namespace smo
