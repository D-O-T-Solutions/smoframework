#pragma once

#include <cstdint>
#include <string>
#include <array>
#include "core/capability/capability.h"

namespace smo {

struct SessionId {
    std::array<uint8_t, 16> bytes{};  // 128-bit session ID
};

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
