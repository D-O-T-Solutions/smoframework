#pragma once

#include <cstdint>
#include <string_view>

namespace smo {

enum class Opcode : uint8_t {
    // MVP (§XVIII.1)
    LS         = 0x01,
    PUT        = 0x02,
    GET        = 0x03,
    EXEC       = 0x04,
    QUARANTINE = 0x05,

    // Post-MVP (§XVIII.2)
    MKDIR      = 0x10,
    RM         = 0x11,
    CP         = 0x12,
    CUSTOM     = 0xFF,
};

struct OpcodeInfo {
    Opcode       code;
    std::string_view name;
    bool         idempotent;
    uint32_t     required_capability_mask;
};

constexpr OpcodeInfo opcode_info(Opcode code) noexcept;

} // namespace smo
