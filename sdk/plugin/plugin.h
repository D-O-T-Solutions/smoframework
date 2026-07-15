#pragma once

#include <cstdint>
#include <string>
#include <system_error>
#include "core/opcode/opcode.h"
#include "core/capability/capability.h"

namespace smo {

// Plugin interface for custom opcodes.
struct PluginContext {
    std::string    contract_id;
    std::string    requester;
    std::string    parameters_json;
    CapabilitySet  granted;
};

class Plugin {
public:
    virtual ~Plugin() = default;
    virtual std::string name() const noexcept = 0;
    virtual Opcode opcode() const noexcept = 0;
    virtual std::error_code execute(const PluginContext& ctx) = 0;
};

} // namespace smo
