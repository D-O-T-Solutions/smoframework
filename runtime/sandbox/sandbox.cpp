#include "runtime/sandbox/sandbox.hpp"

namespace smo {

Result<void> Sandbox::initialise(const Config& cfg) {
    (void)cfg;
    return {};
}

Result<void> Sandbox::execute_sandboxed(const std::string& task_id) {
    (void)task_id;
    return {};
}

void Sandbox::close() {}

SandboxLevel Sandbox::level_for_category(const std::string& category) {
    if (category == "kernel") return SandboxLevel::None;
    if (category == "native") return SandboxLevel::Native;
    return SandboxLevel::Full;
}

} // namespace smo
