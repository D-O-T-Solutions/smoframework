#pragma once

#include <cstdint>
#include <string>
#include "core/errors/error.hpp"

namespace smo {

enum class SandboxLevel : uint8_t {
    None     = 0,
    Native   = 1,
    Full     = 2
};

class Sandbox {
public:
    struct Config {
        bool enable_seccomp{true};
        bool enable_namespaces{true};
        uint32_t timeout_sec{30};
        uint64_t max_memory_bytes{64 * 1024 * 1024};
    };

    Result<void> initialise(const Config& cfg);
    Result<void> execute_sandboxed(const std::string& task_id);
    void close();

    static SandboxLevel level_for_category(const std::string& category);
};

} // namespace smo
