#pragma once

#include "core/errors/error.hpp"

#include <cstdint>
#include <string>

namespace smo {
namespace enroll {

struct AutoEnrollConfig {
    std::string data_dir;
    std::string mesh_dir;
    std::string node_name;
    uint16_t port = 5454;
    bool daemon_mode = true;
};

Result<void> run_join_command(const std::string& token_str,
                               const std::string& data_dir,
                               const std::string& node_name,
                               uint16_t port,
                               const std::string& mesh_dir);

} // namespace enroll
} // namespace smo