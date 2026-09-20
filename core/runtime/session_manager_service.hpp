#pragma once

#include "core/session/session.hpp"
#include "core/errors/error.hpp"

#include <string>

namespace smo::runtime {

class SessionManagerService
{
public:
    SessionManagerService(SessionManager& session_mgr, const std::string& data_dir);

    Result<void> initialize();
    void tick(int64_t now_ns);
    void shutdown();

private:
    SessionManager& session_mgr_;
    std::string data_dir_;
    std::string session_store_path_;
};

} // namespace smo::runtime