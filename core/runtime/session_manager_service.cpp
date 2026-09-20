#include "core/runtime/session_manager_service.hpp"

#include <chrono>
#include <cstdio>

namespace smo::runtime {

SessionManagerService::SessionManagerService(SessionManager& session_mgr, const std::string& data_dir)
    : session_mgr_(session_mgr)
    , data_dir_(data_dir)
    , session_store_path_(data_dir + "/session_store.bin")
{
}

Result<void> SessionManagerService::initialize()
{
    int64_t now_ns = std::chrono::system_clock::now().time_since_epoch().count();
    auto rec_ec = session_mgr_.recover(session_store_path_, now_ns);
    if (!rec_ec)
    {
        std::printf("[smo-node] Session store recover failed: %s\n", rec_ec.error().message.c_str());
    }
    return {};
}

void SessionManagerService::tick(int64_t now_ns)
{
    session_mgr_.tick(now_ns);
    session_mgr_.collect_garbage();

    if (auto persist_ec = session_mgr_.persist(session_store_path_); !persist_ec)
    {
        std::printf("[smo-node] Session store persist failed: %s\n", persist_ec.error().message.c_str());
    }
}

void SessionManagerService::shutdown()
{
    session_mgr_.collect_garbage();
    if (auto persist_ec = session_mgr_.persist(session_store_path_); !persist_ec)
    {
        std::printf("[smo-node] Session store persist failed on shutdown: %s\n", persist_ec.error().message.c_str());
    }
}

} // namespace smo::runtime