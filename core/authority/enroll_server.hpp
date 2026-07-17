#pragma once

#include "authority.hpp"
#include <string>
#include <memory>
#include <thread>
#include <atomic>

namespace smo::authority {

class EnrollServer {
public:
    EnrollServer();
    ~EnrollServer();

    EnrollServer(const EnrollServer&) = delete;
    EnrollServer& operator=(const EnrollServer&) = delete;

    Result<void> start(uint16_t port,
                       MeshAuthority& authority,
                       const std::string& hmac_secret_hex,
                       const HashImpl& hash);

    void stop();
    bool is_running() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace smo::authority
