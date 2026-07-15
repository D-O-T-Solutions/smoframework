#pragma once

#include <memory>
#include <system_error>
#include "core/intent/intent.h"
#include "transport/transport.h"

namespace smo {

// Client API for submitting intents to the mesh.
class SmoClient {
public:
    explicit SmoClient(std::unique_ptr<Transport> transport);
    ~SmoClient();

    SmoClient(const SmoClient&) = delete;
    SmoClient& operator=(const SmoClient&) = delete;

    std::error_code submit(const Intent& intent);
    std::error_code connect(const Endpoint& node);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace smo
