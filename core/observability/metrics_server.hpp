#pragma once

#include "core/observability/http_server.hpp"
#include "core/runtime/telemetry.hpp"

namespace smo::observability {

    class MetricsServer
    {
    public:
        explicit MetricsServer(runtime::Telemetry& telemetry);

        Result<void> start(uint16_t port);
        void stop();
        bool is_running() const;

    private:
        runtime::Telemetry& telemetry_;
        HttpServer http_server_;
    };

} // namespace smo::observability