#pragma once

#include "core/runtime/telemetry.hpp"
#include "core/runtime/structured_logger.hpp"
#include "core/errors/error.hpp"
#include "core/types.hpp"

#include <string>

namespace smo::runtime {

class TelemetryService
{
public:
    TelemetryService(Telemetry& telemetry, StructuredLogger& logger, const std::string& data_dir);

    Result<void> initialize();
    void tick(int64_t now_ns, size_t peer_count, int64_t uptime_ns, uint64_t anti_entropy_repairs);
    void shutdown();

private:
    Telemetry& telemetry_;
    StructuredLogger& logger_;
    std::string data_dir_;
    int64_t last_ready_check_ = 0;
    bool daemon_ready_logged_ = false;
    bool daemon_degraded_logged_ = false;
};

} // namespace smo::runtime