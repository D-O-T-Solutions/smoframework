#include "core/runtime/telemetry_service.hpp"

#include <chrono>
#include <cstdio>
#include <fstream>

namespace smo::runtime {

TelemetryService::TelemetryService(Telemetry& telemetry, StructuredLogger& logger, const std::string& data_dir)
    : telemetry_(telemetry)
    , logger_(logger)
    , data_dir_(data_dir)
{
}

Result<void> TelemetryService::initialize()
{
    return {};
}

void TelemetryService::tick(int64_t now_ns, size_t peer_count, int64_t uptime_ns, uint64_t anti_entropy_repairs)
{
    telemetry_.set_gauge("smo_connected_peers", static_cast<double>(peer_count), "");
    telemetry_.set_gauge("smo_membership_epoch", static_cast<double>(now_ns % 1'000'000), "");
    telemetry_.set_gauge("smo_anti_entropy_repairs_total", static_cast<double>(anti_entropy_repairs), "");

    std::string metrics_path = data_dir_ + "/metrics.prom";
    auto metrics_str = telemetry_.export_prometheus();
    if (!metrics_str.empty())
    {
        if (auto f = std::fopen(metrics_path.c_str(), "w"))
        {
            std::fwrite(metrics_str.data(), 1, metrics_str.size(), f);
            std::fclose(f);
        }
    }

    if (!daemon_ready_logged_ && uptime_ns > 30'000'000'000LL)
    {
        // The readiness check is done in the main loop; we just log here if needed
        daemon_ready_logged_ = true;
    }
}

void TelemetryService::shutdown()
{
    // Nothing to do for now
}

} // namespace smo::runtime