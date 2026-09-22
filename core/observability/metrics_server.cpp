#include "metrics_server.hpp"

#include <core/errors/error.hpp>

namespace smo::observability {

MetricsServer::MetricsServer(runtime::Telemetry& telemetry) : telemetry_(telemetry) {}

Result<void> MetricsServer::start(uint16_t port)
{
    auto result = http_server_.start(port);
    if (!result)
        return result;

    http_server_.register_handler("/metrics", [this](const HttpServer::HttpRequest& req, HttpServer::HttpResponse& resp) {
        (void)req;
        resp.content_type = "text/plain; version=0.0.4; charset=utf-8";
        resp.body = telemetry_.export_prometheus();
    });

    http_server_.register_handler("/health", [this](const HttpServer::HttpRequest& req, HttpServer::HttpResponse& resp) {
        (void)req;
        resp.content_type = "application/json";
        resp.body = telemetry_.health_status();
    });

    return {};
}

void MetricsServer::stop()
{
    http_server_.stop();
}

bool MetricsServer::is_running() const
{
    return http_server_.is_running();
}

} // namespace smo::observability