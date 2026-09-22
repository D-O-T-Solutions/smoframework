#include "otlp_exporter.hpp"

#include <core/errors/error.hpp>
#include <core/runtime/telemetry.hpp>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#include <poll.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <thread>

namespace smo::observability {

namespace {

// Simple HTTP POST helper
bool http_post(const std::string& host, uint16_t port, const std::string& path,
               const std::string& body, const std::unordered_map<std::string, std::string>& headers,
               std::string* response_out = nullptr, int timeout_ms = 5000)
{
    int sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        return false;

    // Set non-blocking for connect timeout
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    ::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) <= 0)
    {
        // Try DNS resolution
        struct addrinfo hints{}, *res = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        std::string port_str = std::to_string(port);
        int gai = ::getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res);
        if (gai != 0 || !res)
        {
            ::close(sock);
            return false;
        }
        addr = *reinterpret_cast<struct sockaddr_in*>(res->ai_addr);
        ::freeaddrinfo(res);
    }

    if (::connect(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0)
    {
        ::close(sock);
        return false;
    }

    std::ostringstream req;
    req << "POST " << path << " HTTP/1.1\r\n";
    req << "Host: " << host << "\r\n";
    req << "Content-Type: application/json\r\n";
    req << "Content-Length: " << body.size() << "\r\n";
    req << "Connection: close\r\n";
    for (const auto& [key, value] : headers)
    {
        req << key << ": " << value << "\r\n";
    }
    req << "\r\n" << body;

    std::string request = req.str();
    if (::send(sock, request.data(), request.size(), 0) != static_cast<ssize_t>(request.size()))
    {
        ::close(sock);
        return false;
    }

    std::string response;
    char buf[4096];
    while (true)
    {
        ssize_t n = ::recv(sock, buf, sizeof(buf), 0);
        if (n <= 0)
            break;
        response.append(buf, n);
    }
    ::close(sock);

    if (response_out)
        *response_out = std::move(response);
    return true;
}

} // anonymous namespace

OtlpExporter::OtlpExporter(const Config& config) : config_(config)
{
    // Ensure max_queue_size is at least batch_size
    if (config_.max_queue_size < config_.batch_size)
        config_.max_queue_size = config_.batch_size * 2;
}

OtlpExporter::~OtlpExporter()
{
    stop();
}

Result<void> OtlpExporter::start()
{
    if (running_.load())
        return {};

    running_ = true;
    worker_ = std::thread([this]() { run(); });
    return {};
}

void OtlpExporter::stop()
{
    if (!running_.load())
        return;

    running_ = false;
    queue_cv_.notify_all();
    if (worker_.joinable())
        worker_.join();

    // Final flush
    flush();
}

void OtlpExporter::export_spans(const std::vector<runtime::Span>& spans)
{
    if (spans.empty())
        return;

    std::lock_guard<std::mutex> lock(queue_mutex_);
    if (span_queue_.size() >= config_.max_queue_size)
    {
        // Drop oldest batch if queue is full
        span_queue_.pop();
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        stats_.spans_dropped += spans.size();
    }
    span_queue_.push(spans);
    queue_cv_.notify_one();
}

bool OtlpExporter::is_running() const
{
    return running_.load();
}

OtlpExporter::Stats OtlpExporter::get_stats() const
{
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void OtlpExporter::run()
{
    auto next_flush = std::chrono::steady_clock::now() + std::chrono::milliseconds(config_.flush_interval_ms);

    while (running_.load())
    {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        auto now = std::chrono::steady_clock::now();

        if (now >= next_flush || !span_queue_.empty())
        {
            lock.unlock();
            flush();
            lock.lock();
            next_flush = std::chrono::steady_clock::now() + std::chrono::milliseconds(config_.flush_interval_ms);
        }
        else
        {
            queue_cv_.wait_until(lock, next_flush);
        }
    }
}

void OtlpExporter::flush()
{
    std::vector<runtime::Span> batch;
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        while (!span_queue_.empty() && batch.size() < config_.batch_size)
        {
            auto& front = span_queue_.front();
            batch.insert(batch.end(), front.begin(), front.end());
            span_queue_.pop();
        }
    }

    if (batch.empty())
        return;

    // Parse endpoint URL
    std::string host = "localhost";
    uint16_t port = 4318;
    std::string path = "/v1/traces";

    if (config_.endpoint.find("://") != std::string::npos)
    {
        std::string url = config_.endpoint;
        auto proto_end = url.find("://");
        url = url.substr(proto_end + 3);
        auto path_start = url.find('/');
        if (path_start != std::string::npos)
        {
            path = url.substr(path_start);
            url = url.substr(0, path_start);
        }
        auto port_sep = url.find(':');
        if (port_sep != std::string::npos)
        {
            host = url.substr(0, port_sep);
            port = static_cast<uint16_t>(std::stoi(url.substr(port_sep + 1)));
        }
        else
        {
            host = url;
        }
    }

    std::string body = serialize_otlp_json(batch);

    std::string response;
    bool ok = http_post(host, port, path, body, {}, &response);

    auto now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                      std::chrono::system_clock::now().time_since_epoch())
                      .count();

    if (ok)
    {
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        stats_.spans_exported += batch.size();
        stats_.last_export_ns = now_ns;
    }
    else
    {
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        stats_.export_failures++;
        stats_.spans_dropped += batch.size();
        // Re-queue for retry (with limit)
        std::lock_guard<std::mutex> lock(queue_mutex_);
        if (span_queue_.size() < config_.max_queue_size)
        {
            span_queue_.push(std::move(batch));
        }
    }
}

std::string OtlpExporter::serialize_otlp_json(const std::vector<runtime::Span>& spans) const
{
    // OTLP JSON format for traces
    // See: https://github.com/open-telemetry/opentelemetry-proto/blob/main/opentelemetry/proto/collector/trace/v1/trace_service.proto
    std::ostringstream oss;
    oss << R"({"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":")"
        << config_.service_name << R"("}}]},"scopeSpans":[{"scope":{"name":"smo-runtime"},"spans":[)";

    bool first = true;
    for (const auto& span : spans)
    {
        if (!first)
            oss << ",";
        first = false;

        int64_t duration_ns = span.end_ns > span.start_ns ? span.end_ns - span.start_ns : 0;
        uint64_t start_ns = static_cast<uint64_t>(span.start_ns);
        uint64_t end_ns = static_cast<uint64_t>(span.end_ns);

        oss << "{";
        oss << "\"traceId\":\"" << span.trace_id << "\",";
        oss << "\"spanId\":\"" << span.span_id << "\",";
        if (!span.parent_span_id.empty())
            oss << "\"parentSpanId\":\"" << span.parent_span_id << "\",";
        oss << "\"name\":\"" << span.operation_name << "\",";
        oss << "\"kind\":0,"; // SPAN_KIND_INTERNAL
        oss << "\"startTimeUnixNano\":\"" << start_ns << "\",";
        oss << "\"endTimeUnixNano\":\"" << end_ns << "\",";
        oss << "\"attributes\":[";
        // Add standard attributes
        oss << "{\"key\":\"smo.operation\",\"value\":{\"stringValue\":\"" << span.operation_name << "\"}},";
        oss << "{\"key\":\"smo.status\",\"value\":{\"stringValue\":\"" << span.status << "\"}}";
        oss << "],";
        oss << "\"status\":{\"code\":" << (span.status == "ok" ? "1" : "2") << "}"; // STATUS_CODE_OK=1, STATUS_CODE_ERROR=2
        oss << "}";
    }

    oss << "]}]}]}";
    return oss.str();
}

} // namespace smo::observability
