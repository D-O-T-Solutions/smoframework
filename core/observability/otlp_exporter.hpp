#pragma once

#include <core/runtime/span.hpp>
#include <core/errors/error.hpp>

#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include <thread>
#include <chrono>
#include <queue>
#include <condition_variable>

namespace smo::observability {

    // OTLP Exporter for OpenTelemetry tracing
    // Exports spans to Jaeger/Tempo via OTLP/HTTP or OTLP/gRPC
    class OtlpExporter
    {
    public:
        struct Config
        {
            std::string endpoint = "http://localhost:4318/v1/traces"; // OTLP/HTTP endpoint
            std::string service_name = "smo-node";
            uint32_t batch_size = 512;
            uint32_t flush_interval_ms = 5000;
            uint32_t max_queue_size = 2048;
            std::string protocol = "http"; // "http" or "grpc"
        };

        explicit OtlpExporter(const Config& config);
        ~OtlpExporter();

        // Start the exporter background thread
        Result<void> start();

        // Stop the exporter
        void stop();

        // Export a batch of spans
        void export_spans(const std::vector<runtime::Span>& spans);

        // Check if exporter is running
        bool is_running() const;

        // Get export statistics
        struct Stats
        {
            uint64_t spans_exported = 0;
            uint64_t spans_dropped = 0;
            uint64_t export_failures = 0;
            uint64_t last_export_ns = 0;
        };
        Stats get_stats() const;

    private:
        void run();
        void flush();
        std::string serialize_otlp_json(const std::vector<runtime::Span>& spans) const;

        Config config_;
        std::atomic<bool> running_{false};
        std::thread worker_;
        std::mutex queue_mutex_;
        std::condition_variable queue_cv_;
        std::queue<std::vector<runtime::Span>> span_queue_;
        mutable std::mutex stats_mutex_;
        Stats stats_;
    };

    // Global OTLP exporter accessor
    inline OtlpExporter& global_otlp_exporter()
    {
        static OtlpExporter* exporter = nullptr;
        static std::once_flag init_flag;
        std::call_once(init_flag, []() {
            exporter = new OtlpExporter(OtlpExporter::Config{});
        });
        return *exporter;
    }

    // Initialize global OTLP exporter with custom config
    inline void init_global_otlp_exporter(const OtlpExporter::Config& config)
    {
        static OtlpExporter* exporter = nullptr;
        static std::once_flag init_flag;
        std::call_once(init_flag, [&config]() {
            exporter = new OtlpExporter(config);
        });
    }

} // namespace smo::observability
