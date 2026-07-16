#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <unordered_map>
#include <functional>
#include <chrono>
#include <memory>
#include "core/types.hpp"
#include "core/errors/error.hpp"
#include "core/contract/contract.hpp"

namespace smo::runtime {

// ===========================================================================
// Scheduler Types
// ===========================================================================

enum class SchedulePriority : uint8_t {
    Low = 0,
    Normal = 50,
    High = 100,
    Critical = 255,
};

struct Task {
    std::string task_id;
    std::string contract_id;
    std::string execution_id;
    std::string trace_id;
    std::vector<std::string> target_nodes;
    uint32_t priority = 50;
    int64_t deadline_ns = 0;
    int32_t max_retries = 3;
    std::unordered_map<std::string, std::string> payload;
};

struct ScheduledTask {
    Task task;
    std::string assigned_node;
    int64_t scheduled_time_ns = 0;
    int64_t started_ns = 0;
    int64_t completed_ns = 0;
    int32_t retry_count = 0;
    std::string status;  // pending, running, completed, failed, cancelled
};

struct ResourceRequirements {
    int64_t cpu_millis = 0;
    int64_t memory_bytes = 0;
    int64_t disk_bytes = 0;
    int64_t network_bps = 0;
    std::vector<std::string> required_devices;
};

struct NodeCapacity {
    std::string node_id;
    int64_t total_cpu_millis = 0;
    int64_t available_cpu_millis = 0;
    int64_t total_memory_bytes = 0;
    int64_t available_memory_bytes = 0;
    int64_t total_disk_bytes = 0;
    int64_t available_disk_bytes = 0;
    std::vector<std::string> available_devices;
    std::vector<std::string> labels;
    int64_t last_update_ns = 0;
    bool healthy = true;
};

// ===========================================================================
// Scheduler Interface
// ===========================================================================

class Scheduler {
public:
    struct Config {
        size_t max_concurrent_tasks = 100;
        size_t worker_threads = 4;
        int64_t scheduling_interval_ns = 100'000'000;  // 100ms
        bool enable_preemption = true;
        bool enable_priority_boost = true;
    };

    explicit Scheduler(const Config& config = {});
    ~Scheduler();

    Scheduler(const Scheduler&) = delete;
    Scheduler& operator=(const Scheduler&) = delete;
    Scheduler(Scheduler&&) = default;
    Scheduler& operator=(Scheduler&&) = default;

    // Submit a task for scheduling
    Result<std::string> submit(const Task& task);

    // Cancel a scheduled/running task
    Result<void> cancel(const std::string& task_id);

    // Get task status
    Result<std::string> status(const std::string& task_id) const;

    // Get task result
    Result<std::string> result(const std::string& task_id) const;

    // Register node capacity
    Result<void> register_node(const NodeCapacity& capacity);

    // Unregister node
    Result<void> unregister_node(const std::string& node_id);

    // Get node status
    Result<NodeCapacity> get_node_status(const std::string& node_id) const;

    // List all nodes
    Result<std::vector<NodeCapacity>> list_nodes() const;

    // Update node health
    Result<void> update_node_health(const std::string& node_id, bool healthy);

    // Get scheduler statistics
    struct Stats {
        size_t pending_tasks = 0;
        size_t running_tasks = 0;
        size_t completed_tasks = 0;
        size_t failed_tasks = 0;
        size_t registered_nodes = 0;
        size_t healthy_nodes = 0;
        int64_t avg_queue_time_ns = 0;
        int64_t avg_execution_time_ns = 0;
    };
    Result<Stats> get_stats() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ===========================================================================
// Retry Policy Engine
// ===========================================================================

struct RetryPolicy {
    int32_t max_attempts = 3;
    int64_t base_delay_ns = 1'000'000'000;  // 1 second
    int64_t max_delay_ns = 60'000'000'000;  // 60 seconds
    double backoff_multiplier = 2.0;
    double jitter_factor = 0.1;  // 10% jitter
    std::vector<int> retryable_errors;  // Error codes that are retryable
    std::function<bool(const std::string& error)> is_retryable;
};

class RetryEngine {
public:
    explicit RetryEngine(const RetryPolicy& policy = {});
    ~RetryEngine() = default;

    // Check if error is retryable
    bool is_retryable(const std::string& error_code, const std::string& error_msg) const;

    // Calculate next delay
    int64_t next_delay(int attempt, const std::string& error_code) const;

    // Execute with retry
    template<typename Func>
    Result<std::string> execute_with_retry(Func&& func, const std::string& context = "") {
        int attempt = 0;
        std::string last_error;

        while (attempt < policy_.max_attempts) {
            auto result = func();
            if (result) {
                return result;
            }

            last_error = result.error().message;
            
            if (!is_retryable(result.error().code_str(), last_error)) {
                return result.error();
            }

            if (attempt + 1 < policy_.max_attempts) {
                int64_t delay = next_delay(attempt, result.error().code_str());
                std::this_thread::sleep_for(std::chrono::nanoseconds(delay));
            }
            ++attempt;
        }

        return SMO_ERR_RUNTIME(1000, Error, NoRetry, None,
            "Max retries exceeded for " + context + ": " + last_error);
    }

private:
    RetryPolicy policy_;
};

} // namespace smo::runtime