#pragma once

#include <cstdint>
#include <string>
#include <chrono>
#include <vector>
#include <optional>
#include <functional>
#include "core/types.hpp"
#include "core/errors/error.hpp"
#include "core/contract/contract.hpp"

namespace smo {

struct ExecutionConfig {
    int64_t timeout_ns = 30'000'000'000;  // 30 seconds default
    int32_t max_retries = 3;
    int32_t priority = 0;  // Higher = more important
    uint32_t control_level = 0;  // 0=safe, 1=normal, 2=force, 3=emergency
    uint32_t scope = 0;  // 0=single, 1=mesh, 2=quorum, 3=witness
    std::string policy_name;
};

struct ExecutionContext {
    ContractID contract_id;
    std::string execution_id;
    std::string trace_id;
    std::string requester_id;
    std::string intent_hash;
    std::vector<std::string> selected_nodes;
    std::vector<std::string> witness_ids;
    ExecutionConfig config;
    std::string policy_name;
    std::vector<std::string> selected_nodes;
    std::vector<std::string> witness_ids;
};

struct ExecutionResult {
    std::string execution_id;
    std::string contract_id;
    std::string trace_id;
    std::string status;  // created, running, completed, failed, cancelled
    std::string result_hash;
    std::string error_message;
    int64_t created_ns = 0;
    int64_t started_ns = 0;
    int64_t completed_ns = 0;
    int32_t retry_count = 0;
};

class ExecutionEngine {
public:
    struct Config {
        size_t max_concurrent_executions = 100;
        size_t worker_threads = 4;
        int64_t default_timeout_ns = 30'000'000'000;
        size_t max_retry_attempts = 3;
    };

    explicit ExecutionEngine(const Config& config = {});
    ~ExecutionEngine();

    ExecutionEngine(const ExecutionEngine&) = delete;
    ExecutionEngine& operator=(const ExecutionEngine&) = delete;
    ExecutionEngine(ExecutionEngine&&) = default;
    ExecutionEngine& operator=(ExecutionEngine&&) = default;

    // Submit execution for processing
    Result<std::string> submit(const ExecutionContext& context);

    // Query execution status
    Result<std::string> get_status(const std::string& execution_id) const;

    // Cancel execution
    Result<void> cancel(const std::string& execution_id);

    // Get execution result
    Result<ExecutionResult> get_result(const std::string& execution_id) const;

    // List active executions
    Result<std::vector<std::string>> list_active() const;

    // Get execution history
    Result<std::vector<std::string>> get_history(const std::string& contract_id) const;

private:
    class Impl;
    std::unique_ptr<class Impl> impl_;
};

// Trace context for distributed tracing
struct TraceContext {
    std::string trace_id;
    std::string span_id;
    std::string parent_span_id;
    std::string trace_flags;
};

} // namespace smo