#include "execution_engine.hpp"

#include <chrono>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>
#include <string>
#include <atomic>
#include <memory>
#include <random>

namespace smo {

struct ExecutionEngine::Impl
{
    Config config;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, ExecutionResult> executions_;
    std::atomic<bool> running_{true};

    Impl(const Config& cfg) : config(cfg) {}
    ~Impl() { running_ = false; }

    std::string generate_execution_id()
    {
        static std::random_device rd;
        static std::mt19937_64 gen(rd());
        static std::uniform_int_distribution<uint64_t> dis;
        return "exec_" + std::to_string(dis(gen));
    }

    int64_t now_ns()
    {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();
    }
};

ExecutionEngine::ExecutionEngine() : impl_(std::make_unique<Impl>(Config{})) {}
ExecutionEngine::ExecutionEngine(const Config& config) : impl_(std::make_unique<Impl>(config)) {}
ExecutionEngine::~ExecutionEngine() = default;

Result<std::string> ExecutionEngine::submit(const ExecutionContext& context)
{
    std::lock_guard<std::mutex> lock(impl_->mutex_);

    if (impl_->executions_.size() >= impl_->config.max_concurrent_executions)
    {
        return SMO_ERR_RUNTIME(1002, Error, RetrySafe, None, "Max concurrent executions reached");
    }

    std::string execution_id = context.execution_id.empty() ? impl_->generate_execution_id() : context.execution_id;

    if (impl_->executions_.find(execution_id) != impl_->executions_.end())
    {
        return SMO_ERR_RUNTIME(1003, Error, NoRetry, None, "Execution ID already exists: " + execution_id);
    }

    ExecutionResult result;
    result.execution_id = execution_id;
    result.contract_id = context.contract_id.to_hex();
    result.trace_id = context.trace_id;
    result.status = "created";
    result.result_hash = "";
    result.error_message = "";
    result.created_ns = impl_->now_ns();
    result.started_ns = 0;
    result.completed_ns = 0;
    result.retry_count = 0;

    impl_->executions_[execution_id] = std::move(result);
    return execution_id;
}

Result<std::string> ExecutionEngine::get_status(const std::string& execution_id) const
{
    std::lock_guard<std::mutex> lock(impl_->mutex_);

    auto it = impl_->executions_.find(execution_id);
    if (it == impl_->executions_.end())
    {
        return SMO_ERR_RUNTIME(1004, Info, RetrySafe, None, "Execution not found: " + execution_id);
    }

    return it->second.status;
}

Result<void> ExecutionEngine::cancel(const std::string& execution_id)
{
    std::lock_guard<std::mutex> lock(impl_->mutex_);

    auto it = impl_->executions_.find(execution_id);
    if (it == impl_->executions_.end())
    {
        return SMO_ERR_RUNTIME(1004, Info, RetrySafe, None, "Execution not found: " + execution_id);
    }

    if (it->second.status == "completed" || it->second.status == "failed" || it->second.status == "cancelled")
    {
        return SMO_ERR_RUNTIME(1005, Error, NoRetry, None, "Execution already in terminal state: " + it->second.status);
    }

    it->second.status = "cancelled";
    it->second.completed_ns = impl_->now_ns();
    it->second.error_message = "Cancelled by user";

    return {};
}

Result<ExecutionResult> ExecutionEngine::get_result(const std::string& execution_id) const
{
    std::lock_guard<std::mutex> lock(impl_->mutex_);

    auto it = impl_->executions_.find(execution_id);
    if (it == impl_->executions_.end())
    {
        return SMO_ERR_RUNTIME(1004, Info, RetrySafe, None, "Execution not found: " + execution_id);
    }

    return it->second;
}

Result<std::vector<std::string>> ExecutionEngine::list_active() const
{
    std::lock_guard<std::mutex> lock(impl_->mutex_);

    std::vector<std::string> active;
    for (const auto& [id, result] : impl_->executions_)
    {
        if (result.status == "created" || result.status == "running")
        {
            active.push_back(id);
        }
    }

    return active;
}

Result<std::vector<std::string>> ExecutionEngine::get_history(const std::string& contract_id) const
{
    std::lock_guard<std::mutex> lock(impl_->mutex_);

    std::vector<std::string> history;
    for (const auto& [id, result] : impl_->executions_)
    {
        if (result.contract_id == contract_id)
        {
            history.push_back(id);
        }
    }

    return history;
}

} // namespace smo