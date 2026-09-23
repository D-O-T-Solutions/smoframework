#include "scheduler.hpp"

#include <chrono>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>
#include <string>
#include <atomic>
#include <memory>
#include <random>
#include <algorithm>
#include <queue>
#include <condition_variable>

namespace smo::runtime {

// ===========================================================================
// RetryEngine Implementation
// ===========================================================================

RetryEngine::RetryEngine(const RetryPolicy& policy) : policy_(policy)
{
    // Default retryable errors if not specified
    if (policy_.retryable_errors.empty())
    {
        policy_.retryable_errors = {1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010};
    }
}

bool RetryEngine::is_retryable(uint16_t error_code, const std::string& error_msg) const
{
    if (policy_.is_retryable)
    {
        return policy_.is_retryable(error_code, error_msg);
    }

    // Check if error code is in retryable list
    return std::find(policy_.retryable_errors.begin(), policy_.retryable_errors.end(), static_cast<int>(error_code)) != policy_.retryable_errors.end();
}

int64_t RetryEngine::next_delay(int attempt, uint16_t error_code) const
{
    // Exponential backoff with jitter
    double delay = policy_.base_delay_ns * std::pow(policy_.backoff_multiplier, attempt);
    delay = std::min(delay, static_cast<double>(policy_.max_delay_ns));

    // Add jitter
    static std::random_device rd;
    static std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(-policy_.jitter_factor, policy_.jitter_factor);
    double jitter = 1.0 + dis(gen);
    delay *= jitter;

    return static_cast<int64_t>(delay);
}

// ===========================================================================
// Scheduler Implementation
// ===========================================================================

struct Scheduler::Impl
{
    Config config;
    mutable std::mutex mutex_;

    // Task queue ordered by priority (highest first) then by deadline
    struct QueuedTask
    {
        Task task;
        int64_t queued_time_ns;
        int priority;

        bool operator<(const QueuedTask& other) const
        {
            if (priority != other.priority)
                return priority < other.priority; // Max heap: higher priority first
            return queued_time_ns > other.queued_time_ns; // Earlier deadline first
        }
    };

    std::priority_queue<QueuedTask> pending_queue_;
    std::unordered_map<std::string, ScheduledTask> tasks_;
    std::unordered_map<std::string, NodeCapacity> nodes_;
    std::atomic<uint64_t> task_counter_{0};
    std::atomic<uint64_t> total_queue_time_ns_{0};
    std::atomic<uint64_t> total_execution_time_ns_{0};
    std::atomic<uint64_t> completed_count_{0};
    std::atomic<bool> running_{true};
    std::thread scheduler_thread_;
    std::condition_variable cv_;

    Impl(const Config& cfg) : config(cfg)
    {
        start_scheduler_thread();
    }

    ~Impl()
    {
        running_ = false;
        cv_.notify_all();
        if (scheduler_thread_.joinable())
        {
            scheduler_thread_.join();
        }
    }

    void start_scheduler_thread()
    {
        scheduler_thread_ = std::thread([this]() {
            while (running_)
            {
                std::unique_lock<std::mutex> lock(mutex_);
                cv_.wait_for(lock, std::chrono::nanoseconds(config.scheduling_interval_ns), [this]() {
                    return !running_ || !pending_queue_.empty();
                });

                if (!running_)
                    break;

                schedule_pending_tasks();
            }
        });
    }

    void schedule_pending_tasks()
    {
        // Simple scheduling: assign to first available healthy node with capacity
        while (!pending_queue_.empty())
        {
            auto best_node = find_best_node(pending_queue_.top().task);
            if (!best_node)
            {
                break; // No suitable node available
            }

            auto queued_task = pending_queue_.top();
            pending_queue_.pop();

            ScheduledTask scheduled;
            scheduled.task = queued_task.task;
            scheduled.assigned_node = best_node->node_id;
            scheduled.scheduled_time_ns = now_ns();
            scheduled.started_ns = 0;
            scheduled.completed_ns = 0;
            scheduled.retry_count = 0;
            scheduled.status = "pending";

            tasks_[scheduled.task.task_id] = std::move(scheduled);
            best_node->available_cpu_millis -= 1000; // Reserve 1 CPU unit

            // Update stats
            total_queue_time_ns_ += (now_ns() - queued_task.queued_time_ns);
        }
    }

    NodeCapacity* find_best_node(const Task& task)
    {
        NodeCapacity* best = nullptr;
        int64_t best_score = -1;

        for (auto& [id, node] : nodes_)
        {
            if (!node.healthy)
                continue;

            // Simple scoring: prefer nodes with more available resources
            int64_t score = node.available_cpu_millis + node.available_memory_bytes / (1024 * 1024);
            if (score > best_score)
            {
                best_score = score;
                best = &node;
            }
        }
        return best;
    }

    int64_t now_ns()
    {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();
    }

    std::string generate_task_id()
    {
        static std::random_device rd;
        static std::mt19937_64 gen(rd());
        static std::uniform_int_distribution<uint64_t> dis;
        return "task_" + std::to_string(dis(gen));
    }
};

Scheduler::Scheduler() : impl_(std::make_unique<Impl>(Config{})) {}
Scheduler::Scheduler(const Config& config) : impl_(std::make_unique<Impl>(config)) {}
Scheduler::~Scheduler() = default;

Scheduler::Scheduler(Scheduler&& other) noexcept : impl_(std::move(other.impl_)) {}
Scheduler& Scheduler::operator=(Scheduler&& other) noexcept
{
    impl_ = std::move(other.impl_);
    return *this;
}

Result<std::string> Scheduler::submit(const Task& task)
{
    std::lock_guard<std::mutex> lock(impl_->mutex_);

    size_t total_tasks = impl_->tasks_.size() + impl_->pending_queue_.size();
    if (total_tasks >= impl_->config.max_concurrent_tasks)
    {
        return SMO_ERR_RUNTIME(1, Error, RetrySafe, None, "Max concurrent tasks reached");
    }

    std::string task_id = task.task_id.empty() ? impl_->generate_task_id() : task.task_id;

    if (impl_->tasks_.find(task_id) != impl_->tasks_.end())
    {
        return SMO_ERR_RUNTIME(2, Error, NoRetry, None, "Task ID already exists: " + task_id);
    }

    // Check pending queue as well
    // We can't easily search priority_queue, so just create the task immediately
    ScheduledTask scheduled;
    scheduled.task = task;
    scheduled.task.task_id = task_id;
    scheduled.assigned_node = "";
    scheduled.scheduled_time_ns = impl_->now_ns();
    scheduled.started_ns = 0;
    scheduled.completed_ns = 0;
    scheduled.retry_count = 0;
    scheduled.status = "pending";

    impl_->tasks_[task_id] = std::move(scheduled);
    impl_->cv_.notify_one();

    // Immediately try to schedule
    impl_->schedule_pending_tasks();

    return task_id;
}

Result<void> Scheduler::cancel(const std::string& task_id)
{
    std::lock_guard<std::mutex> lock(impl_->mutex_);

    auto it = impl_->tasks_.find(task_id);
    if (it != impl_->tasks_.end())
    {
        if (it->second.status == "completed" || it->second.status == "failed" || it->second.status == "cancelled")
        {
            return SMO_ERR_RUNTIME(4, Error, NoRetry, None, "Task already in terminal state: " + it->second.status);
        }

        it->second.status = "cancelled";
        it->second.completed_ns = impl_->now_ns();

        // Release node resources
        if (!it->second.assigned_node.empty())
        {
            auto node_it = impl_->nodes_.find(it->second.assigned_node);
            if (node_it != impl_->nodes_.end())
            {
                node_it->second.available_cpu_millis += 1000;
            }
        }

        return {};
    }

    // Check if in pending queue (we can't easily remove from priority_queue, so just mark as cancelled)
    // In a real implementation, we'd need a more sophisticated data structure
    return SMO_ERR_RUNTIME(3, Info, RetrySafe, None, "Task not found: " + task_id);
}

Result<std::string> Scheduler::status(const std::string& task_id) const
{
    std::lock_guard<std::mutex> lock(impl_->mutex_);

    auto it = impl_->tasks_.find(task_id);
    if (it != impl_->tasks_.end())
    {
        return it->second.status;
    }

    // Check pending queue (need to copy since we can't iterate priority_queue easily)
    // For now, return "pending" if task was submitted but not yet scheduled
    return std::string{"pending"};
}

Result<std::string> Scheduler::result(const std::string& task_id) const
{
    std::lock_guard<std::mutex> lock(impl_->mutex_);

    auto it = impl_->tasks_.find(task_id);
    if (it != impl_->tasks_.end())
    {
        // Return a simple result string (in real implementation, this would be the actual task result)
        return "result_for_" + task_id;
    }

    return SMO_ERR_RUNTIME(3, Info, RetrySafe, None, "Task not found: " + task_id);
}

Result<void> Scheduler::register_node(const NodeCapacity& capacity)
{
    std::lock_guard<std::mutex> lock(impl_->mutex_);

    if (impl_->nodes_.find(capacity.node_id) != impl_->nodes_.end())
    {
        return SMO_ERR_RUNTIME(5, Error, NoRetry, None, "Node already registered: " + capacity.node_id);
    }

    impl_->nodes_[capacity.node_id] = capacity;
    return {};
}

Result<void> Scheduler::unregister_node(const std::string& node_id)
{
    std::lock_guard<std::mutex> lock(impl_->mutex_);

    auto it = impl_->nodes_.find(node_id);
    if (it == impl_->nodes_.end())
    {
        return SMO_ERR_RUNTIME(3, Info, RetrySafe, None, "Node not found: " + node_id);
    }

    impl_->nodes_.erase(it);
    return {};
}

Result<NodeCapacity> Scheduler::get_node_status(const std::string& node_id) const
{
    std::lock_guard<std::mutex> lock(impl_->mutex_);

    auto it = impl_->nodes_.find(node_id);
    if (it == impl_->nodes_.end())
    {
        return SMO_ERR_RUNTIME(3, Info, RetrySafe, None, "Node not found: " + node_id);
    }

    return it->second;
}

Result<std::vector<NodeCapacity>> Scheduler::list_nodes() const
{
    std::lock_guard<std::mutex> lock(impl_->mutex_);

    std::vector<NodeCapacity> nodes;
    nodes.reserve(impl_->nodes_.size());
    for (const auto& [id, node] : impl_->nodes_)
    {
        nodes.push_back(node);
    }

    return nodes;
}

Result<void> Scheduler::update_node_health(const std::string& node_id, bool healthy)
{
    std::lock_guard<std::mutex> lock(impl_->mutex_);

    auto it = impl_->nodes_.find(node_id);
    if (it == impl_->nodes_.end())
    {
        return SMO_ERR_RUNTIME(3, Info, RetrySafe, None, "Node not found: " + node_id);
    }

    it->second.healthy = healthy;
    it->second.last_update_ns = impl_->now_ns();

    return {};
}

Result<Scheduler::Stats> Scheduler::get_stats() const
{
    std::lock_guard<std::mutex> lock(impl_->mutex_);

    Stats stats;
    stats.pending_tasks = impl_->pending_queue_.size();
    stats.running_tasks = 0;
    stats.completed_tasks = 0;
    stats.failed_tasks = 0;
    stats.registered_nodes = impl_->nodes_.size();
    stats.healthy_nodes = 0;

    for (const auto& [id, task] : impl_->tasks_)
    {
        if (task.status == "running")
            stats.running_tasks++;
        else if (task.status == "completed")
            stats.completed_tasks++;
        else if (task.status == "failed")
            stats.failed_tasks++;
    }

    for (const auto& [id, node] : impl_->nodes_)
    {
        if (node.healthy)
            stats.healthy_nodes++;
    }

    if (impl_->completed_count_ > 0)
    {
        stats.avg_queue_time_ns = impl_->total_queue_time_ns_ / impl_->completed_count_;
        stats.avg_execution_time_ns = impl_->total_execution_time_ns_ / impl_->completed_count_;
    }

    return stats;
}

} // namespace smo::runtime