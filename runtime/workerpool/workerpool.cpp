#include "runtime/workerpool/workerpool.hpp"

namespace smo {

    WorkerPool::WorkerPool(uint32_t num_workers) : num_workers_(std::max(1u, num_workers)), running_(true)
    {
        for (uint32_t i = 0; i < num_workers_; ++i)
        {
            workers_.emplace_back([this]() {
                while (running_.load())
                {
                    QueuedTask queued_task;
                    {
                        std::unique_lock<std::mutex> lock(queue_mutex_);
                        cv_.wait(lock, [this]() { return !running_.load() || !task_queue_.empty(); });
                        if (!running_.load() && task_queue_.empty())
                            break;
                        if (task_queue_.empty())
                            continue;
                        queued_task = std::move(task_queue_.front());
                        task_queue_.pop();
                        active_tasks_++;
                    }
                    // Execute the task
                    auto result = queued_task.task();
                    (void)result; // Result is captured but not propagated in this simple implementation
                    active_tasks_--;
                }
            });
        }
    }

    WorkerPool::~WorkerPool()
    {
        running_.store(false);
        cv_.notify_all();
        for (auto& w : workers_)
        {
            if (w.joinable())
                w.join();
        }
    }

    Result<void> WorkerPool::submit(const std::string& task_id, Task task)
    {
        if (!running_.load())
        {
            return SMO_ERR_RUNTIME(1, Error, NoRetry, None, "WorkerPool is not running");
        }

        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            task_queue_.push({task_id, std::move(task)});
        }
        cv_.notify_one();
        return {};
    }

    void WorkerPool::wait_all()
    {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        cv_.wait(lock, [this]() { return task_queue_.empty() && active_tasks_.load() == 0; });
    }

    size_t WorkerPool::queue_size() const
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        return task_queue_.size();
    }

} // namespace smo
