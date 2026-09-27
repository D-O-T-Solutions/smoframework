#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>
#include "core/errors/error.hpp"

namespace smo {

    class WorkerPool
    {
    public:
        using Task = std::function<Result<void>()>;

        explicit WorkerPool(uint32_t num_workers = 4);
        ~WorkerPool();

        Result<void> submit(const std::string& task_id, Task task);
        void wait_all();
        uint32_t worker_count() const { return num_workers_; }
        size_t queue_size() const;

    private:
        struct QueuedTask
        {
            std::string task_id;
            Task task;
        };

        uint32_t num_workers_;
        std::vector<std::thread> workers_;
        std::queue<QueuedTask> task_queue_;
        mutable std::mutex queue_mutex_;
        std::condition_variable cv_;
        std::atomic<bool> running_{false};
        std::atomic<size_t> active_tasks_{0};
    };

} // namespace smo
