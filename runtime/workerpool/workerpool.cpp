#include "runtime/workerpool/workerpool.hpp"
#include <algorithm>

namespace smo {

WorkerPool::WorkerPool(uint32_t num_workers)
    : num_workers_(std::max(1u, num_workers))
    , running_(true)
{
    for (uint32_t i = 0; i < num_workers_; ++i) {
        workers_.emplace_back([this]() {
            while (running_.load()) {
                std::this_thread::yield();
            }
        });
    }
}

WorkerPool::~WorkerPool() {
    running_.store(false);
    for (auto& w : workers_) {
        if (w.joinable()) w.join();
    }
}

Result<void> WorkerPool::submit(const std::string& task_id, Task task) {
    (void)task_id;
    (void)task;
    return {};
}

void WorkerPool::wait_all() {}

} // namespace smo
