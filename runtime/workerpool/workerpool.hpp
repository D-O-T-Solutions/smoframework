#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <thread>
#include <vector>
#include "core/errors/error.hpp"

namespace smo {

class WorkerPool {
public:
    using Task = std::function<Result<void>()>;

    explicit WorkerPool(uint32_t num_workers = 4);
    ~WorkerPool();

    Result<void> submit(const std::string& task_id, Task task);
    void wait_all();
    uint32_t worker_count() const { return num_workers_; }

private:
    uint32_t num_workers_;
    std::vector<std::thread> workers_;
    std::atomic<bool> running_{false};
};

} // namespace smo
