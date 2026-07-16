#include "scheduler.hpp"

#include <queue>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <random>
#include <algorithm>
#include <iostream>

namespace smo::runtime {

// ===========================================================================
// RetryEngine
// ===========================================================================

RetryEngine::RetryEngine(const RetryPolicy& policy) : policy_(policy) {}

RetryEngine::~RetryEngine() = default;

bool RetryEngine::is_retryable(const std::string& error_code, const std::string& error_msg) const {
    // Check explicit retryable errors
    if (std::find(policy_.retryable_errors.begin(), policy_.retryable_errors.end(), error_code) 
        != policy_.retryable_errors.end()) {
        return true;
    }

    // Custom retryable check
    if (policy_.is_retryable) {
        return policy_.is_retryable(error_msg);
    }

    // Default: retry on network errors, timeouts, temporary failures
    static const std::vector<std::string> default_retryable = {
        "timeout", "connection refused", "connection reset", "temporary failure",
        "network unreachable", "host unreachable", "service unavailable",
        "503", "504", "502", "429", "ETIMEDOUT", "ECONNREFUSED", "ECONNRESET"
    };

    std::string lower_msg = error_msg;
    std::transform(lower_msg.begin(), lower_msg.end(), lower_msg.begin(), ::tolower);

    for (const auto& pattern : default_retryable) {
        if (lower_msg.find(pattern) != std::string::npos) {
            return true;
        }
    }

    return false;
}

int64_t RetryEngine::next_delay(int attempt, const std::string& error_code) const {
    double base = static_cast<double>(policy_.base_delay_ns);
    double delay = base * std::pow(policy_.backoff_multiplier, attempt);

    // Apply jitter
    double jitter = 1.0 + (static_cast<double>(rand()) / RAND_MAX - 0.5) * 2.0 * policy_.jitter_factor;
    delay *= jitter;

    // Cap at max delay
    if (delay > policy_.max_delay_ns) {
        delay = policy_.max_delay_ns;
    }

    return static_cast<int64_t>(delay);
}

} // namespace smo::runtime