// SPDX-License-Identifier: Apache-2.0
//
// Scheduler and RetryEngine — unit tests

#include <runtime/scheduler.hpp>
#include <cstdio>
#include <cstring>
#include <vector>
#include <string>
#include <thread>
#include <chrono>

using namespace smo;
using namespace smo::runtime;

// ---------------------------------------------------------------------------
// Minimal test runner
// ---------------------------------------------------------------------------
static int failures = 0;

#define TEST(name)                                                                                                     \
    do                                                                                                                 \
    {                                                                                                                  \
        printf("  TEST %-50s ... ", name);                                                                             \
        fflush(stdout);

#define END_TEST(result)                                                                                               \
    if (result)                                                                                                        \
    {                                                                                                                  \
        printf("PASS\n");                                                                                              \
    }                                                                                                                  \
    else                                                                                                               \
    {                                                                                                                  \
        printf("FAIL\n");                                                                                              \
        ++failures;                                                                                                    \
    }                                                                                                                  \
    }                                                                                                                  \
    while (false)

#define ASSERT(cond)                                                                                                   \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(cond))                                                                                                   \
        {                                                                                                              \
            printf("\n    ASSERTION FAILED at %s:%d: %s\n", __FILE__, __LINE__, #cond);                                \
            return false;                                                                                              \
        }                                                                                                              \
    } while (false)

#define ASSERT_EQ(a, b)                                                                                                \
    do                                                                                                                 \
    {                                                                                                                  \
        if ((a) != (b))                                                                                                \
        {                                                                                                              \
            printf("\n    ASSERTION FAILED at %s:%d: %s != %s\n", __FILE__, __LINE__, #a, #b);                        \
            return false;                                                                                              \
        }                                                                                                              \
    } while (false)

#define ASSERT_STREQ(a, b)                                                                                             \
    do                                                                                                                 \
    {                                                                                                                  \
        if (std::strcmp((a), (b)) != 0)                                                                                \
        {                                                                                                              \
            printf("\n    ASSERTION FAILED at %s:%d: %s == %s\n"                                                       \
                   "      LHS=%s  RHS=%s\n",                                                                           \
                   __FILE__, __LINE__, #a, #b, (a), (b));                                                              \
            return false;                                                                                              \
        }                                                                                                              \
    } while (false)

#define ASSERT_VECTOR_EQ(a, b)                                                                                         \
    do                                                                                                                 \
    {                                                                                                                  \
        if ((a).size() != (b).size())                                                                                  \
        {                                                                                                              \
            printf("\n    VECTOR SIZE MISMATCH at %s:%d: %s.size()=%zu vs %s.size()=%zu\n",                           \
                   __FILE__, __LINE__, #a, (a).size(), #b, (b).size());                                                \
            return false;                                                                                              \
        }                                                                                                              \
        for (size_t i = 0; i < (a).size(); ++i)                                                                       \
        {                                                                                                              \
            if ((a)[i] != (b)[i])                                                                                      \
            {                                                                                                          \
                printf("\n    VECTOR ELEMENT MISMATCH at %s:%d: %s[%zu]=%s vs %s[%zu]=%s\n",                          \
                       __FILE__, __LINE__, #a, i, (a)[i].c_str(), #b, i, (b)[i].c_str());                             \
                return false;                                                                                          \
            }                                                                                                          \
        }                                                                                                              \
    } while (false)

#define ASSERT_GE(a, b)                                                                                                \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!((a) >= (b)))                                                                                             \
        {                                                                                                              \
            printf("\n    ASSERTION FAILED at %s:%d: %s >= %s\n", __FILE__, __LINE__, #a, #b);                        \
            return false;                                                                                              \
        }                                                                                                              \
    } while (false)

// ==========================================================================
// Tests - RetryEngine
// ==========================================================================

static bool test_retry_engine_basic()
{
    RetryEngine engine;

    // Test is_retryable with default policy
    ASSERT(engine.is_retryable(1001, "timeout error"));
    ASSERT(engine.is_retryable(1002, "connection failed"));
    ASSERT(!engine.is_retryable(9999, "permanent error"));

    // Test next_delay
    int64_t delay1 = engine.next_delay(0, 1001);
    int64_t delay2 = engine.next_delay(1, 1001);
    int64_t delay3 = engine.next_delay(2, 1001);

    ASSERT(delay1 > 0);
    ASSERT(delay2 > delay1); // Exponential backoff
    ASSERT(delay3 > delay2);

    return true;
}

static bool test_retry_engine_custom_policy()
{
    RetryPolicy policy;
    policy.max_attempts = 5;
    policy.base_delay_ns = 100'000'000; // 100ms
    policy.max_delay_ns = 1'000'000'000; // 1s
    policy.backoff_multiplier = 2.0;
    policy.jitter_factor = 0.0; // No jitter for deterministic test

    RetryEngine engine(policy);

    int64_t delay1 = engine.next_delay(0, 1001);
    int64_t delay2 = engine.next_delay(1, 1001);
    int64_t delay3 = engine.next_delay(2, 1001);

    // With no jitter: 100ms, 200ms, 400ms
    ASSERT_EQ(delay1, 100'000'000);
    ASSERT_EQ(delay2, 200'000'000);
    ASSERT_EQ(delay3, 400'000'000);

    // Test max delay cap
    int64_t delay10 = engine.next_delay(10, 1001);
    ASSERT_EQ(delay10, 1'000'000'000); // Capped at max_delay_ns

    return true;
}

static bool test_retry_engine_custom_retryable()
{
    RetryPolicy policy;
    policy.is_retryable = [](uint16_t error_code, const std::string& error) {
        return error.find("retryable") != std::string::npos;
    };

    RetryEngine engine(policy);

    ASSERT(engine.is_retryable(9999, "this is retryable"));
    ASSERT(!engine.is_retryable(9999, "this is not"));
    return true;
}

static bool test_retry_engine_execute_with_retry_success()
{
    RetryPolicy policy;
    policy.max_attempts = 3;
    policy.base_delay_ns = 1'000'000; // 1ms for fast test
    policy.jitter_factor = 0.0;

    RetryEngine engine(policy);

    int attempt_count = 0;
    auto result = engine.execute_with_retry([&]() -> Result<std::string> {
        ++attempt_count;
        if (attempt_count >= 2)
            return std::string("success");
        return SMO_ERR_RUNTIME(1001, Error, RetrySafe, RetryOperation, "temporary error");
    }, "test_context");

    ASSERT(result);
    ASSERT_STREQ(result.value().c_str(), "success");
    ASSERT_EQ(attempt_count, 2);
    return true;
}

static bool test_retry_engine_execute_with_retry_max_exceeded()
{
    RetryPolicy policy;
    policy.max_attempts = 3;
    policy.base_delay_ns = 1'000'000; // 1ms for fast test
    policy.jitter_factor = 0.0;

    RetryEngine engine(policy);

    int attempt_count = 0;
    auto result = engine.execute_with_retry([&]() -> Result<std::string> {
        ++attempt_count;
        return SMO_ERR_RUNTIME(1001, Error, RetrySafe, RetryOperation, "always fails");
    }, "test_context");

    ASSERT(!result);
    ASSERT_EQ(attempt_count, 3);
    ASSERT_STREQ(std::to_string(result.error().code.code).c_str(), "1000");
    return true;
}

static bool test_retry_engine_execute_with_retry_non_retryable()
{
    RetryPolicy policy;
    policy.max_attempts = 3;
    policy.base_delay_ns = 1'000'000;
    policy.jitter_factor = 0.0;

    RetryEngine engine(policy);

    int attempt_count = 0;
    auto result = engine.execute_with_retry([&]() -> Result<std::string> {
        ++attempt_count;
        return SMO_ERR_RUNTIME(9999, Error, NoRetry, None, "permanent error");
    }, "test_context");

    ASSERT(!result);
    ASSERT_EQ(attempt_count, 1); // Should not retry non-retryable errors
    return true;
}

// ==========================================================================
// Tests - Scheduler
// ==========================================================================

static bool test_scheduler_submit_basic()
{
    Scheduler scheduler;

    Task task;
    task.contract_id = "contract1";
    task.execution_id = "exec1";
    task.trace_id = "trace1";
    task.target_nodes = {"node1", "node2"};
    task.priority = 50;
    task.max_retries = 3;

    auto result = scheduler.submit(task);
    ASSERT(result);
    ASSERT_STREQ(result.value().substr(0, 5).c_str(), "task_");
    return true;
}

static bool test_scheduler_submit_with_custom_id()
{
    Scheduler scheduler;

    Task task;
    task.contract_id = "contract1";
    task.execution_id = "exec1";
    task.trace_id = "trace1";
    task.task_id = "custom_task_123";

    auto result = scheduler.submit(task);
    ASSERT(result);
    ASSERT_STREQ(result.value().c_str(), "custom_task_123");
    return true;
}

static bool test_scheduler_cancel()
{
    Scheduler scheduler;

    Task task;
    task.contract_id = "contract1";
    task.execution_id = "exec1";
    task.trace_id = "trace1";
    task.task_id = "task_to_cancel";

    scheduler.submit(task);

    auto cancel_result = scheduler.cancel("task_to_cancel");
    ASSERT(cancel_result);

    auto status = scheduler.status("task_to_cancel");
    ASSERT(status);
    ASSERT_STREQ(status.value().c_str(), "cancelled");
    return true;
}

static bool test_scheduler_cancel_not_found()
{
    Scheduler scheduler;

    auto cancel_result = scheduler.cancel("nonexistent");
    ASSERT(!cancel_result);
    ASSERT_EQ(cancel_result.error().code.code, 3);
    return true;
}

static bool test_scheduler_status()
{
    Scheduler scheduler;

    Task task;
    task.contract_id = "contract1";
    task.execution_id = "exec1";
    task.trace_id = "trace1";
    task.task_id = "task_status_test";

    scheduler.submit(task);

    auto status = scheduler.status("task_status_test");
    ASSERT(status);
    // Status could be "pending" or "running" depending on scheduling
    ASSERT(status.value() == "pending" || status.value() == "running");
    return true;
}

static bool test_scheduler_result()
{
    Scheduler scheduler;

    Task task;
    task.contract_id = "contract1";
    task.execution_id = "exec1";
    task.trace_id = "trace1";
    task.task_id = "task_result_test";

    scheduler.submit(task);

    auto result = scheduler.result("task_result_test");
    ASSERT(result);
    ASSERT_STREQ(result.value().substr(0, 13).c_str(), "result_for_ta");
    return true;
}

static bool test_scheduler_register_node()
{
    Scheduler scheduler;

    NodeCapacity node;
    node.node_id = "node1";
    node.total_cpu_millis = 4000;
    node.available_cpu_millis = 4000;
    node.total_memory_bytes = 8LL * 1024 * 1024 * 1024;
    node.available_memory_bytes = 8LL * 1024 * 1024 * 1024;
    node.healthy = true;

    auto result = scheduler.register_node(node);
    ASSERT(result);

    auto status = scheduler.get_node_status("node1");
    ASSERT(status);
    ASSERT_STREQ(status.value().node_id.c_str(), "node1");
    ASSERT_EQ(status.value().available_cpu_millis, 4000);
    return true;
}

static bool test_scheduler_unregister_node()
{
    Scheduler scheduler;

    NodeCapacity node;
    node.node_id = "node1";
    node.total_cpu_millis = 4000;
    node.available_cpu_millis = 4000;
    node.healthy = true;

    scheduler.register_node(node);

    auto result = scheduler.unregister_node("node1");
    ASSERT(result);

    auto status = scheduler.get_node_status("node1");
    ASSERT(!status);
    ASSERT_EQ(status.error().code.code, 3);
    return true;
}

static bool test_scheduler_list_nodes()
{
    Scheduler scheduler;

    NodeCapacity node1;
    node1.node_id = "node1";
    node1.total_cpu_millis = 4000;
    node1.available_cpu_millis = 4000;
    node1.healthy = true;

    NodeCapacity node2;
    node2.node_id = "node2";
    node2.total_cpu_millis = 8000;
    node2.available_cpu_millis = 8000;
    node2.healthy = true;

    scheduler.register_node(node1);
    scheduler.register_node(node2);

    auto nodes = scheduler.list_nodes();
    ASSERT(nodes);
    ASSERT_EQ(nodes.value().size(), 2);
    return true;
}

static bool test_scheduler_update_node_health()
{
    Scheduler scheduler;

    NodeCapacity node;
    node.node_id = "node1";
    node.total_cpu_millis = 4000;
    node.available_cpu_millis = 4000;
    node.healthy = true;

    scheduler.register_node(node);

    auto result1 = scheduler.update_node_health("node1", false);
    ASSERT(result1);

    auto status1 = scheduler.get_node_status("node1");
    ASSERT(status1);
    ASSERT(!status1.value().healthy);

    auto result2 = scheduler.update_node_health("node1", true);
    ASSERT(result2);

    auto status2 = scheduler.get_node_status("node1");
    ASSERT(status2);
    ASSERT(status2.value().healthy);
    return true;
}

static bool test_scheduler_get_stats()
{
    Scheduler scheduler;

    NodeCapacity node;
    node.node_id = "node1";
    node.total_cpu_millis = 4000;
    node.available_cpu_millis = 4000;
    node.healthy = true;

    scheduler.register_node(node);

    Task task;
    task.contract_id = "contract1";
    task.execution_id = "exec1";
    task.trace_id = "trace1";
    task.task_id = "task_stats_test";

    scheduler.submit(task);

    // Give scheduler thread time to process
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    auto stats = scheduler.get_stats();
    ASSERT(stats);
    ASSERT_EQ(stats.value().registered_nodes, 1);
    ASSERT_EQ(stats.value().healthy_nodes, 1);
    // pending_tasks is size_t (unsigned), so just verify it's accessible
    (void)stats.value().pending_tasks;
    return true;
}

static bool test_scheduler_priority()
{
    Scheduler scheduler;

    NodeCapacity node;
    node.node_id = "node1";
    node.total_cpu_millis = 4000;
    node.available_cpu_millis = 4000;
    node.healthy = true;

    scheduler.register_node(node);

    // Submit low priority task first
    Task low_task;
    low_task.contract_id = "contract1";
    low_task.execution_id = "exec1";
    low_task.trace_id = "trace1";
    low_task.task_id = "low_priority";
    low_task.priority = 10;

    // Submit high priority task second
    Task high_task;
    high_task.contract_id = "contract1";
    high_task.execution_id = "exec2";
    high_task.trace_id = "trace2";
    high_task.task_id = "high_priority";
    high_task.priority = 200;

    scheduler.submit(low_task);
    scheduler.submit(high_task);

    // Give scheduler thread time to process
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Both should be scheduled (or at least not fail)
    auto low_status = scheduler.status("low_priority");
    auto high_status = scheduler.status("high_priority");

    ASSERT(low_status);
    ASSERT(high_status);
    return true;
}

static bool test_scheduler_max_concurrent()
{
    Scheduler::Config config;
    config.max_concurrent_tasks = 2;
    Scheduler scheduler(config);

    Task task1;
    task1.contract_id = "contract1";
    task1.execution_id = "exec1";
    task1.trace_id = "trace1";
    task1.task_id = "task_1";

    Task task2;
    task2.contract_id = "contract1";
    task2.execution_id = "exec2";
    task2.trace_id = "trace2";
    task2.task_id = "task_2";

    Task task3;
    task3.contract_id = "contract1";
    task3.execution_id = "exec3";
    task3.trace_id = "trace3";
    task3.task_id = "task_3";

    ASSERT(scheduler.submit(task1));
    ASSERT(scheduler.submit(task2));
    auto result3 = scheduler.submit(task3);
    ASSERT(!result3);
    ASSERT_EQ(result3.error().code.code, 1);
    return true;
}

// ==========================================================================
// Main
// ==========================================================================

int main(int, char*[])
{
    printf("SMO Scheduler & RetryEngine — Unit Tests\n");
    printf("==========================================\n\n");

    // RetryEngine tests
    TEST("RetryEngineBasic") END_TEST(test_retry_engine_basic());
    TEST("RetryEngineCustomPolicy") END_TEST(test_retry_engine_custom_policy());
    TEST("RetryEngineCustomRetryable") END_TEST(test_retry_engine_custom_retryable());
    TEST("RetryEngineExecuteWithRetrySuccess") END_TEST(test_retry_engine_execute_with_retry_success());
    TEST("RetryEngineExecuteWithRetryMaxExceeded") END_TEST(test_retry_engine_execute_with_retry_max_exceeded());
    TEST("RetryEngineExecuteWithRetryNonRetryable") END_TEST(test_retry_engine_execute_with_retry_non_retryable());

    // Scheduler tests
    TEST("SchedulerSubmitBasic") END_TEST(test_scheduler_submit_basic());
    TEST("SchedulerSubmitWithCustomId") END_TEST(test_scheduler_submit_with_custom_id());
    TEST("SchedulerCancel") END_TEST(test_scheduler_cancel());
    TEST("SchedulerCancelNotFound") END_TEST(test_scheduler_cancel_not_found());
    TEST("SchedulerStatus") END_TEST(test_scheduler_status());
    TEST("SchedulerResult") END_TEST(test_scheduler_result());
    TEST("SchedulerRegisterNode") END_TEST(test_scheduler_register_node());
    TEST("SchedulerUnregisterNode") END_TEST(test_scheduler_unregister_node());
    TEST("SchedulerListNodes") END_TEST(test_scheduler_list_nodes());
    TEST("SchedulerUpdateNodeHealth") END_TEST(test_scheduler_update_node_health());
    TEST("SchedulerGetStats") END_TEST(test_scheduler_get_stats());
    TEST("SchedulerPriority") END_TEST(test_scheduler_priority());
    TEST("SchedulerMaxConcurrent") END_TEST(test_scheduler_max_concurrent());

    printf("\n");
    if (failures == 0)
    {
        printf("ALL TESTS PASSED\n");
        return 0;
    }
    else
    {
        printf("%d TEST(S) FAILED\n", failures);
        return 1;
    }
}