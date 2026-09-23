// SPDX-License-Identifier: Apache-2.0
//
// ExecutionEngine — unit tests

#include <runtime/execution_engine.hpp>
#include <cstdio>
#include <cstring>
#include <vector>
#include <string>

using namespace smo;

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

// ==========================================================================
// Helpers
// ==========================================================================

static ExecutionContext make_context(const std::string& contract_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                                     const std::string& execution_id = "",
                                     const std::string& trace_id = "trace1")
{
    ExecutionContext ctx;
    ctx.contract_id = ContractID{}; // Will be overwritten
    // Parse hex string to ContractID
    if (contract_id.size() == 64)
    {
        std::array<uint8_t, 32> bytes{};
        for (size_t i = 0; i < 32; ++i)
        {
            std::string byte_str = contract_id.substr(i * 2, 2);
            bytes[i] = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
        }
        ctx.contract_id = ContractID{bytes};
    }
    ctx.execution_id = execution_id;
    ctx.trace_id = trace_id;
    ctx.requester_id = "requester1";
    ctx.intent_hash = "intent_hash_123";
    ctx.selected_nodes = {"node1", "node2"};
    ctx.witness_ids = {"witness1", "witness2"};
    ctx.config.timeout_ns = 30'000'000'000;
    ctx.config.max_retries = 3;
    ctx.config.priority = 50;
    ctx.config.control_level = 1;
    ctx.config.scope = 1;
    ctx.config.policy_name = "default";
    ctx.policy_name = "default";
    return ctx;
}

// ==========================================================================
// Tests
// ==========================================================================

static bool test_submit_basic()
{
    ExecutionEngine engine;
    auto ctx = make_context();

    auto result = engine.submit(ctx);
    ASSERT(result);
    ASSERT_STREQ(result.value().substr(0, 5).c_str(), "exec_");
    return true;
}

static bool test_submit_with_custom_id()
{
    ExecutionEngine engine;
    auto ctx = make_context("", "custom_exec_123");

    auto result = engine.submit(ctx);
    ASSERT(result);
    ASSERT_STREQ(result.value().c_str(), "custom_exec_123");
    return true;
}

static bool test_submit_duplicate_id_fails()
{
    ExecutionEngine engine;
    auto ctx1 = make_context("", "duplicate_id");
    auto ctx2 = make_context("", "duplicate_id");

    auto result1 = engine.submit(ctx1);
    ASSERT(result1);

    auto result2 = engine.submit(ctx2);
    ASSERT(!result2);
    ASSERT_EQ(result2.error().code.code, 1003);
    return true;
}

static bool test_get_status()
{
    ExecutionEngine engine;
    auto ctx = make_context("", "exec_status_test");

    auto submit_result = engine.submit(ctx);
    ASSERT(submit_result);

    auto status = engine.get_status("exec_status_test");
    ASSERT(status);
    ASSERT_STREQ(status.value().c_str(), "created");
    return true;
}

static bool test_get_status_not_found()
{
    ExecutionEngine engine;

    auto status = engine.get_status("nonexistent");
    ASSERT(!status);
    ASSERT_EQ(status.error().code.code, 1004);
    return true;
}

static bool test_cancel()
{
    ExecutionEngine engine;
    auto ctx = make_context("", "exec_cancel_test");

    auto submit_result = engine.submit(ctx);
    ASSERT(submit_result);

    auto cancel_result = engine.cancel("exec_cancel_test");
    ASSERT(cancel_result);

    auto status = engine.get_status("exec_cancel_test");
    ASSERT(status);
    ASSERT_STREQ(status.value().c_str(), "cancelled");

    // Try to cancel again - should fail
    auto cancel_result2 = engine.cancel("exec_cancel_test");
    ASSERT(!cancel_result2);
    ASSERT_EQ(cancel_result2.error().code.code, 1005);
    return true;
}

static bool test_cancel_not_found()
{
    ExecutionEngine engine;

    auto cancel_result = engine.cancel("nonexistent");
    ASSERT(!cancel_result);
    ASSERT_EQ(cancel_result.error().code.code, 1004);
    return true;
}

static bool test_get_result()
{
    ExecutionEngine engine;
    auto ctx = make_context("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "exec_result_test");

    auto submit_result = engine.submit(ctx);
    ASSERT(submit_result);

    auto result = engine.get_result("exec_result_test");
    ASSERT(result);
    ASSERT_STREQ(result.value().execution_id.c_str(), "exec_result_test");
    ASSERT_STREQ(result.value().contract_id.c_str(), "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    ASSERT_STREQ(result.value().trace_id.c_str(), "trace1");
    ASSERT_STREQ(result.value().status.c_str(), "created");
    ASSERT_EQ(result.value().retry_count, 0);
    return true;
}

static bool test_get_result_not_found()
{
    ExecutionEngine engine;

    auto result = engine.get_result("nonexistent");
    ASSERT(!result);
    ASSERT_EQ(result.error().code.code, 1004);
    return true;
}

static bool test_list_active()
{
    ExecutionEngine engine;
    auto ctx1 = make_context("", "exec_active_1");
    auto ctx2 = make_context("", "exec_active_2");
    auto ctx3 = make_context("", "exec_completed"); // We can't actually complete it, but we can test filtering

    engine.submit(ctx1);
    engine.submit(ctx2);
    engine.submit(ctx3);

    // Manually mark one as completed by cancelling it
    engine.cancel("exec_completed");

    auto active = engine.list_active();
    ASSERT(active);
    // Should have 2 active (created) and 1 cancelled
    ASSERT_EQ(active.value().size(), 2);
    return true;
}

static bool test_get_history()
{
    ExecutionEngine engine;
    std::string contract_hex1 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    std::string contract_hex2 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    auto ctx1 = make_context(contract_hex1, "exec_hist_1");
    auto ctx2 = make_context(contract_hex1, "exec_hist_2");
    auto ctx3 = make_context(contract_hex2, "exec_hist_3");

    engine.submit(ctx1);
    engine.submit(ctx2);
    engine.submit(ctx3);

    auto history1 = engine.get_history(contract_hex1);
    ASSERT(history1);
    ASSERT_EQ(history1.value().size(), 2);

    auto history2 = engine.get_history(contract_hex2);
    ASSERT(history2);
    ASSERT_EQ(history2.value().size(), 1);

    auto history3 = engine.get_history("contract3");
    ASSERT(history3);
    ASSERT_EQ(history3.value().size(), 0);
    return true;
}

static bool test_max_concurrent()
{
    ExecutionEngine::Config config;
    config.max_concurrent_executions = 2;
    ExecutionEngine engine(config);

    auto ctx1 = make_context("", "exec_max_1");
    auto ctx2 = make_context("", "exec_max_2");
    auto ctx3 = make_context("", "exec_max_3");

    ASSERT(engine.submit(ctx1));
    ASSERT(engine.submit(ctx2));
    auto result3 = engine.submit(ctx3);
    ASSERT(!result3);
    ASSERT_EQ(result3.error().code.code, 1002);
    return true;
}

// ==========================================================================
// Main
// ==========================================================================

int main(int, char*[])
{
    printf("SMO ExecutionEngine — Unit Tests\n");
    printf("=================================\n\n");

    TEST("SubmitBasic") END_TEST(test_submit_basic());
    TEST("SubmitWithCustomId") END_TEST(test_submit_with_custom_id());
    TEST("SubmitDuplicateIdFails") END_TEST(test_submit_duplicate_id_fails());
    TEST("GetStatus") END_TEST(test_get_status());
    TEST("GetStatusNotFound") END_TEST(test_get_status_not_found());
    TEST("Cancel") END_TEST(test_cancel());
    TEST("CancelNotFound") END_TEST(test_cancel_not_found());
    TEST("GetResult") END_TEST(test_get_result());
    TEST("GetResultNotFound") END_TEST(test_get_result_not_found());
    TEST("ListActive") END_TEST(test_list_active());
    TEST("GetHistory") END_TEST(test_get_history());
    TEST("MaxConcurrent") END_TEST(test_max_concurrent());

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