// SPDX-License-Identifier: Apache-2.0
//
// HistoryService — unit tests

#include <runtime/history.hpp>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <chrono>
#include <thread>

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

// Temporary directory helper
struct TempDir
{
    std::string path;
    TempDir()
    {
        auto tmp = std::filesystem::temp_directory_path();
        path = (tmp / "smo_test_history_XXXXXX").string();
        char buf[256];
        std::strncpy(buf, path.c_str(), sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
        ::mkdtemp(buf);
        path = buf;
    }
    ~TempDir() { std::filesystem::remove_all(path); }
    std::string file(const char* name) const { return path + "/" + name; }
};

// ==========================================================================
// Helpers
// ==========================================================================

static ContractHistoryEntry make_contract_entry(const std::string& contract_id)
{
    ContractHistoryEntry e;
    e.contract_id = contract_id;
    e.name = "Test Contract";
    e.version = "1.0.0";
    e.publisher = "test_publisher";
    e.abi_hash = "abi_hash_123";
    e.semantic_hash = "semantic_hash_456";
    e.published_at = std::chrono::duration_cast<std::chrono::nanoseconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    e.publisher_id = "publisher_1";
    return e;
}

static ExecutionHistoryEntry make_execution_entry(const std::string& execution_id, const std::string& contract_id,
                                                  const std::string& trace_id, const std::string& status = "completed")
{
    ExecutionHistoryEntry e;
    e.execution_id = execution_id;
    e.contract_id = contract_id;
    e.trace_id = trace_id;
    e.requester_id = "requester1";
    e.responder_id = "responder1";
    e.witness_ids = {"witness1", "witness2"};
    e.selected_nodes = {"node1", "node2"};
    e.created_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                       .count();
    e.started_ns = e.created_ns + 1000;
    e.completed_ns = e.started_ns + 1000;
    e.timeout_ns = 30'000'000'000;
    e.retry_count = 0;
    e.max_retries = 3;
    e.status = status;
    e.result_hash = "result_hash_123";
    e.error_message = "";
    return e;
}

static ExecutionEventEntry make_event_entry(uint64_t sequence, const std::string& execution_id,
                                            const std::string& trace_id, const std::string& contract_id,
                                            const std::string& event_type = "Created")
{
    ExecutionEventEntry e;
    e.sequence = sequence;
    e.event_type = event_type;
    e.timestamp_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    e.execution_id = execution_id;
    e.trace_id = trace_id;
    e.contract_id = contract_id;
    e.actor_id = "actor1";
    e.node_id = "node1";
    e.payload = "test_payload";
    e.prev_hash = "prev_hash";
    e.event_hash = "event_hash";
    return e;
}

static NodeHistoryEntry make_node_entry(const std::string& node_id, const std::string& mesh_name)
{
    NodeHistoryEntry e;
    e.node_id = node_id;
    e.display_name = "Test Node";
    e.mesh_name = mesh_name;
    e.role = "validator";
    e.tags = {"tag1", "tag2"};
    e.platform = "linux";
    e.arch = "x86_64";
    e.version = "1.0.0";
    e.last_seen = std::chrono::duration_cast<std::chrono::nanoseconds>(
                      std::chrono::system_clock::now().time_since_epoch())
                      .count();
    e.ping_misses = 0;
    e.rtt_ms = 10.5;
    return e;
}

static PolicyHistoryEntry make_policy_entry(uint64_t sequence, const std::string& policy_name)
{
    PolicyHistoryEntry e;
    e.sequence = sequence;
    e.policy_name = policy_name;
    e.actor_id = "actor1";
    e.target_id = "target1";
    e.details = "policy check passed";
    e.timestamp_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    return e;
}

static MeshHistoryEntry make_mesh_entry(const std::string& mesh_id, const std::string& mesh_name)
{
    MeshHistoryEntry e;
    e.mesh_id = mesh_id;
    e.mesh_name = mesh_name;
    e.epoch = 1;
    e.authority = "authority1";
    e.action = "mesh_created";
    e.timestamp_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    return e;
}

// ==========================================================================
// Tests
// ==========================================================================

static bool test_open_close()
{
    TempDir dir;
    HistoryService::Config config;
    config.audit_db_path = dir.file("history.db");
    HistoryService service(config);

    auto r = service.open();
    ASSERT(r);

    service.close();
    return true;
}

static bool test_contract_history()
{
    TempDir dir;
    HistoryService::Config config;
    config.audit_db_path = dir.file("history.db");
    HistoryService service(config);
    ASSERT(service.open());

    // Note: The current implementation doesn't have a method to insert contract history
    // This test verifies the query returns empty for non-existent contracts
    auto result = service.get_contract_history("nonexistent", 10, 0);
    ASSERT(result);
    ASSERT_EQ(result.value().size(), 0);

    auto contract = service.get_contract("nonexistent");
    ASSERT(!contract);
    ASSERT_EQ(contract.error().code.code, 902);

    return true;
}

static bool test_execution_history()
{
    TempDir dir;
    HistoryService::Config config;
    config.audit_db_path = dir.file("history.db");
    HistoryService service(config);
    ASSERT(service.open());

    // Query non-existent execution
    auto result = service.get_execution_history("nonexistent");
    ASSERT(result);
    ASSERT_EQ(result.value().size(), 0);

    return true;
}

static bool test_contract_executions()
{
    TempDir dir;
    HistoryService::Config config;
    config.audit_db_path = dir.file("history.db");
    HistoryService service(config);
    ASSERT(service.open());

    auto result = service.get_contract_executions("contract1", 10, 0);
    ASSERT(result);
    ASSERT_EQ(result.value().size(), 0);
    return true;
}

static bool test_node_executions()
{
    TempDir dir;
    HistoryService::Config config;
    config.audit_db_path = dir.file("history.db");
    HistoryService service(config);
    ASSERT(service.open());

    auto result = service.get_node_executions("node1", 10, 0);
    ASSERT(result);
    ASSERT_EQ(result.value().size(), 0);
    return true;
}

static bool test_failed_executions()
{
    TempDir dir;
    HistoryService::Config config;
    config.audit_db_path = dir.file("history.db");
    HistoryService service(config);
    ASSERT(service.open());

    auto now = std::chrono::duration_cast<std::chrono::nanoseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();
    auto result = service.get_failed_executions(now - 1000000, now + 1000000, 10);
    ASSERT(result);
    ASSERT_EQ(result.value().size(), 0);
    return true;
}

static bool test_execution_events()
{
    TempDir dir;
    HistoryService::Config config;
    config.audit_db_path = dir.file("history.db");
    HistoryService service(config);
    ASSERT(service.open());

    auto result = service.get_execution_events("exec1");
    ASSERT(result);
    ASSERT_EQ(result.value().size(), 0);
    return true;
}

static bool test_trace_events()
{
    TempDir dir;
    HistoryService::Config config;
    config.audit_db_path = dir.file("history.db");
    HistoryService service(config);
    ASSERT(service.open());

    auto result = service.get_trace_events("trace1");
    ASSERT(result);
    ASSERT_EQ(result.value().size(), 0);
    return true;
}

static bool test_node_history()
{
    TempDir dir;
    HistoryService::Config config;
    config.audit_db_path = dir.file("history.db");
    HistoryService service(config);
    ASSERT(service.open());

    auto result = service.get_node_history("node1", 10);
    ASSERT(result);
    ASSERT_EQ(result.value().size(), 0);
    return true;
}

static bool test_mesh_nodes()
{
    TempDir dir;
    HistoryService::Config config;
    config.audit_db_path = dir.file("history.db");
    HistoryService service(config);
    ASSERT(service.open());

    auto result = service.get_mesh_nodes("mesh1", 10);
    ASSERT(result);
    ASSERT_EQ(result.value().size(), 0);
    return true;
}

static bool test_policy_history()
{
    TempDir dir;
    HistoryService::Config config;
    config.audit_db_path = dir.file("history.db");
    HistoryService service(config);
    ASSERT(service.open());

    auto result = service.get_policy_history("policy1", 10);
    ASSERT(result);
    ASSERT_EQ(result.value().size(), 0);
    return true;
}

static bool test_mesh_history()
{
    TempDir dir;
    HistoryService::Config config;
    config.audit_db_path = dir.file("history.db");
    HistoryService service(config);
    ASSERT(service.open());

    auto result = service.get_mesh_history("mesh1", 10);
    ASSERT(result);
    ASSERT_EQ(result.value().size(), 0);
    return true;
}

static bool test_query_executions()
{
    TempDir dir;
    HistoryService::Config config;
    config.audit_db_path = dir.file("history.db");
    HistoryService service(config);
    ASSERT(service.open());

    auto result = service.query_executions("contract1", "node1", "completed", 0, 0, 10, 0);
    ASSERT(result);
    ASSERT_EQ(result.value().size(), 0);
    return true;
}

static bool test_query_events()
{
    TempDir dir;
    HistoryService::Config config;
    config.audit_db_path = dir.file("history.db");
    HistoryService service(config);
    ASSERT(service.open());

    auto result = service.query_events("exec1", "trace1", "Created", 0, 0, 10, 0);
    ASSERT(result);
    ASSERT_EQ(result.value().size(), 0);
    return true;
}

static bool test_trace_executions()
{
    TempDir dir;
    HistoryService::Config config;
    config.audit_db_path = dir.file("history.db");
    HistoryService service(config);
    ASSERT(service.open());

    auto result = service.get_trace_executions("trace1");
    ASSERT(result);
    ASSERT_EQ(result.value().size(), 0);
    return true;
}

// ==========================================================================
// Main
// ==========================================================================

int main(int, char*[])
{
    printf("SMO HistoryService — Unit Tests\n");
    printf("================================\n\n");

    TEST("OpenClose") END_TEST(test_open_close());
    TEST("ContractHistory") END_TEST(test_contract_history());
    TEST("ExecutionHistory") END_TEST(test_execution_history());
    TEST("ContractExecutions") END_TEST(test_contract_executions());
    TEST("NodeExecutions") END_TEST(test_node_executions());
    TEST("FailedExecutions") END_TEST(test_failed_executions());
    TEST("ExecutionEvents") END_TEST(test_execution_events());
    TEST("TraceEvents") END_TEST(test_trace_events());
    TEST("NodeHistory") END_TEST(test_node_history());
    TEST("MeshNodes") END_TEST(test_mesh_nodes());
    TEST("PolicyHistory") END_TEST(test_policy_history());
    TEST("MeshHistory") END_TEST(test_mesh_history());
    TEST("QueryExecutions") END_TEST(test_query_executions());
    TEST("QueryEvents") END_TEST(test_query_events());
    TEST("TraceExecutions") END_TEST(test_trace_executions());

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