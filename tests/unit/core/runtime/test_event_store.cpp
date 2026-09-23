// SPDX-License-Identifier: Apache-2.0
//
// EventStore — unit tests

#include <runtime/event_store.hpp>
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

#define ASSERT_GT(a, b)                                                                                                \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!((a) > (b)))                                                                                              \
        {                                                                                                              \
            printf("\n    ASSERTION FAILED at %s:%d: %s > %s\n", __FILE__, __LINE__, #a, #b);                         \
            return false;                                                                                              \
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
        path = (tmp / "smo_test_eventstore_XXXXXX").string();
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

static EventRecord make_event(uint64_t seq, const std::string& exec_id, const std::string& trace_id,
                              const std::string& contract_id, EventType type = EventType::Created)
{
    EventRecord e;
    e.sequence = seq;
    e.type = type;
    e.timestamp_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    e.contract_id = contract_id;
    e.execution_id = exec_id;
    e.trace_id = trace_id;
    e.node_id = "node1";
    e.actor_id = "actor1";
    e.payload = "test_payload";
    e.prev_hash = "";
    e.event_hash = "";
    e.signature = "";
    return e;
}

static ExecutionRecord make_execution(const std::string& exec_id, const std::string& contract_id,
                                      const std::string& trace_id)
{
    ExecutionRecord r;
    r.execution_id = exec_id;
    r.contract_id = contract_id;
    r.trace_id = trace_id;
    r.requester_id = "requester1";
    r.responder_id = "responder1";
    r.witness_ids = {"witness1", "witness2"};
    r.selected_nodes = {"node1", "node2"};
    r.intent_hash = "intent_hash_123";
    r.policy_name = "default";
    r.control_level = 1;
    r.scope = 1;
    r.created_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                       .count();
    r.started_ns = 0;
    r.completed_ns = 0;
    r.timeout_ns = 30'000'000'000;
    r.retry_count = 0;
    r.max_retries = 3;
    r.priority = 50;
    r.status = "created";
    r.result_hash = "";
    r.error_message = "";
    return r;
}

// ==========================================================================
// Tests
// ==========================================================================

static bool test_open_close()
{
    TempDir dir;
    EventStore::Config config;
    config.db_path = dir.file("events.db");
    EventStore store(config);

    auto r = store.open();
    ASSERT(r);
    store.close();
    return true;
}

static bool test_append_and_query_by_execution()
{
    TempDir dir;
    EventStore::Config config;
    config.db_path = dir.file("events.db");
    EventStore store(config);
    ASSERT(store.open());

    auto e1 = make_event(0, "exec1", "trace1", "contract1", EventType::Created);
    auto r1 = store.append(e1);
    ASSERT(r1);
    ASSERT_GT(r1.value(), 0);

    auto e2 = make_event(0, "exec1", "trace1", "contract1", EventType::Validated);
    auto r2 = store.append(e2);
    ASSERT(r2);
    ASSERT_GT(r2.value(), 0);

    auto events = store.query_by_execution("exec1");
    ASSERT(events);
    ASSERT_EQ(events.value().size(), 2);
    ASSERT_EQ(events.value()[0].type, EventType::Created);
    ASSERT_EQ(events.value()[1].type, EventType::Validated);
    return true;
}

static bool test_query_by_trace()
{
    TempDir dir;
    EventStore::Config config;
    config.db_path = dir.file("events.db");
    EventStore store(config);
    ASSERT(store.open());

    store.append(make_event(0, "exec1", "trace1", "contract1", EventType::Created));
    store.append(make_event(0, "exec2", "trace1", "contract1", EventType::Created));
    store.append(make_event(0, "exec3", "trace2", "contract1", EventType::Created));

    auto events1 = store.query_by_trace("trace1");
    ASSERT(events1);
    ASSERT_EQ(events1.value().size(), 2);

    auto events2 = store.query_by_trace("trace2");
    ASSERT(events2);
    ASSERT_EQ(events2.value().size(), 1);
    return true;
}

static bool test_query_by_contract()
{
    TempDir dir;
    EventStore::Config config;
    config.db_path = dir.file("events.db");
    EventStore store(config);
    ASSERT(store.open());

    store.append(make_event(0, "exec1", "trace1", "contract1", EventType::Created));
    store.append(make_event(0, "exec2", "trace2", "contract2", EventType::Created));

    auto events = store.query_by_contract("contract1");
    ASSERT(events);
    ASSERT_EQ(events.value().size(), 1);
    ASSERT_EQ(events.value()[0].contract_id, "contract1");
    return true;
}

static bool test_query_by_node()
{
    TempDir dir;
    EventStore::Config config;
    config.db_path = dir.file("events.db");
    EventStore store(config);
    ASSERT(store.open());

    auto e1 = make_event(0, "exec1", "trace1", "contract1", EventType::Created);
    e1.node_id = "node1";
    store.append(e1);

    auto e2 = make_event(0, "exec2", "trace2", "contract1", EventType::Created);
    e2.node_id = "node2";
    store.append(e2);

    auto events = store.query_by_node("node1");
    ASSERT(events);
    ASSERT_EQ(events.value().size(), 1);
    ASSERT_EQ(events.value()[0].node_id, "node1");
    return true;
}

static bool test_query_range()
{
    TempDir dir;
    EventStore::Config config;
    config.db_path = dir.file("events.db");
    EventStore store(config);
    ASSERT(store.open());

    auto now = std::chrono::duration_cast<std::chrono::nanoseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();
    store.append(make_event(0, "exec1", "trace1", "contract1", EventType::Created));
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    store.append(make_event(0, "exec2", "trace2", "contract1", EventType::Created));

    auto events = store.query_range(now, now + 100'000'000, 1000);
    ASSERT(events);
    ASSERT_GE(events.value().size(), 1);
    return true;
}

static bool test_query_latest()
{
    TempDir dir;
    EventStore::Config config;
    config.db_path = dir.file("events.db");
    EventStore store(config);
    ASSERT(store.open());

    store.append(make_event(0, "exec1", "trace1", "contract1", EventType::Created));
    store.append(make_event(0, "exec2", "trace2", "contract1", EventType::Created));
    store.append(make_event(0, "exec3", "trace3", "contract1", EventType::Created));

    auto events = store.query_latest(2);
    ASSERT(events);
    ASSERT_EQ(events.value().size(), 2);
    return true;
}

static bool test_upsert_and_get_execution()
{
    TempDir dir;
    EventStore::Config config;
    config.db_path = dir.file("events.db");
    EventStore store(config);
    ASSERT(store.open());

    auto rec = make_execution("exec1", "contract1", "trace1");
    auto r = store.upsert_execution(rec);
    ASSERT(r);

    auto got = store.get_execution("exec1");
    ASSERT(got);
    ASSERT_EQ(got.value().execution_id, "exec1");
    ASSERT_EQ(got.value().contract_id, "contract1");
    ASSERT_EQ(got.value().trace_id, "trace1");
    ASSERT_EQ(got.value().witness_ids.size(), 2);
    ASSERT_EQ(got.value().selected_nodes.size(), 2);
    return true;
}

static bool test_get_execution_not_found()
{
    TempDir dir;
    EventStore::Config config;
    config.db_path = dir.file("events.db");
    EventStore store(config);
    ASSERT(store.open());

    auto got = store.get_execution("nonexistent");
    ASSERT(!got);
    ASSERT_EQ(got.error().code.code, 902);
    return true;
}

static bool test_query_executions_by_contract()
{
    TempDir dir;
    EventStore::Config config;
    config.db_path = dir.file("events.db");
    EventStore store(config);
    ASSERT(store.open());

    store.upsert_execution(make_execution("exec1", "contract1", "trace1"));
    store.upsert_execution(make_execution("exec2", "contract1", "trace2"));
    store.upsert_execution(make_execution("exec3", "contract2", "trace3"));

    auto execs = store.query_executions_by_contract("contract1");
    ASSERT(execs);
    ASSERT_EQ(execs.value().size(), 2);
    return true;
}

static bool test_query_executions_by_trace()
{
    TempDir dir;
    EventStore::Config config;
    config.db_path = dir.file("events.db");
    EventStore store(config);
    ASSERT(store.open());

    store.upsert_execution(make_execution("exec1", "contract1", "trace1"));
    store.upsert_execution(make_execution("exec2", "contract2", "trace1"));

    auto execs = store.query_executions_by_trace("trace1");
    ASSERT(execs);
    ASSERT_EQ(execs.value().size(), 2);
    return true;
}

static bool test_query_recent_executions()
{
    TempDir dir;
    EventStore::Config config;
    config.db_path = dir.file("events.db");
    EventStore store(config);
    ASSERT(store.open());

    store.upsert_execution(make_execution("exec1", "contract1", "trace1"));
    store.upsert_execution(make_execution("exec2", "contract1", "trace2"));
    store.upsert_execution(make_execution("exec3", "contract2", "trace3"));

    auto execs = store.query_recent_executions(2);
    ASSERT(execs);
    ASSERT_EQ(execs.value().size(), 2);
    return true;
}

static bool test_serialize_deserialize_event()
{
    auto e = make_event(1, "exec1", "trace1", "contract1", EventType::Completed);
    e.payload = "test_payload_data";
    e.prev_hash = "prev_hash_123";
    e.event_hash = "event_hash_456";
    e.signature = "sig_789";

    Bytes serialized = EventStore::serialize_event(e);
    ASSERT_GT(serialized.size(), 0);

    auto deserialized = EventStore::deserialize_event(serialized);
    ASSERT(deserialized);
    ASSERT_EQ(deserialized.value().sequence, e.sequence);
    ASSERT_EQ(deserialized.value().type, e.type);
    ASSERT_EQ(deserialized.value().contract_id, e.contract_id);
    ASSERT_EQ(deserialized.value().execution_id, e.execution_id);
    ASSERT_EQ(deserialized.value().trace_id, e.trace_id);
    ASSERT_EQ(deserialized.value().payload, e.payload);
    ASSERT_EQ(deserialized.value().prev_hash, e.prev_hash);
    ASSERT_EQ(deserialized.value().event_hash, e.event_hash);
    ASSERT_EQ(deserialized.value().signature, e.signature);
    return true;
}

static bool test_serialize_deserialize_execution()
{
    auto r = make_execution("exec1", "contract1", "trace1");
    r.status = "completed";
    r.result_hash = "result_abc";
    r.error_message = "";

    Bytes serialized = EventStore::serialize_execution(r);
    ASSERT_GT(serialized.size(), 0);

    auto deserialized = EventStore::deserialize_execution(serialized);
    ASSERT(deserialized);
    ASSERT_EQ(deserialized.value().execution_id, r.execution_id);
    ASSERT_EQ(deserialized.value().contract_id, r.contract_id);
    ASSERT_EQ(deserialized.value().trace_id, r.trace_id);
    ASSERT_VECTOR_EQ(deserialized.value().witness_ids, r.witness_ids);
    ASSERT_VECTOR_EQ(deserialized.value().selected_nodes, r.selected_nodes);
    ASSERT_EQ(deserialized.value().status, r.status);
    ASSERT_EQ(deserialized.value().result_hash, r.result_hash);
    return true;
}

static bool test_vacuum()
{
    TempDir dir;
    EventStore::Config config;
    config.db_path = dir.file("events.db");
    EventStore store(config);
    ASSERT(store.open());

    store.append(make_event(0, "exec1", "trace1", "contract1", EventType::Created));
    auto r = store.vacuum();
    ASSERT(r);
    return true;
}

static bool test_count_events_and_executions()
{
    TempDir dir;
    EventStore::Config config;
    config.db_path = dir.file("events.db");
    EventStore store(config);
    ASSERT(store.open());

    store.append(make_event(0, "exec1", "trace1", "contract1", EventType::Created));
    store.append(make_event(0, "exec2", "trace2", "contract1", EventType::Created));
    store.upsert_execution(make_execution("exec1", "contract1", "trace1"));
    store.upsert_execution(make_execution("exec2", "contract1", "trace2"));

    auto event_count = store.count_events();
    ASSERT(event_count);
    ASSERT_EQ(event_count.value(), 2);

    auto exec_count = store.count_executions();
    ASSERT(exec_count);
    ASSERT_EQ(exec_count.value(), 2);
    return true;
}

static bool test_db_size_bytes()
{
    TempDir dir;
    EventStore::Config config;
    config.db_path = dir.file("events.db");
    EventStore store(config);
    ASSERT(store.open());

    store.append(make_event(0, "exec1", "trace1", "contract1", EventType::Created));

    auto size = store.db_size_bytes();
    ASSERT(size);
    ASSERT_GT(size.value(), 0);
    return true;
}

static bool test_iterator_all()
{
    TempDir dir;
    EventStore::Config config;
    config.db_path = dir.file("events.db");
    EventStore store(config);
    ASSERT(store.open());

    store.append(make_event(0, "exec1", "trace1", "contract1", EventType::Created));
    store.append(make_event(0, "exec2", "trace2", "contract1", EventType::Created));

    auto iter = store.iterate_all();
    ASSERT(iter != nullptr);

    int count = 0;
    EventRecord e;
    while (iter->next(e))
    {
        ++count;
    }
    ASSERT_EQ(count, 2);
    return true;
}

static bool test_iterator_execution()
{
    TempDir dir;
    EventStore::Config config;
    config.db_path = dir.file("events.db");
    EventStore store(config);
    ASSERT(store.open());

    store.append(make_event(0, "exec1", "trace1", "contract1", EventType::Created));
    store.append(make_event(0, "exec1", "trace1", "contract1", EventType::Validated));
    store.append(make_event(0, "exec2", "trace2", "contract1", EventType::Created));

    auto iter = store.iterate_execution("exec1");
    ASSERT(iter != nullptr);

    int count = 0;
    EventRecord e;
    while (iter->next(e))
    {
        ++count;
        ASSERT_STREQ(e.execution_id.c_str(), "exec1");
    }
    ASSERT_EQ(count, 2);
    return true;
}

// ==========================================================================
// Main
// ==========================================================================

int main(int, char*[])
{
    printf("SMO EventStore — Unit Tests\n");
    printf("============================\n\n");

    TEST("OpenClose") END_TEST(test_open_close());
    TEST("AppendAndQueryByExecution") END_TEST(test_append_and_query_by_execution());
    TEST("QueryByTrace") END_TEST(test_query_by_trace());
    TEST("QueryByContract") END_TEST(test_query_by_contract());
    TEST("QueryByNode") END_TEST(test_query_by_node());
    TEST("QueryRange") END_TEST(test_query_range());
    TEST("QueryLatest") END_TEST(test_query_latest());
    TEST("UpsertAndGetExecution") END_TEST(test_upsert_and_get_execution());
    TEST("GetExecutionNotFound") END_TEST(test_get_execution_not_found());
    TEST("QueryExecutionsByContract") END_TEST(test_query_executions_by_contract());
    TEST("QueryExecutionsByTrace") END_TEST(test_query_executions_by_trace());
    TEST("QueryRecentExecutions") END_TEST(test_query_recent_executions());
    TEST("SerializeDeserializeEvent") END_TEST(test_serialize_deserialize_event());
    TEST("SerializeDeserializeExecution") END_TEST(test_serialize_deserialize_execution());
    TEST("Vacuum") END_TEST(test_vacuum());
    TEST("CountEventsAndExecutions") END_TEST(test_count_events_and_executions());
    TEST("DbSizeBytes") END_TEST(test_db_size_bytes());
    TEST("IteratorAll") END_TEST(test_iterator_all());
    TEST("IteratorExecution") END_TEST(test_iterator_execution());

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