#include <gtest/gtest.h>

#include <core/runtime/action_executor.hpp>
#include <core/runtime/runtime_types.hpp>
#include <core/runtime/dispatcher.hpp>
#include <core/runtime/event_bus.hpp>
#include <core/runtime/event_store.hpp>
#include <core/runtime/scheduler.hpp>
#include <core/runtime/services/audit_service.hpp>
#include <protocol/packet/packet.h>

#include <memory>
#include <string>

namespace smo::runtime {

class MockDispatcher : public Dispatcher
{
public:
    Result<ContractResult> execute(const std::string& contract_id, const ContractInput& input,
                                   const RuntimeContext& ctx) override
    {
        (void)contract_id;
        (void)input;
        (void)ctx;
        ContractResult result;
        result.status = ContractResult::Status::Success;
        result.data = "mock result";
        return result;
    }
};

class MockAuditService : public AuditService
{
public:
    std::vector<AuditEvent> events;

    void emit(const AuditEvent& event) override
    {
        events.push_back(event);
    }
};

TEST(NextActionTest, DispatchMessage)
{
    EventBus event_bus;
    Packet original_pkt;
    original_pkt.intent_id.fill(0xAA);
    original_pkt.session_id().fill(0xBB);
    original_pkt.opcode_id = 0x1234;

    ActionExecutor::Dependencies deps;
    deps.send_response = [&](Packet&& resp) -> Result<void> {
        EXPECT_EQ(resp.opcode_id, 0x1234);
        EXPECT_EQ(resp.intent_id, original_pkt.intent_id);
        return {};
    };
    deps.event_bus = &event_bus;

    ActionExecutor executor(deps);

    NextAction action = dispatch_message("TEST_OP", std::vector<uint8_t>{1, 2, 3});
    auto res = executor.execute(action, original_pkt);
    EXPECT_TRUE(res);
}

TEST(NextActionTest, DispatchContract)
{
    MockDispatcher dispatcher;
    EventBus event_bus;
    Packet original_pkt;
    original_pkt.intent_id.fill(0xAA);
    original_pkt.session_id().fill(0xBB);

    ActionExecutor::Dependencies deps;
    deps.send_response = [&](Packet&&) -> Result<void> { return {}; };
    deps.event_bus = &event_bus;
    deps.dispatcher = &dispatcher;

    ActionExecutor executor(deps);

    NextAction action = dispatch_contract("test.contract", ContractInput::method_only("test_method"));
    auto res = executor.execute(action, original_pkt);
    EXPECT_TRUE(res);
}

TEST(NextActionTest, ScheduleRetry)
{
    Scheduler scheduler(Scheduler::Config{.max_concurrent_tasks = 10, .worker_threads = 1});
    EventBus event_bus;
    Packet original_pkt;
    original_pkt.intent_id.fill(0xAA);
    original_pkt.session_id().fill(0xBB);

    ActionExecutor::Dependencies deps;
    deps.send_response = [&](Packet&&) -> Result<void> { return {}; };
    deps.event_bus = &event_bus;
    deps.scheduler = &scheduler;

    ActionExecutor executor(deps);

    NextAction action = schedule_retry(1'000'000'000, 3, 2.0);
    auto res = executor.execute(action, original_pkt);
    EXPECT_TRUE(res);
}

TEST(NextActionTest, SpawnPlan)
{
    MockDispatcher dispatcher;
    EventBus event_bus;
    Packet original_pkt;
    original_pkt.intent_id.fill(0xAA);
    original_pkt.session_id().fill(0xBB);

    ActionExecutor::Dependencies deps;
    deps.send_response = [&](Packet&&) -> Result<void> { return {}; };
    deps.event_bus = &event_bus;
    deps.dispatcher = &dispatcher;

    ActionExecutor executor(deps);

    NextAction action = spawn_plan("test.plan", {{"param1", "value1"}}, ExecutionMode::Sequential);
    auto res = executor.execute(action, original_pkt);
    EXPECT_TRUE(res);
}

TEST(NextActionTest, EmitEvent)
{
    EventBus event_bus;
    MockAuditService audit_service;
    EventStore event_store(EventStore::Config{.db_path = "/tmp/test_events.db", .max_events = 1000});
    event_store.open();

    Packet original_pkt;
    original_pkt.intent_id.fill(0xAA);
    original_pkt.session_id().fill(0xBB);

    ActionExecutor::Dependencies deps;
    deps.send_response = [&](Packet&&) -> Result<void> { return {}; };
    deps.event_bus = &event_bus;
    deps.event_store = &event_store;
    deps.audit_service = &audit_service;
    deps.local_node_id = "test_node";

    ActionExecutor executor(deps);

    NextAction action = emit_event("ExecutionCompleted", "test payload", EventPriority::Normal);
    auto res = executor.execute(action, original_pkt);
    EXPECT_TRUE(res);

    EXPECT_EQ(audit_service.events.size(), 1);
    EXPECT_EQ(audit_service.events[0].event_type, "ExecutionCompleted");
    EXPECT_EQ(audit_service.events[0].source_id, "test_node");
}

TEST(NextActionTest, StoreContext)
{
    EventBus event_bus;
    Packet original_pkt;
    original_pkt.intent_id.fill(0xAA);
    original_pkt.session_id().fill(0xBB);

    ActionExecutor::Dependencies deps;
    deps.send_response = [&](Packet&&) -> Result<void> { return {}; };
    deps.event_bus = &event_bus;

    ActionExecutor executor(deps);

    NextAction action = store_context("test_key", ContextValue("test_value"));
    auto res = executor.execute(action, original_pkt);
    EXPECT_TRUE(res);
}

TEST(NextActionTest, Notify)
{
    EventBus event_bus;
    MockAuditService audit_service;
    Packet original_pkt;
    original_pkt.intent_id.fill(0xAA);
    original_pkt.session_id().fill(0xBB);

    ActionExecutor::Dependencies deps;
    deps.send_response = [&](Packet&&) -> Result<void> { return {}; };
    deps.event_bus = &event_bus;
    deps.audit_service = &audit_service;
    deps.local_node_id = "test_node";

    ActionExecutor executor(deps);

    NextAction action = notify_action("target_node", "test message", {{"key", "value"}});
    auto res = executor.execute(action, original_pkt);
    EXPECT_TRUE(res);

    EXPECT_EQ(audit_service.events.size(), 1);
    EXPECT_EQ(audit_service.events[0].event_type, "NotificationSent");
}

TEST(NextActionTest, Compensate)
{
    MockDispatcher dispatcher;
    EventBus event_bus;
    MockAuditService audit_service;
    Packet original_pkt;
    original_pkt.intent_id.fill(0xAA);
    original_pkt.session_id().fill(0xBB);

    ActionExecutor::Dependencies deps;
    deps.send_response = [&](Packet&&) -> Result<void> { return {}; };
    deps.event_bus = &event_bus;
    deps.dispatcher = &dispatcher;
    deps.audit_service = &audit_service;
    deps.local_node_id = "test_node";

    ActionExecutor executor(deps);

    NextAction action = compensate_plan("compensation.plan", "test reason");
    auto res = executor.execute(action, original_pkt);
    EXPECT_TRUE(res);

    EXPECT_EQ(audit_service.events.size(), 1);
    EXPECT_EQ(audit_service.events[0].event_type, "CompensationTriggered");
}

TEST(NextActionTest, Abort)
{
    MockDispatcher dispatcher;
    EventBus event_bus;
    MockAuditService audit_service;
    Packet original_pkt;
    original_pkt.intent_id.fill(0xAA);
    original_pkt.session_id().fill(0xBB);

    ActionExecutor::Dependencies deps;
    deps.send_response = [&](Packet&&) -> Result<void> { return {}; };
    deps.event_bus = &event_bus;
    deps.dispatcher = &dispatcher;
    deps.audit_service = &audit_service;
    deps.local_node_id = "test_node";

    ActionExecutor executor(deps);

    NextAction action = abort_plan("test abort reason", true);
    auto res = executor.execute(action, original_pkt);
    EXPECT_TRUE(res);

    EXPECT_EQ(audit_service.events.size(), 1);
    EXPECT_EQ(audit_service.events[0].event_type, "ExecutionAborted");
}

TEST(NextActionTest, AllNineActions)
{
    MockDispatcher dispatcher;
    EventBus event_bus;
    MockAuditService audit_service;
    Scheduler scheduler(Scheduler::Config{.max_concurrent_tasks = 10, .worker_threads = 1});
    EventStore event_store(EventStore::Config{.db_path = "/tmp/test_events2.db", .max_events = 1000});
    event_store.open();

    Packet original_pkt;
    original_pkt.intent_id.fill(0xAA);
    original_pkt.session_id().fill(0xBB);
    original_pkt.opcode_id = 0x1234;

    ActionExecutor::Dependencies deps;
    deps.send_response = [&](Packet&&) -> Result<void> { return {}; };
    deps.event_bus = &event_bus;
    deps.dispatcher = &dispatcher;
    deps.scheduler = &scheduler;
    deps.event_store = &event_store;
    deps.audit_service = &audit_service;
    deps.local_node_id = "test_node";

    ActionExecutor executor(deps);

    std::vector<NextAction> actions = {
        dispatch_message("OP1", std::vector<uint8_t>{1}),
        dispatch_contract("contract1", ContractInput::method_only("method1")),
        schedule_retry(1'000'000'000, 3, 2.0),
        emit_event("Event1", "payload1"),
        store_context("key1", ContextValue("value1")),
        spawn_plan("plan1", {{"p1", "v1"}}, ExecutionMode::Sequential),
        notify_action("target1", "message1", {{"k1", "v1"}}),
        compensate_plan("comp1", "reason1"),
        abort_plan("reason2", false)
    };

    for (const auto& action : actions)
    {
        auto res = executor.execute(action, original_pkt);
        EXPECT_TRUE(res) << "Action failed: " << (res ? "ok" : res.error().message);
    }

    EXPECT_EQ(audit_service.events.size(), 7);
}

} // namespace smo::runtime