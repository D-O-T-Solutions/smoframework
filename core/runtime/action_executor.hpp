#pragma once

#include "runtime_types.hpp"
#include "protocol/packet/packet.h"
#include "transport/transport.h"
#include "event_bus.hpp"
#include "event_store.hpp"
#include "dispatcher.hpp"
#include "scheduler.hpp"
#include "services/audit_service.hpp"

#include <cstdint>
#include <functional>
#include <memory>

namespace smo::runtime {

    // ActionExecutor: dispatches NextActions (RFC 0039/0041)
    //
    // Implements all 9 action types:
    //   - ActionDispatchMessage → build response Packet, send via transport
    //   - ActionDispatchContract → forward to target contract via Dispatcher
    //   - ActionScheduleRetry → schedule retry with exponential backoff via Scheduler
    //   - ActionSpawnPlan → resolve and execute sub-plan via PlanResolver
    //   - ActionEmitEvent → publish to EventBus + EventStore (audit)
    //   - ActionStoreContext → applied inline by contract (no-op here)
    //   - ActionNotify → deliver notification via EventBus
    //   - ActionCompensate → trigger saga rollback via Dispatcher
    //   - ActionAbort → forced termination + cleanup
    //
    // Executor is synchronous (inline, no thread pool).
    class ActionExecutor
    {
    public:
        using SendResponse = std::function<Result<void>(Packet&&)>;

        struct Dependencies
        {
            SendResponse send_response;
            EventBus* event_bus = nullptr;
            ::smo::EventStore* event_store = nullptr;
            Dispatcher* dispatcher = nullptr;
            Scheduler* scheduler = nullptr;
            AuditService* audit_service = nullptr;
            std::string local_node_id;
        };

        explicit ActionExecutor(const Dependencies& deps)
            : send_response_(std::move(deps.send_response))
            , event_bus_(deps.event_bus)
            , event_store_(deps.event_store)
            , dispatcher_(deps.dispatcher)
            , scheduler_(deps.scheduler)
            , audit_service_(deps.audit_service)
            , local_node_id_(std::move(deps.local_node_id))
        {
        }

        // Execute a single NextAction.
        Result<void> execute(const NextAction& action, const Packet& original_pkt);

    private:
        SendResponse send_response_;
        EventBus* event_bus_ = nullptr;
        ::smo::EventStore* event_store_ = nullptr;
        Dispatcher* dispatcher_ = nullptr;
        Scheduler* scheduler_ = nullptr;
        AuditService* audit_service_ = nullptr;
        std::string local_node_id_;

        Result<void> on_dispatch_message(const ActionDispatchMessage& msg, const Packet& original_pkt);
        Result<void> on_dispatch_contract(const ActionDispatchContract& action, const Packet& original_pkt);
        Result<void> on_schedule_retry(const ActionScheduleRetry& action, const Packet& original_pkt);
        Result<void> on_spawn_plan(const ActionSpawnPlan& action, const Packet& original_pkt);
        Result<void> on_emit_event(const ActionEmitEvent& action, const Packet& original_pkt);
        Result<void> on_notify(const ActionNotify& action, const Packet& original_pkt);
        Result<void> on_compensate(const ActionCompensate& action, const Packet& original_pkt);
        Result<void> on_abort(const ActionAbort& action, const Packet& original_pkt);

        Result<void> emit_audit_event(const std::string& event_type, const std::string& details,
                                      const std::string& correlation_id = "",
                                      const std::string& execution_id = "",
                                      const std::string& contract_id = "");
        uint64_t generate_execution_id();
    };

} // namespace smo::runtime
