#include "action_executor.hpp"

#include "core/runtime/runtime_types.hpp"
#include "protocol/packet/packet.h"
#include "event_store.hpp"
#include "core/session/session_id.hpp"

#include <chrono>
#include <random>
#include <sstream>
#include <iomanip>

namespace {

std::string session_id_to_hex(const std::array<uint8_t, 16>& sid)
{
    std::ostringstream oss;
    for (uint8_t b : sid)
    {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return oss.str();
}

std::string intent_id_to_hex(const std::array<uint8_t, 16>& iid)
{
    std::ostringstream oss;
    for (uint8_t b : iid)
    {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return oss.str();
}

} // anonymous namespace

namespace smo::runtime {

    Result<void> ActionExecutor::execute(const NextAction& action, const Packet& original_pkt)
    {
        return std::visit(overloaded{
                              [&](const ActionDispatchMessage& msg) { return on_dispatch_message(msg, original_pkt); },
                              [&](const ActionDispatchContract& a) { return on_dispatch_contract(a, original_pkt); },
                              [&](const ActionScheduleRetry& a) { return on_schedule_retry(a, original_pkt); },
                              [&](const ActionEmitEvent& a) { return on_emit_event(a, original_pkt); },
                              [&](const ActionStoreContext&) {
                                  return Result<void>{};
                              },
                              [&](const ActionSpawnPlan& a) { return on_spawn_plan(a, original_pkt); },
                              [&](const ActionNotify& a) { return on_notify(a, original_pkt); },
                              [&](const ActionCompensate& a) { return on_compensate(a, original_pkt); },
                              [&](const ActionAbort& a) { return on_abort(a, original_pkt); },
                          },
                          action);
    }

    Result<void> ActionExecutor::on_dispatch_message(const ActionDispatchMessage& msg, const Packet& original_pkt)
    {
        Packet resp;
        resp.header = original_pkt.header;
        resp.opcode_id = original_pkt.opcode_id;
        resp.session_id() = original_pkt.session_id();
        resp.intent_id = original_pkt.intent_id;
        resp.timestamp() =
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                .count();
        resp.payload = msg.data;

        return send_response_(std::move(resp));
    }

    Result<void> ActionExecutor::on_dispatch_contract(const ActionDispatchContract& action, const Packet& original_pkt)
    {
        if (!dispatcher_)
        {
            return Result<void>(static_cast<Error>(RuntimeError::internal("Dispatcher not available for DispatchContract")));
        }

        RuntimeContext dummy_ctx;
        dummy_ctx.info.contract_id = action.contract_id;
        dummy_ctx.info.requester = local_node_id_;
        dummy_ctx.info.execution_id = generate_execution_id();

        auto res = dispatcher_->execute(action.contract_id, action.input, dummy_ctx);
        if (!res)
        {
            return Result<void>(res.error());
        }

        auto& contract_result = res.value();
        if (!contract_result.next_actions.empty())
        {
            for (const auto& next_action : contract_result.next_actions)
            {
                auto exec_res = execute(next_action, original_pkt);
                if (!exec_res)
                {
                    return exec_res;
                }
            }
        }

        return Result<void>{};
    }

    Result<void> ActionExecutor::on_schedule_retry(const ActionScheduleRetry& action, const Packet& original_pkt)
    {
        if (!scheduler_)
        {
            return Result<void>(static_cast<Error>(RuntimeError::internal("Scheduler not available for ScheduleRetry")));
        }

        Task task;
        task.task_id = "retry-" + intent_id_to_hex(original_pkt.intent_id) + "-" + std::to_string(action.delay_ns);
        task.contract_id = "system.retry";
        task.execution_id = intent_id_to_hex(original_pkt.intent_id);
        task.trace_id = session_id_to_hex(original_pkt.session_id());
        task.deadline_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                               std::chrono::system_clock::now().time_since_epoch())
                               .count() +
                           static_cast<int64_t>(action.delay_ns);
        task.max_retries = static_cast<int32_t>(action.max_retries);
        task.priority = 50;

        task.payload["original_intent_id"] = intent_id_to_hex(original_pkt.intent_id);
        task.payload["original_opcode"] = std::to_string(original_pkt.opcode_id);
        task.payload["delay_ns"] = std::to_string(action.delay_ns);
        task.payload["max_retries"] = std::to_string(action.max_retries);
        task.payload["backoff_multiplier"] = std::to_string(action.backoff_multiplier);

        auto submit_res = scheduler_->submit(task);
        if (!submit_res)
        {
            return Result<void>(submit_res.error());
        }

        emit_audit_event("RetryScheduled",
                         "Scheduled retry for intent " + intent_id_to_hex(original_pkt.intent_id) +
                             " with delay " + std::to_string(action.delay_ns) + "ns, max_retries=" + std::to_string(action.max_retries),
                         session_id_to_hex(original_pkt.session_id()),
                         intent_id_to_hex(original_pkt.intent_id),
                         "system.retry");

        return Result<void>{};
    }

    Result<void> ActionExecutor::on_spawn_plan(const ActionSpawnPlan& action, const Packet& original_pkt)
    {
        if (!dispatcher_)
        {
            return Result<void>(static_cast<Error>(RuntimeError::internal("Dispatcher/PlanResolver not available for SpawnPlan")));
        }

        RuntimeContext dummy_ctx;
        dummy_ctx.info.contract_id = action.plan_id;
        dummy_ctx.info.requester = local_node_id_;
        dummy_ctx.info.execution_id = generate_execution_id();

        for (const auto& [key, val] : action.plan_params)
        {
            dummy_ctx.vars.set(key, ContextValue(val));
        }

        auto res = dispatcher_->execute(action.plan_id, ContractInput::method_only("execute"), dummy_ctx);
        if (!res)
        {
            return Result<void>(res.error());
        }

        auto& contract_result = res.value();
        if (!contract_result.next_actions.empty())
        {
            for (const auto& next_action : contract_result.next_actions)
            {
                auto exec_res = execute(next_action, original_pkt);
                if (!exec_res)
                {
                    return exec_res;
                }
            }
        }

        emit_audit_event("PlanSpawned",
                         "Spawned plan " + action.plan_id + " with mode " + std::to_string(static_cast<int>(action.mode)),
                         session_id_to_hex(original_pkt.session_id()),
                         intent_id_to_hex(original_pkt.intent_id),
                         action.plan_id);

        return Result<void>{};
    }

    Result<void> ActionExecutor::on_emit_event(const ActionEmitEvent& action, const Packet& original_pkt)
    {
        if (event_bus_)
        {
            Event ev;
            ev.type = event_type_from_string(action.event_type);
            ev.source_id = local_node_id_;
            ev.correlation_id = session_id_to_hex(original_pkt.session_id());
            ev.execution_id = intent_id_to_hex(original_pkt.intent_id);
            ev.details = action.payload;
            ev.timestamp_ns =
                std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch())
                    .count();
            event_bus_->publish(ev);
        }

        if (event_store_)
        {
            ::smo::EventRecord record;
            record.type = static_cast<::smo::EventType>(static_cast<uint8_t>(event_type_from_string(action.event_type)));
            record.timestamp_ns =
                std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch())
                    .count();
            record.contract_id = "action_executor";
            record.execution_id = intent_id_to_hex(original_pkt.intent_id);
            record.trace_id = session_id_to_hex(original_pkt.session_id());
            record.node_id = local_node_id_;
            record.actor_id = local_node_id_;
            record.payload = action.payload;
            (void)event_store_->append(record);
        }

        if (audit_service_)
        {
            AuditEvent audit_ev;
            audit_ev.event_type = action.event_type;
            audit_ev.source_id = local_node_id_;
            audit_ev.correlation_id = session_id_to_hex(original_pkt.session_id());
            audit_ev.details = action.payload;
            audit_ev.timestamp_ns =
                std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch())
                    .count();
            audit_service_->emit(audit_ev);
        }

        return Result<void>{};
    }

    Result<void> ActionExecutor::on_notify(const ActionNotify& action, const Packet& original_pkt)
    {
        if (event_bus_)
        {
            Event ev;
            ev.type = EventType::ContractInvoked;
            ev.source_id = local_node_id_;
            ev.correlation_id = session_id_to_hex(original_pkt.session_id());
            ev.execution_id = intent_id_to_hex(original_pkt.intent_id);
            ev.details = "Notify to " + action.target + ": " + action.message;
            for (const auto& [k, v] : action.metadata)
            {
                ev.tags[k] = v;
            }
            ev.timestamp_ns =
                std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch())
                    .count();
            event_bus_->publish(ev);
        }

        emit_audit_event("NotificationSent",
                         "Notification to " + action.target + ": " + action.message,
                         session_id_to_hex(original_pkt.session_id()),
                         intent_id_to_hex(original_pkt.intent_id),
                         "action_executor");

        return Result<void>{};
    }

    Result<void> ActionExecutor::on_compensate(const ActionCompensate& action, const Packet& original_pkt)
    {
        if (!dispatcher_)
        {
            return Result<void>(static_cast<Error>(RuntimeError::internal("Dispatcher not available for Compensate")));
        }

        RuntimeContext dummy_ctx;
        dummy_ctx.info.contract_id = action.compensation_plan_id;
        dummy_ctx.info.requester = local_node_id_;
        dummy_ctx.info.execution_id = generate_execution_id();

        ContractInput cin = ContractInput::method_only("compensate");
        cin.arguments = ContextValue(action.reason);

        auto res = dispatcher_->execute(action.compensation_plan_id, cin, dummy_ctx);
        if (!res)
        {
            return Result<void>(res.error());
        }

        emit_audit_event("CompensationTriggered",
                         "Triggered compensation plan " + action.compensation_plan_id + " for reason: " + action.reason,
                         session_id_to_hex(original_pkt.session_id()),
                         intent_id_to_hex(original_pkt.intent_id),
                         action.compensation_plan_id);

        return Result<void>{};
    }

    Result<void> ActionExecutor::on_abort(const ActionAbort& action, const Packet& original_pkt)
    {
        if (action.trigger_compensation && dispatcher_)
        {
            RuntimeContext dummy_ctx;
            dummy_ctx.info.contract_id = "system.compensation";
            dummy_ctx.info.requester = local_node_id_;
            dummy_ctx.info.execution_id = generate_execution_id();

            ContractInput cin = ContractInput::method_only("abort");
            cin.arguments = ContextValue(action.reason);

            (void)dispatcher_->execute("system.compensation", cin, dummy_ctx);
        }

        emit_audit_event("ExecutionAborted",
                         "Aborted execution for intent " + intent_id_to_hex(original_pkt.intent_id) + ": " + action.reason,
                         session_id_to_hex(original_pkt.session_id()),
                         intent_id_to_hex(original_pkt.intent_id),
                         "action_executor");

        return Result<void>{};
    }

    Result<void> ActionExecutor::emit_audit_event(const std::string& event_type, const std::string& details,
                                                  const std::string& correlation_id,
                                                  const std::string& execution_id,
                                                  const std::string& contract_id)
    {
        if (audit_service_)
        {
            AuditEvent audit_ev;
            audit_ev.event_type = event_type;
            audit_ev.source_id = local_node_id_;
            audit_ev.correlation_id = correlation_id;
            audit_ev.details = details;
            audit_ev.timestamp_ns =
                std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch())
                    .count();
            audit_service_->emit(audit_ev);
        }
        return Result<void>{};
    }

    uint64_t ActionExecutor::generate_execution_id()
    {
        static std::atomic<uint64_t> counter{1};
        return counter.fetch_add(1);
    }

} // namespace smo::runtime