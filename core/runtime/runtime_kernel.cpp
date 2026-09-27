#include "runtime_kernel.hpp"
#include "runtime_context.hpp"
#include "dispatcher.hpp"
#include "output_manager.hpp"
#include "event_bus.hpp"
#include "middleware.hpp"
#include "plan_executor.hpp"
#include "runtime/workerpool/workerpool.hpp"

#include <chrono>
#include <random>
#include <future>

namespace smo::runtime {

    using smo::Result;
    using smo::WorkerPool;

    // Global worker pool for async execution (could be injected in future)
    static WorkerPool* g_worker_pool = nullptr;

    RuntimeKernel::RuntimeKernel(EventBus& bus, OutputManager& output_mgr, Dispatcher& dispatcher,
                                 PlanResolver& resolver)
        : event_bus_(bus), output_mgr_(output_mgr), dispatcher_(dispatcher), resolver_(resolver)
    {
        // Initialize global worker pool on first use
        static WorkerPool global_worker_pool(4);
        g_worker_pool = &global_worker_pool;
    }

    // ── Public API ────────────────────────────────────────────────────────

    Result<RuntimeResult> RuntimeKernel::execute(const RuntimeRequest& req)
    {
        auto start = std::chrono::steady_clock::now();

        last_plan_output_.reset();

        RuntimeContext ctx;
        if (req.context)
        {
            ctx = *req.context;
        }
        ctx.info.execution_id = generate_execution_id();
        ctx.info.started_at_ns =
            std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch())
                .count();
        ctx.info.contract_id = req.contract_id;
        ctx.info.requester = req.requester;

        SMO_TRY(validate(req, ctx));
        SMO_TRY(resolve(req, ctx));

        SMO_TRY(execute_plan(req, ctx));

        SMO_TRY(dispatch(req, ctx));

        SMO_TRY(collect(ctx));
        SMO_TRY(aggregate(ctx));
        SMO_TRY(audit(ctx, true));
        SMO_TRY(complete(ctx));

        output_mgr_.add_result("local", "test", "test", "success", "");

        auto elapsed =
            std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - start).count();

        RuntimeResult result;
        result.execution_id = std::to_string(ctx.info.execution_id);
        result.status = RuntimeResult::Status::Success;
        result.elapsed_ns = elapsed;

        // Carry the plan's contract output + next_actions to the caller so a
        // transport layer can build a response packet from the real result.
        if (last_plan_output_)
        {
            result.output = *last_plan_output_;
            result.next_actions = last_plan_output_->next_actions;
            result.metrics = last_plan_output_->metrics;
            result.status = (last_plan_output_->status == ContractResult::Status::Success)
                                ? RuntimeResult::Status::Success
                                : RuntimeResult::Status::Error;
            last_plan_output_.reset();
        }

        return result;
    }

    Result<std::string> RuntimeKernel::execute_async(const RuntimeRequest& req)
    {
        // Generate execution ID upfront
        uint64_t exec_id_num = generate_execution_id();
        std::string execution_id = "exec_" + std::to_string(exec_id_num);

        // Create async execution tracking entry
        auto async_exec = std::make_unique<AsyncExecution>();
        async_exec->state = AsyncExecution::State::Pending;
        async_exec->started_at_ns =
            std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch())
                .count();

        // Submit to worker pool
        auto promise = std::make_shared<std::promise<RuntimeResult>>();
        async_exec->future = promise->get_future();

        // Store the async execution (need to copy execution_id for the lambda)
        std::string exec_id_copy = execution_id;
        {
            std::lock_guard<std::mutex> lock(async_mutex_);
            async_executions_[execution_id] = std::move(async_exec);
        }

        // Submit task to worker pool
        auto task = [this, req, exec_id_copy, promise]() -> Result<void> {
            // Update state to running
            {
                std::lock_guard<std::mutex> lock(async_mutex_);
                auto it = async_executions_.find(exec_id_copy);
                if (it != async_executions_.end())
                {
                    it->second->state = AsyncExecution::State::Running;
                }
            }

            // Execute the request synchronously in the worker thread
            RuntimeResult result;
            try
            {
                auto exec_result = execute(req);
                if (exec_result)
                {
                    result = exec_result.value();
                    result.execution_id = exec_id_copy;
                }
                else
                {
                    result.status = RuntimeResult::Status::Error;
                    result.error = RuntimeError::internal(exec_result.error().message);
                    result.execution_id = exec_id_copy;
                }
            }
            catch (const std::exception& e)
            {
                result.status = RuntimeResult::Status::Error;
                result.error = RuntimeError::internal(std::string("Exception: ") + e.what());
                result.execution_id = exec_id_copy;
            }

            // Update completion state
            {
                std::lock_guard<std::mutex> lock(async_mutex_);
                auto it = async_executions_.find(exec_id_copy);
                if (it != async_executions_.end())
                {
                    it->second->result = result;
                    it->second->completed_at_ns =
                        std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::steady_clock::now().time_since_epoch()).count();
                    if (result.status == RuntimeResult::Status::Success)
                    {
                        it->second->state = AsyncExecution::State::Completed;
                    }
                    else
                    {
                        it->second->state = AsyncExecution::State::Failed;
                    }
                }
            }

            // Fulfill the promise
            promise->set_value(result);
            return {};
        };

        if (g_worker_pool)
        {
            auto submit_res = g_worker_pool->submit(execution_id, std::move(task));
            if (!submit_res)
            {
                // Clean up on submit failure
                std::lock_guard<std::mutex> lock(async_mutex_);
                async_executions_.erase(execution_id);
                return Result<std::string>(submit_res.error());
            }
        }
        else
        {
            // Fallback: execute synchronously if no worker pool
            auto exec_result = execute(req);
            if (!exec_result)
            {
                std::lock_guard<std::mutex> lock(async_mutex_);
                async_executions_.erase(execution_id);
                return Result<std::string>(exec_result.error());
            }
            // Update state immediately
            {
                std::lock_guard<std::mutex> lock(async_mutex_);
                auto it = async_executions_.find(execution_id);
                if (it != async_executions_.end())
                {
                    it->second->result = exec_result.value();
                    it->second->result.execution_id = execution_id;
                    it->second->state = AsyncExecution::State::Completed;
                    it->second->completed_at_ns =
                        std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::steady_clock::now().time_since_epoch()).count();
                }
            }
            promise->set_value(exec_result.value());
        }

        return execution_id;
    }

    Result<RuntimeResult> RuntimeKernel::get_async_result(const std::string& execution_id)
    {
        std::shared_ptr<std::promise<RuntimeResult>> promise_ptr;
        AsyncExecution* async_exec = nullptr;

        {
            std::lock_guard<std::mutex> lock(async_mutex_);
            auto it = async_executions_.find(execution_id);
            if (it == async_executions_.end())
            {
                return Result<RuntimeResult>(static_cast<Error>(RuntimeError::not_found("async execution not found: " + execution_id)));
            }
            async_exec = it->second.get();
        }

        // Wait for the future to complete (with a reasonable timeout for polling)
        if (async_exec->future.valid())
        {
            auto status = async_exec->future.wait_for(std::chrono::milliseconds(0));
            if (status == std::future_status::ready)
            {
                return async_exec->future.get();
            }
            else
            {
                // Still running - return pending status
                RuntimeResult pending_result;
                pending_result.execution_id = execution_id;
                pending_result.status = RuntimeResult::Status::Pending;
                return pending_result;
            }
        }

        // Future not valid - return stored result
        return async_exec->result;
    }

    Result<void> RuntimeKernel::cancel_async(const std::string& execution_id)
    {
        std::lock_guard<std::mutex> lock(async_mutex_);
        auto it = async_executions_.find(execution_id);
        if (it == async_executions_.end())
        {
            return Result<void>(static_cast<Error>(RuntimeError::not_found("async execution not found: " + execution_id)));
        }

        auto& exec = *it->second;
        if (exec.state == AsyncExecution::State::Completed ||
            exec.state == AsyncExecution::State::Failed ||
            exec.state == AsyncExecution::State::Cancelled)
        {
            return Result<void>(static_cast<Error>(RuntimeError::internal("execution already in terminal state")));
        }

        exec.state = AsyncExecution::State::Cancelled;
        exec.completed_at_ns =
            std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();

        // Note: We can't actually cancel a running std::future/task in C++ without
        // cooperative cancellation. The task will complete but its result will be ignored.
        // For true cancellation, we'd need a cancellation token passed to execute().

        return {};
    }

    Result<AsyncExecution::State> RuntimeKernel::get_async_state(const std::string& execution_id)
    {
        std::lock_guard<std::mutex> lock(async_mutex_);
        auto it = async_executions_.find(execution_id);
        if (it == async_executions_.end())
        {
            return Result<AsyncExecution::State>(static_cast<Error>(RuntimeError::not_found("async execution not found: " + execution_id)));
        }
        return it->second->state;
    }

    // ── Pipeline Stages ─────────────────────────────────────────────────

    Result<RuntimeResult> RuntimeKernel::validate(const RuntimeRequest& req, RuntimeContext& ctx)
    {
        if (req.contract_id.empty())
        {
            return Result<RuntimeResult>(static_cast<Error>(RuntimeError::validation("empty contract_id")));
        }
        if (!dispatcher_.has_contract(req.contract_id))
        {
            return Result<RuntimeResult>(
                static_cast<Error>(RuntimeError::not_found("contract not registered: " + req.contract_id)));
        }

        auto* contract = dispatcher_.get_contract(req.contract_id);
        if (contract)
        {
            auto val_res = contract->validate(req.input);
            if (!val_res)
            {
                return Result<RuntimeResult>(static_cast<Error>(
                    RuntimeError::validation("input validation failed: " + val_res.error().message)));
            }
        }

        return RuntimeResult{RuntimeResult::Status::Success};
    }

    Result<RuntimeResult> RuntimeKernel::resolve(const RuntimeRequest& req, RuntimeContext& ctx)
    {
        auto plan_res = resolver_.resolve(req.contract_id);
        if (!plan_res)
        {
            return Result<RuntimeResult>(plan_res.error());
        }

        // Copy plan context into Variables
        for (const auto& [key, val] : plan_res.value().context)
        {
            ctx.vars.set(key, ContextValue(val));
        }

        auto val_res = plan_res.value().validate();
        if (!val_res)
        {
            return Result<RuntimeResult>(val_res.error());
        }

        return RuntimeResult{RuntimeResult::Status::Success};
    }

    // ── Pipeline Stages ─────────────────────────────────────────────────

    Result<RuntimeResult> RuntimeKernel::execute_plan(const RuntimeRequest& req, RuntimeContext& ctx)
    {
        // Re-resolve plan from vars
        auto plan_res = resolver_.resolve(req.contract_id);
        if (!plan_res)
        {
            return Result<RuntimeResult>(plan_res.error());
        }

        ExecutionPlan plan = std::move(plan_res).value();

        PlanContext plan_ctx;
        plan_ctx.request_id = req.request_id;
        plan_ctx.plan_id = plan.plan_id;
        plan_ctx.execution_id = std::to_string(ctx.info.execution_id);
        plan_ctx.deadline_ns = req.deadline_ns;
        plan_ctx.event_bus = &event_bus_;
        plan_ctx.dispatcher = &dispatcher_;
        plan_ctx.output = &output_mgr_;
        plan_ctx.services = &ctx.services;
        for (const auto& [key, val] : plan.context)
        {
            plan_ctx.context[key] = val;
        }

        // Use the method and arguments from the request (extracted by RuntimeBridge)
        // instead of the hardcoded "invoke" + template.
        const std::string& request_method = req.input.method;
        const ContextValue& request_args = req.input.arguments;

        PlanExecutor executor(plan, [&](const Step& step, PlanContext& pctx) -> PlanExecutor::StepResult {
            (void)pctx; // unused: we use request's method/args directly

            ContractInput cin;
            cin.method = request_method.empty() ? "invoke" : request_method;
            cin.arguments = request_args;

            auto* contract = dispatcher_.get_contract(step.contract_id);
            if (!contract)
            {
                return PlanExecutor::StepResult{
                    false, {}, RuntimeError::not_found("contract not found: " + step.contract_id)};
            }

            auto res = contract->execute(cin, ctx);
            if (!res)
            {
                return PlanExecutor::StepResult{false, {}, RuntimeError::internal(res.error().message)};
            }

            // Capture the raw contract result for response delivery downstream.
            last_plan_output_ = res.value();
            return PlanExecutor::StepResult{true, std::move(res).value(), {}};
        });

        auto result = executor.execute(plan_ctx);

        if (!result.success)
        {
            return Result<RuntimeResult>(static_cast<Error>(result.error));
        }

        for (const auto& [key, val] : result.outputs)
        {
            ctx.vars.set(key, ContextValue(val));
        }

        return RuntimeResult{RuntimeResult::Status::Success};
    }

    Result<RuntimeResult> RuntimeKernel::dispatch(const RuntimeRequest& req, RuntimeContext& ctx)
    {
        (void)req;
        (void)ctx;
        return RuntimeResult{};
    }

    Result<RuntimeResult> RuntimeKernel::collect(RuntimeContext& ctx)
    {
        (void)ctx;
        return RuntimeResult{RuntimeResult::Status::Success};
    }

    Result<RuntimeResult> RuntimeKernel::aggregate(RuntimeContext& ctx)
    {
        output_mgr_.add_result(ctx.info.node_id, ctx.info.contract_id, std::to_string(ctx.info.execution_id), "success",
                               "");
        return RuntimeResult{RuntimeResult::Status::Success};
    }

    Result<RuntimeResult> RuntimeKernel::audit(RuntimeContext& ctx, bool success, const std::string& error)
    {
        (void)ctx;
        (void)success;
        (void)error;
        return RuntimeResult{RuntimeResult::Status::Success};
    }

    Result<RuntimeResult> RuntimeKernel::complete(RuntimeContext& ctx)
    {
        (void)ctx;
        return RuntimeResult{RuntimeResult::Status::Success};
    }

    uint64_t RuntimeKernel::generate_execution_id()
    {
        static std::atomic<uint64_t> counter{1};
        return counter.fetch_add(1);
    }

} // namespace smo::runtime
