#pragma once

#include "core/runtime/output_manager.hpp"
#include "core/runtime/runtime_kernel.hpp"
#include "core/runtime/runtime_bridge.hpp"
#include "core/runtime/dispatcher.hpp"
#include "core/runtime/event_bus.hpp"
#include "core/errors/error.hpp"

namespace smo::runtime {

class RuntimeKernelService
{
public:
    struct Dependencies
    {
        EventBus& event_bus;
        OutputManager& output_mgr;
        Dispatcher& dispatcher;
        PlanResolver& plan_resolver;
    };

    RuntimeKernelService(Dependencies deps);

    Result<void> initialize();
    void tick(int64_t now_ns);
    void shutdown();

    RuntimeKernel& kernel() { return kernel_; }
    RuntimeBridge& bridge() { return bridge_; }

private:
    RuntimeKernel kernel_;
    RuntimeBridge bridge_;
};

} // namespace smo::runtime