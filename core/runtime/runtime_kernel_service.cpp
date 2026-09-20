#include "core/runtime/runtime_kernel_service.hpp"

namespace smo::runtime {

RuntimeKernelService::RuntimeKernelService(Dependencies deps)
    : kernel_(deps.event_bus, deps.output_mgr, deps.dispatcher, deps.plan_resolver)
    , bridge_(kernel_, deps.dispatcher)
{
}

Result<void> RuntimeKernelService::initialize()
{
    return {};
}

void RuntimeKernelService::tick(int64_t now_ns)
{
    (void)now_ns;
    // No periodic tick needed for runtime kernel currently
}

void RuntimeKernelService::shutdown()
{
    // Nothing to do for now
}

} // namespace smo::runtime