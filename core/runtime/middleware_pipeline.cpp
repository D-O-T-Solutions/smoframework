#include "middleware_pipeline.hpp"

namespace smo::runtime {

void MiddlewarePipeline::push(std::unique_ptr<Middleware> mw) {
    middlewares_.push_back(std::move(mw));
}

void MiddlewarePipeline::clear() {
    middlewares_.clear();
}

Result<void> MiddlewarePipeline::process(PacketContext& ctx) {
    for (auto& mw : middlewares_) {
        auto res = mw->process(ctx);
        if (!res) return res;
        if (ctx.denied) {
            return Error(
                ErrorCode(ErrorCategory::Session, 507,
                          Severity::Error, RetryClass::NoRetry,
                          Recovery::None),
                ctx.deny_reason.empty()
                    ? "denied by " + mw->name()
                    : ctx.deny_reason,
                __FILE__, __LINE__);
        }
    }
    return {};
}

} // namespace smo::runtime