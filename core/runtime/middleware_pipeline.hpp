#pragma once

#include "core/errors/error.hpp"
#include "core/session/session.hpp"
#include "core/types.hpp"

#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace smo::runtime {

// Context passed through each middleware in the packet pipeline.
// NOT the same as runtime_types MiddlewareContext (kernel execution).
struct PacketContext {
    const Session* session = nullptr;      // validated session (null if anonymous)
    std::string contract_id;               // resolved from opcode
    std::string method;                    // method within contract
    BytesView payload;                     // raw packet payload
    std::string opcode_hex;               // for audit/debug

    // Policy decision output
    bool denied = false;
    std::string deny_reason;
    bool audit = false;
    bool sandbox = false;
    bool ratelimit = false;
};

// Middleware interface: each middleware inspects/transforms context.
// Return error to DENY, success to continue chain.
class Middleware {
public:
    virtual ~Middleware() = default;
    virtual Result<void> process(PacketContext& ctx) = 0;
    virtual std::string name() const = 0;
};

// Pluggable middleware pipeline.
// Usage:
//   MiddlewarePipeline pipeline;
//   pipeline.push<PolicyMiddleware>(policy_engine);
//   pipeline.push<AuditMiddleware>(audit_log);
//   bool ok = pipeline.process(ctx);
class MiddlewarePipeline {
public:
    void push(std::unique_ptr<Middleware> mw);
    void clear();

    // Process context through all middlewares in order.
    // Returns error if any middleware denies.
    Result<void> process(PacketContext& ctx);

private:
    std::vector<std::unique_ptr<Middleware>> middlewares_;
};

} // namespace smo::runtime