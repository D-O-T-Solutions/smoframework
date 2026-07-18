#include "runtime_bridge.hpp"
#include "runtime_kernel.hpp"

#include <chrono>
#include <random>

namespace smo::runtime {

void RuntimeBridge::register_route(uint32_t opcode_id,
                                    std::string contract_id,
                                    std::string method) {
    routes_[opcode_id] = OpcodeRoute{
        std::move(contract_id),
        std::move(method)
    };
}

void RuntimeBridge::set_anonymous(const std::string& contract_id, bool anonymous) {
    auth_mgr_.set_anonymous(contract_id, anonymous);
}

const OpcodeRoute* RuntimeBridge::resolve(uint32_t opcode_id) const {
    auto it = routes_.find(opcode_id);
    return it != routes_.end() ? &it->second : nullptr;
}

Result<RuntimeResult> RuntimeBridge::bridge(Packet&& pkt) {
    // 1. Resolve opcode → route
    auto* route = resolve(pkt.opcode_id);
    if (!route) {
        return Result<RuntimeResult>(
            static_cast<Error>(RuntimeError::not_found(
                "unknown opcode: " + std::to_string(pkt.opcode_id))));
    }

    // 2. ── Authorization ────────────────────────────────────────
    //    Parse session_id from packet (first 16 bytes)
    SessionId session_id;
    bool has_session = pkt.session_id.size() >= 16;
    if (has_session) {
        auto sid_res = SessionId::from_bytes(
            BytesView(pkt.session_id.data(), 16));
        if (!sid_res) {
            return Result<RuntimeResult>(
                static_cast<Error>(RuntimeError::unauthorized(
                    "invalid session_id in packet")));
        }
        session_id = std::move(sid_res.value());
    }

    //    Get contract metadata for capability check
    const ContractMetadata* meta = dispatcher_.get_metadata(route->contract_id);
    if (!meta) {
        return Result<RuntimeResult>(
            static_cast<Error>(RuntimeError::not_found(
                "no metadata for contract: " + route->contract_id)));
    }

    //    Only check authorization if a session_id is present
    if (has_session) {
        auto auth_res = auth_mgr_.authorize(session_id, *meta);
        if (!auth_res) {
            return Result<RuntimeResult>(
                static_cast<Error>(RuntimeError::unauthorized(
                    "authorization denied: " + auth_res.error().message)));
        }
    } else if (!auth_mgr_.is_anonymous(route->contract_id)) {
        // No session but contract requires authorization → deny
        return Result<RuntimeResult>(
            static_cast<Error>(RuntimeError::unauthorized(
                "session required for: " + route->contract_id)));
    }

    // 3. Build RuntimeRequest from packet
    RuntimeRequest req;
    req.contract_id = route->contract_id;
    if (has_session) {
        req.requester = bytes_to_hex(pkt.session_id);
    }
    req.input.method = route->method;
    // Fix: pass payload as Bytes (not string) — contracts expect Bytes
    req.input.arguments = ContextValue(
        Bytes(pkt.payload.begin(), pkt.payload.end()));

    // 4. Execute via RuntimeKernel (direct path, no plan/middleware)
    return kernel_.execute_direct(req);
}

} // namespace smo::runtime
