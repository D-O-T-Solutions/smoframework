#include "runtime_bridge.hpp"

#include <chrono>
#include <cctype>
#include <string>
#include <unordered_map>

namespace smo::runtime {

    // ── Simple JSON parser for payload ──────────────────────────────────────
    // Expected format: {"method": "list", "key": "value", ...}
    // Returns pair<method, arguments_map>
    static Result<std::pair<std::string, std::unordered_map<std::string, std::string>>> parse_payload(BytesView payload)
    {
        std::string json(reinterpret_cast<const char*>(payload.data()), payload.size());

        // Find "method" field
        const std::string method_key = "\"method\"";
        size_t method_pos = json.find(method_key);
        if (method_pos == std::string::npos)
        {
            return Result<std::pair<std::string, std::unordered_map<std::string, std::string>>>(
                static_cast<Error>(RuntimeError::validation("payload missing 'method' field")));
        }

        // Find the value after "method":
        size_t colon = json.find(':', method_pos);
        if (colon == std::string::npos)
        {
            return Result<std::pair<std::string, std::unordered_map<std::string, std::string>>>(
                static_cast<Error>(RuntimeError::validation("invalid payload format: missing colon after method")));
        }

        // Skip whitespace
        size_t val_start = colon + 1;
        while (val_start < json.size() && std::isspace(static_cast<unsigned char>(json[val_start])))
            ++val_start;

        if (val_start >= json.size() || json[val_start] != '"')
        {
            return Result<std::pair<std::string, std::unordered_map<std::string, std::string>>>(
                static_cast<Error>(RuntimeError::validation("method value must be a string")));
        }

        size_t val_end = json.find('"', val_start + 1);
        if (val_end == std::string::npos)
        {
            return Result<std::pair<std::string, std::unordered_map<std::string, std::string>>>(
                static_cast<Error>(RuntimeError::validation("unterminated method string")));
        }

        std::string method = json.substr(val_start + 1, val_end - val_start - 1);

        // Parse remaining key-value pairs as arguments
        std::unordered_map<std::string, std::string> args;

        // Simple parsing: find all "key": "value" pairs
        size_t pos = 0;
        while (true)
        {
            pos = json.find('"', pos);
            if (pos == std::string::npos)
                break;
            size_t key_start = pos;
            size_t key_end = json.find('"', pos + 1);
            if (key_end == std::string::npos)
                break;
            std::string key = json.substr(key_start + 1, key_end - key_start - 1);

            pos = key_end + 1;
            // Skip whitespace and colon
            while (pos < json.size() && (std::isspace(static_cast<unsigned char>(json[pos])) || json[pos] == ':'))
                ++pos;
            if (pos >= json.size() || json[pos] != '"')
            {
                pos = key_end + 1;
                continue;
            }

            size_t val_start = pos;
            size_t val_end = json.find('"', val_start + 1);
            if (val_end == std::string::npos)
                break;
            std::string value = json.substr(val_start + 1, val_end - val_start - 1);

            if (key != "method") // Skip the method field itself
                args[key] = value;

            pos = val_end + 1;
        }

        return std::make_pair(std::move(method), std::move(args));
    }

    void RuntimeBridge::register_route(uint32_t opcode_id, std::string contract_id, std::string method)
    {
        routes_[opcode_id] = OpcodeRoute{std::move(contract_id), std::move(method)};
    }

    const OpcodeRoute* RuntimeBridge::resolve(uint32_t opcode_id) const
    {
        auto it = routes_.find(opcode_id);
        return it != routes_.end() ? &it->second : nullptr;
    }

    Result<RuntimeResult> RuntimeBridge::bridge(Packet&& pkt)
    {
        auto* route = resolve(pkt.opcode_id);
        if (!route)
        {
            return Result<RuntimeResult>(
                static_cast<Error>(RuntimeError::not_found("unknown opcode: " + std::to_string(pkt.opcode_id))));
        }

        // Parse payload to extract method and arguments
        auto parsed = parse_payload(BytesView(pkt.payload.data(), pkt.payload.size()));
        if (!parsed)
        {
            return Result<RuntimeResult>(parsed.error());
        }

        RuntimeRequest req;
        req.contract_id = route->contract_id;
        req.input.method = parsed.value().first;                   // extracted method
        req.input.arguments = ContextValue(parsed.value().second); // arguments map

        return kernel_.execute(req);
    }

} // namespace smo::runtime