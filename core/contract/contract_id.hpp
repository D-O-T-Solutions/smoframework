#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <array>
#include <cstdio>
#include <functional>
#include <cstring>
#include <random>
#include "core/types.hpp"
#include "core/errors/error.hpp"
#include "core/crypto/hash_provider.hpp"

namespace smo {

// ===========================================================================
// Contract ID
// ===========================================================================

struct ContractID {
    std::array<uint8_t, 32> bytes{};

    ContractID() = default;

    explicit ContractID(const std::array<uint8_t, 32>& b) : bytes(b) {}

    bool operator==(const ContractID& other) const noexcept = default;
    bool operator!=(const ContractID& other) const noexcept = default;
    auto operator<=>(const ContractID& other) const noexcept = default;

    std::string to_hex() const {
        char buf[65];
        for (size_t i = 0; i < 32; ++i) {
            std::snprintf(&buf[i*2], 3, "%02x", bytes[i]);
        }
        return std::string(buf, 64);
    }

    const uint8_t* data() const noexcept { return bytes.data(); }
    const uint8_t* begin() const noexcept { return bytes.data(); }
    const uint8_t* end() const noexcept { return bytes.data() + 32; }

    bool empty() const noexcept {
        return std::all_of(bytes.begin(), bytes.end(), [](uint8_t v) { return v == 0; });
    }

    explicit operator bool() const noexcept { return !empty(); }

    const std::array<uint8_t, 32>& value() const noexcept { return bytes; }

    static ContractID compute(std::string_view data) {
        ContractID id;
        auto& hp = HashProvider::default_provider();
        auto raw = hp.hash(data);
        if (raw.size() >= 32) {
            std::copy(raw.begin(), raw.begin() + 32, id.bytes.begin());
        }
        return id;
    }

    static Result<ContractID> compute_result(std::string_view data) {
        ContractID id;
        auto& hp = HashProvider::default_provider();
        auto raw = hp.hash(data);
        if (raw.size() < 32) {
            return SMO_ERR(Crypto, 100, Error, NoRetry, None, "hash output too short");
        }
        std::copy(raw.begin(), raw.begin() + 32, id.bytes.begin());
        return id;
    }

    static ContractID from_hex(std::string_view hex) {
        ContractID id;
        if (hex.size() != 64) return id;
        for (size_t i = 0; i < 32; ++i) {
            std::string byte_str(hex.substr(i*2, 2));
            id.bytes[i] = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
        }
        return id;
    }

    static Result<ContractID> from_hex_checked(std::string_view hex) {
        if (hex.size() != 64) {
            return SMO_ERR(Contract, 100, Error, NoRetry, None, "Invalid hex length for ContractID");
        }
        ContractID id;
        for (size_t i = 0; i < 32; ++i) {
            std::string byte_str(hex.substr(i*2, 2));
            id.bytes[i] = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
        }
        return id;
    }

    static bool is_valid_hex(std::string_view h) noexcept {
        if (h.size() != 64) return false;
        for (char c : h) {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                return false;
        }
        return true;
    }
};

inline std::ostream& operator<<(std::ostream& os, const ContractID& id) {
    return os << id.to_hex();
}

// ===========================================================================
// Execution ID
// ===========================================================================

struct ExecutionID {
    std::array<uint8_t, 32> bytes{};

    ExecutionID() = default;
    explicit ExecutionID(const std::array<uint8_t, 32>& b) : bytes(b) {}

    bool operator==(const ExecutionID& other) const noexcept = default;
    bool operator!=(const ExecutionID& other) const noexcept = default;
    auto operator<=>(const ExecutionID& other) const noexcept = default;

    std::string to_hex() const {
        char buf[65];
        for (size_t i = 0; i < 32; ++i) {
            std::snprintf(&buf[i*2], 3, "%02x", bytes[i]);
        }
        return std::string(buf, 64);
    }

    static ExecutionID generate(const ContractID& contract_id,
                                const std::string& requester_id,
                                const std::vector<std::string>& selected_nodes,
                                int64_t timestamp_ns) {
        std::string canonical = "EXEC|";
        canonical += "CID:" + contract_id.to_hex() + "|";
        canonical += "REQ:" + requester_id + "|";
        canonical += "NODES:" + std::to_string(selected_nodes.size()) + "|";
        canonical += "TS:" + std::to_string(timestamp_ns) + "|";
        canonical += "NONCE:" + std::to_string(std::rand());

        auto& hp = HashProvider::default_provider();
        auto raw = hp.hash(canonical);
        ExecutionID id;
        if (raw.size() >= 32) {
            std::copy(raw.begin(), raw.begin() + 32, id.bytes.begin());
        }
        return id;
    }
};

// ===========================================================================
// Trace ID
// ===========================================================================

struct TraceID {
    std::array<uint8_t, 32> bytes{};

    TraceID() = default;
    explicit TraceID(const std::array<uint8_t, 32>& b) : bytes(b) {}

    bool operator==(const TraceID& other) const noexcept = default;
    bool operator!=(const TraceID& other) const noexcept = default;
    auto operator<=>(const TraceID& other) const noexcept = default;

    std::string to_hex() const {
        char buf[65];
        for (size_t i = 0; i < 32; ++i) {
            std::snprintf(&buf[i*2], 3, "%02x", bytes[i]);
        }
        return std::string(buf, 64);
    }

    static TraceID generate() {
        std::string canonical = "TRACE|" +
            std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) +
            "|" + std::to_string(std::rand());

        auto& hp = HashProvider::default_provider();
        auto raw = hp.hash(canonical);
        TraceID id;
        if (raw.size() >= 32) {
            std::copy(raw.begin(), raw.begin() + 32, id.bytes.begin());
        }
        return id;
    }
};

} // namespace smo

namespace std {
template<>
struct hash<smo::ContractID> {
    size_t operator()(const smo::ContractID& id) const noexcept {
        size_t h = 0;
        for (size_t i = 0; i < 32; i += sizeof(size_t)) {
            size_t v = 0;
            size_t copy = std::min(sizeof(size_t), static_cast<size_t>(32 - i));
            std::memcpy(&v, id.bytes.data() + i, copy);
            h ^= v + 0x9e3779b9 + (h << 6) + (h >> 2);
        }
        return h;
    }
};
} // namespace std