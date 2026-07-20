#pragma once

#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <span>
#include <string>
#include <vector>

namespace smo {

using Bytes       = std::vector<uint8_t>;
using BytesView   = std::span<const uint8_t>;
using BytesMutView = std::span<uint8_t>;

// ---------------------------------------------------------------------------
// Hex encoding
// ---------------------------------------------------------------------------
inline std::string bytes_to_hex(BytesView data) {
    std::ostringstream oss;
    for (uint8_t b : data)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return oss.str();
}

// ---------------------------------------------------------------------------
// Base64 encoding (standard, with padding)
// ---------------------------------------------------------------------------
inline std::string bytes_to_base64(BytesView data) {
    static const char kEnc[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                               "abcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    for (size_t i = 0; i < data.size(); i += 3) {
        uint32_t v = (uint32_t)data[i] << 16;
        if (i + 1 < data.size()) v |= (uint32_t)data[i + 1] << 8;
        if (i + 2 < data.size()) v |= (uint32_t)data[i + 2];
        out += kEnc[(v >> 18) & 0x3f];
        out += kEnc[(v >> 12) & 0x3f];
        out += kEnc[(v >> 6) & 0x3f];
        out += kEnc[v & 0x3f];
    }
    // Padding
    size_t pad = (3 - data.size() % 3) % 3;
    for (size_t i = 0; i < pad; ++i) out[out.size() - 1 - i] = '=';
    return out;
}

// ---------------------------------------------------------------------------
// SeedInfo — bootstrap seed endpoint with metadata for smart seed selection.
// Client uses weighted random for selection.
// ---------------------------------------------------------------------------
struct SeedInfo {
    std::string endpoint;          // "host:port"
    std::string region;            // "us-east-1", "ap-southeast-1", etc.
    uint32_t    weight = 100;      // relative weight for weighted random selection
    double      health_score = 1.0; // 0.0–1.0 (from health monitor)
};

} // namespace smo
