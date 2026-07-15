#pragma once

#include <cstdint>
#include <vector>
#include <span>

namespace smo {

// Serialization interface for packet payloads.
// MVP uses JSON (simdjson for zero-copy parsing).
// Future: FlatBuffers, Cap'n Proto, or custom binary.

// Serialize a value to JSON bytes.
template <typename T>
std::vector<uint8_t> serialize(const T& value);

// Deserialize JSON bytes to a value.
// Returns nullopt on parse failure.
template <typename T>
T deserialize(std::span<const uint8_t> data);

} // namespace smo
