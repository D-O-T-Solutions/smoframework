#pragma once

#include "../types.hpp"
#include "../errors/error.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace smo {

    // Forward declaration — full definition in core/crypto/impl.hpp.
    struct HashImpl;

    // ── SessionId ────────────────────────────────────────────────────────
    // Canonical 128-bit session identifier — single source of truth shared by
    // Session/SessionManager, ACL/storage, and the G3 security layer.
    // Value type: 16 bytes, trivially copyable, comparable.
    struct SessionId
    {
        static constexpr size_t kSize = 16;
        std::array<uint8_t, kSize> bytes{};

        bool operator==(const SessionId& other) const noexcept = default;
        bool operator!=(const SessionId& other) const noexcept = default;

        bool is_zero() const noexcept;

        Bytes to_bytes() const;
        static Result<SessionId> from_bytes(BytesView data);

        // Convert to hex string
        std::string to_hex() const;

        // Derive from a byte sequence (e.g., Blake3(peer_pubkey || nonce))
        static Result<SessionId> derive(BytesView seed, const HashImpl& hash);
    };

} // namespace smo
