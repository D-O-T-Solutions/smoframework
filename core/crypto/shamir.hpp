#pragma once

#include "core/crypto/fwd.hpp"
#include "core/crypto/impl.hpp"
#include "core/errors/error.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace smo {
    namespace crypto {

        // Shamir Secret Sharing (M-of-N threshold)
        //
        // Field: GF(256) with irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11D)
        // Shares are (x, y) pairs where x ∈ [1..255], y ∈ GF(256)
        // Secret is the constant term of a degree-(M-1) polynomial.
        //
        // Each share is encoded as 33 bytes: [index(1)][y-coordinate(32)]
        // This allows sharing a 32-byte secret (e.g., AES-256 key, Ed25519 seed).

        struct ShamirShare
        {
            uint8_t index;   // Share index (x-coordinate), 1..N
            Bytes y;         // y-coordinate (32 bytes for 256-bit secret)

            Result<Bytes> serialize() const;
            static Result<ShamirShare> deserialize(BytesView data);
        };

        // Split a 32-byte secret into N shares with threshold M.
        // Returns vector of N shares. Caller must ensure M <= N <= 255.
        Result<std::vector<ShamirShare>> shamir_split(BytesView secret, uint8_t N, uint8_t M, RngRef& rng);

        // Recover secret from at least M shares.
        // shares.size() >= M required. Returns 32-byte secret.
        Result<Bytes> shamir_recover(const std::vector<ShamirShare>& shares, uint8_t M);

        // Internal: GF(256) arithmetic
        namespace shamir_detail {
            uint8_t gf_add(uint8_t a, uint8_t b) noexcept;
            uint8_t gf_mul(uint8_t a, uint8_t b) noexcept;
            uint8_t gf_pow(uint8_t a, int n) noexcept;
            uint8_t gf_inv(uint8_t a) noexcept;
            uint8_t gf_div(uint8_t a, uint8_t b) noexcept;
        } // namespace shamir_detail

    } // namespace crypto
} // namespace smo