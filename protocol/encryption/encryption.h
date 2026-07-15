#pragma once

#include <cstdint>
#include <array>
#include <vector>
#include <span>

namespace smo {

// §XV.1 — Phase 1 Cryptography
// XChaCha20-Poly1305 for symmetric encryption.

struct SymmetricKey {
    std::array<uint8_t, 32> value{};
};

struct Nonce {
    std::array<uint8_t, 24> value{};   // XChaCha20 nonce
};

// Encrypt plaintext under the given key and nonce.
// Output: ciphertext + authentication tag (Poly1305)
std::vector<uint8_t> encrypt(std::span<const uint8_t> plaintext,
                              const SymmetricKey& key,
                              const Nonce& nonce);

// Decrypt and verify. Returns empty span on authentication failure.
std::vector<uint8_t> decrypt(std::span<const uint8_t> ciphertext,
                              const SymmetricKey& key,
                              const Nonce& nonce);

} // namespace smo
