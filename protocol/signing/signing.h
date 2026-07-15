#pragma once

#include <cstdint>
#include <array>
#include <span>

namespace smo {

// §XV.1 — Phase 1 Cryptography
// Ed25519 for identity and signing.

struct PublicKey {
    std::array<uint8_t, 32> value{};   // Ed25519 public key
};

struct SecretKey {
    std::array<uint8_t, 64> value{};   // Ed25519 seed + expanded
};

struct Signature {
    std::array<uint8_t, 64> value{};   // Ed25519 signature
};

// Generate a new Ed25519 keypair.
void keypair_generate(PublicKey& pk, SecretKey& sk);

// Sign a message with the given secret key.
Signature sign(std::span<const uint8_t> msg, const SecretKey& sk);

// Verify a message against a public key.
bool verify(std::span<const uint8_t> msg, const Signature& sig, const PublicKey& pk);

} // namespace smo
