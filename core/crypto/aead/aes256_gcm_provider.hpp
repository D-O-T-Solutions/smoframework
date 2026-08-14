#pragma once

#include "core/crypto/impl.hpp"

#include <cstddef>
#include <cstdint>

namespace smo {
    namespace aead {

        // AES-256-GCM backend for the SMO RecoveryDomain (P0-EX).
        //
        // Backed by OpenSSL 3 EVP (EVP_aes_256_gcm). This provider is the SMO
        // abstraction boundary: RecoveryDomain / authority code MUST NOT call
        // EVP_* directly — they go through this provider (and
        // crypto::RecoveryCryptoProvider).
        //
        // There is intentionally NO fallback to a self-written AES-GCM. If
        // OpenSSL is unavailable at build time, the build fails.
        //
        // Wire format: encrypt() returns ciphertext || tag(16). decrypt()
        // accepts the same layout and rejects on tag mismatch.
        struct AES256GCMProvider
        {
            static constexpr size_t kKeySize = 32;   // AES-256
            static constexpr size_t kNonceSize = 12; // AES-GCM standard nonce
            static constexpr size_t kMacSize = 16;   // GCM auth tag

            static Bytes encrypt(BytesView plaintext, BytesView aad, BytesView key, BytesView nonce);
            static Bytes decrypt(BytesView ciphertext, BytesView aad, BytesView key, BytesView nonce);
        };

    } // namespace aead
} // namespace smo
