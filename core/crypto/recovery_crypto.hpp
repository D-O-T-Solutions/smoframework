#pragma once

#include "core/crypto/fwd.hpp"
#include "core/crypto/impl.hpp"
#include "core/crypto/kdf/argon2id.hpp"
#include "core/crypto/aead/aes256_gcm_provider.hpp"

#include <cstddef>
#include <cstdint>
#include <string>

namespace smo {
    namespace crypto {

        // ─────────────────────────────────────────────────────────────────────
        // RecoveryCryptoProvider — the dedicated crypto DOMAIN for recovery
        // (P0-EX, DISCUSSION_0046 §17.9 / §24.4 / §26.3).
        //
        //   RecoveryDomain
        //       │
        //       ├── Argon2id   (Monocypher, CRYPTO_ARGON2_ID)   → 32 B key
        //       └── AES-256-GCM (OpenSSL 3 EVP)                 → nonce 12 B, tag 16 B
        //
        // This domain does NOT inherit the RFC 0024 mesh cipher suite. Callers
        // (recovery package, authority.sec tooling) go through this provider and
        // never touch EVP_* directly. There is NO fallback to a self-written
        // AES-GCM: if OpenSSL is missing, the build fails.
        //
        // Versioned envelope (version 1):
        //   [ 0]  magic[2]   = "SM"  (0x53 0x4D)
        //   [ 2]  version    = 1
        //   [ 3]  reserved   = 0
        //   [ 4]  mem_kib    = u32 BE  (argon2 memory)
        //   [ 8]  iterations = u32 BE
        //   [12]  lanes      = u32 BE
        //   [16]  salt       = 32 B
        //   [48]  nonce      = 12 B
        //   [60]  ciphertext = AES-256-GCM ct || tag(16)
        // ─────────────────────────────────────────────────────────────────────
        class RecoveryCryptoProvider
        {
        public:
            static constexpr size_t kSaltSize = 32;
            static constexpr size_t kNonceSize = 12;
            static constexpr size_t kTagSize = 16;
            static constexpr size_t kKeySize = 32;

            // Envelope header size (fixed): magic(2) + version(1) + reserved(1)
            // + mem_kib(4) + iterations(4) + lanes(4) + salt(32) + nonce(12).
            static constexpr size_t kEnvelopeHeaderSize = 60;

            // Derive the 32-byte AES-256 key from passphrase + salt via Argon2id.
            static Bytes derive_key(BytesView passphrase, BytesView salt, const kdf::Argon2idParams& params);

            // Encrypt `plaintext` into a versioned envelope. Generates a fresh
            // random salt + nonce. AAD is bound into the GCM tag.
            static Result<Bytes> seal(BytesView plaintext, BytesView aad, BytesView passphrase,
                                      const kdf::Argon2idParams& params, RngRef& rng);

            // Decrypt a versioned envelope. On wrong passphrase / tampered data
            // returns an error (GCM tag mismatch).
            static Result<Bytes> open(BytesView envelope, BytesView aad, BytesView passphrase);

            // True if the blob looks like a versioned SMO recovery envelope.
            static bool is_envelope(BytesView blob);

            // Parse the Argon2 parameters embedded in the envelope header.
            static kdf::Argon2idParams parse_params(BytesView envelope);

            // Serialize salt/params/nonce/ciphertext into the envelope.
            static Bytes build_envelope(const kdf::Argon2idParams& params, BytesView salt, BytesView nonce,
                                        BytesView ciphertext);

        private:
            static constexpr uint8_t kMagic[2] = {0x53, 0x4D}; // "SM"
            static constexpr uint8_t kVersion = 1;
        };

    } // namespace crypto
} // namespace smo
