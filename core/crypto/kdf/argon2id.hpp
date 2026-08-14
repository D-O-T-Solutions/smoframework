#pragma once

#include "core/crypto/fwd.hpp"
#include "core/crypto/impl.hpp"

#include <cstdint>

namespace smo {
    namespace kdf {

        // Argon2id password KDF for the SMO RecoveryDomain (P0-EX).
        //
        // Backed by Monocypher's crypto_argon2 (CRYPTO_ARGON2_ID). This is a
        // RecoveryDomain primitive — it is NOT part of the RFC 0024 cipher
        // suite abstraction.
        //
        // Default parameters match the locked recovery spec (DISCUSSION_0046
        // §17.9 / §26.3): memory 64 MiB, 3 passes, 4 lanes, salt 32 B.
        struct Argon2idParams
        {
            uint32_t memory_kib = 65536; // 64 MiB
            uint32_t iterations = 3;     // passes
            uint32_t lanes = 4;          // parallelism
        };

        // Derive `out_len` bytes from passphrase + salt via Argon2id.
        // Throws std::invalid_argument on bad config; out_len <= 0xFFFFFFFF.
        Bytes argon2id_derive(BytesView passphrase, BytesView salt, const Argon2idParams& params, size_t out_len);

    } // namespace kdf
} // namespace smo
