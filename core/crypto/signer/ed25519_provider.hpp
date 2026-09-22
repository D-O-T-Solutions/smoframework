#pragma once

#include "core/crypto/impl.hpp"

namespace smo {
    namespace signer {

        struct Ed25519Provider
        {
            static KeypairResult generate_keypair(RngRef& rng);
            static Bytes sign(BytesView msg, BytesView secret_key, RngRef& rng);
            static bool verify(BytesView msg, BytesView signature, BytesView public_key);

            // Derive keypair from 32-byte seed (for Shamir SSS recovery)
            static Result<KeypairResult> derive_keypair_from_seed(BytesView seed);
        };

    } // namespace signer
} // namespace smo
