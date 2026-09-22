#include "ed25519_provider.hpp"

#include <monocypher.h>
#include <cstring>

#include "core/errors/error.hpp"

namespace smo {
    namespace signer {

        KeypairResult Ed25519Provider::generate_keypair(RngRef& rng)
        {
            Bytes secret_key(32);
            rng.fill(BytesMutView{secret_key.data(), secret_key.size()});

            Bytes public_key(32);
            uint8_t full_sk[64];
            crypto_eddsa_key_pair(full_sk, public_key.data(), secret_key.data());
            // secret_key is the seed; full_sk = seed || public_key
            Bytes full(64);
            std::memcpy(full.data(), full_sk, 64);
            return KeypairResult{std::move(public_key), std::move(full)};
        }

        Bytes Ed25519Provider::sign(BytesView msg, BytesView secret_key, RngRef&)
        {
            Bytes signature(64);
            crypto_eddsa_sign(signature.data(), secret_key.data(), msg.data(), msg.size());
            return signature;
        }

        bool Ed25519Provider::verify(BytesView msg, BytesView signature, BytesView public_key)
        {
            return crypto_eddsa_check(signature.data(), public_key.data(), msg.data(), msg.size()) == 0;
        }

        Result<KeypairResult> Ed25519Provider::derive_keypair_from_seed(BytesView seed)
        {
            if (seed.size() != 32)
            {
                return SMO_ERR_CRYPTO(172, Error, NoRetry, ManualIntervention,
                                      "Ed25519 seed must be 32 bytes");
            }

            Bytes public_key(32);
            uint8_t full_sk[64];
            uint8_t seed_copy[32];
            std::memcpy(seed_copy, seed.data(), 32);
            crypto_eddsa_key_pair(full_sk, public_key.data(), seed_copy);
            // full_sk = seed || public_key (64 bytes)
            Bytes secret_key(64);
            std::memcpy(secret_key.data(), full_sk, 64);

            return KeypairResult{std::move(public_key), std::move(secret_key)};
        }

    } // namespace signer
} // namespace smo
