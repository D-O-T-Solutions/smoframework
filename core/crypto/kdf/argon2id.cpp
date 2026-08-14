#include "argon2id.hpp"

#include "core/crypto/secure/zeroize.hpp"

#include <monocypher.h>

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace smo {
    namespace kdf {

        Bytes argon2id_derive(BytesView passphrase, BytesView salt, const Argon2idParams& params, size_t out_len)
        {
            if (params.lanes == 0)
                throw std::invalid_argument("Argon2id: lanes must be > 0");
            if (params.iterations == 0)
                throw std::invalid_argument("Argon2id: iterations must be > 0");
            if (params.memory_kib < 8 * params.lanes)
                throw std::invalid_argument("Argon2id: memory range too small for lanes");
            if (out_len == 0 || out_len > 0xFFFFFFFFULL)
                throw std::invalid_argument("Argon2id: invalid output length");

            uint32_t nb_blocks = params.memory_kib; // 1 KiB per block

            // Work area: nb_blocks * 1024 bytes, zeroized after use.
            std::vector<uint8_t> work_area(static_cast<size_t>(nb_blocks) * 1024u);

            crypto_argon2_config config;
            config.algorithm = CRYPTO_ARGON2_ID;
            config.nb_blocks = nb_blocks;
            config.nb_passes = params.iterations;
            config.nb_lanes = params.lanes;

            crypto_argon2_inputs inputs;
            inputs.pass = passphrase.data();
            inputs.salt = salt.data();
            inputs.pass_size = static_cast<uint32_t>(passphrase.size());
            inputs.salt_size = static_cast<uint32_t>(salt.size());

            crypto_argon2_extras extras = crypto_argon2_no_extras;

            Bytes out(out_len, 0);
            crypto_argon2(out.data(), static_cast<uint32_t>(out_len), work_area.data(), config, inputs, extras);

            secure::zeroize(work_area.data(), work_area.size());
            return out;
        }

    } // namespace kdf
} // namespace smo