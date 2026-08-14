#include "recovery_crypto.hpp"

#include "core/errors/error.hpp"
#include "core/crypto/secure/zeroize.hpp"

#include <cstring>
#include <stdexcept>

namespace smo {
    namespace crypto {

        namespace {

            void store_u32_be(uint8_t* p, uint32_t v) noexcept
            {
                p[0] = static_cast<uint8_t>((v >> 24) & 0xFF);
                p[1] = static_cast<uint8_t>((v >> 16) & 0xFF);
                p[2] = static_cast<uint8_t>((v >> 8) & 0xFF);
                p[3] = static_cast<uint8_t>(v & 0xFF);
            }

            uint32_t load_u32_be(const uint8_t* p) noexcept
            {
                return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
                       (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
            }

        } // namespace

        Bytes RecoveryCryptoProvider::derive_key(BytesView passphrase, BytesView salt,
                                                 const kdf::Argon2idParams& params)
        {
            return kdf::argon2id_derive(passphrase, salt, params, kKeySize);
        }

        Bytes RecoveryCryptoProvider::build_envelope(const kdf::Argon2idParams& params, BytesView salt,
                                                     BytesView nonce, BytesView ciphertext)
        {
            Bytes envelope(kEnvelopeHeaderSize + ciphertext.size());
            uint8_t* p = envelope.data();

            std::memcpy(p, kMagic, 2);
            p[2] = kVersion;
            p[3] = 0;
            store_u32_be(p + 4, params.memory_kib);
            store_u32_be(p + 8, params.iterations);
            store_u32_be(p + 12, params.lanes);
            std::memcpy(p + 16, salt.data(), salt.size());
            std::memcpy(p + 48, nonce.data(), nonce.size());
            std::memcpy(p + kEnvelopeHeaderSize, ciphertext.data(), ciphertext.size());
            return envelope;
        }

        bool RecoveryCryptoProvider::is_envelope(BytesView blob)
        {
            if (blob.size() < kEnvelopeHeaderSize)
                return false;
            return blob[0] == kMagic[0] && blob[1] == kMagic[1] && blob[2] == kVersion;
        }

        kdf::Argon2idParams RecoveryCryptoProvider::parse_params(BytesView envelope)
        {
            if (envelope.size() < kEnvelopeHeaderSize)
                throw std::runtime_error("RecoveryCrypto: envelope too small");
            kdf::Argon2idParams params;
            params.memory_kib = load_u32_be(envelope.data() + 4);
            params.iterations = load_u32_be(envelope.data() + 8);
            params.lanes = load_u32_be(envelope.data() + 12);
            return params;
        }

        Result<Bytes> RecoveryCryptoProvider::seal(BytesView plaintext, BytesView aad, BytesView passphrase,
                                                   const kdf::Argon2idParams& params, RngRef& rng)
        {
            try
            {
                Bytes salt(kSaltSize, 0);
                rng.fill(BytesMutView{salt.data(), salt.size()});
                Bytes nonce(kNonceSize, 0);
                rng.fill(BytesMutView{nonce.data(), nonce.size()});

                Bytes key = derive_key(passphrase, BytesView(salt), params);
                auto ct = aead::AES256GCMProvider::encrypt(plaintext, aad, BytesView(key), BytesView(nonce));
                secure::zeroize(key.data(), key.size());

                return build_envelope(params, BytesView(salt), BytesView(nonce), BytesView(ct));
            }
            catch (const std::exception& e)
            {
                return SMO_ERR_CRYPTO(151, Error, NoRetry, ManualIntervention, std::string("recovery seal failed: ") + e.what());
            }
        }

        Result<Bytes> RecoveryCryptoProvider::open(BytesView envelope, BytesView aad, BytesView passphrase)
        {
            if (!is_envelope(envelope))
            {
                return SMO_ERR_CRYPTO(152, Error, NoRetry, ManualIntervention,
                                      "recovery envelope: unsupported format (expected versioned SMO envelope)");
            }

            try
            {
                kdf::Argon2idParams params = parse_params(envelope);
                BytesView salt(envelope.data() + 16, kSaltSize);
                BytesView nonce(envelope.data() + 48, kNonceSize);
                BytesView ciphertext(envelope.data() + kEnvelopeHeaderSize, envelope.size() - kEnvelopeHeaderSize);

                Bytes key = derive_key(passphrase, salt, params);
                auto plain = aead::AES256GCMProvider::decrypt(ciphertext, aad, BytesView(key), nonce);
                secure::zeroize(key.data(), key.size());
                return plain;
            }
            catch (const std::exception& e)
            {
                return SMO_ERR_CRYPTO(153, Error, NoRetry, ManualIntervention,
                                      std::string("recovery open failed: ") + e.what());
            }
        }

    } // namespace crypto
} // namespace smo