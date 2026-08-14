#include "aes256_gcm_provider.hpp"

#include <openssl/evp.h>

#include <cstring>
#include <stdexcept>

namespace smo {
    namespace aead {

        namespace {

            // Validate key/nonce sizes shared by both directions.
            void validate_params(BytesView key, BytesView nonce)
            {
                if (key.size() != AES256GCMProvider::kKeySize)
                    throw std::runtime_error("AES-256-GCM: invalid key size");
                if (nonce.size() != AES256GCMProvider::kNonceSize)
                    throw std::runtime_error("AES-256-GCM: invalid nonce size");
            }

        } // namespace

        Bytes AES256GCMProvider::encrypt(BytesView plaintext, BytesView aad, BytesView key, BytesView nonce)
        {
            validate_params(key, nonce);

            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            if (!ctx)
                throw std::runtime_error("AES-256-GCM: failed to allocate EVP context");

            Bytes result(plaintext.size() + kMacSize);
            uint8_t tag[kMacSize];
            int len = 0, final_len = 0;

            try
            {
                if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
                    throw std::runtime_error("AES-256-GCM: EncryptInit failed");
                if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kNonceSize, nullptr) != 1)
                    throw std::runtime_error("AES-256-GCM: failed to set IV length");
                if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1)
                    throw std::runtime_error("AES-256-GCM: failed to set key/IV");

                if (!aad.empty())
                {
                    if (EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1)
                        throw std::runtime_error("AES-256-GCM: AAD update failed");
                }

                if (!plaintext.empty())
                {
                    if (EVP_EncryptUpdate(ctx, result.data(), &len, plaintext.data(),
                                          static_cast<int>(plaintext.size())) != 1)
                        throw std::runtime_error("AES-256-GCM: encrypt failed");
                }

                if (EVP_EncryptFinal_ex(ctx, result.data() + len, &final_len) != 1)
                    throw std::runtime_error("AES-256-GCM: finalize failed");
                len += final_len;

                if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kMacSize, tag) != 1)
                    throw std::runtime_error("AES-256-GCM: failed to get tag");

                std::memcpy(result.data() + len, tag, kMacSize);
                result.resize(len + kMacSize);
            }
            catch (...)
            {
                EVP_CIPHER_CTX_free(ctx);
                throw;
            }

            EVP_CIPHER_CTX_free(ctx);
            return result;
        }

        Bytes AES256GCMProvider::decrypt(BytesView ciphertext, BytesView aad, BytesView key, BytesView nonce)
        {
            validate_params(key, nonce);
            if (ciphertext.size() < kMacSize)
                throw std::runtime_error("AES-256-GCM: truncated ciphertext");

            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            if (!ctx)
                throw std::runtime_error("AES-256-GCM: failed to allocate EVP context");

            size_t ct_len = ciphertext.size() - kMacSize;
            Bytes result(ct_len);
            const uint8_t* tag = ciphertext.data() + ct_len;
            int len = 0, final_len = 0;

            try
            {
                if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
                    throw std::runtime_error("AES-256-GCM: DecryptInit failed");
                if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kNonceSize, nullptr) != 1)
                    throw std::runtime_error("AES-256-GCM: failed to set IV length");
                if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1)
                    throw std::runtime_error("AES-256-GCM: failed to set key/IV");
                if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, kMacSize, const_cast<uint8_t*>(tag)) != 1)
                    throw std::runtime_error("AES-256-GCM: failed to set tag");

                if (!aad.empty())
                {
                    if (EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1)
                        throw std::runtime_error("AES-256-GCM: AAD update failed");
                }

                if (ct_len > 0)
                {
                    if (EVP_DecryptUpdate(ctx, result.data(), &len, ciphertext.data(),
                                          static_cast<int>(ct_len)) != 1)
                        throw std::runtime_error("AES-256-GCM: decrypt failed");
                }

                // EVP_DecryptFinal_ex returns <=0 when the tag check fails.
                if (EVP_DecryptFinal_ex(ctx, result.data() + len, &final_len) <= 0)
                    throw std::runtime_error("AES-256-GCM: decryption failed (tag mismatch)");
                len += final_len;
                result.resize(len);
            }
            catch (...)
            {
                EVP_CIPHER_CTX_free(ctx);
                throw;
            }

            EVP_CIPHER_CTX_free(ctx);
            return result;
        }

    } // namespace aead
} // namespace smo