#ifndef CRYPTO_CORE_HPP
#define CRYPTO_CORE_HPP

#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <cstring>

#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>

#include <oqs/oqs.h> // liboqs: Kyber + Falcon

#include "json.hpp"
#include "base64.hpp"

using json = nlohmann::json;

namespace CryptoCore {

    // ==========================================
    // 1. TIỆN ÍCH CƠ BẢN (UTILS)
    // ==========================================

    inline std::string base64_encode_str(const std::string &s) { return base64::to_base64(s); }
    inline std::string base64_decode_str(const std::string &s) { return base64::from_base64(s); }

    // Hàm Hash SHA256 (Dùng để tạo NodeID hoặc Digest cho Falcon)
    inline std::string sha256(const std::string &data) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256((const unsigned char*)data.data(), data.size(), hash);
        return std::string((char*)hash, SHA256_DIGEST_LENGTH);
    }

    // Helper: Convert binary bytes to 64-char hex string (SHA-256)
    inline std::string bytes_to_hex(const std::string &bytes) {
        std::stringstream ss;
        for (unsigned char c : bytes) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
        }
        return ss.str();
    }

    // Helper: Convert hex string back to binary
    inline std::string hex_to_bytes(const std::string &hex) {
        std::string bytes;
        for (size_t i = 0; i < hex.length(); i += 2) {
            std::string hex_byte = hex.substr(i, 2);
            char byte = (char)strtol(hex_byte.c_str(), nullptr, 16);
            bytes += byte;
        }
        return bytes;
    }

    // ==========================================
    // 2. FALCON-512 (Ký số & Xác thực)
    // ==========================================

    // Sinh cặp khóa Falcon (Trả về dạng Binary String)
    inline bool generate_falcon_keypair(std::string &out_pub, std::string &out_priv) {
        if (!OQS_SIG_alg_is_enabled("Falcon-512")) return false;
        OQS_SIG *sig = OQS_SIG_new("Falcon-512");
        if (!sig) return false;

        std::vector<uint8_t> public_key(sig->length_public_key);
        std::vector<uint8_t> private_key(sig->length_secret_key);

        if (OQS_SIG_keypair(sig, public_key.data(), private_key.data()) == OQS_SUCCESS) {
            out_pub.assign((char*)public_key.data(), public_key.size());
            out_priv.assign((char*)private_key.data(), private_key.size());
            OQS_SIG_free(sig);
            return true;
        }
        OQS_SIG_free(sig);
        return false;
    }

    // Ký lên dữ liệu (Sign)
    inline bool falcon_sign(const std::string &priv_key, const std::string &msg, std::string &out_signature) {
        OQS_SIG *sig = OQS_SIG_new("Falcon-512");
        if (!sig) return false;

        // Hash message trước khi ký (Theo chuẩn của code cũ bạn dùng)
        std::string digest = sha256(msg);

        std::vector<uint8_t> sigbuf(sig->length_signature);
        size_t siglen = 0;

        OQS_STATUS rc = OQS_SIG_sign(sig, sigbuf.data(), &siglen, 
                                     (const uint8_t*)digest.data(), digest.size(), 
                                     (const uint8_t*)priv_key.data());
        
        OQS_SIG_free(sig);
        if (rc == OQS_SUCCESS) {
            out_signature.assign((char*)sigbuf.data(), siglen);
            return true;
        }
        return false;
    }

    // Xác thực chữ ký (Verify) - KHÔNG DÙNG MYSQL NỮA
    inline bool falcon_verify(const std::string &pub_key, const std::string &msg, const std::string &signature) {
        OQS_SIG *sig = OQS_SIG_new("Falcon-512");
        if (!sig) return false;

        std::string digest = sha256(msg);

        OQS_STATUS rc = OQS_SIG_verify(sig, 
                                       (const uint8_t*)digest.data(), digest.size(),
                                       (const uint8_t*)signature.data(), signature.size(),
                                       (const uint8_t*)pub_key.data());
        OQS_SIG_free(sig);
        return (rc == OQS_SUCCESS);
    }

    // ==========================================
    // 3. KYBER-512 (Trao đổi khóa KEM)
    // ==========================================

    inline bool generate_kyber_keypair(std::string &out_pub, std::string &out_priv) {
        if (!OQS_KEM_alg_is_enabled("Kyber512")) return false;
        OQS_KEM *kem = OQS_KEM_new("Kyber512");
        if (!kem) return false;

        std::vector<uint8_t> pk(kem->length_public_key);
        std::vector<uint8_t> sk(kem->length_secret_key);

        if (OQS_KEM_keypair(kem, pk.data(), sk.data()) == OQS_SUCCESS) {
            out_pub.assign((char*)pk.data(), pk.size());
            out_priv.assign((char*)sk.data(), sk.size());
            OQS_KEM_free(kem);
            return true;
        }
        OQS_KEM_free(kem);
        return false;
    }

    // Đóng gói (Encaps): Client dùng PubKey của Server để tạo ra (Ciphertext, SharedSecret)
    inline bool kyber_encaps(const std::string &remote_pub_key, std::string &out_ciphertext, std::string &out_shared_secret) {
        OQS_KEM *kem = OQS_KEM_new("Kyber512");
        if (!kem) return false;

        if (remote_pub_key.size() != kem->length_public_key) {
            OQS_KEM_free(kem); return false;
        }

        std::vector<uint8_t> ct(kem->length_ciphertext);
        std::vector<uint8_t> ss(kem->length_shared_secret);

        OQS_STATUS rc = OQS_KEM_encaps(kem, ct.data(), ss.data(), (const uint8_t*)remote_pub_key.data());
        
        OQS_KEM_free(kem);
        if (rc == OQS_SUCCESS) {
            out_ciphertext.assign((char*)ct.data(), ct.size());
            out_shared_secret.assign((char*)ss.data(), ss.size());
            return true;
        }
        return false;
    }

    // Giải mã (Decaps): Server dùng PrivKey của mình để giải mã Ciphertext -> SharedSecret
    inline bool kyber_decaps(const std::string &my_priv_key, const std::string &ciphertext, std::string &out_shared_secret) {
        OQS_KEM *kem = OQS_KEM_new("Kyber512");
        if (!kem) return false;

        if (my_priv_key.size() != kem->length_secret_key || ciphertext.size() != kem->length_ciphertext) {
            OQS_KEM_free(kem); return false;
        }

        std::vector<uint8_t> ss(kem->length_shared_secret);
        OQS_STATUS rc = OQS_KEM_decaps(kem, ss.data(), (const uint8_t*)ciphertext.data(), (const uint8_t*)my_priv_key.data());

        OQS_KEM_free(kem);
        if (rc == OQS_SUCCESS) {
            out_shared_secret.assign((char*)ss.data(), ss.size());
            return true;
        }
        return false;
    }

    // ==========================================
    // 4. AES-256-GCM (Mã hóa Payload)
    // ==========================================

    inline bool aes_gcm_encrypt(const std::string &key, const std::string &nonce, 
                         const std::string &plaintext, const std::string &aad,
                         std::string &out_ciphertext, std::string &out_tag) 
    {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;

        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) { EVP_CIPHER_CTX_free(ctx); return false; }
        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), NULL)) { EVP_CIPHER_CTX_free(ctx); return false; }
        if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, (const uint8_t*)key.data(), (const uint8_t*)nonce.data())) { EVP_CIPHER_CTX_free(ctx); return false; }

        // AAD (Header data)
        int len;
        if (!aad.empty()) {
            if (1 != EVP_EncryptUpdate(ctx, NULL, &len, (const uint8_t*)aad.data(), aad.size())) { EVP_CIPHER_CTX_free(ctx); return false; }
        }

        std::vector<uint8_t> ct(plaintext.size());
        if (1 != EVP_EncryptUpdate(ctx, ct.data(), &len, (const uint8_t*)plaintext.data(), plaintext.size())) { EVP_CIPHER_CTX_free(ctx); return false; }
        
        int ciphertext_len = len;
        if (1 != EVP_EncryptFinal_ex(ctx, ct.data() + len, &len)) { EVP_CIPHER_CTX_free(ctx); return false; }
        ciphertext_len += len;
        ct.resize(ciphertext_len);

        std::vector<uint8_t> tag(16);
        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data())) { EVP_CIPHER_CTX_free(ctx); return false; }

        out_ciphertext.assign((char*)ct.data(), ct.size());
        out_tag.assign((char*)tag.data(), tag.size());
        
        EVP_CIPHER_CTX_free(ctx);
        return true;
    }

    inline bool aes_gcm_decrypt(const std::string &key, const std::string &nonce, 
                         const std::string &ciphertext, const std::string &tag,
                         const std::string &aad, std::string &out_plaintext) 
    {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;

        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) { EVP_CIPHER_CTX_free(ctx); return false; }
        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), NULL)) { EVP_CIPHER_CTX_free(ctx); return false; }
        if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, (const uint8_t*)key.data(), (const uint8_t*)nonce.data())) { EVP_CIPHER_CTX_free(ctx); return false; }

        int len;
        if (!aad.empty()) {
            if (1 != EVP_DecryptUpdate(ctx, NULL, &len, (const uint8_t*)aad.data(), aad.size())) { EVP_CIPHER_CTX_free(ctx); return false; }
        }

        std::vector<uint8_t> pt(ciphertext.size());
        if (1 != EVP_DecryptUpdate(ctx, pt.data(), &len, (const uint8_t*)ciphertext.data(), ciphertext.size())) { EVP_CIPHER_CTX_free(ctx); return false; }
        int plaintext_len = len;

        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), (void*)tag.data())) { EVP_CIPHER_CTX_free(ctx); return false; }
        
        int ret = EVP_DecryptFinal_ex(ctx, pt.data() + len, &len);
        EVP_CIPHER_CTX_free(ctx);

        if (ret > 0) {
            plaintext_len += len;
            pt.resize(plaintext_len);
            out_plaintext.assign((char*)pt.data(), pt.size());
            return true;
        }
        return false;
    }

    // ==========================================
    // 5. HKDF (Tạo khóa AES từ Kyber Secret)
    // ==========================================
    inline bool hkdf_derive(const std::string &salt, const std::string &ikm,
                     std::string &out_key32, std::string &out_nonce12) {
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
        if (EVP_PKEY_derive_init(pctx) <= 0) return false;
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256());
        
        if (!salt.empty()) EVP_PKEY_CTX_set1_hkdf_salt(pctx, (const uint8_t*)salt.data(), salt.size());
        EVP_PKEY_CTX_set1_hkdf_key(pctx, (const uint8_t*)ikm.data(), ikm.size());

        uint8_t outbuf[44]; // 32 bytes Key + 12 bytes Nonce
        size_t outlen = sizeof(outbuf);
        if (EVP_PKEY_derive(pctx, outbuf, &outlen) <= 0) {
            EVP_PKEY_CTX_free(pctx); return false;
        }

        out_key32.assign((char*)outbuf, 32);
        out_nonce12.assign((char*)outbuf + 32, 12);
        
        EVP_PKEY_CTX_free(pctx);
        return true;
    }

    // ==========================================
    // 6. ECDHE (X25519) - PHIÊN BẢN CHUẨN STRING
    // ==========================================

    // Sinh cặp khóa (Trả về String Raw Bytes thay vì con trỏ EVP_PKEY)
    inline bool generate_x25519_keypair(std::string &out_pub, std::string &out_priv) {
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
        if (EVP_PKEY_keygen_init(pctx) <= 0) { EVP_PKEY_CTX_free(pctx); return false; }

        EVP_PKEY *pkey = NULL;
        if (EVP_PKEY_keygen(pctx, &pkey) <= 0) { EVP_PKEY_CTX_free(pctx); return false; }

        // 1. Lấy Raw Public Key (32 bytes)
        size_t len_pub = 0;
        EVP_PKEY_get_raw_public_key(pkey, NULL, &len_pub);
        std::vector<uint8_t> pub(len_pub);
        EVP_PKEY_get_raw_public_key(pkey, pub.data(), &len_pub);

        // 2. Lấy Raw Private Key (32 bytes)
        size_t len_priv = 0;
        EVP_PKEY_get_raw_private_key(pkey, NULL, &len_priv);
        std::vector<uint8_t> priv(len_priv);
        EVP_PKEY_get_raw_private_key(pkey, priv.data(), &len_priv);

        // 3. Gán vào String output
        out_pub.assign((char*)pub.data(), pub.size());
        out_priv.assign((char*)priv.data(), priv.size());

        // Dọn dẹp con trỏ ngay tại đây, Main không cần lo nữa
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        return true;
    }

    // Tính Shared Secret (Nhập vào String Private Key thay vì con trỏ)
    inline bool compute_x25519_secret(const std::string &my_priv_raw, const std::string &peer_pub_raw, std::string &out_secret) {
        // 1. Tái tạo lại Private Key từ Raw Bytes
        EVP_PKEY *my_pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, (const uint8_t*)my_priv_raw.data(), my_priv_raw.size());
        if (!my_pkey) return false;

        // 2. Tái tạo lại Peer Public Key từ Raw Bytes
        EVP_PKEY *peer_pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, (const uint8_t*)peer_pub_raw.data(), peer_pub_raw.size());
        if (!peer_pkey) { EVP_PKEY_free(my_pkey); return false; }

        // 3. Tính toán ECDH
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(my_pkey, NULL);
        if (!ctx) { EVP_PKEY_free(my_pkey); EVP_PKEY_free(peer_pkey); return false; }

        if (EVP_PKEY_derive_init(ctx) <= 0 ||
            EVP_PKEY_derive_set_peer(ctx, peer_pkey) <= 0) {
            EVP_PKEY_free(my_pkey); EVP_PKEY_free(peer_pkey); EVP_PKEY_CTX_free(ctx); return false;
        }

        size_t secret_len;
        if (EVP_PKEY_derive(ctx, NULL, &secret_len) <= 0) {
            EVP_PKEY_free(my_pkey); EVP_PKEY_free(peer_pkey); EVP_PKEY_CTX_free(ctx); return false;
        }

        std::vector<uint8_t> secret(secret_len);
        if (EVP_PKEY_derive(ctx, secret.data(), &secret_len) <= 0) {
            EVP_PKEY_free(my_pkey); EVP_PKEY_free(peer_pkey); EVP_PKEY_CTX_free(ctx); return false;
        }

        out_secret.assign((char*)secret.data(), secret.size());

        // Dọn dẹp
        EVP_PKEY_free(my_pkey);
        EVP_PKEY_free(peer_pkey);
        EVP_PKEY_CTX_free(ctx);
        return true;
    }

    // SỬA LẠI HÀM NÀY
    inline bool derive_hybrid_key(const std::string &kyber_ss, const std::string &ecdh_ss, 
                           std::string &out_aes_key, std::string &out_nonce) { // <--- Tham số tên là out_aes_key, out_nonce
        // Nối chuỗi đơn giản
        std::string hybrid_secret = kyber_ss + ecdh_ss;
        
        // Salt có thể là chuỗi cố định hoặc random nonce trao đổi lúc Hello
        std::string salt = "ShellMap_Hybrid_v1"; 
        
        // LỖI CŨ: return hkdf_derive(salt, hybrid_secret, out_key32, out_nonce12); 
        // SỬA THÀNH: Truyền đúng tên biến
        return hkdf_derive(salt, hybrid_secret, out_aes_key, out_nonce); 
    }
} // namespace CryptoCore

#endif