#include "core/crypto/fwd.hpp"
#include "core/crypto/suite.hpp"
#include "core/crypto/impl.hpp"
#include "core/crypto/registry.hpp"
#include "core/crypto/hash_provider.hpp"
#include "core/crypto/secure/zeroize.hpp"
#include "core/crypto/secure/secure_compare.hpp"
#include "core/crypto/random/getrandom.hpp"
#include "core/crypto/kdf/hkdf.hpp"
#include "core/crypto/kdf/argon2id.hpp"
#include "core/crypto/aead/aes256_gcm_provider.hpp"
#include "core/crypto/recovery_crypto.hpp"
#include "core/crypto/hash/sha256.hpp"
#include "core/crypto/signer/ed25519_provider.hpp"
#include "core/crypto/kem/x25519_provider.hpp"
#include "core/crypto/aead/xchacha20_provider.hpp"
#include "core/crypto/signer/mldsa_provider.hpp"
#include "core/crypto/kem/mlkem_provider.hpp"
#include "core/types.hpp"

#include <cstdio>
#include <cstring>
#include <string>

using namespace smo;

static int failures = 0;

#define TEST(name)                                                                                                     \
    do                                                                                                                 \
    {                                                                                                                  \
        printf("  TEST %-50s ... ", name);                                                                             \
        fflush(stdout);

#define END_TEST(result)                                                                                               \
    if (result)                                                                                                        \
    {                                                                                                                  \
        printf("PASS\n");                                                                                              \
    }                                                                                                                  \
    else                                                                                                               \
    {                                                                                                                  \
        printf("FAIL\n");                                                                                              \
        ++failures;                                                                                                    \
    }                                                                                                                  \
    }                                                                                                                  \
    while (false)

#define ASSERT(cond)                                                                                                   \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(cond))                                                                                                   \
        {                                                                                                              \
            printf("\n    ASSERTION FAILED at %s:%d: %s\n", __FILE__, __LINE__, #cond);                                \
            return false;                                                                                              \
        }                                                                                                              \
    } while (false)

// ==========================================================================
// Secure utilities
// ==========================================================================

static bool test_zeroize()
{
    uint8_t buf[16];
    memset(buf, 0xFF, sizeof(buf));
    secure::zeroize(buf, sizeof(buf));
    for (auto b : buf)
        ASSERT(b == 0);
    return true;
}

static bool test_secure_buffer()
{
    {
        secure::SecureBuffer sb(32);
        ASSERT(sb.size() == 32);
        memset(sb.data(), 0xAB, 32);
    }
    // After destruction, memory is zeroed (can't verify directly, but no crash)
    return true;
}

static bool test_constant_time_compare()
{
    uint8_t a[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t b[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t c[8] = {1, 2, 3, 4, 5, 6, 7, 9};
    ASSERT(secure::constant_time_compare(a, b, 8));
    ASSERT(!secure::constant_time_compare(a, c, 8));
    ASSERT(secure::constant_time_compare(a, b, 0)); // empty
    return true;
}

static bool test_getrandom()
{
    uint8_t buf1[32], buf2[32];
    random::fill(BytesMutView{buf1, 32});
    random::fill(BytesMutView{buf2, 32});
    // Very unlikely to collide
    ASSERT(memcmp(buf1, buf2, 32) != 0);
    return true;
}

// ==========================================================================
// SHA-256
// ==========================================================================

static bool test_sha256_known()
{
    hash::Sha256Provider h;
    auto result = h.hash(BytesView{});
    // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    ASSERT(result.size() == 32);
    ASSERT(result[0] == 0xe3);
    ASSERT(result[1] == 0xb0);
    ASSERT(result[2] == 0xc4);
    ASSERT(result[3] == 0x42);
    return true;
}

static bool test_sha256_hello()
{
    hash::Sha256Provider h;
    auto data = BytesView(reinterpret_cast<const uint8_t*>("hello"), 5);
    auto result = h.hash(data);
    ASSERT(result.size() == 32);
    // SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
    ASSERT(result[0] == 0x2c);
    ASSERT(result[1] == 0xf2);
    ASSERT(result[2] == 0x4d);
    return true;
}

// ==========================================================================
// Ed25519
// ==========================================================================

static bool test_ed25519_sign_verify()
{
    RngRef rng(nullptr, [](void*, uint8_t* buf, size_t len) { random::fill(BytesMutView{buf, len}); });

    auto kp = signer::Ed25519Provider::generate_keypair(rng);
    Bytes msg = {0x01, 0x02, 0x03, 0x04};

    auto sig = signer::Ed25519Provider::sign(msg, kp.secret_key, rng);
    ASSERT(sig.size() == 64);

    bool ok = signer::Ed25519Provider::verify(msg, sig, kp.public_key);
    ASSERT(ok);
    return true;
}

static bool test_ed25519_reject_bad_sig()
{
    RngRef rng(nullptr, [](void*, uint8_t* buf, size_t len) { random::fill(BytesMutView{buf, len}); });

    auto kp = signer::Ed25519Provider::generate_keypair(rng);
    Bytes msg = {0x01, 0x02, 0x03, 0x04};
    Bytes wrong_msg = {0x05, 0x06, 0x07, 0x08};

    auto sig = signer::Ed25519Provider::sign(msg, kp.secret_key, rng);
    bool ok = signer::Ed25519Provider::verify(wrong_msg, sig, kp.public_key);
    ASSERT(!ok);
    return true;
}

// ==========================================================================
// X25519
// ==========================================================================

static bool test_x25519_encap_decap()
{
    RngRef rng(nullptr, [](void*, uint8_t* buf, size_t len) { random::fill(BytesMutView{buf, len}); });

    auto alice = kem::X25519Provider::generate_keypair(rng);
    auto bob = kem::X25519Provider::generate_keypair(rng);

    // Alice encaps with Bob's public key
    auto enc = kem::X25519Provider::encapsulate(bob.public_key, rng);
    ASSERT(enc.ciphertext.size() == 32);
    ASSERT(enc.shared_secret.size() == 32);

    // Bob decaps
    auto shared = kem::X25519Provider::decapsulate(bob.secret_key, enc.ciphertext);
    ASSERT(shared == enc.shared_secret);
    return true;
}

// ==========================================================================
// XChaCha20-Poly1305
// ==========================================================================

static bool test_xchacha20_encrypt_decrypt()
{
    Bytes key(32, 0xAB);
    Bytes nonce(24, 0xCD);
    Bytes plaintext = {0x01, 0x02, 0x03, 0x04, 0x05};
    Bytes aad = {0x10, 0x20};

    auto ct = aead::XChaCha20Provider::encrypt(plaintext, aad, key, nonce);
    ASSERT(ct.size() == plaintext.size() + 16); // + MAC

    auto pt2 = aead::XChaCha20Provider::decrypt(ct, aad, key, nonce);
    ASSERT(pt2 == plaintext);
    return true;
}

static bool test_xchacha20_reject_tampered()
{
    Bytes key(32, 0xAB);
    Bytes nonce(24, 0xCD);
    Bytes plaintext = {0x01, 0x02, 0x03, 0x04, 0x05};
    Bytes aad = {0x10, 0x20};

    auto ct = aead::XChaCha20Provider::encrypt(plaintext, aad, key, nonce);
    ct[0] ^= 0x01; // tamper

    bool threw = false;
    try
    {
        aead::XChaCha20Provider::decrypt(ct, aad, key, nonce);
    }
    catch (...)
    {
        threw = true;
    }
    ASSERT(threw);
    return true;
}

// ==========================================================================
// HKDF
// ==========================================================================

static bool test_hkdf_basic()
{
    Bytes salt = {0x01, 0x02, 0x03, 0x04};
    Bytes ikm = {0x05, 0x06, 0x07, 0x08};
    Bytes info = {0x09, 0x0A};

    auto okm = kdf::hkdf(salt, ikm, info, 32);
    ASSERT(okm.size() == 32);
    return true;
}

// ==========================================================================
// ML-DSA (PQC signature)
// ==========================================================================

#ifdef SMO_WITH_PQC

static bool test_mldsa_sign_verify()
{
    RngRef rng(nullptr, [](void*, uint8_t* buf, size_t len) { random::fill(BytesMutView{buf, len}); });

    auto kp = signer::MLDSAProvider::generate_keypair(rng);
    Bytes msg = {0x01, 0x02, 0x03, 0x04};

    auto sig = signer::MLDSAProvider::sign(msg, kp.secret_key, rng);
    ASSERT(!sig.empty());

    bool ok = signer::MLDSAProvider::verify(msg, sig, kp.public_key);
    ASSERT(ok);
    return true;
}

static bool test_mldsa_reject_bad_sig()
{
    RngRef rng(nullptr, [](void*, uint8_t* buf, size_t len) { random::fill(BytesMutView{buf, len}); });

    auto kp = signer::MLDSAProvider::generate_keypair(rng);
    Bytes msg = {0x01, 0x02, 0x03, 0x04};
    Bytes wrong_msg = {0x05, 0x06, 0x07, 0x08};

    auto sig = signer::MLDSAProvider::sign(msg, kp.secret_key, rng);
    bool ok = signer::MLDSAProvider::verify(wrong_msg, sig, kp.public_key);
    ASSERT(!ok);
    return true;
}

// ==========================================================================
// ML-KEM (PQC KEM)
// ==========================================================================

static bool test_mlkem_encap_decap()
{
    RngRef rng(nullptr, [](void*, uint8_t* buf, size_t len) { random::fill(BytesMutView{buf, len}); });

    auto alice = kem::MLKEMProvider::generate_keypair(rng);
    auto bob = kem::MLKEMProvider::generate_keypair(rng);

    auto enc = kem::MLKEMProvider::encapsulate(bob.public_key, rng);
    ASSERT(!enc.ciphertext.empty());
    ASSERT(!enc.shared_secret.empty());

    auto shared = kem::MLKEMProvider::decapsulate(bob.secret_key, enc.ciphertext);
    ASSERT(shared == enc.shared_secret);
    return true;
}

#endif // SMO_WITH_PQC

// ==========================================================================
// CryptoRegistry suite tests
// ==========================================================================

static bool test_crypto_suite_constants()
{
    ASSERT(kSuiteClassical == 1);
    ASSERT(kSuiteHybridPQC == 2);
    ASSERT(kSuitePurePQC == 3);
    ASSERT(kSuiteMin == 1);
    ASSERT(kSuiteMax == 3);
    return true;
}

static bool test_hash_suite_classification()
{
    ASSERT(is_crypto_hash(HashSuite::Blake3));
    ASSERT(is_crypto_hash(HashSuite::Sha256));
    ASSERT(is_crypto_hash(HashSuite::Sha3_256));
    ASSERT(!is_crypto_hash(HashSuite::XxHash3));
    ASSERT(!is_crypto_hash(HashSuite::Crc32C));

    ASSERT(is_performance_hash(HashSuite::XxHash3));
    ASSERT(is_performance_hash(HashSuite::Crc32C));
    ASSERT(is_performance_hash(HashSuite::CityHash));
    ASSERT(!is_performance_hash(HashSuite::Blake3));
    return true;
}

// ==========================================================================
// RecoveryDomain (P0-EX): Argon2id + AES-256-GCM via RecoveryCryptoProvider
// ==========================================================================

static bool test_recovery_crypto_roundtrip()
{
    RngRef rng(nullptr, [](void*, uint8_t* buf, size_t len) { random::fill(BytesMutView{buf, len}); });

    // Small memory for test speed (still >= 8 * lanes)
    kdf::Argon2idParams params;
    params.memory_kib = 8192; // 8 MiB
    params.iterations = 2;
    params.lanes = 4;

    std::string passphrase = "correct horse battery staple";
    Bytes secret(48, 0xAB);
    std::string mesh_id = "TestMesh";
    BytesView aad(reinterpret_cast<const uint8_t*>(mesh_id.data()), mesh_id.size());
    BytesView pass(reinterpret_cast<const uint8_t*>(passphrase.data()), passphrase.size());

    auto envelope_res = crypto::RecoveryCryptoProvider::seal(BytesView(secret), aad, pass, params, rng);
    ASSERT(envelope_res);
    auto envelope = std::move(envelope_res).value();

    // Versioned envelope self-describing: header(60) + ciphertext(48+16 tag)
    ASSERT(crypto::RecoveryCryptoProvider::is_envelope(BytesView(envelope)));
    ASSERT(envelope.size() == crypto::RecoveryCryptoProvider::kEnvelopeHeaderSize + secret.size() +
                                   aead::AES256GCMProvider::kMacSize);

    auto plain_res = crypto::RecoveryCryptoProvider::open(BytesView(envelope), aad, pass);
    ASSERT(plain_res);
    ASSERT(plain_res.value() == secret);
    return true;
}

static bool test_recovery_crypto_wrong_passphrase()
{
    RngRef rng(nullptr, [](void*, uint8_t* buf, size_t len) { random::fill(BytesMutView{buf, len}); });

    kdf::Argon2idParams params;
    params.memory_kib = 8192;
    params.iterations = 2;
    params.lanes = 4;

    std::string passphrase = "right";
    std::string wrong = "wrong";
    Bytes secret(32, 0x11);
    std::string mesh_id = "MeshA";
    BytesView aad(reinterpret_cast<const uint8_t*>(mesh_id.data()), mesh_id.size());

    auto envelope_res =
        crypto::RecoveryCryptoProvider::seal(BytesView(secret), aad,
                                             BytesView(reinterpret_cast<const uint8_t*>(passphrase.data()), passphrase.size()),
                                             params, rng);
    ASSERT(envelope_res);
    auto envelope = std::move(envelope_res).value();

    auto plain_res =
        crypto::RecoveryCryptoProvider::open(BytesView(envelope), aad,
                                             BytesView(reinterpret_cast<const uint8_t*>(wrong.data()), wrong.size()));
    ASSERT(!plain_res);
    return true;
}

static bool test_recovery_crypto_tamper()
{
    RngRef rng(nullptr, [](void*, uint8_t* buf, size_t len) { random::fill(BytesMutView{buf, len}); });

    kdf::Argon2idParams params;
    params.memory_kib = 8192;
    params.iterations = 2;
    params.lanes = 4;

    std::string passphrase = "tamper-check";
    Bytes secret(24, 0x22);
    std::string mesh_id = "MeshB";
    BytesView aad(reinterpret_cast<const uint8_t*>(mesh_id.data()), mesh_id.size());
    BytesView pass(reinterpret_cast<const uint8_t*>(passphrase.data()), passphrase.size());

    auto envelope_res = crypto::RecoveryCryptoProvider::seal(BytesView(secret), aad, pass, params, rng);
    ASSERT(envelope_res);
    auto envelope = std::move(envelope_res).value();

    // Flip a ciphertext byte → GCM tag must reject
    envelope[envelope.size() - 1] ^= 0x01;
    auto plain_res = crypto::RecoveryCryptoProvider::open(BytesView(envelope), aad, pass);
    ASSERT(!plain_res);
    return true;
}

static bool test_recovery_crypto_legacy_rejected()
{
    // Old scheme blob (nonce24 || ct) must NOT be accepted as a versioned
    // envelope — no silent downgrade (SPEC §26.3 / P0-EX lock).
    Bytes legacy(80, 0x00);
    ASSERT(!crypto::RecoveryCryptoProvider::is_envelope(BytesView(legacy)));
    std::string pass = "x";
    auto res = crypto::RecoveryCryptoProvider::open(
        BytesView(legacy), BytesView(reinterpret_cast<const uint8_t*>("m"), 1),
        BytesView(reinterpret_cast<const uint8_t*>(pass.data()), pass.size()));
    ASSERT(!res);
    return true;
}

static bool test_aes256_gcm_known_vector()
{
    // NIST GCM test vector (CAVS, AES-256-GCM):
    // key 0000000000000000000000000000000000000000000000000000000000000000
    // iv  000000000000000000000000
    // aad ""
    // plaintext ""
    // tag  530f8afbc74536b9a963b4f1c4cb738b
    uint8_t key_b[32] = {0};
    uint8_t nonce_b[12] = {0};
    auto ct = aead::AES256GCMProvider::encrypt(BytesView{}, BytesView{}, BytesView(key_b), BytesView(nonce_b));
    ASSERT(ct.size() == 16);
    const uint8_t expected[16] = {0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9,
                                  0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb, 0x73, 0x8b};
    ASSERT(memcmp(ct.data(), expected, 16) == 0);
    return true;
}

static bool test_argon2id_deterministic()
{
    kdf::Argon2idParams params;
    params.memory_kib = 1024;
    params.iterations = 2;
    params.lanes = 2;

    std::string pass = "Argon2id-test";
    std::string salt = "0123456789abcdef";
    BytesView p(reinterpret_cast<const uint8_t*>(pass.data()), pass.size());
    BytesView s(reinterpret_cast<const uint8_t*>(salt.data()), salt.size());

    auto a = kdf::argon2id_derive(p, s, params, 32);
    auto b = kdf::argon2id_derive(p, s, params, 32);
    ASSERT(a == b);
    ASSERT(a.size() == 32);
    // Different salt → different output
    std::string salt2 = "fedcba9876543210";
    BytesView s2(reinterpret_cast<const uint8_t*>(salt2.data()), salt2.size());
    auto c = kdf::argon2id_derive(p, s2, params, 32);
    ASSERT(a != c);
    return true;
}

// ==========================================================================
// Main
// ==========================================================================

int main()
{
    printf("=== SMO Crypto Architecture Tests ===\n\n");

    printf("[Secure Utilities]\n");
    TEST("Zeroize memory");
    END_TEST(test_zeroize());
    TEST("SecureBuffer RAII");
    END_TEST(test_secure_buffer());
    TEST("Constant-time compare");
    END_TEST(test_constant_time_compare());
    TEST("getrandom CSPRNG");
    END_TEST(test_getrandom());

    printf("\n[SHA-256]\n");
    TEST("Empty hash known vector");
    END_TEST(test_sha256_known());
    TEST("Hello hash known vector");
    END_TEST(test_sha256_hello());

    printf("\n[Ed25519]\n");
    TEST("Sign and verify");
    END_TEST(test_ed25519_sign_verify());
    TEST("Reject bad signature");
    END_TEST(test_ed25519_reject_bad_sig());

    printf("\n[X25519]\n");
    TEST("Encapsulate/Decapsulate");
    END_TEST(test_x25519_encap_decap());

    printf("\n[XChaCha20-Poly1305]\n");
    TEST("Encrypt and decrypt");
    END_TEST(test_xchacha20_encrypt_decrypt());
    TEST("Reject tampered ciphertext");
    END_TEST(test_xchacha20_reject_tampered());

    printf("\n[HKDF]\n");
    TEST("Basic derive");
    END_TEST(test_hkdf_basic());

#ifdef SMO_WITH_PQC
    printf("\n[ML-DSA (PQC)]\n");
    TEST("Sign and verify");
    END_TEST(test_mldsa_sign_verify());
    TEST("Reject bad signature");
    END_TEST(test_mldsa_reject_bad_sig());

    printf("\n[ML-KEM (PQC)]\n");
    TEST("Encapsulate/Decapsulate");
    END_TEST(test_mlkem_encap_decap());
#else
    printf("\n[PQC]\n");
    printf("  SKIPPED (WITH_PQC=OFF)\n");
#endif

    printf("\n[Suite Constants]\n");
    TEST("CryptoSuiteID values");
    END_TEST(test_crypto_suite_constants());
    TEST("HashSuite classification");
    END_TEST(test_hash_suite_classification());

    printf("\n[RecoveryDomain (P0-EX)]\n");
    TEST("AES-256-GCM known vector (NIST CAVS)");
    END_TEST(test_aes256_gcm_known_vector());
    TEST("Argon2id deterministic derive");
    END_TEST(test_argon2id_deterministic());
    TEST("RecoveryCryptoProvider seal/open roundtrip");
    END_TEST(test_recovery_crypto_roundtrip());
    TEST("Wrong passphrase rejected");
    END_TEST(test_recovery_crypto_wrong_passphrase());
    TEST("Tampered ciphertext rejected");
    END_TEST(test_recovery_crypto_tamper());
    TEST("Legacy (nonce24) envelope rejected");
    END_TEST(test_recovery_crypto_legacy_rejected());

    printf("\n=== %s ===\n", failures ? "FAILURES" : "ALL PASS");
    return failures ? 1 : 0;
}
