#include "core/crypto/impl.hpp"
#include "core/crypto/random/getrandom.hpp"
#include "core/crypto/kdf/argon2id.hpp"
#include "core/crypto/recovery_crypto.hpp"
#include "core/crypto/signer/ed25519_provider.hpp"
#include "core/genesis/recovery_package.hpp"
#include "core/types.hpp"

#include <cstdio>
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

static RngRef make_test_rng()
{
    return RngRef(nullptr, [](void*, uint8_t* buf, size_t len) {
        random::fill(BytesMutView{buf, len});
    });
}

// Fast Argon2id params for tests (still >= 8 * lanes KiB).
static kdf::Argon2idParams fast_params()
{
    kdf::Argon2idParams p;
    p.memory_kib = 8192;
    p.iterations = 2;
    p.lanes = 4;
    return p;
}

static bool test_recovery_package_seal_unlock_roundtrip()
{
    RngRef rng = make_test_rng();
    auto params = fast_params();

    // Deterministic keypair blob: [u16BE pubkey_len][pubkey][seckey]
    auto kp_result = signer::Ed25519Provider::generate_keypair(rng);
    Bytes plaintext;
    uint16_t pk_len = (uint16_t)kp_result.public_key.size();
    plaintext.push_back((uint8_t)(pk_len >> 8));
    plaintext.push_back((uint8_t)(pk_len & 0xFF));
    plaintext.insert(plaintext.end(), kp_result.public_key.begin(), kp_result.public_key.end());
    plaintext.insert(plaintext.end(), kp_result.secret_key.begin(), kp_result.secret_key.end());

    std::string passphrase = "recovery-password-1";
    std::string mesh_id = "MeshXYZ";
    BytesView aad(reinterpret_cast<const uint8_t*>(mesh_id.data()), mesh_id.size());
    BytesView pass(reinterpret_cast<const uint8_t*>(passphrase.data()), passphrase.size());

    auto envelope_res = crypto::RecoveryCryptoProvider::seal(BytesView(plaintext), aad, pass, params, rng);
    ASSERT(envelope_res);
    auto envelope = std::move(envelope_res).value();
    ASSERT(crypto::RecoveryCryptoProvider::is_envelope(BytesView(envelope)));

    // Build package, serialize, deserialize, unlock
    genesis::RecoveryPackage pkg;
    pkg.mesh_id = mesh_id;
    pkg.root_public_key = bytes_to_hex(kp_result.public_key);
    pkg.root_keypair_encrypted = envelope;
    pkg.recovery_params = params;
    pkg.created_at = 1000;
    pkg.genesis_manifest_json = "{\"epoch\":0}";

    auto ser = pkg.serialize();
    ASSERT(ser);

    auto depkg_res = genesis::RecoveryPackage::deserialize(BytesView(ser.value()));
    ASSERT(depkg_res);
    auto& depkg = depkg_res.value();

    // Params survived roundtrip
    ASSERT(depkg.recovery_params.memory_kib == params.memory_kib);
    ASSERT(depkg.recovery_params.iterations == params.iterations);
    ASSERT(depkg.recovery_params.lanes == params.lanes);

    // Correct passphrase verifies + unlocks
    ASSERT(depkg.verify_passphrase(passphrase));

    auto unlocked = depkg.unlock_keypair(passphrase);
    ASSERT(unlocked);
    ASSERT(unlocked.value().secret_key == kp_result.secret_key);
    ASSERT(unlocked.value().public_key == kp_result.public_key);

    // SignerImpl table for unlock() RootSession construction.
    smo::SignerImpl signer_impl;
    signer_impl.generate_keypair = +[](RngRef& r) -> Result<KeypairResult> {
        return signer::Ed25519Provider::generate_keypair(r);
    };
    signer_impl.sign = +[](BytesView msg, BytesView sk, RngRef& r) -> Result<Bytes> {
        return signer::Ed25519Provider::sign(msg, sk, r);
    };

    auto session = depkg.unlock(passphrase, signer_impl, rng);
    ASSERT(session);
    ASSERT(session.value().root_public_key == pkg.root_public_key);
    return true;
}

static bool test_recovery_package_wrong_passphrase()
{
    genesis::RecoveryPackage pkg;
    pkg.mesh_id = "MeshErr";
    pkg.root_public_key = "00";
    pkg.root_keypair_encrypted.assign(crypto::RecoveryCryptoProvider::kEnvelopeHeaderSize + 32, 0xEE);
    // Not a valid envelope → verify_passphrase must be false (GCM cannot be
    // satisfied), never a leftover-plaintext-hash acceptance.
    ASSERT(!pkg.verify_passphrase("any-pass"));
    return true;
}

static bool test_recovery_package_legacy_rejected()
{
    // Pre-P0-EX recovery blob: SHA-256(passphrase) hash field exists (old JSON
    // schema "recovery_passphrase_hash") plus a non-versioned cipher blob.
    // The new deserializer must not accept the hash as verification authority,
    // and a raw (magic-less) blob must be rejected.
    std::string legacy_json =
        "{\"mesh_id\":\"M\",\"root_public_key\":\"00\",\"root_keypair_encrypted\":"
        "\"0000000000000000000000000000000000000000000000000000000000000000\"}";
    auto depkg_res = genesis::RecoveryPackage::deserialize(
        BytesView(reinterpret_cast<const uint8_t*>(legacy_json.data()), legacy_json.size()));
    ASSERT(depkg_res);
    ASSERT(depkg_res.value().root_keypair_encrypted.size() == 32);
    // Not a versioned envelope (magic mismatch) → never "valid".
    ASSERT(!crypto::RecoveryCryptoProvider::is_envelope(BytesView(depkg_res.value().root_keypair_encrypted)));
    ASSERT(!depkg_res.value().verify_passphrase("anything"));
    return true;
}

int main()
{
    printf("=== SMO Recovery Package Tests (P0-EX RecoveryDomain format v1) ===\n\n");

    TEST("seal→serialize→deserialize→unlock roundtrip");
    END_TEST(test_recovery_package_seal_unlock_roundtrip());
    TEST("wrong/garbage blob rejected");
    END_TEST(test_recovery_package_wrong_passphrase());
    TEST("legacy non-versioned blob rejected");
    END_TEST(test_recovery_package_legacy_rejected());

    printf("\n=== %s ===\n", failures ? "FAILURES" : "ALL PASS");
    return failures ? 1 : 0;
}