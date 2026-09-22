#include "core/crypto/shamir.hpp"
#include "core/crypto/random/getrandom.hpp"
#include "core/crypto/signer/ed25519_provider.hpp"
#include "core/genesis/recovery_package.hpp"

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

static bool test_shamir_split_recover_roundtrip()
{
    RngRef rng = make_test_rng();

    Bytes secret(32);
    rng.fill(BytesMutView{secret.data(), secret.size()});

    // Test various M-of-N configurations (smaller for test speed)
    struct TestCase { uint8_t N, M; };
    TestCase cases[] = {{3, 2}, {5, 3}, {10, 5}, {20, 10}};

    for (auto tc : cases)
    {
        auto shares_res = crypto::shamir_split(BytesView(secret), tc.N, tc.M, rng);
        ASSERT(shares_res);
        auto shares = std::move(shares_res).value();
        ASSERT(shares.size() == tc.N);

        // Recover with exactly M shares
        std::vector<crypto::ShamirShare> subset(shares.begin(), shares.begin() + tc.M);
        auto recovered_res = crypto::shamir_recover(subset, tc.M);
        ASSERT(recovered_res);
        ASSERT(recovered_res.value() == secret);

        // Recover with more than M shares (should also work)
        auto recovered_all_res = crypto::shamir_recover(shares, tc.M);
        ASSERT(recovered_all_res);
        ASSERT(recovered_all_res.value() == secret);

        // Verify share serialization roundtrip
        for (const auto& s : shares)
        {
            auto ser = s.serialize();
            ASSERT(ser);
            auto deser = crypto::ShamirShare::deserialize(BytesView(ser.value()));
            ASSERT(deser);
            ASSERT(deser.value().index == s.index);
            ASSERT(deser.value().y == s.y);
        }
    }

    return true;
}

static bool test_shamir_wrong_threshold_fails()
{
    RngRef rng = make_test_rng();
    Bytes secret(32);
    rng.fill(BytesMutView{secret.data(), secret.size()});

    // 5-of-3 split
    auto shares_res = crypto::shamir_split(BytesView(secret), 5, 3, rng);
    ASSERT(shares_res);
    auto shares = std::move(shares_res).value();

    // Try to recover with only 2 shares (below threshold)
    std::vector<crypto::ShamirShare> subset2(shares.begin(), shares.begin() + 2);
    auto recovered2_res = crypto::shamir_recover(subset2, 3);
    ASSERT(!recovered2_res);

    // Try to recover with threshold=2 but 3 shares (wrong M)
    std::vector<crypto::ShamirShare> subset3(shares.begin(), shares.begin() + 3);
    auto recovered3_res = crypto::shamir_recover(subset3, 2);
    ASSERT(!recovered3_res || recovered3_res.value() != secret);

    return true;
}

static bool test_shamir_tampered_share_fails()
{
    RngRef rng = make_test_rng();
    Bytes secret(32);
    rng.fill(BytesMutView{secret.data(), secret.size()});

    auto shares_res = crypto::shamir_split(BytesView(secret), 5, 3, rng);
    ASSERT(shares_res);
    auto shares = std::move(shares_res).value();

    // Tamper with one share's y-coordinate
    shares[0].y[0] ^= 0x01;

    // Recovery with tampered share should fail or produce wrong secret
    auto recovered_res = crypto::shamir_recover(shares, 3);
    if (recovered_res)
    {
        ASSERT(recovered_res.value() != secret);
    }
    else
    {
        // Also acceptable: returns error
    }

    return true;
}

static bool test_shamir_duplicate_indices_rejected()
{
    RngRef rng = make_test_rng();
    Bytes secret(32);
    rng.fill(BytesMutView{secret.data(), secret.size()});

    auto shares_res = crypto::shamir_split(BytesView(secret), 5, 3, rng);
    ASSERT(shares_res);
    auto shares = std::move(shares_res).value();

    // Create duplicate indices
    shares[4].index = shares[0].index;

    auto recovered_res = crypto::shamir_recover(shares, 3);
    ASSERT(!recovered_res);

    return true;
}

static bool test_shamir_share_serialization()
{
    RngRef rng = make_test_rng();
    Bytes secret(32);
    rng.fill(BytesMutView{secret.data(), secret.size()});

    auto shares_res = crypto::shamir_split(BytesView(secret), 3, 2, rng);
    ASSERT(shares_res);
    auto shares = std::move(shares_res).value();

    // Serialize all shares
    std::vector<Bytes> serialized;
    for (const auto& s : shares)
    {
        auto ser = s.serialize();
        ASSERT(ser);
        serialized.push_back(std::move(ser).value());
    }

    // Deserialize and verify
    std::vector<crypto::ShamirShare> deserialized;
    for (const auto& s : serialized)
    {
        auto deser = crypto::ShamirShare::deserialize(BytesView(s));
        ASSERT(deser);
        deserialized.push_back(std::move(deser).value());
    }

    // Recover from deserialized shares
    auto recovered_res = crypto::shamir_recover(deserialized, 2);
    ASSERT(recovered_res);
    ASSERT(recovered_res.value() == secret);

    return true;
}

static bool test_recovery_package_v2_create_recover()
{
    RngRef rng = make_test_rng();

    // Generate a keypair
    auto kp = signer::Ed25519Provider::generate_keypair(rng);

    genesis::UnlockedKeypair keypair;
    keypair.public_key = std::move(kp.public_key);
    keypair.secret_key = std::move(kp.secret_key);

    // Create v2 package: 5 shares, threshold 3
    std::vector<std::string> passphrases = {"pass1", "pass2", "pass3", "pass4", "pass5"};

    smo::kdf::Argon2idParams params;
    params.memory_kib = 8192;
    params.iterations = 2;
    params.lanes = 4;

    auto pkg_res = genesis::RecoveryPackageV2::create("TestMesh", keypair, 3, 5, params, passphrases, rng);
    ASSERT(pkg_res);
    auto pkg = std::move(pkg_res).value();

    ASSERT(pkg.threshold == 3);
    ASSERT(pkg.total_shares == 5);
    ASSERT(pkg.shares.size() == 5);
    ASSERT(pkg.root_public_key == bytes_to_hex(keypair.public_key));

    // Serialize and deserialize
    auto ser = pkg.serialize();
    ASSERT(ser);
    auto depkg_res = genesis::RecoveryPackageV2::deserialize(BytesView(ser.value()));
    ASSERT(depkg_res);
    auto depkg = std::move(depkg_res).value();

    ASSERT(depkg.threshold == 3);
    ASSERT(depkg.total_shares == 5);
    ASSERT(depkg.shares.size() == 5);

    // Recover with 3 passphrases (indices 1, 2, 3)
    std::vector<std::pair<uint8_t, std::string>> recovery_passphrases = {
        {1, "pass1"}, {2, "pass2"}, {3, "pass3"}
    };

    auto recovered_kp = depkg.recover(recovery_passphrases);
    ASSERT(recovered_kp);
    ASSERT(recovered_kp.value().secret_key == keypair.secret_key);
    ASSERT(recovered_kp.value().public_key == keypair.public_key);

    return true;
}

static bool test_recovery_package_v2_wrong_passphrase_fails()
{
    RngRef rng = make_test_rng();

    auto kp = signer::Ed25519Provider::generate_keypair(rng);

    genesis::UnlockedKeypair keypair;
    keypair.public_key = std::move(kp.public_key);
    keypair.secret_key = std::move(kp.secret_key);

    std::vector<std::string> passphrases = {"pass1", "pass2", "pass3"};
    smo::kdf::Argon2idParams params;
    params.memory_kib = 8192;
    params.iterations = 2;
    params.lanes = 4;

    auto pkg_res = genesis::RecoveryPackageV2::create("TestMesh", keypair, 2, 3, params, passphrases, rng);
    ASSERT(pkg_res);
    auto pkg = std::move(pkg_res).value();

    auto ser = pkg.serialize();
    ASSERT(ser);
    auto depkg_res = genesis::RecoveryPackageV2::deserialize(BytesView(ser.value()));
    ASSERT(depkg_res);
    auto depkg = std::move(depkg_res).value();

    // Try recovery with wrong passphrase
    std::vector<std::pair<uint8_t, std::string>> wrong_passes = {
        {1, "wrong1"}, {2, "pass2"}
    };

    auto recovered_kp = depkg.recover(wrong_passes);
    ASSERT(!recovered_kp);

    return true;
}

static bool test_recovery_package_v2_insufficient_shares_fails()
{
    RngRef rng = make_test_rng();

    auto kp = signer::Ed25519Provider::generate_keypair(rng);

    genesis::UnlockedKeypair keypair;
    keypair.public_key = std::move(kp.public_key);
    keypair.secret_key = std::move(kp.secret_key);

    std::vector<std::string> passphrases = {"pass1", "pass2", "pass3", "pass4", "pass5"};
    smo::kdf::Argon2idParams params;
    params.memory_kib = 8192;
    params.iterations = 2;
    params.lanes = 4;

    auto pkg_res = genesis::RecoveryPackageV2::create("TestMesh", keypair, 3, 5, params, passphrases, rng);
    ASSERT(pkg_res);
    auto pkg = std::move(pkg_res).value();

    auto ser = pkg.serialize();
    ASSERT(ser);
    auto depkg_res = genesis::RecoveryPackageV2::deserialize(BytesView(ser.value()));
    ASSERT(depkg_res);
    auto depkg = std::move(depkg_res).value();

    // Only provide 2 passphrases for threshold 3
    std::vector<std::pair<uint8_t, std::string>> insufficient = {
        {1, "pass1"}, {2, "pass2"}
    };

    auto recovered_kp = depkg.recover(insufficient);
    ASSERT(!recovered_kp);

    return true;
}

static bool test_recovery_package_v2_tampered_share_fails()
{
    RngRef rng = make_test_rng();

    auto kp = signer::Ed25519Provider::generate_keypair(rng);

    genesis::UnlockedKeypair keypair;
    keypair.public_key = std::move(kp.public_key);
    keypair.secret_key = std::move(kp.secret_key);

    std::vector<std::string> passphrases = {"pass1", "pass2", "pass3"};
    smo::kdf::Argon2idParams params;
    params.memory_kib = 8192;
    params.iterations = 2;
    params.lanes = 4;

    auto pkg_res = genesis::RecoveryPackageV2::create("TestMesh", keypair, 2, 3, params, passphrases, rng);
    ASSERT(pkg_res);
    auto pkg = std::move(pkg_res).value();

    auto ser = pkg.serialize();
    ASSERT(ser);

    // Tamper with the serialized JSON (flip a byte in encrypted share)
    std::string json_str(reinterpret_cast<char*>(ser.value().data()), ser.value().size());
    size_t enc_pos = json_str.find("encrypted_share");
    if (enc_pos != std::string::npos)
    {
        enc_pos = json_str.find(':', enc_pos);
        if (enc_pos != std::string::npos)
        {
            enc_pos = json_str.find('"', enc_pos);
            if (enc_pos != std::string::npos)
            {
                enc_pos++;
                if (enc_pos < json_str.size())
                    json_str[enc_pos] ^= 0x01;
            }
        }
    }

    Bytes tampered(json_str.begin(), json_str.end());
    auto depkg_res = genesis::RecoveryPackageV2::deserialize(BytesView(tampered));
    ASSERT(depkg_res);
    auto depkg = std::move(depkg_res).value();

    // Try recovery - should fail due to tampered share
    std::vector<std::pair<uint8_t, std::string>> passes = {
        {1, "pass1"}, {2, "pass2"}
    };

    auto recovered_kp = depkg.recover(passes);
    ASSERT(!recovered_kp);

    return true;
}

static bool test_recovery_package_v2_shareholder_index_not_found()
{
    RngRef rng = make_test_rng();

    auto kp = signer::Ed25519Provider::generate_keypair(rng);

    genesis::UnlockedKeypair keypair;
    keypair.public_key = std::move(kp.public_key);
    keypair.secret_key = std::move(kp.secret_key);

    std::vector<std::string> passphrases = {"pass1", "pass2", "pass3"};
    smo::kdf::Argon2idParams params;
    params.memory_kib = 8192;
    params.iterations = 2;
    params.lanes = 4;

    auto pkg_res = genesis::RecoveryPackageV2::create("TestMesh", keypair, 2, 3, params, passphrases, rng);
    ASSERT(pkg_res);
    auto pkg = std::move(pkg_res).value();

    auto ser = pkg.serialize();
    ASSERT(ser);
    auto depkg_res = genesis::RecoveryPackageV2::deserialize(BytesView(ser.value()));
    ASSERT(depkg_res);
    auto depkg = std::move(depkg_res).value();

    // Try to unlock share with non-existent index
    auto share_res = depkg.verify_and_unlock_share(99, "pass1");
    ASSERT(!share_res);

    return true;
}

int main()
{
    printf("=== SMO Shamir SSS Tests (C8) ===\n\n");

    printf("[Shamir Core]\n");
    TEST("split/recover roundtrip (various M,N)");
    END_TEST(test_shamir_split_recover_roundtrip());
    TEST("wrong threshold fails");
    END_TEST(test_shamir_wrong_threshold_fails());
    TEST("tampered share fails");
    END_TEST(test_shamir_tampered_share_fails());
    TEST("duplicate indices rejected");
    END_TEST(test_shamir_duplicate_indices_rejected());
    TEST("share serialization roundtrip");
    END_TEST(test_shamir_share_serialization());

    printf("\n[RecoveryPackage v2]\n");
    TEST("create/recover roundtrip");
    END_TEST(test_recovery_package_v2_create_recover());
    TEST("wrong passphrase fails");
    END_TEST(test_recovery_package_v2_wrong_passphrase_fails());
    TEST("insufficient shares fails");
    END_TEST(test_recovery_package_v2_insufficient_shares_fails());
    TEST("tampered share fails");
    END_TEST(test_recovery_package_v2_tampered_share_fails());
    TEST("shareholder index not found");
    END_TEST(test_recovery_package_v2_shareholder_index_not_found());

    printf("\n=== %s ===\n", failures ? "FAILURES" : "ALL PASS");
    return failures ? 1 : 0;
}