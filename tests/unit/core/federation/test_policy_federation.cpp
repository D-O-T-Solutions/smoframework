#include <federation/policy_federation.hpp>
#include <acl/policy_engine.hpp>
#include <crypto/registry.hpp>
#include <crypto/impl.hpp>

#include <cstdio>
#include <cstring>

using namespace smo;

// ---------------------------------------------------------------------------
// Minimal test runner
// ---------------------------------------------------------------------------
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

#define ASSERT_EQ(a, b)                                                                                                \
    do                                                                                                                 \
    {                                                                                                                  \
        if ((a) != (b))                                                                                                \
        {                                                                                                              \
            printf("\n    ASSERTION FAILED at %s:%d: %s == %s\n"                                                       \
                   "      LHS=%lld  RHS=%lld\n",                                                                       \
                   __FILE__, __LINE__, #a, #b, static_cast<long long>(a), static_cast<long long>(b));                  \
            return false;                                                                                              \
        }                                                                                                              \
    } while (false)

#define ASSERT_STREQ(a, b)                                                                                             \
    do                                                                                                                 \
    {                                                                                                                  \
        const auto& _a = (a);                                                                                          \
        const auto& _b = (b);                                                                                          \
        if (_a != _b)                                                                                                  \
        {                                                                                                              \
            printf("\n    ASSERTION FAILED at %s:%d: %s == %s\n"                                                       \
                   "      LHS=\"%s\"  RHS=\"%s\"\n",                                                                   \
                   __FILE__, __LINE__, #a, #b, std::string(_a).c_str(), std::string(_b).c_str());                      \
            return false;                                                                                              \
        }                                                                                                              \
    } while (false)

// Mock crypto provider
static Result<Bytes> mock_hash(BytesView data)
{
    Bytes out(16, 0);
    out[0] = static_cast<uint8_t>(data.size());
    for (size_t i = 0; i < data.size(); ++i)
        out[(i % 15) + 1] ^= data[i];
    return out;
}

static Result<Bytes> mock_hmac(BytesView key, BytesView data)
{
    (void)key;
    return mock_hash(data);
}

static Result<bool> mock_verify(BytesView msg, BytesView sig, BytesView pk)
{
    (void)msg;
    (void)sig;
    (void)pk;
    return true;
}

static Result<Bytes> mock_sign(BytesView msg, BytesView sk, RngRef& rng)
{
    (void)msg;
    (void)sk;
    Bytes sig(64);
    rng.fill(sig);
    return sig;
}

static Result<KeypairResult> mock_kem_generate_keypair(RngRef& rng)
{
    (void)rng;
    KeypairResult kp;
    kp.public_key = Bytes(32, 0);
    kp.secret_key = Bytes(32, 0);
    return kp;
}

static Result<EncapsResult> mock_kem_encapsulate(BytesView pk, RngRef& rng)
{
    (void)pk;
    EncapsResult result;
    result.ciphertext = Bytes(32, 0);
    rng.fill(result.ciphertext);
    result.shared_secret = Bytes(32, 0);
    rng.fill(result.shared_secret);
    return result;
}

static Result<Bytes> mock_kem_decapsulate(BytesView privkey, BytesView ciphertext)
{
    (void)privkey;
    (void)ciphertext;
    return Bytes(32, 0);
}

static Result<Bytes> mock_aead_encrypt(BytesView key, BytesView nonce, BytesView aad, BytesView pt)
{
    (void)key; (void)nonce; (void)aad;
    Bytes ct(pt.size() + 16);
    std::copy(pt.begin(), pt.end(), ct.begin());
    return ct;
}

static Result<Bytes> mock_aead_decrypt(BytesView key, BytesView nonce, BytesView aad, BytesView ct)
{
    (void)key; (void)nonce; (void)aad;
    if (ct.size() < 16)
        return Error(ErrorCode(ErrorCategory::Crypto, 1, Severity::Error, RetryClass::NoRetry, Recovery::None), "ct too short", __FILE__, __LINE__);
    return Bytes(ct.begin(), ct.end() - 16);
}

static const HashImpl kHash{mock_hash, mock_hmac};
static const SignerImpl kSigner{nullptr, mock_sign, mock_verify};
static const KemImpl kKem{mock_kem_generate_keypair, mock_kem_encapsulate, mock_kem_decapsulate};
static const AeadImpl kAead{mock_aead_encrypt, mock_aead_decrypt};

static const CryptoProvider kCryptoProvider{
    .suite_id = kSuitePurePQC,
    .name = "mock",
    .rng_ctx = nullptr,
    .rng_fill = nullptr,
    .hash = kHash,
    .perf_hash = {nullptr, nullptr},
    .aead = kAead,
    .kem = kKem,
    .signer = kSigner,
};

static void mock_rng_fill_fn(void* ctx, uint8_t* buf, size_t len)
{
    (void)ctx;
    for (size_t i = 0; i < len; ++i)
        buf[i] = static_cast<uint8_t>(rand());
}

static RngRef kRng{nullptr, mock_rng_fill_fn};

static int64_t now_ns()
{
    return static_cast<int64_t>(std::chrono::system_clock::now().time_since_epoch().count());
}

// ============================================================================
// PolicyDelta Tests
// ============================================================================

static bool test_policy_delta_roundtrip()
{
    federation::PolicyDelta delta;
    delta.mesh_id = "mesh-a";
    delta.version = 42;
    delta.timestamp = 1234567890;

    acl::PolicySet policy1;
    policy1.name = "policy-1";
    policy1.description = "Test policy 1";
    policy1.version = "1.0";
    policy1.created_at = 1000;
    policy1.created_by = "admin";

    acl::PolicyRule rule1;
    rule1.name = "rule-1";
    rule1.description = "Allow read";
    rule1.priority = 50;
    rule1.required_capabilities = {"CAP_VERIFY", "CAP_FS_READ"};
    rule1.effect = acl::PolicyDecision::Allow;
    rule1.mesh_id = "mesh-a";
    policy1.rules.push_back(rule1);

    delta.added_policies.push_back(policy1);

    delta.removed_policies.push_back("old-policy");

    acl::PolicySet policy2;
    policy2.name = "policy-2";
    policy2.description = "Updated policy";
    policy2.version = "2.0";
    delta.updated_policies.push_back(policy2);

    auto ser = delta.serialize();
    ASSERT(!ser.empty());

    auto deser = federation::PolicyDelta::deserialize(ser);
    ASSERT(deser);
    ASSERT_STREQ(deser.value().mesh_id, "mesh-a");
    ASSERT_EQ(deser.value().version, 42);
    ASSERT_EQ(deser.value().added_policies.size(), 1);
    ASSERT_STREQ(deser.value().added_policies[0].name, "policy-1");
    ASSERT_EQ(deser.value().added_policies[0].rules.size(), 1);
    ASSERT_STREQ(deser.value().added_policies[0].rules[0].name, "rule-1");
    ASSERT_EQ(deser.value().added_policies[0].rules[0].required_capabilities.size(), 2);
    ASSERT_EQ(deser.value().removed_policies.size(), 1);
    ASSERT_STREQ(deser.value().removed_policies[0], "old-policy");
    ASSERT_EQ(deser.value().updated_policies.size(), 1);
    ASSERT_STREQ(deser.value().updated_policies[0].name, "policy-2");
    ASSERT_EQ(deser.value().timestamp, 1234567890);

    return true;
}

static bool test_trust_anchor_delta_roundtrip()
{
    federation::TrustAnchorDelta delta;
    delta.mesh_id = "mesh-a";
    delta.version = 10;
    delta.timestamp = 9876543210;

    Certificate anchor1;
    anchor1.subject_pubkey = {0x11, 0x22, 0x33, 0x44};
    anchor1.issuer_pubkey = {0x55, 0x66};
    anchor1.mesh_id = {0xAA, 0xBB};
    anchor1.role = Role::Authority;
    anchor1.epoch = 1;
    anchor1.not_before = 1000;
    anchor1.not_after = 2000;
    delta.added_anchors.push_back(anchor1);

    delta.removed_anchor_fingerprints.push_back("fp-old-anchor");

    auto ser = delta.serialize();
    ASSERT(!ser.empty());

    auto deser = federation::TrustAnchorDelta::deserialize(ser);
    ASSERT(deser);
    ASSERT_STREQ(deser.value().mesh_id, "mesh-a");
    ASSERT_EQ(deser.value().version, 10);
    ASSERT_EQ(deser.value().added_anchors.size(), 1);
    ASSERT_EQ(deser.value().added_anchors[0].subject_pubkey[0], 0x11);
    ASSERT_EQ(deser.value().removed_anchor_fingerprints.size(), 1);
    ASSERT_STREQ(deser.value().removed_anchor_fingerprints[0], "fp-old-anchor");
    ASSERT_EQ(deser.value().timestamp, 9876543210);

    return true;
}

// ============================================================================
// PolicyFederation Tests
// ============================================================================

static bool test_policy_federation_register_mesh()
{
    acl::PolicyEngine policy_engine;
    federation::PolicyFederation::Config config;
    config.local_mesh_id = "mesh-local";
    config.data_dir = "/tmp/test_federation";

    federation::PolicyFederation fed(config, policy_engine);

    ASSERT(fed.initialize());

    bool send_called = false;
    Bytes sent_data;

    auto send_fn = [&](const std::string& mesh_id, BytesView data) -> Result<void> {
        send_called = true;
        sent_data = Bytes(data.begin(), data.end());
        return {};
    };

    auto res = fed.register_remote_mesh("mesh-remote", send_fn);
    ASSERT(res);

    auto unreg = fed.unregister_remote_mesh("mesh-remote");
    ASSERT(unreg);

    return true;
}

static bool test_policy_federation_duplicate_register_fails()
{
    acl::PolicyEngine policy_engine;
    federation::PolicyFederation::Config config;
    config.local_mesh_id = "mesh-local";
    config.data_dir = "/tmp/test_federation";

    federation::PolicyFederation fed(config, policy_engine);
    ASSERT(fed.initialize());

    auto send_fn = [](const std::string&, BytesView) -> Result<void> { return {}; };

    ASSERT(fed.register_remote_mesh("mesh-remote", send_fn));
    auto res = fed.register_remote_mesh("mesh-remote", send_fn);
    ASSERT(!res);

    return true;
}

static bool test_policy_federation_sync_policy()
{
    acl::PolicyEngine policy_engine;
    federation::PolicyFederation::Config config;
    config.local_mesh_id = "mesh-local";
    config.data_dir = "/tmp/test_federation";

    federation::PolicyFederation fed(config, policy_engine);
    ASSERT(fed.initialize());

    bool send_called = false;

    auto send_fn = [&](const std::string& mesh_id, BytesView data) -> Result<void> {
        send_called = true;
        return {};
    };

    ASSERT(fed.register_remote_mesh("mesh-remote", send_fn));
    auto res = fed.sync_policy_to_mesh("mesh-remote");
    ASSERT(res);
    ASSERT(send_called);

    return true;
}

static bool test_policy_federation_sync_trust_anchors()
{
    acl::PolicyEngine policy_engine;
    federation::PolicyFederation::Config config;
    config.local_mesh_id = "mesh-local";
    config.data_dir = "/tmp/test_federation";

    federation::PolicyFederation fed(config, policy_engine);
    ASSERT(fed.initialize());

    bool send_called = false;

    auto send_fn = [&](const std::string& mesh_id, BytesView data) -> Result<void> {
        send_called = true;
        return {};
    };

    ASSERT(fed.register_remote_mesh("mesh-remote", send_fn));
    auto res = fed.sync_trust_anchors_to_mesh("mesh-remote");
    ASSERT(res);
    ASSERT(send_called);

    return true;
}

static bool test_policy_federation_handle_policy_delta()
{
    acl::PolicyEngine policy_engine;
    federation::PolicyFederation::Config config;
    config.local_mesh_id = "mesh-local";
    config.data_dir = "/tmp/test_federation";

    federation::PolicyFederation fed(config, policy_engine);
    ASSERT(fed.initialize());

    federation::PolicyDelta delta;
    delta.mesh_id = "mesh-remote";
    delta.version = 1;
    delta.timestamp = now_ns();

    acl::PolicySet policy;
    policy.name = "synced-policy";
    policy.description = "Policy from remote mesh";
    policy.version = "1.0";
    policy.created_at = now_ns();
    policy.created_by = "remote-admin";

    acl::PolicyRule rule;
    rule.name = "synced-rule";
    rule.description = "Synced rule";
    rule.priority = 50;
    rule.required_capabilities = {"CAP_VERIFY"};
    rule.effect = acl::PolicyDecision::Allow;
    policy.rules.push_back(rule);

    delta.added_policies.push_back(policy);

    auto ser = delta.serialize();
    ASSERT(!ser.empty());

    bool callback_called = false;
    std::string captured_mesh_id;
    std::string captured_policy_name;
    bool captured_added = false;
    fed.set_on_policy_change([&](const std::string& mesh_id, const acl::PolicySet& p, bool added) {
        callback_called = true;
        captured_mesh_id = mesh_id;
        captured_policy_name = p.name;
        captured_added = added;
    });

    auto res = fed.handle_policy_delta("mesh-remote", ser);
    ASSERT(res);
    ASSERT(callback_called);
    ASSERT_STREQ(std::string(captured_mesh_id), "mesh-remote");
    ASSERT_STREQ(std::string(captured_policy_name), "synced-policy");
    ASSERT(captured_added);
    ASSERT(res);
    ASSERT(callback_called);

    return true;
}

static bool test_policy_federation_handle_trust_anchor_delta()
{
    acl::PolicyEngine policy_engine;
    federation::PolicyFederation::Config config;
    config.local_mesh_id = "mesh-local";
    config.data_dir = "/tmp/test_federation";

    federation::PolicyFederation fed(config, policy_engine);
    ASSERT(fed.initialize());

    federation::TrustAnchorDelta delta;
    delta.mesh_id = "mesh-remote";
    delta.version = 1;
    delta.timestamp = now_ns();

    Certificate anchor;
    anchor.subject_pubkey = {0xAA, 0xBB, 0xCC, 0xDD};
    anchor.issuer_pubkey = {0xEE, 0xFF};
    anchor.mesh_id = {0x11, 0x22};
    anchor.role = Role::Authority;
    anchor.epoch = 1;
    delta.added_anchors.push_back(anchor);

    auto ser = delta.serialize();
    ASSERT(!ser.empty());

    bool callback_called = false;
    std::string captured_mesh_id;
    uint8_t captured_pubkey = 0;
    bool captured_added = false;
    fed.set_on_trust_anchor_change([&](const std::string& mesh_id, const Certificate& a, bool added) {
        callback_called = true;
        captured_mesh_id = mesh_id;
        captured_pubkey = a.subject_pubkey[0];
        captured_added = added;
    });

    auto res = fed.handle_trust_anchor_delta("mesh-remote", ser);
    ASSERT(res);
    ASSERT(callback_called);
    ASSERT_STREQ(std::string(captured_mesh_id), "mesh-remote");
    ASSERT_EQ(captured_pubkey, 0xAA);
    ASSERT(captured_added);
    ASSERT(res);
    ASSERT(callback_called);

    return true;
}

// ============================================================================
// Main
// ============================================================================

int main(int, char*[])
{
    printf("SMO Policy Federation — Unit Tests\n");
    printf("===================================\n\n");

    TEST("PolicyDelta roundtrip") END_TEST(test_policy_delta_roundtrip());
    TEST("TrustAnchorDelta roundtrip") END_TEST(test_trust_anchor_delta_roundtrip());
    TEST("PolicyFederation register mesh") END_TEST(test_policy_federation_register_mesh());
    TEST("PolicyFederation duplicate register fails") END_TEST(test_policy_federation_duplicate_register_fails());
    TEST("PolicyFederation sync policy") END_TEST(test_policy_federation_sync_policy());
    TEST("PolicyFederation sync trust anchors") END_TEST(test_policy_federation_sync_trust_anchors());
    TEST("PolicyFederation handle policy delta") END_TEST(test_policy_federation_handle_policy_delta());
    TEST("PolicyFederation handle trust anchor delta") END_TEST(test_policy_federation_handle_trust_anchor_delta());

    printf("\n");
    if (failures == 0)
    {
        printf("ALL TESTS PASSED\n");
        return 0;
    }
    else
    {
        printf("%d TEST(S) FAILED\n", failures);
        return 1;
    }
}