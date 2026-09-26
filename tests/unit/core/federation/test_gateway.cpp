#include <federation/gateway.hpp>
#include <crypto/registry.hpp>
#include <crypto/impl.hpp>
#include <acl/policy_engine.hpp>

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

// ============================================================================
// CrossMeshRoutingTable Tests
// ============================================================================

static bool test_routing_table_add_mesh()
{
    federation::CrossMeshRoutingTable::Config config;
    config.local_mesh_id = "mesh-local";
    config.local_gateway_node_id = "gateway-local";

    federation::CrossMeshRoutingTable table(config);

    federation::MeshInfo mesh;
    mesh.mesh_id = "mesh-remote";
    mesh.display_name = "Remote Mesh";
    mesh.authority_pubkey = "auth-pubkey";
    mesh.root_pubkey = "root-pubkey";
    mesh.cipher_suite = kSuitePurePQC;
    mesh.epoch = 1;
    mesh.role = federation::MeshRole::Remote;
    mesh.gateway_node_id = "gateway-remote";
    mesh.advertise_endpoints = {"tcp://10.0.0.1:7777"};

    auto res = table.add_mesh(mesh);
    ASSERT(res);

    auto get_res = table.get_mesh("mesh-remote");
    ASSERT(get_res);
    ASSERT_STREQ(get_res.value().mesh_id, "mesh-remote");
    ASSERT_STREQ(get_res.value().display_name, "Remote Mesh");
    ASSERT_EQ(get_res.value().cipher_suite, kSuitePurePQC);
    ASSERT_EQ(get_res.value().role, federation::MeshRole::Remote);

    return true;
}

static bool test_routing_table_duplicate_mesh_fails()
{
    federation::CrossMeshRoutingTable::Config config;
    config.local_mesh_id = "mesh-local";
    config.local_gateway_node_id = "gateway-local";

    federation::CrossMeshRoutingTable table(config);

    federation::MeshInfo mesh;
    mesh.mesh_id = "mesh-remote";
    mesh.display_name = "Remote Mesh";
    mesh.authority_pubkey = "auth-pubkey";
    mesh.root_pubkey = "root-pubkey";

    ASSERT(table.add_mesh(mesh));
    auto res = table.add_mesh(mesh);
    ASSERT(!res);

    return true;
}

static bool test_routing_table_add_route()
{
    federation::CrossMeshRoutingTable::Config config;
    config.local_mesh_id = "mesh-local";
    config.local_gateway_node_id = "gateway-local";

    federation::CrossMeshRoutingTable table(config);

    federation::MeshInfo mesh;
    mesh.mesh_id = "mesh-remote";
    mesh.display_name = "Remote Mesh";
    ASSERT(table.add_mesh(mesh));

    federation::CrossMeshRoute route;
    route.destination_mesh_id = "mesh-remote";
    route.next_hop_mesh_id = "mesh-remote";
    route.gateway_node_id = "gateway-remote";
    route.metric = 10;

    auto res = table.add_route(route);
    ASSERT(res);

    auto find_res = table.find_route("mesh-remote");
    ASSERT(find_res);
    ASSERT_STREQ(find_res.value().destination_mesh_id, "mesh-remote");
    ASSERT_STREQ(find_res.value().gateway_node_id, "gateway-remote");
    ASSERT_EQ(find_res.value().metric, 10);

    return true;
}

static bool test_routing_table_route_to_unknown_mesh_fails()
{
    federation::CrossMeshRoutingTable::Config config;
    config.local_mesh_id = "mesh-local";
    config.local_gateway_node_id = "gateway-local";

    federation::CrossMeshRoutingTable table(config);

    federation::CrossMeshRoute route;
    route.destination_mesh_id = "mesh-unknown";
    route.next_hop_mesh_id = "mesh-unknown";
    route.gateway_node_id = "gateway-unknown";

    auto res = table.add_route(route);
    ASSERT(!res);

    return true;
}

static bool test_routing_table_gateway_policy()
{
    federation::CrossMeshRoutingTable::Config config;
    config.local_mesh_id = "mesh-local";
    config.local_gateway_node_id = "gateway-local";

    federation::CrossMeshRoutingTable table(config);

    federation::GatewayPolicy policy;
    policy.name = "allow-echo";
    policy.source_mesh = "mesh-local";
    policy.destination_mesh = "mesh-remote";
    policy.allowed_contracts = {"echo"};
    policy.required_capabilities = {"CAP_VERIFY"};
    policy.default_decision = acl::PolicyDecision::Allow;
    policy.priority = 100;
    policy.enabled = true;

    table.set_gateway_policy(policy);

    auto get_res = table.get_gateway_policy("mesh-local", "mesh-remote");
    ASSERT(get_res);
    ASSERT_STREQ(get_res.value().name, "allow-echo");
    ASSERT_EQ(get_res.value().allowed_contracts.size(), 1);
    ASSERT_STREQ(get_res.value().allowed_contracts[0], "echo");

    // Test default policy when none set
    auto default_res = table.get_gateway_policy("mesh-local", "mesh-unknown");
    ASSERT(default_res);
    ASSERT_STREQ(default_res.value().name, "default");
    ASSERT_EQ(default_res.value().default_decision, acl::PolicyDecision::Allow);

    return true;
}

static bool test_routing_table_check_route_policy()
{
    federation::CrossMeshRoutingTable::Config config;
    config.local_mesh_id = "mesh-local";
    config.local_gateway_node_id = "gateway-local";

    federation::CrossMeshRoutingTable table(config);

    federation::GatewayPolicy policy;
    policy.name = "allow-echo";
    policy.source_mesh = "mesh-local";
    policy.destination_mesh = "mesh-remote";
    policy.allowed_contracts = {"echo", "transfer"};
    policy.required_capabilities = {"CAP_VERIFY"};
    policy.default_decision = acl::PolicyDecision::Deny;
    policy.enabled = true;

    table.set_gateway_policy(policy);

    // Allowed contract with required capability
    auto check1 = table.check_route_policy("mesh-local", "mesh-remote", "echo", {"CAP_VERIFY"});
    ASSERT(check1);
    ASSERT(check1.value());

    // Allowed contract without required capability
    auto check2 = table.check_route_policy("mesh-local", "mesh-remote", "echo", {});
    ASSERT(check2);
    ASSERT(!check2.value());

    // Denied contract
    auto check3 = table.check_route_policy("mesh-local", "mesh-remote", "admin", {"CAP_VERIFY"});
    ASSERT(check3);
    ASSERT(!check3.value());

    // Unknown mesh uses default allow
    auto check4 = table.check_route_policy("mesh-local", "mesh-unknown", "any", {});
    ASSERT(check4);
    ASSERT(check4.value());

    return true;
}

static bool test_routing_table_mesh_health()
{
    federation::CrossMeshRoutingTable::Config config;
    config.local_mesh_id = "mesh-local";
    config.local_gateway_node_id = "gateway-local";

    federation::CrossMeshRoutingTable table(config);

    federation::MeshInfo mesh;
    mesh.mesh_id = "mesh-remote";
    mesh.display_name = "Remote Mesh";
    ASSERT(table.add_mesh(mesh));

    auto get1 = table.get_mesh("mesh-remote");
    ASSERT(get1);
    ASSERT(get1.value().healthy);

    ASSERT(table.update_mesh_health("mesh-remote", false));

    auto get2 = table.get_mesh("mesh-remote");
    ASSERT(get2);
    ASSERT(!get2.value().healthy);

    return true;
}

// ============================================================================
// Main
// ============================================================================

int main(int, char*[])
{
    printf("SMO Federation Gateway — Unit Tests\n");
    printf("====================================\n\n");

    TEST("RoutingTable add mesh") END_TEST(test_routing_table_add_mesh());
    TEST("RoutingTable duplicate mesh fails") END_TEST(test_routing_table_duplicate_mesh_fails());
    TEST("RoutingTable add route") END_TEST(test_routing_table_add_route());
    TEST("RoutingTable route to unknown mesh fails") END_TEST(test_routing_table_route_to_unknown_mesh_fails());
    TEST("RoutingTable gateway policy") END_TEST(test_routing_table_gateway_policy());
    TEST("RoutingTable check route policy") END_TEST(test_routing_table_check_route_policy());
    TEST("RoutingTable mesh health") END_TEST(test_routing_table_mesh_health());

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