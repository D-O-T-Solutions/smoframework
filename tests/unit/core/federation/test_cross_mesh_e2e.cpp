#include <federation/gateway.hpp>
#include <federation/federation_handshake.hpp>
#include <federation/policy_federation.hpp>
#include <federation/cross_mesh_router.hpp>
#include <acl/policy_engine.hpp>
#include <crypto/registry.hpp>
#include <crypto/impl.hpp>
#include <runtime/runtime_types.hpp>
#include <runtime/dispatcher.hpp>
#include <runtime/contracts/echo_contract.hpp>

#include <cstdio>
#include <cstring>
#include <thread>
#include <chrono>

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
// E2E Cross-Mesh Test
// ============================================================================

static bool test_cross_mesh_contract_execution()
{
    // Setup Mesh A (local)
    acl::PolicyEngine policy_engine_a;
    federation::PolicyFederation::Config fed_config_a;
    fed_config_a.local_mesh_id = "mesh-a";
    fed_config_a.data_dir = "/tmp/test_mesh_a";
    fed_config_a.sync_interval_ns = 1000000000; // 1s for test

    federation::PolicyFederation policy_fed_a(fed_config_a, policy_engine_a);
    ASSERT(policy_fed_a.initialize());

    // Setup Mesh B (remote)
    acl::PolicyEngine policy_engine_b;
    federation::PolicyFederation::Config fed_config_b;
    fed_config_b.local_mesh_id = "mesh-b";
    fed_config_b.data_dir = "/tmp/test_mesh_b";
    fed_config_b.sync_interval_ns = 1000000000;

    federation::PolicyFederation policy_fed_b(fed_config_b, policy_engine_b);
    ASSERT(policy_fed_b.initialize());

    // Setup cross-mesh router for Mesh A
    federation::CrossMeshRouter::Config router_config_a;
    router_config_a.local_mesh_id = "mesh-a";
    router_config_a.local_gateway_node_id = "gateway-a";

    bool execute_called_a = false;
    federation::CrossMeshRouter::ExecuteLocalFn execute_local_a = [&](const std::string& contract_id, const runtime::ContractInput& input, const runtime::RuntimeContext&) -> Result<runtime::ContractResult> {
        execute_called_a = true;
        ASSERT_STREQ(contract_id, "echo");
        runtime::ContractResult result;
        result.output = input.params; // Echo back
        return result;
    };

    bool send_called_a = false;
    std::string sent_to_mesh;
    federation::CrossMeshRouter::SendRemoteFn send_remote_a = [&](const std::string& dest_mesh, const std::string&, BytesView) -> Result<void> {
        send_called_a = true;
        sent_to_mesh = dest_mesh;
        return {};
    };

    federation::CrossMeshExecutionResponse response_from_a;
    bool response_received_a = false;
    federation::CrossMeshRouter::OnResponseFn on_response_a = [&](const std::string&, const federation::CrossMeshExecutionResponse& resp) {
        response_received_a = true;
        response_from_a = resp;
    };

    federation::CrossMeshRouter router_a(router_config_a, execute_local_a, send_remote_a, on_response_a);

    // Add route from A to B
    federation::CrossMeshRouteEntry route_a_to_b;
    route_a_to_b.destination_mesh = "mesh-b";
    route_a_to_b.gateway_session_id = "session-a-to-b";
    route_a_to_b.next_hop_gateway = "gateway-b";
    route_a_to_b.metric = 10;
    ASSERT(router_a.add_route(route_a_to_b));

    // Setup cross-mesh router for Mesh B
    federation::CrossMeshRouter::Config router_config_b;
    router_config_b.local_mesh_id = "mesh-b";
    router_config_b.local_gateway_node_id = "gateway-b";

    bool execute_called_b = false;
    federation::CrossMeshRouter::ExecuteLocalFn execute_local_b = [&](const std::string& contract_id, const runtime::ContractInput& input, const runtime::RuntimeContext&) -> Result<runtime::ContractResult> {
        execute_called_b = true;
        ASSERT_STREQ(contract_id, "echo");
        runtime::ContractResult result;
        result.output = input.params; // Echo back
        return result;
    };

    bool send_called_b = false;
    federation::CrossMeshRouter::SendRemoteFn send_remote_b = [&](const std::string&, const std::string&, BytesView) -> Result<void> {
        send_called_b = true;
        return {};
    };

    federation::CrossMeshRouter::OnResponseFn on_response_b = [&](const std::string&, const federation::CrossMeshExecutionResponse&) {};

    federation::CrossMeshRouter router_b(router_config_b, execute_local_b, send_remote_b, on_response_b);

    // Add route from B to A
    federation::CrossMeshRouteEntry route_b_to_a;
    route_b_to_a.destination_mesh = "mesh-a";
    route_b_to_a.gateway_session_id = "session-b-to-a";
    route_b_to_a.next_hop_gateway = "gateway-a";
    route_b_to_a.metric = 10;
    ASSERT(router_b.add_route(route_b_to_a));

    // Execute cross-mesh contract from A to B
    federation::CrossMeshExecutionRequest request;
    request.source_mesh_id = "mesh-a";
    request.destination_mesh_id = "mesh-b";
    request.contract_id = "echo";
    request.input.params = Bytes{'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd'};
    request.session_id = "session-a-to-b";
    request.capabilities = {"CAP_VERIFY"};
    request.timeout_ns = 5000000000LL; // 5s

    auto req_id = router_a.execute_cross_mesh(request);
    ASSERT(req_id);
    ASSERT(send_called_a);
    ASSERT_STREQ(sent_to_mesh, "mesh-b");

    // Simulate B receiving the request and responding
    // In real scenario, this would come over the network
    // For test, we directly call handle_incoming_request on B
    federation::CrossMeshExecutionRequest request_for_b = request;
    request_for_b.source_mesh_id = "mesh-a";
    request_for_b.destination_mesh_id = "mesh-b";

    auto handle_res = router_b.handle_incoming_request(req_id.value(), request_for_b);
    ASSERT(handle_res);
    ASSERT(execute_called_b);

    // Now simulate the response coming back to A
    federation::CrossMeshExecutionResponse response;
    response.success = true;
    response.result.output = request.input.params;
    response.execution_time_ns = now_ns();

    auto resp_res = router_a.handle_response(req_id.value(), response);
    ASSERT(resp_res);
    ASSERT(response_received_a);
    ASSERT(response_from_a.success);
    ASSERT_EQ(response_from_a.result.output.size(), 11);
    ASSERT_STREQ(std::string((char*)response_from_a.result.output.data(), 11), "Hello World");

    return true;
}

static bool test_cross_mesh_policy_sync()
{
    acl::PolicyEngine policy_engine_a;
    federation::PolicyFederation::Config fed_config_a;
    fed_config_a.local_mesh_id = "mesh-a";
    fed_config_a.data_dir = "/tmp/test_mesh_a_policy";

    federation::PolicyFederation policy_fed_a(fed_config_a, policy_engine_a);
    ASSERT(policy_fed_a.initialize());

    acl::PolicyEngine policy_engine_b;
    federation::PolicyFederation::Config fed_config_b;
    fed_config_b.local_mesh_id = "mesh-b";
    fed_config_b.data_dir = "/tmp/test_mesh_b_policy";

    federation::PolicyFederation policy_fed_b(fed_config_b, policy_engine_b);
    ASSERT(policy_fed_b.initialize());

    // Register meshes with each other
    Bytes last_sent_delta;
    bool a_sent_to_b = false;

    auto send_a_to_b = [&](const std::string& mesh_id, BytesView data) -> Result<void> {
        a_sent_to_b = true;
        last_sent_delta = Bytes(data.begin(), data.end());
        return {};
    };

    Bytes last_sent_delta_b;
    bool b_sent_to_a = false;

    auto send_b_to_a = [&](const std::string& mesh_id, BytesView data) -> Result<void> {
        b_sent_to_a = true;
        last_sent_delta_b = Bytes(data.begin(), data.end());
        return {};
    };

    ASSERT(policy_fed_a.register_remote_mesh("mesh-b", send_a_to_b));
    ASSERT(policy_fed_b.register_remote_mesh("mesh-a", send_b_to_a));

    // Add a policy on mesh A
    acl::PolicySet policy_a;
    policy_a.name = "cross-mesh-policy";
    policy_a.description = "Policy for cross-mesh access";
    policy_a.version = "1.0";
    policy_a.created_at = now_ns();
    policy_a.created_by = "admin-a";

    acl::PolicyRule rule_a;
    rule_a.name = "allow-echo-cross-mesh";
    rule_a.description = "Allow echo contract from remote mesh";
    rule_a.priority = 50;
    rule_a.required_capabilities = {"CAP_VERIFY", "CAP_CROSS_MESH"};
    rule_a.effect = acl::PolicyDecision::Allow;
    rule_a.mesh_id = "mesh-a";
    policy_a.rules.push_back(rule_a);

    ASSERT(policy_engine_a.load_policy_set(policy_a));

    // Sync policy from A to B
    ASSERT(policy_fed_a.sync_policy_to_mesh("mesh-b"));
    ASSERT(a_sent_to_b);

    // B receives the delta
    bool policy_callback_called = false;
    policy_fed_b.set_on_policy_change([&](const std::string& mesh_id, const acl::PolicySet& policy, bool added) {
        policy_callback_called = true;
        ASSERT_STREQ(mesh_id, "mesh-a");
        ASSERT_STREQ(policy.name, "cross-mesh-policy");
        ASSERT(added);
    });

    ASSERT(policy_fed_b.handle_policy_delta("mesh-a", last_sent_delta));
    ASSERT(policy_callback_called);

    // Verify B now has the policy
    auto policy_names = policy_engine_b.list_policies();
    ASSERT(policy_names);
    bool found = false;
    for (const auto& name : policy_names.value())
    {
        if (name == "cross-mesh-policy")
        {
            found = true;
            break;
        }
    }
    ASSERT(found);

    return true;
}

static bool test_cross_mesh_trust_anchor_sync()
{
    acl::PolicyEngine policy_engine_a;
    federation::PolicyFederation::Config fed_config_a;
    fed_config_a.local_mesh_id = "mesh-a";
    fed_config_a.data_dir = "/tmp/test_mesh_a_ta";

    federation::PolicyFederation policy_fed_a(fed_config_a, policy_engine_a);
    ASSERT(policy_fed_a.initialize());

    acl::PolicyEngine policy_engine_b;
    federation::PolicyFederation::Config fed_config_b;
    fed_config_b.local_mesh_id = "mesh-b";
    fed_config_b.data_dir = "/tmp/test_mesh_b_ta";

    federation::PolicyFederation policy_fed_b(fed_config_b, policy_engine_b);
    ASSERT(policy_fed_b.initialize());

    Bytes last_sent_delta;
    bool sent = false;

    auto send_fn = [&](const std::string& mesh_id, BytesView data) -> Result<void> {
        sent = true;
        last_sent_delta = Bytes(data.begin(), data.end());
        return {};
    };

    ASSERT(policy_fed_a.register_remote_mesh("mesh-b", send_fn));
    ASSERT(policy_fed_b.register_remote_mesh("mesh-a", send_fn));

    // Sync trust anchors from A to B
    ASSERT(policy_fed_a.sync_trust_anchors_to_mesh("mesh-b"));
    ASSERT(sent);

    // B receives the delta
    bool ta_callback_called = false;
    policy_fed_b.set_on_trust_anchor_change([&](const std::string& mesh_id, const Certificate& anchor, bool added) {
        ta_callback_called = true;
        ASSERT_STREQ(mesh_id, "mesh-a");
        ASSERT(added);
    });

    ASSERT(policy_fed_b.handle_trust_anchor_delta("mesh-a", last_sent_delta));
    ASSERT(ta_callback_called);

    return true;
}

static bool test_federation_handshake_full()
{
    // Initiator (Mesh A gateway)
    federation::FederationHandshake::Config config_a;
    config_a.local_mesh_id = "mesh-a";
    config_a.local_gateway_node_id = "gateway-a";
    config_a.local_identity_key = Bytes(32, 0xAA);
    config_a.local_certificate_path = "/tmp/cert_a.smoc";
    config_a.trust_anchors_dir = "/tmp/trust_a";
    config_a.handshake_timeout_ns = 30'000'000'000LL;

    federation::FederationHandshake handshake_a(config_a, kCryptoProvider, kRng);

    // Responder (Mesh B gateway)
    federation::FederationHandshake::Config config_b;
    config_b.local_mesh_id = "mesh-b";
    config_b.local_gateway_node_id = "gateway-b";
    config_b.local_identity_key = Bytes(32, 0xBB);
    config_b.local_certificate_path = "/tmp/cert_b.smoc";
    config_b.trust_anchors_dir = "/tmp/trust_b";
    config_b.handshake_timeout_ns = 30'000'000'000LL;

    federation::FederationHandshake handshake_b(config_b, kCryptoProvider, kRng);

    // A initiates handshake
    std::vector<Bytes> messages_a_to_b;
    std::vector<Bytes> messages_b_to_a;
    bool a_completed = false;
    bool b_completed = false;
    Result<void> a_result;
    Result<void> b_result;

    auto send_a = [&](BytesView data) -> Result<void> {
        messages_a_to_b.push_back(Bytes(data.begin(), data.end()));
        return {};
    };

    auto send_b = [&](BytesView data) -> Result<void> {
        messages_b_to_a.push_back(Bytes(data.begin(), data.end()));
        return {};
    };

    auto complete_a = [&](Result<void> result) {
        a_completed = true;
        a_result = result;
    };

    auto complete_b = [&](Result<void> result) {
        b_completed = true;
        b_result = result;
    };

    // A starts handshake
    ASSERT(handshake_a.start_as_initiator(send_a, complete_a));
    ASSERT_EQ(handshake_a.state(), federation::FederationHandshakeState::SentHello);
    ASSERT_EQ(messages_a_to_b.size(), 1);
    ASSERT_EQ(messages_a_to_b[0][0], 0x01); // Hello

    // B receives Hello
    ASSERT(handshake_b.handle_message(messages_a_to_b[0], send_b));
    ASSERT_EQ(handshake_b.state(), federation::FederationHandshakeState::SentAuth);
    ASSERT_EQ(messages_b_to_a.size(), 1);
    ASSERT_EQ(messages_b_to_a[0][0], 0x02); // Auth
    ASSERT_STREQ(handshake_b.peer_mesh_id(), "mesh-a");

    // A receives Auth
    ASSERT(handshake_a.handle_message(messages_b_to_a[0], send_a));
    ASSERT_EQ(handshake_a.state(), federation::FederationHandshakeState::Completed);
    ASSERT_EQ(messages_a_to_b.size(), 2);
    ASSERT_EQ(messages_a_to_b[1][0], 0x03); // Ack
    ASSERT_STREQ(handshake_a.peer_mesh_id(), "mesh-b");

    // B receives Ack
    ASSERT(handshake_b.handle_message(messages_a_to_b[1], send_b));
    ASSERT_EQ(handshake_b.state(), federation::FederationHandshakeState::Completed);

    // Both completed
    ASSERT(a_completed);
    ASSERT(b_completed);
    ASSERT(a_result);
    ASSERT(b_result);

    return true;
}

// ============================================================================
// Main
// ============================================================================

int main(int, char*[])
{
    printf("SMO Cross-Mesh E2E — Integration Tests\n");
    printf("=======================================\n\n");

    TEST("Cross-mesh contract execution") END_TEST(test_cross_mesh_contract_execution());
    TEST("Cross-mesh policy sync") END_TEST(test_cross_mesh_policy_sync());
    TEST("Cross-mesh trust anchor sync") END_TEST(test_cross_mesh_trust_anchor_sync());
    TEST("Federation handshake full") END_TEST(test_federation_handshake_full());

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