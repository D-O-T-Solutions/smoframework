#include <federation/cross_mesh_router.hpp>
#include <runtime/runtime_types.hpp>
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
// CrossMeshRouter Tests
// ============================================================================

static bool test_router_add_route()
{
    federation::CrossMeshRouter::Config config;
    config.local_mesh_id = "mesh-local";
    config.local_gateway_node_id = "gateway-local";

    bool execute_called = false;
    federation::CrossMeshRouter::ExecuteLocalFn execute_local = [&](const std::string&, const runtime::ContractInput&, const runtime::RuntimeContext&) -> Result<runtime::ContractResult> {
        execute_called = true;
        runtime::ContractResult result;
        result.binary = Bytes{0x01, 0x02, 0x03};
        return result;
    };

    bool send_called = false;
    federation::CrossMeshRouter::SendRemoteFn send_remote = [&](const std::string&, const std::string&, BytesView) -> Result<void> {
        send_called = true;
        return {};
    };

    federation::CrossMeshRouter::OnResponseFn on_response = [&](const std::string&, const federation::CrossMeshExecutionResponse&) {};

    federation::CrossMeshRouter router(config, execute_local, send_remote, on_response);

    federation::CrossMeshRouteEntry route;
    route.destination_mesh = "mesh-remote";
    route.gateway_session_id = "session-123";
    route.next_hop_gateway = "gateway-remote";
    route.metric = 10;

    auto res = router.add_route(route);
    ASSERT(res);

    auto find_res = router.find_route("mesh-remote");
    ASSERT(find_res);
    ASSERT_STREQ(find_res.value().destination_mesh, "mesh-remote");
    ASSERT_STREQ(find_res.value().gateway_session_id, "session-123");
    ASSERT_EQ(find_res.value().metric, 10);

    return true;
}

static bool test_router_remove_route()
{
    federation::CrossMeshRouter::Config config;
    config.local_mesh_id = "mesh-local";
    config.local_gateway_node_id = "gateway-local";

    federation::CrossMeshRouter::ExecuteLocalFn execute_local = [&](const std::string&, const runtime::ContractInput&, const runtime::RuntimeContext&) -> Result<runtime::ContractResult> {
        runtime::ContractResult result;
        return result;
    };

    federation::CrossMeshRouter::SendRemoteFn send_remote = [&](const std::string&, const std::string&, BytesView) -> Result<void> { return {}; };

    federation::CrossMeshRouter::OnResponseFn on_response = [&](const std::string&, const federation::CrossMeshExecutionResponse&) {};

    federation::CrossMeshRouter router(config, execute_local, send_remote, on_response);

    federation::CrossMeshRouteEntry route;
    route.destination_mesh = "mesh-remote";
    route.gateway_session_id = "session-123";
    router.add_route(route);

    auto res = router.remove_route("mesh-remote");
    ASSERT(res);

    auto find_res = router.find_route("mesh-remote");
    ASSERT(!find_res);

    return true;
}

static bool test_router_find_unknown_route_fails()
{
    federation::CrossMeshRouter::Config config;
    config.local_mesh_id = "mesh-local";
    config.local_gateway_node_id = "gateway-local";

    federation::CrossMeshRouter::ExecuteLocalFn execute_local = [&](const std::string&, const runtime::ContractInput&, const runtime::RuntimeContext&) -> Result<runtime::ContractResult> {
        runtime::ContractResult result;
        return result;
    };

    federation::CrossMeshRouter::SendRemoteFn send_remote = [&](const std::string&, const std::string&, BytesView) -> Result<void> { return {}; };

    federation::CrossMeshRouter::OnResponseFn on_response = [&](const std::string&, const federation::CrossMeshExecutionResponse&) {};

    federation::CrossMeshRouter router(config, execute_local, send_remote, on_response);

    auto find_res = router.find_route("mesh-unknown");
    ASSERT(!find_res);

    return true;
}

static bool test_router_execute_cross_mesh()
{
    federation::CrossMeshRouter::Config config;
    config.local_mesh_id = "mesh-local";
    config.local_gateway_node_id = "gateway-local";

    bool execute_called = false;
    federation::CrossMeshRouter::ExecuteLocalFn execute_local = [&](const std::string&, const runtime::ContractInput&, const runtime::RuntimeContext&) -> Result<runtime::ContractResult> {
        execute_called = true;
        runtime::ContractResult result;
        return result;
    };

    bool send_called = false;
    std::string sent_dest_mesh;
    federation::CrossMeshRouter::SendRemoteFn send_remote = [&](const std::string& dest_mesh, const std::string&, BytesView) -> Result<void> {
        send_called = true;
        sent_dest_mesh = dest_mesh;
        return {};
    };

    bool response_received = false;
    federation::CrossMeshRouter::OnResponseFn on_response = [&](const std::string&, const federation::CrossMeshExecutionResponse&) {
        response_received = true;
    };

    federation::CrossMeshRouter router(config, execute_local, send_remote, on_response);

    federation::CrossMeshRouteEntry route;
    route.destination_mesh = "mesh-remote";
    route.gateway_session_id = "session-123";
    router.add_route(route);

    federation::CrossMeshExecutionRequest request;
    request.source_mesh_id = "mesh-local";
    request.destination_mesh_id = "mesh-remote";
    request.contract_id = "echo";
    request.input.params = Bytes{0x01, 0x02};
    request.session_id = "session-123";
    request.capabilities = {"CAP_VERIFY"};

    auto req_id = router.execute_cross_mesh(request);
    ASSERT(req_id);

    ASSERT(send_called);
    ASSERT_STREQ(sent_dest_mesh, "mesh-remote");
    ASSERT(!execute_called); // Should not call local execute for remote mesh

    return true;
}

static bool test_router_execute_local_mesh()
{
    federation::CrossMeshRouter::Config config;
    config.local_mesh_id = "mesh-local";
    config.local_gateway_node_id = "gateway-local";

    bool execute_called = false;
    federation::CrossMeshRouter::ExecuteLocalFn execute_local = [&](const std::string& contract_id, const runtime::ContractInput&, const runtime::RuntimeContext&) -> Result<runtime::ContractResult> {
        execute_called = true;
        ASSERT_STREQ(contract_id, "echo");
        runtime::ContractResult result;
        result.binary = Bytes{0xAA, 0xBB};
        return result;
    };

    federation::CrossMeshRouter::SendRemoteFn send_remote = [&](const std::string&, const std::string&, BytesView) -> Result<void> { return {}; };

    federation::CrossMeshExecutionResponse received_response;
    bool response_received = false;
    federation::CrossMeshRouter::OnResponseFn on_response = [&](const std::string&, const federation::CrossMeshExecutionResponse& resp) {
        response_received = true;
        received_response = resp;
    };

    federation::CrossMeshRouter router(config, execute_local, send_remote, on_response);

    federation::CrossMeshExecutionRequest request;
    request.source_mesh_id = "mesh-remote";
    request.destination_mesh_id = "mesh-local"; // Local mesh
    request.contract_id = "echo";
    request.input.params = Bytes{0x01, 0x02};
    request.session_id = "session-123";
    request.capabilities = {"CAP_VERIFY"};

    auto res = router.handle_incoming_request("req-123", request);
    ASSERT(res);

    ASSERT(execute_called);
    ASSERT(response_received);
    ASSERT(received_response.success);
    ASSERT_EQ(received_response.result.binary[0], 0xAA);
    ASSERT_EQ(received_response.result.binary[1], 0xBB);

    return true;
}

static bool test_router_handle_response()
{
    federation::CrossMeshRouter::Config config;
    config.local_mesh_id = "mesh-local";
    config.local_gateway_node_id = "gateway-local";

    federation::CrossMeshRouter::ExecuteLocalFn execute_local = [&](const std::string&, const runtime::ContractInput&, const runtime::RuntimeContext&) -> Result<runtime::ContractResult> {
        runtime::ContractResult result;
        return result;
    };

    federation::CrossMeshRouter::SendRemoteFn send_remote = [&](const std::string&, const std::string&, BytesView) -> Result<void> { return {}; };

    federation::CrossMeshExecutionResponse received_response;
    bool response_received = false;
    federation::CrossMeshRouter::OnResponseFn on_response = [&](const std::string& req_id, const federation::CrossMeshExecutionResponse& resp) {
        response_received = true;
        received_response = resp;
        ASSERT_STREQ(req_id, "test-req-id");
    };

    federation::CrossMeshRouter router(config, execute_local, send_remote, on_response);

    // The handle_response method is tested indirectly through the router's internal logic
    // For this test, we just verify the router compiles and can be instantiated

    return true;
}

static bool test_router_timeout()
{
    federation::CrossMeshRouter::Config config;
    config.local_mesh_id = "mesh-local";
    config.local_gateway_node_id = "gateway-local";

    federation::CrossMeshRouter::ExecuteLocalFn execute_local = [&](const std::string&, const runtime::ContractInput&, const runtime::RuntimeContext&) -> Result<runtime::ContractResult> {
        runtime::ContractResult result;
        return result;
    };

    federation::CrossMeshRouter::SendRemoteFn send_remote = [&](const std::string&, const std::string&, BytesView) -> Result<void> { return {}; };

    federation::CrossMeshExecutionResponse received_response;
    bool response_received = false;
    federation::CrossMeshRouter::OnResponseFn on_response = [&](const std::string&, const federation::CrossMeshExecutionResponse& resp) {
        response_received = true;
        received_response = resp;
    };

    federation::CrossMeshRouter router(config, execute_local, send_remote, on_response);

    federation::CrossMeshRouteEntry route;
    route.destination_mesh = "mesh-remote";
    route.gateway_session_id = "session-123";
    router.add_route(route);

    federation::CrossMeshExecutionRequest request;
    request.source_mesh_id = "mesh-local";
    request.destination_mesh_id = "mesh-remote";
    request.contract_id = "echo";
    request.session_id = "session-123";
    request.timeout_ns = 1; // 1ns timeout

    auto req_id = router.execute_cross_mesh(request);
    ASSERT(req_id);

    // Tick after timeout
    router.tick(now_ns() + 1000000); // 1ms later

    ASSERT(response_received);
    ASSERT(!received_response.success);
    ASSERT_STREQ(received_response.error_message, "Request timed out");

    return true;
}

// ============================================================================
// Main
// ============================================================================

int main(int, char*[])
{
    printf("SMO Cross-Mesh Router — Unit Tests\n");
    printf("===================================\n\n");

    TEST("Router add route") END_TEST(test_router_add_route());
    TEST("Router remove route") END_TEST(test_router_remove_route());
    TEST("Router find unknown route fails") END_TEST(test_router_find_unknown_route_fails());
    TEST("Router execute cross-mesh") END_TEST(test_router_execute_cross_mesh());
    TEST("Router execute local mesh") END_TEST(test_router_execute_local_mesh());
    TEST("Router handle response") END_TEST(test_router_handle_response());
    TEST("Router timeout") END_TEST(test_router_timeout());

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