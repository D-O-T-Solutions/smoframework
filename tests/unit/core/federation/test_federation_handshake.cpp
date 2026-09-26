#include <federation/federation_handshake.hpp>
#include <crypto/registry.hpp>
#include <crypto/impl.hpp>

#include <cstdio>
#include <cstring>
#include <vector>

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
// FederationHandshake Tests
// ============================================================================

static bool test_federation_hello_roundtrip()
{
    federation::FederationHello hello;
    hello.local_mesh_id = "mesh-a";
    hello.local_gateway_node_id = "gateway-a";
    hello.supported_suites = {"suite3_purepqc", "suite2_modern"};
    hello.authority_pubkey = "auth-pubkey-hex";
    hello.root_pubkey = "root-pubkey-hex";
    hello.epoch = 5;
    hello.timestamp = 1234567890;

    auto ser = hello.serialize();
    ASSERT(!ser.empty());

    auto deser = federation::FederationHello::deserialize(ser);
    ASSERT(deser);
    ASSERT_STREQ(deser.value().local_mesh_id, "mesh-a");
    ASSERT_STREQ(deser.value().local_gateway_node_id, "gateway-a");
    ASSERT_EQ(deser.value().supported_suites.size(), 2);
    ASSERT_STREQ(deser.value().supported_suites[0], "suite3_purepqc");
    ASSERT_STREQ(deser.value().supported_suites[1], "suite2_modern");
    ASSERT_STREQ(deser.value().authority_pubkey, "auth-pubkey-hex");
    ASSERT_STREQ(deser.value().root_pubkey, "root-pubkey-hex");
    ASSERT_EQ(deser.value().epoch, 5);
    ASSERT_EQ(deser.value().timestamp, 1234567890);

    return true;
}

static bool test_federation_auth_roundtrip()
{
    federation::FederationAuth auth;
    auth.remote_mesh_id = "mesh-b";
    auth.local_mesh_id = "mesh-a";
    auth.signature = Bytes(64, 0xAB);
    auth.timestamp = 9876543210;

    Certificate cert;
    cert.subject_pubkey = {0x01, 0x02};
    cert.issuer_pubkey = {0x03, 0x04};
    cert.mesh_id = {0xAA, 0xBB};
    cert.role = Role::Authority;
    cert.epoch = 1;
    cert.not_before = 1000;
    cert.not_after = 2000;
    auth.local_certificate = cert;

    Certificate anchor;
    anchor.subject_pubkey = {0x11, 0x22};
    anchor.issuer_pubkey = {0x33, 0x44};
    anchor.mesh_id = {0xCC, 0xDD};
    anchor.role = Role::Authority;
    anchor.epoch = 1;
    auth.trust_anchors.push_back(anchor);

    auto ser = auth.serialize();
    ASSERT(!ser.empty());

    auto deser = federation::FederationAuth::deserialize(ser);
    ASSERT(deser);
    ASSERT_STREQ(deser.value().remote_mesh_id, "mesh-b");
    ASSERT_STREQ(deser.value().local_mesh_id, "mesh-a");
    ASSERT_EQ(deser.value().signature.size(), 64);
    ASSERT_EQ(deser.value().signature[0], 0xAB);
    ASSERT_EQ(deser.value().local_certificate.subject_pubkey[0], 0x01);
    ASSERT_EQ(deser.value().trust_anchors.size(), 1);
    ASSERT_EQ(deser.value().trust_anchors[0].subject_pubkey[0], 0x11);
    ASSERT_EQ(deser.value().timestamp, 9876543210);

    return true;
}

static bool test_federation_ack_roundtrip()
{
    federation::FederationAck ack;
    ack.remote_mesh_id = "mesh-b";
    ack.local_mesh_id = "mesh-a";
    ack.accepted = true;
    ack.rejection_reason = "";
    ack.signature = Bytes(64, 0xCD);
    ack.timestamp = 1111111111;

    auto ser = ack.serialize();
    ASSERT(!ser.empty());

    auto deser = federation::FederationAck::deserialize(ser);
    ASSERT(deser);
    ASSERT_STREQ(deser.value().remote_mesh_id, "mesh-b");
    ASSERT_STREQ(deser.value().local_mesh_id, "mesh-a");
    ASSERT(deser.value().accepted);
    ASSERT_STREQ(deser.value().rejection_reason, "");
    ASSERT_EQ(deser.value().signature.size(), 64);
    ASSERT_EQ(deser.value().signature[0], 0xCD);
    ASSERT_EQ(deser.value().timestamp, 1111111111);

    return true;
}

static bool test_federation_ack_rejected_roundtrip()
{
    federation::FederationAck ack;
    ack.remote_mesh_id = "mesh-b";
    ack.local_mesh_id = "mesh-a";
    ack.accepted = false;
    ack.rejection_reason = "Certificate verification failed";
    ack.signature = Bytes(64, 0xEF);
    ack.timestamp = 2222222222;

    auto ser = ack.serialize();
    ASSERT(!ser.empty());

    auto deser = federation::FederationAck::deserialize(ser);
    ASSERT(deser);
    ASSERT_STREQ(deser.value().remote_mesh_id, "mesh-b");
    ASSERT_STREQ(deser.value().local_mesh_id, "mesh-a");
    ASSERT(!deser.value().accepted);
    ASSERT_STREQ(deser.value().rejection_reason, "Certificate verification failed");
    ASSERT_EQ(deser.value().signature.size(), 64);
    ASSERT_EQ(deser.value().signature[0], 0xEF);
    ASSERT_EQ(deser.value().timestamp, 2222222222);

    return true;
}

static bool test_handshake_initiator_flow()
{
    federation::FederationHandshake::Config config;
    config.local_mesh_id = "mesh-a";
    config.local_gateway_node_id = "gateway-a";
    config.local_identity_key = Bytes(32, 0x42);
    
    // Create a minimal certificate for testing
    Certificate test_cert;
    test_cert.subject_pubkey = Bytes(32, 0x01);
    test_cert.issuer_pubkey = Bytes(32, 0x02);
    test_cert.mesh_id = Bytes(32, 0x03);
    test_cert.role = Role::Authority;
    test_cert.epoch = 1;
    test_cert.not_before = 1000;
    test_cert.not_after = 2000;
    config.local_certificate_data = test_cert.serialize();
    
    config.trust_anchors_dir = "/tmp/trust_anchors";
    config.handshake_timeout_ns = 30'000'000'000LL;

    federation::FederationHandshake handshake(config, kCryptoProvider, kRng);

    ASSERT_EQ(handshake.state(), federation::FederationHandshakeState::Init);

    std::vector<Bytes> sent_messages;
    bool completed = false;
    Result<void> completion_result;

    auto send_fn = [&](BytesView data) -> Result<void> {
        sent_messages.push_back(Bytes(data.begin(), data.end()));
        return {};
    };

    auto on_complete = [&](Result<void> result) {
        completed = true;
        completion_result = result;
    };

    auto res = handshake.start_as_initiator(send_fn, on_complete);
    ASSERT(res);

    ASSERT_EQ(handshake.state(), federation::FederationHandshakeState::SentHello);
    ASSERT_EQ(sent_messages.size(), 1);
    ASSERT_EQ(sent_messages[0][0], 0x01); // Hello message type

    return true;
}

static bool test_handshake_responder_flow()
{
    federation::FederationHandshake::Config config;
    config.local_mesh_id = "mesh-b";
    config.local_gateway_node_id = "gateway-b";
    config.local_identity_key = Bytes(32, 0x43);
    
    // Create a minimal certificate for testing
    Certificate test_cert;
    test_cert.subject_pubkey = Bytes(32, 0x01);
    test_cert.issuer_pubkey = Bytes(32, 0x02);
    test_cert.mesh_id = Bytes(32, 0x03);
    test_cert.role = Role::Authority;
    test_cert.capabilities = Bytes{1, 2, 3};
    test_cert.epoch = 1;
    test_cert.not_before = 1000;
    test_cert.not_after = 2000;
    config.local_certificate_data = test_cert.serialize();
    
    config.trust_anchors_dir = "/tmp/trust_anchors";
    config.handshake_timeout_ns = 30'000'000'000LL;
    
    federation::FederationHandshake handshake(config, kCryptoProvider, kRng);
    
    // Create a hello message from initiator
    federation::FederationHello hello;
    hello.local_mesh_id = "mesh-a";
    hello.local_gateway_node_id = "gateway-a";
    hello.supported_suites = {"suite3_purepqc"};
    hello.authority_pubkey = "auth-pubkey";
    hello.root_pubkey = "root-pubkey";
    hello.epoch = 1;
    hello.timestamp = now_ns();
    
    Bytes hello_data = hello.serialize();
    Bytes msg;
    msg.push_back(0x01);
    msg.insert(msg.end(), hello_data.begin(), hello_data.end());
    
    std::vector<Bytes> sent_messages;
    
    auto send_fn = [&](BytesView data) -> Result<void> {
        sent_messages.push_back(Bytes(data.begin(), data.end()));
        return {};
    };
    
    auto res = handshake.handle_message(msg, send_fn);
    if (!res) {
        printf("ERROR: %s\n", res.error().message.c_str());
    }
    ASSERT(res);

    ASSERT_EQ(handshake.state(), federation::FederationHandshakeState::SentAuth);
    ASSERT_EQ(sent_messages.size(), 1);
    ASSERT_EQ(sent_messages[0][0], 0x02); // Auth message type
    ASSERT_STREQ(handshake.peer_mesh_id(), "mesh-a");

    return true;
}

// ============================================================================
// Main
// ============================================================================

int main(int, char*[])
{
    printf("SMO Federation Handshake — Unit Tests\n");
    printf("======================================\n\n");

    TEST("FederationHello roundtrip") END_TEST(test_federation_hello_roundtrip());
    TEST("FederationAuth roundtrip") END_TEST(test_federation_auth_roundtrip());
    TEST("FederationAck roundtrip (accepted)") END_TEST(test_federation_ack_roundtrip());
    TEST("FederationAck roundtrip (rejected)") END_TEST(test_federation_ack_rejected_roundtrip());
    TEST("Handshake initiator flow") END_TEST(test_handshake_initiator_flow());
    TEST("Handshake responder flow") END_TEST(test_handshake_responder_flow());

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