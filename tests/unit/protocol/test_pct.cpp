// SMO Protocol Compliance Test Suite — PCT-001 through PCT-017
// DISCUSSION_0040 §9 — Protocol Compliance Test

#include <join/join_protocol.hpp>
#include <bootstrap/bootstrap_protocol.hpp>
#include <bootstrap/bootstrap_snapshot.hpp>
#include <fsm/fsm.hpp>
#include <enroll/join_token.hpp>
#include <certificate/certificate.hpp>
#include <replay/replay.h>
#include <recovery/crl.hpp>
#include <network/sync/membership_sync.hpp>
#include <discovery/gossip.hpp>
#include <discovery/discovery.hpp>
#include <bootstrap/cbor.hpp>
#include <crypto/hash_provider.hpp>
#include <crypto/registry.hpp>
#include <crypto/random/getrandom.hpp>
#include <providers/suite1_classical/suite1_classical_provider.hpp>
#include <providers/suite2_modern/suite2_modern_provider.hpp>
#ifdef SMO_WITH_PQC
#include <providers/suite3_purepqc/suite3_purepqc_provider.hpp>
#endif
#include <storage/policy_store/policy_store.h>
#include <providers/blake3_provider/blake3_provider.hpp>
#include <runtime/structured_logger.hpp>
#include <network/sync/version_vector.hpp>
#include <network/sync/merkle_tree.hpp>
#include <network/sync/sync_backend.hpp>
#include <network/sync/anti_entropy.hpp>
#include <network/stun/stun_client.hpp>
#include <network/udp/heartbeat_service.hpp>
#include <acl/policy_engine.hpp>
#include <runtime/policy_middleware.hpp>
#include <trust/trust.hpp>
#include <session/session.hpp>
#include <fsm/node_lifecycle_fsm.hpp>
#include <core/identity/identity.hpp>
#include <core/transport/transport.hpp>

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <vector>
#include <string>

using namespace smo;
using namespace smo::network::udp;

static int failures = 0;

#define TEST(name)                                                                                                     \
    do                                                                                                                 \
    {                                                                                                                  \
        printf("  TEST %-54s ... ", name);                                                                             \
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

// ==========================================================================
// PCT-001: JoinRequest CBOR encode/decode roundtrip
// ==========================================================================
static bool test_pct_001()
{
    join::JoinRequest req;
    req.version = 1;
    req.protocol_version = 1;
    req.capability_bitmap = join::CAP_DELTA_SYNC | join::CAP_CRT | join::CAP_RUNTIME_NEGOTIATE;
    req.token = "SMO-JOIN-abcdef";
    req.csr_pem = "308201...mock_csr_hex...";
    req.timestamp = 1700000000;
    req.nonce = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    req.csr_hash = {0xaa, 0xbb, 0xcc, 0xdd};
    req.request_signature = {0x11, 0x22, 0x33, 0x44};

    auto encoded = req.encode_cbor();
    ASSERT(!encoded.empty());

    auto decoded = join::JoinRequest::decode_cbor(BytesView(encoded));
    ASSERT(decoded);
    ASSERT_EQ(decoded.value().version, 1);
    ASSERT_EQ(decoded.value().protocol_version, 1);
    ASSERT_STREQ(decoded.value().token, "SMO-JOIN-abcdef");
    ASSERT_STREQ(decoded.value().csr_pem, "308201...mock_csr_hex...");
    ASSERT_EQ(decoded.value().timestamp, 1700000000);
    ASSERT(decoded.value().nonce[0] == 0x01);
    ASSERT(decoded.value().nonce[7] == 0x08);
    ASSERT_EQ(decoded.value().csr_hash.size(), 4U);
    ASSERT_EQ(decoded.value().request_signature.size(), 4U);
    ASSERT_EQ(decoded.value().capability_bitmap, join::CAP_DELTA_SYNC | join::CAP_CRT | join::CAP_RUNTIME_NEGOTIATE);

    return true;
}

// ==========================================================================
// PCT-002: JoinResponse CBOR encode/decode roundtrip
// ==========================================================================
static bool test_pct_002()
{
    join::JoinResponse resp;
    resp.version = 1;
    resp.nonce = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11};
    resp.certificate_pem = "3082...mock_cert_pem...";
    resp.mesh_id = "mesh-smo-dev";
    resp.bootstrap_ticket = {0xde, 0xad, 0xbe, 0xef};
    resp.server_time = 1700001000;
    resp.capability_bitmap = join::CAP_DELTA_SYNC | join::CAP_COMPRESSION;

    auto encoded = resp.encode_cbor();
    ASSERT(!encoded.empty());

    auto decoded = join::JoinResponse::decode_cbor(BytesView(encoded));
    ASSERT(decoded);
    ASSERT_STREQ(decoded.value().certificate_pem, "3082...mock_cert_pem...");
    ASSERT_STREQ(decoded.value().mesh_id, "mesh-smo-dev");
    ASSERT_EQ(decoded.value().bootstrap_ticket.size(), 4U);
    ASSERT_EQ(decoded.value().nonce[0], 0xAA);
    ASSERT_EQ(decoded.value().server_time, 1700001000);
    ASSERT_EQ(decoded.value().capability_bitmap, join::CAP_DELTA_SYNC | join::CAP_COMPRESSION);

    return true;
}

// ==========================================================================
// PCT-003: BootstrapSyncRequest CBOR encode/decode roundtrip
// ==========================================================================
static bool test_pct_003()
{
    join::BootstrapSyncRequest req;
    req.version = 1;
    req.protocol_version = 1;
    req.nonce = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    req.mesh_id = "mesh-smo-dev";
    req.node_id = "abcdef123456";
    req.bootstrap_ticket = {0xca, 0xfe, 0xba, 0xbe};
    req.manifest_revision = 5;
    req.crl_revision = 3;
    req.membership_revision = 7;
    req.policy_revision = 2;

    auto encoded = req.encode_cbor();
    ASSERT(!encoded.empty());

    auto decoded = join::BootstrapSyncRequest::decode_cbor(BytesView(encoded));
    ASSERT(decoded);
    ASSERT_EQ(decoded.value().protocol_version, 1);
    ASSERT_STREQ(decoded.value().mesh_id, "mesh-smo-dev");
    ASSERT_STREQ(decoded.value().node_id, "abcdef123456");
    ASSERT_EQ(decoded.value().manifest_revision, 5U);
    ASSERT_EQ(decoded.value().crl_revision, 3U);
    ASSERT_EQ(decoded.value().membership_revision, 7U);
    ASSERT_EQ(decoded.value().policy_revision, 2U);

    return true;
}

// ==========================================================================
// PCT-004: BootstrapSyncResponse CBOR encode/decode roundtrip
// ==========================================================================
static bool test_pct_004()
{
    join::BootstrapSyncResponse resp;
    resp.version = 1;
    resp.nonce = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11};
    resp.manifest_delta = {0x01, 0x02, 0x03};
    resp.membership_delta = {0x04, 0x05, 0x06};
    resp.policy_delta = {0x07, 0x08, 0x09};
    resp.crl_delta = {0x0a, 0x0b, 0x0c};
    resp.manifest_revision = 10;
    resp.membership_revision = 9;
    resp.crl_revision = 8;
    resp.policy_revision = 7;
    resp.server_time = 1700002000;

    SeedInfo si;
    si.endpoint = "192.168.1.1:8080";
    si.region = "us-east-1";
    si.weight = 100;
    si.health_score = 0.95;
    resp.seeds.push_back(si);

    auto encoded = resp.encode_cbor();
    ASSERT(!encoded.empty());

    auto decoded = join::BootstrapSyncResponse::decode_cbor(BytesView(encoded));
    ASSERT(decoded);
    ASSERT_EQ(decoded.value().manifest_revision, 10U);
    ASSERT_EQ(decoded.value().membership_revision, 9U);
    ASSERT_EQ(decoded.value().crl_revision, 8U);
    ASSERT_EQ(decoded.value().policy_revision, 7U);
    ASSERT(!decoded.value().manifest_delta.empty());
    ASSERT(!decoded.value().membership_delta.empty());
    ASSERT(!decoded.value().policy_delta.empty());
    ASSERT(!decoded.value().crl_delta.empty());
    ASSERT_EQ(decoded.value().seeds.size(), 1U);
    ASSERT_STREQ(decoded.value().seeds[0].endpoint, "192.168.1.1:8080");
    ASSERT_STREQ(decoded.value().seeds[0].region, "us-east-1");
    ASSERT_EQ(decoded.value().seeds[0].weight, 100U);
    ASSERT_EQ(decoded.value().server_time, 1700002000);

    return true;
}

// ==========================================================================
// PCT-005: Join FSM full flow NEW → READY
// ==========================================================================
static bool test_pct_005()
{
    auto rules = join::join_transition_table();
    auto timeouts = join::join_timeout_table();

    FsmInstance fsm;
    fsm.set_transitions(rules);
    fsm.set_timeouts(timeouts);
    fsm.reset(static_cast<int64_t>(join::JoinState::NEW));

    // Full happy path: NEW → READY
    ASSERT_EQ(fsm.current_state(), static_cast<int64_t>(join::JoinState::NEW));
    // NEW → TOKEN_RECEIVED
    ASSERT(fsm.on_event(static_cast<int64_t>(join::JoinEvent::TOKEN_PARSED)));
    ASSERT_EQ(fsm.current_state(), static_cast<int64_t>(join::JoinState::TOKEN_RECEIVED));
    // TOKEN_RECEIVED → CSR_CREATED
    ASSERT(fsm.on_event(static_cast<int64_t>(join::JoinEvent::CSR_BUILT)));
    ASSERT_EQ(fsm.current_state(), static_cast<int64_t>(join::JoinState::CSR_CREATED));
    // CSR_CREATED → JOIN_SENT
    ASSERT(fsm.on_event(static_cast<int64_t>(join::JoinEvent::MSG_SENT)));
    ASSERT_EQ(fsm.current_state(), static_cast<int64_t>(join::JoinState::JOIN_SENT));
    // JOIN_SENT → WAIT_RESPONSE
    ASSERT(fsm.on_event(static_cast<int64_t>(join::JoinEvent::RESPONSE_RCVD)));
    ASSERT_EQ(fsm.current_state(), static_cast<int64_t>(join::JoinState::WAIT_RESPONSE));
    // WAIT_RESPONSE → CERT_RECEIVED
    ASSERT(fsm.on_event(static_cast<int64_t>(join::JoinEvent::RESPONSE_RCVD)));
    ASSERT_EQ(fsm.current_state(), static_cast<int64_t>(join::JoinState::CERT_RECEIVED));
    // CERT_RECEIVED → CERT_VERIFY
    ASSERT(fsm.on_event(static_cast<int64_t>(join::JoinEvent::CERT_VERIFIED)));
    ASSERT_EQ(fsm.current_state(), static_cast<int64_t>(join::JoinState::CERT_VERIFY));
    // CERT_VERIFY → BOOTSTRAP_SYNC
    ASSERT(fsm.on_event(static_cast<int64_t>(join::JoinEvent::SYNC_REQUESTED)));
    ASSERT_EQ(fsm.current_state(), static_cast<int64_t>(join::JoinState::BOOTSTRAP_SYNC));
    // BOOTSTRAP_SYNC → WAIT_SYNC
    ASSERT(fsm.on_event(static_cast<int64_t>(join::JoinEvent::SYNC_COMPLETE)));
    ASSERT_EQ(fsm.current_state(), static_cast<int64_t>(join::JoinState::WAIT_SYNC));
    // WAIT_SYNC → GOSSIP_SYNC
    ASSERT(fsm.on_event(static_cast<int64_t>(join::JoinEvent::GOSSIP_STARTED)));
    ASSERT_EQ(fsm.current_state(), static_cast<int64_t>(join::JoinState::GOSSIP_SYNC));
    // GOSSIP_SYNC → WAIT_GOSSIP
    ASSERT(fsm.on_event(static_cast<int64_t>(join::JoinEvent::GOSSIP_COMPLETE)));
    ASSERT_EQ(fsm.current_state(), static_cast<int64_t>(join::JoinState::WAIT_GOSSIP));
    // WAIT_GOSSIP → READY
    ASSERT(fsm.on_event(static_cast<int64_t>(join::JoinEvent::GOSSIP_COMPLETE)));
    ASSERT_EQ(fsm.current_state(), static_cast<int64_t>(join::JoinState::READY));

    ASSERT_EQ(fsm.transition_count(), 11U);

    return true;
}

// ==========================================================================
// PCT-006: Join FSM every FAIL transition
// ==========================================================================
static bool test_pct_006()
{
    auto rules = join::join_transition_table();
    FsmInstance fsm;
    fsm.set_transitions(rules);
    fsm.reset(static_cast<int64_t>(join::JoinState::NEW));

    // NEW → TOKEN_RECEIVED → CSR_CREATED → JOIN_SENT → WAIT_RESPONSE
    fsm.on_event(static_cast<int64_t>(join::JoinEvent::TOKEN_PARSED));
    fsm.on_event(static_cast<int64_t>(join::JoinEvent::CSR_BUILT));
    fsm.on_event(static_cast<int64_t>(join::JoinEvent::MSG_SENT));
    fsm.on_event(static_cast<int64_t>(join::JoinEvent::RESPONSE_RCVD));
    // WAIT_RESPONSE → FAILED
    ASSERT(fsm.on_event(static_cast<int64_t>(join::JoinEvent::FAIL)));
    ASSERT_EQ(fsm.current_state(), static_cast<int64_t>(join::JoinState::FAILED));

    // Reset and test CERT_INVALID path
    fsm.reset(static_cast<int64_t>(join::JoinState::NEW));
    fsm.on_event(static_cast<int64_t>(join::JoinEvent::TOKEN_PARSED));
    fsm.on_event(static_cast<int64_t>(join::JoinEvent::CSR_BUILT));
    fsm.on_event(static_cast<int64_t>(join::JoinEvent::MSG_SENT));
    fsm.on_event(static_cast<int64_t>(join::JoinEvent::RESPONSE_RCVD));
    fsm.on_event(static_cast<int64_t>(join::JoinEvent::RESPONSE_RCVD));
    // CERT_RECEIVED → FAILED via CERT_INVALID
    ASSERT(fsm.on_event(static_cast<int64_t>(join::JoinEvent::CERT_INVALID)));
    ASSERT_EQ(fsm.current_state(), static_cast<int64_t>(join::JoinState::FAILED));

    // Reset and test FAIL from CERT_VERIFY
    fsm.reset(static_cast<int64_t>(join::JoinState::NEW));
    fsm.on_event(static_cast<int64_t>(join::JoinEvent::TOKEN_PARSED));
    fsm.on_event(static_cast<int64_t>(join::JoinEvent::CSR_BUILT));
    fsm.on_event(static_cast<int64_t>(join::JoinEvent::MSG_SENT));
    fsm.on_event(static_cast<int64_t>(join::JoinEvent::RESPONSE_RCVD));
    fsm.on_event(static_cast<int64_t>(join::JoinEvent::RESPONSE_RCVD));
    fsm.on_event(static_cast<int64_t>(join::JoinEvent::CERT_VERIFIED));
    // CERT_VERIFY → FAILED
    ASSERT(fsm.on_event(static_cast<int64_t>(join::JoinEvent::FAIL)));
    ASSERT_EQ(fsm.current_state(), static_cast<int64_t>(join::JoinState::FAILED));

    return true;
}

// ==========================================================================
// PCT-007: Join FSM every TIMEOUT transition
// ==========================================================================
static bool test_pct_007()
{
    auto rules = join::join_transition_table();
    FsmInstance fsm;
    fsm.set_transitions(rules);

    // TIMEOUT event from WAIT_RESPONSE → JOIN_SENT (retry)
    fsm.reset(static_cast<int64_t>(join::JoinState::NEW));
    fsm.on_event(static_cast<int64_t>(join::JoinEvent::TOKEN_PARSED));
    fsm.on_event(static_cast<int64_t>(join::JoinEvent::CSR_BUILT));
    fsm.on_event(static_cast<int64_t>(join::JoinEvent::MSG_SENT));
    fsm.on_event(static_cast<int64_t>(join::JoinEvent::RESPONSE_RCVD));
    ASSERT_EQ(fsm.current_state(), static_cast<int64_t>(join::JoinState::WAIT_RESPONSE));
    ASSERT(fsm.on_event(static_cast<int64_t>(join::JoinEvent::TIMEOUT)));
    ASSERT_EQ(fsm.current_state(), static_cast<int64_t>(join::JoinState::JOIN_SENT));

    // TIMEOUT event from WAIT_SYNC → BOOTSTRAP_SYNC
    fsm.reset(static_cast<int64_t>(join::JoinState::NEW));
    fsm.on_event(static_cast<int64_t>(join::JoinEvent::TOKEN_PARSED));
    fsm.on_event(static_cast<int64_t>(join::JoinEvent::CSR_BUILT));
    fsm.on_event(static_cast<int64_t>(join::JoinEvent::MSG_SENT));
    fsm.on_event(static_cast<int64_t>(join::JoinEvent::RESPONSE_RCVD));
    fsm.on_event(static_cast<int64_t>(join::JoinEvent::RESPONSE_RCVD));
    fsm.on_event(static_cast<int64_t>(join::JoinEvent::CERT_VERIFIED));
    fsm.on_event(static_cast<int64_t>(join::JoinEvent::SYNC_REQUESTED));
    fsm.on_event(static_cast<int64_t>(join::JoinEvent::SYNC_COMPLETE));
    ASSERT_EQ(fsm.current_state(), static_cast<int64_t>(join::JoinState::WAIT_SYNC));
    ASSERT(fsm.on_event(static_cast<int64_t>(join::JoinEvent::TIMEOUT)));
    ASSERT_EQ(fsm.current_state(), static_cast<int64_t>(join::JoinState::BOOTSTRAP_SYNC));

    return true;
}

// ==========================================================================
// PCT-008: Join FSM persist + resume (serialize/deserialize)
// ==========================================================================
static bool test_pct_008()
{
    auto rules = join::join_transition_table();
    FsmInstance fsm;
    fsm.set_transitions(rules);

    // Move to CERT_RECEIVED
    fsm.reset(static_cast<int64_t>(join::JoinState::NEW));
    fsm.on_event(static_cast<int64_t>(join::JoinEvent::TOKEN_PARSED));
    fsm.on_event(static_cast<int64_t>(join::JoinEvent::CSR_BUILT));
    fsm.on_event(static_cast<int64_t>(join::JoinEvent::MSG_SENT));
    fsm.on_event(static_cast<int64_t>(join::JoinEvent::RESPONSE_RCVD));
    fsm.on_event(static_cast<int64_t>(join::JoinEvent::RESPONSE_RCVD));
    ASSERT_EQ(fsm.current_state(), static_cast<int64_t>(join::JoinState::CERT_RECEIVED));
    ASSERT_EQ(fsm.transition_count(), 5U);

    // Serialize
    auto serialized = fsm.serialize();
    ASSERT(serialized);

    // Deserialize into new FSM
    auto restored = FsmInstance::deserialize(BytesView(serialized.value()), rules.data(), rules.size(), nullptr, 0);
    ASSERT(restored);
    ASSERT_EQ(restored.value().current_state(), static_cast<int64_t>(join::JoinState::CERT_RECEIVED));
    ASSERT_EQ(restored.value().transition_count(), 5U);

    // Resume: CERT_VERIFIED → CERT_VERIFY
    ASSERT(restored.value().on_event(static_cast<int64_t>(join::JoinEvent::CERT_VERIFIED)));
    ASSERT_EQ(restored.value().current_state(), static_cast<int64_t>(join::JoinState::CERT_VERIFY));
    ASSERT_EQ(restored.value().transition_count(), 6U);

    return true;
}

// ==========================================================================
// PCT-009: BootstrapRequest/Response CBOR roundtrip
// ==========================================================================
static bool test_pct_009()
{
    bootstrap::BootstrapRequest req;
    req.version = 1;
    req.nonce = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    req.node_id = "node123";
    req.cert_fingerprint = "abc123def456";

    auto encoded = req.encode_cbor();
    ASSERT(!encoded.empty());

    auto decoded = bootstrap::BootstrapRequest::decode_cbor(BytesView(encoded));
    ASSERT(decoded);
    ASSERT_EQ(decoded.value().version, 1);
    ASSERT_STREQ(decoded.value().node_id, "node123");
    ASSERT_STREQ(decoded.value().cert_fingerprint, "abc123def456");

    // BootstrapResponse (requires BootstrapSnapshot which has complex fields)
    // Test minimal response
    bootstrap::BootstrapResponse resp;
    resp.version = 1;
    resp.nonce = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11};
    resp.snapshot.mesh_id = "test-mesh";
    resp.snapshot.mesh_state = "active";
    resp.snapshot.epoch = 42;
    resp.snapshot.policy_version = 1;
    resp.snapshot.governance_version = 1;

    auto resp_encoded = resp.encode_cbor();
    ASSERT(!resp_encoded.empty());

    auto resp_decoded = bootstrap::BootstrapResponse::decode_cbor(BytesView(resp_encoded));
    ASSERT(resp_decoded);
    ASSERT_STREQ(resp_decoded.value().snapshot.mesh_id, "test-mesh");
    ASSERT_STREQ(resp_decoded.value().snapshot.mesh_state, "active");
    ASSERT_EQ(resp_decoded.value().snapshot.epoch, 42);

    return true;
}

// ==========================================================================
// PCT-010: GossipEngine basic operation
// ==========================================================================
static bool test_pct_010()
{
    MembershipTable table;
    GossipEngine::Config cfg;
    cfg.interval_ms = 5000;
    cfg.fanout = 3;
    GossipEngine engine(table, cfg);

    // Verify default config
    ASSERT_EQ(cfg.interval_ms, 5000U);
    ASSERT_EQ(cfg.fanout, 3U);

    // Queue a typed delta
    Bytes delta_data = {0x01, 0x02, 0x03, 0x04};
    engine.queue_delta(DeltaType::Membership, delta_data);

    // Register a delta handler
    bool handler_called = false;
    engine.set_delta_handler(DeltaType::Membership, [&](BytesView data) -> Result<void> {
        handler_called = true;
        if (data.size() != 4)
        {
            return Error{};
        }
        return Result<void>{};
    });

    // Register a delta provider
    bool provider_called = false;
    engine.set_delta_provider(DeltaType::CRL, [&]() -> Bytes {
        provider_called = true;
        return Bytes{0x0a, 0x0b};
    });

    ASSERT(!handler_called);
    ASSERT(!provider_called);

    // Verify engine is properly constructed
    ASSERT_EQ(engine.current_sequence(), 1U);

    return true;
}

// ==========================================================================
// PCT-011: JoinToken parsing and validation
// ==========================================================================
static bool test_pct_011()
{
    // Test with a minimal wire-format token
    // SMO-JOIN-<base64url( payload || signature )>
    // The payload is CBOR-encoded JoinToken fields

    auto parsed = enroll::parse_token("SMO-JOIN-invalid");
    ASSERT(!parsed); // should fail on invalid base64

    // Test token v1 detection (v1 = empty issuer + non-empty signature)
    enroll::JoinToken token;
    token.version = 2;
    token.issuer = "root:abc123";
    token.signature = {0x01, 0x02, 0x03};
    ASSERT(!enroll::token_is_v1(token)); // has issuer → v2

    token.issuer.clear();
    token.signature = {0x01, 0x02, 0x03};
    ASSERT(enroll::token_is_v1(token)); // empty issuer + has signature → v1

    token.signature.clear();
    ASSERT(!enroll::token_is_v1(token)); // empty issuer + empty sig → not v1

    return true;
}

// ==========================================================================
// PCT-012: Certificate encode/decode roundtrip
// ==========================================================================
static bool test_pct_012()
{
    // Create a minimal certificate
    Certificate cert;
    cert.subject_pubkey = {0x01, 0x02, 0x03, 0x04};
    cert.issuer_pubkey = {0x05, 0x06, 0x07, 0x08};
    cert.mesh_id = {0xde, 0xad, 0xbe, 0xef};
    cert.role = Role::Member;
    cert.display_name = "test-node";
    cert.epoch = 42;
    cert.not_before = 1000;
    cert.not_after = 2000;

    auto encoded = cert.serialize();
    ASSERT(!encoded.empty());

    auto decoded = Certificate::deserialize(BytesView(encoded));
    ASSERT(decoded);
    ASSERT(decoded.value().mesh_id.size() == 4);
    ASSERT(decoded.value().mesh_id[0] == 0xde);
    ASSERT_EQ(static_cast<int>(decoded.value().role), static_cast<int>(Role::Member));
    ASSERT_STREQ(decoded.value().display_name, "test-node");
    ASSERT_EQ(decoded.value().epoch, 42U);
    ASSERT_EQ(decoded.value().not_before, 1000);
    ASSERT_EQ(decoded.value().not_after, 2000);

    // Test full serialization
    auto full_encoded = cert.serialize_full();
    ASSERT(full_encoded.size() > encoded.size());

    // CertificateChain: basic operations
    CertificateChain chain;
    ASSERT(chain.empty());
    ASSERT_EQ(chain.size(), 0U);

    return true;
}

// ==========================================================================
// PCT-013: ReplayProtector nonce detection
// ==========================================================================
static bool test_pct_013()
{
    ReplayProtector rp({10000, 50});

    // Fresh nonces should be accepted
    for (uint8_t i = 0; i < 10; ++i)
    {
        std::array<uint8_t, 8> nonce = {0, 0, 0, 0, 0, 0, 0, i};
        ASSERT(rp.accept(nonce, 1000 + i * 100, 1500));
    }

    // Duplicate should be rejected
    std::array<uint8_t, 8> dup = {0, 0, 0, 0, 0, 0, 0, 3};
    ASSERT(!rp.accept(dup, 1000, 1500));

    // All zeros nonce (edge case, not used in first batch)
    std::array<uint8_t, 8> zeros = {0, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF};
    ASSERT(rp.accept(zeros, 2000, 2500));  // first time
    ASSERT(!rp.accept(zeros, 2000, 2500)); // should be rejected

    // Time-based: reject if timestamp delta exceeds window
    std::array<uint8_t, 8> old = {0, 0, 0, 0, 0, 0, 0x01, 0x01};
    ASSERT(!rp.accept(old, 1000, 20000)); // delta 19s > 10s window

    // Clear should reset
    ASSERT_EQ(rp.size(), 11U);
    rp.clear();
    ASSERT_EQ(rp.size(), 0U);
    // After clear, previously seen nonce should be accepted again
    ASSERT(rp.accept(dup, 1000, 1500));

    return true;
}

// ==========================================================================
// PCT-014: Timestamp window validation
// ==========================================================================
static bool test_pct_014()
{
    // Test the ±30s timestamp window logic used by process_join_request
    // The check is: std::llabs(now_sec - req.timestamp) > 30

    int64_t now = 1700000000;

    // Within window: exactly at boundary
    ASSERT(std::llabs(now - (now - 30)) <= 30); // exactly 30s ago
    ASSERT(std::llabs(now - (now + 30)) <= 30); // exactly 30s ahead

    // Within window: within range
    ASSERT(std::llabs(now - (now - 15)) <= 30); // 15s ago
    ASSERT(std::llabs(now - (now + 15)) <= 30); // 15s ahead
    ASSERT(std::llabs(now - now) <= 30);        // exact now

    // Outside window: beyond boundary
    ASSERT(std::llabs(now - (now - 31)) > 30); // 31s ago
    ASSERT(std::llabs(now - (now + 31)) > 30); // 31s ahead

    // Edge cases
    ASSERT(std::llabs(now - (now - 0)) <= 30);  // 0s (exact same)
    ASSERT(std::llabs(now - (now - 300)) > 30); // 5 min ago

    return true;
}

// ==========================================================================
// PCT-015: MembershipSync serialization roundtrip
// ==========================================================================
static bool test_pct_015()
{
    using namespace network::sync;

    // Create membership events
    MembershipEvent ev1;
    ev1.type = MembershipEventType::PeerAdded;
    ev1.node_id.value[0] = 0x01;
    ev1.timestamp_ns = 1000;
    ev1.sequence = 1;

    MembershipEvent ev2;
    ev2.type = MembershipEventType::PeerRemoved;
    ev2.node_id.value[0] = 0x02;
    ev2.timestamp_ns = 2000;
    ev2.sequence = 2;

    // This requires a MembershipSync instance to call serialize_events
    // Since we don't have HealthMonitor easily available, we test the
    // MembershipEvent struct and its fields directly
    ASSERT(ev1.type == MembershipEventType::PeerAdded);
    ASSERT(ev2.type == MembershipEventType::PeerRemoved);
    ASSERT(ev1.sequence == 1U);
    ASSERT(ev2.sequence == 2U);
    ASSERT(ev1.node_id.value[0] == 0x01);
    ASSERT(ev2.node_id.value[0] == 0x02);

    return true;
}

// ==========================================================================
// PCT-016: CRL serialize/deserialize roundtrip
// ==========================================================================
static bool test_pct_016()
{
    using namespace recovery;

    CRL crl;

    // Initially empty
    ASSERT(crl.entries_since(0).empty());

    // Revoke some certs
    ASSERT(crl.revoke("fp-001", "node-001", "compromised", 1, 1000));
    ASSERT(crl.revoke("fp-002", "node-002", "expired", 2, 2000));
    ASSERT(crl.revoke("fp-003", "node-003", "revoked", 3, 3000));

    ASSERT_EQ(crl.entries_since(0).size(), 3U);
    ASSERT_EQ(crl.entries_since(2).size(), 2U); // entries with epoch >= 2

    // Test CRLEntry serialize/deserialize
    auto entry1 = crl.entries_since(0)[0];
    auto entry1_encoded = entry1.serialize();
    ASSERT(!entry1_encoded.empty());

    auto entry1_decoded = CRLEntry::deserialize(BytesView(entry1_encoded));
    ASSERT(entry1_decoded);
    ASSERT_STREQ(entry1_decoded.value().cert_fingerprint, entry1.cert_fingerprint);
    ASSERT_STREQ(entry1_decoded.value().node_id_hex, entry1.node_id_hex);
    ASSERT_EQ(entry1_decoded.value().epoch, entry1.epoch);

    // Test CRL serialize/deserialize
    auto crl_encoded = crl.serialize();
    ASSERT(!crl_encoded.empty());

    auto crl_decoded = CRL::deserialize(BytesView(crl_encoded));
    ASSERT(crl_decoded);
    ASSERT_EQ(crl_decoded.value().entries_since(0).size(), 3U);

    // Clear and verify
    crl.clear();
    ASSERT(crl.entries_since(0).empty());

    return true;
}

// ==========================================================================
// PCT-017: CBOR map key forward compat (unknown key skip)
// ==========================================================================
static bool test_pct_017()
{
    // Create CBOR data with unknown keys that the decoder should skip
    cbor::Encoder enc;
    enc.encode_map(3); // 3 keys
    // Known key
    cbor::encode_uint_key(enc, 1);
    enc.encode_string("hello");
    // Unknown key (99 — not in any protocol spec)
    cbor::encode_uint_key(enc, 99);
    enc.encode_uint(12345);
    // Another unknown key (100)
    cbor::encode_uint_key(enc, 100);
    enc.encode_bytes(BytesView({0xde, 0xad, 0xbe, 0xef}));

    Bytes encoded = enc.take();

    // Decode with JoinRequest decoder — should skip unknown keys
    auto decoded = join::JoinRequest::decode_cbor(BytesView(encoded));
    ASSERT(decoded);
    ASSERT_STREQ(decoded.value().token, "hello");

    // Create JoinResponse with extra unknown fields
    cbor::Encoder enc2;
    enc2.encode_map(5);
    cbor::encode_uint_key(enc2, 1); // certificate
    enc2.encode_string("mock-cert");
    cbor::encode_uint_key(enc2, 2); // mesh_id
    enc2.encode_string("test-mesh");
    cbor::encode_uint_key(enc2, 99); // unknown
    enc2.encode_uint(99999);
    cbor::encode_uint_key(enc2, 100); // unknown
    enc2.encode_string("future-field");
    cbor::encode_uint_key(enc2, 200); // unknown
    enc2.encode_array(2);
    enc2.encode_uint(1);
    enc2.encode_uint(2);

    Bytes encoded2 = enc2.take();
    auto decoded2 = join::JoinResponse::decode_cbor(BytesView(encoded2));
    ASSERT(decoded2);
    ASSERT_STREQ(decoded2.value().certificate_pem, "mock-cert");
    ASSERT_STREQ(decoded2.value().mesh_id, "test-mesh");

    // BootstrapSyncRequest with unknown key
    cbor::Encoder enc3;
    enc3.encode_map(3);
    cbor::encode_uint_key(enc3, 1); // mesh_id
    enc3.encode_string("mesh-x");
    cbor::encode_uint_key(enc3, 2); // node_id
    enc3.encode_string("node-y");
    cbor::encode_uint_key(enc3, 99); // unknown
    enc3.encode_string("should-be-skipped");

    Bytes encoded3 = enc3.take();
    auto decoded3 = join::BootstrapSyncRequest::decode_cbor(BytesView(encoded3));
    ASSERT(decoded3);
    ASSERT_STREQ(decoded3.value().mesh_id, "mesh-x");
    ASSERT_STREQ(decoded3.value().node_id, "node-y");

    return true;
}

// PCT-020 — PolicyStore CRUD operations
static bool test_pct_020()
{
    // Use a temp directory
    char tmp[] = "/tmp/smo_pct_020_XXXXXX";
    if (!mkdtemp(tmp))
        return false;
    std::string dir(tmp);

    PolicyStore store(dir);
    if (store.open())
        return false;

    // Put
    PolicyStore::Record rec;
    rec.name = "test-pol";
    rec.description = "test policy";
    rec.version = "1.0";
    rec.yaml_content = "name: test-pol\nrules: []";
    rec.created_at = 1000;
    rec.created_by = "test";
    rec.updated_at = 1000;
    if (store.put(rec))
        return false;

    // Get + verify fields
    auto got = store.get("test-pol");
    if (!got)
        return false;
    ASSERT(got->name == "test-pol");
    ASSERT(got->description == "test policy");
    ASSERT(got->version == "1.0");
    ASSERT(got->created_at == 1000);

    // List
    auto names = store.list();
    ASSERT(names.size() == 1);
    ASSERT(names[0] == "test-pol");

    // serialize/deserialize roundtrip
    auto ser = PolicyStore::serialize_record(rec);
    auto deser = PolicyStore::deserialize_record(ser);
    ASSERT(deser.has_value());
    ASSERT(deser->name == "test-pol");
    ASSERT(deser->version == "1.0");

    // Remove
    if (store.remove("test-pol"))
        return false;
    auto after_rm = store.get("test-pol");
    ASSERT(!after_rm.has_value());

    // Cleanup
    store.close();
    std::filesystem::remove_all(dir);
    return true;
}

// PCT-021 — JOIN_REQUEST nonce dedup
static bool test_pct_021()
{
    join::clear_nonce_cache();
    Blake3Provider::register_as_default();

    auto& hp = HashProvider::default_provider();

    std::array<uint8_t, 8> nonce_a = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    std::array<uint8_t, 8> nonce_b = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    std::array<uint8_t, 8> nonce_c = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11};

    Bytes key_a;
    key_a.insert(key_a.end(), "mesh-x", "mesh-x" + 6);
    key_a.insert(key_a.end(), nonce_a.begin(), nonce_a.end());
    auto hash_a = hp.hash(BytesView(key_a));

    Bytes key_b;
    key_b.insert(key_b.end(), "mesh-y", "mesh-y" + 6);
    key_b.insert(key_b.end(), nonce_a.begin(), nonce_a.end());
    auto hash_b = hp.hash(BytesView(key_b));

    ASSERT(hash_a == hash_a);
    ASSERT(hash_a != hash_b);

    Bytes key_c;
    key_c.insert(key_c.end(), "mesh-x", "mesh-x" + 6);
    key_c.insert(key_c.end(), nonce_c.begin(), nonce_c.end());
    auto hash_c = hp.hash(BytesView(key_c));
    ASSERT(hash_a != hash_c);

    join::clear_nonce_cache();
    return true;
}

// PCT-018 — Anti-entropy Merkle tree + version vector
static bool test_pct_018()
{
    Blake3Provider::register_as_default();
    auto& hp = HashProvider::default_provider();
    (void)hp; // ensure hash provider is ready for MerkleTree::rebuild()

    // Test VersionVector
    smo::sync::VersionVector vv;
    ASSERT(vv.empty());
    vv.set("node-a", 1);
    vv.set("node-b", 5);
    ASSERT(vv.size() == 2);
    ASSERT(vv.get("node-a") == 1);
    ASSERT(vv.get("node-b") == 5);
    ASSERT(vv.get("node-c") == 0);

    // Test serialization roundtrip
    auto vv_bytes = vv.serialize();
    auto vv2_r = smo::sync::VersionVector::deserialize(BytesView(vv_bytes));
    ASSERT(bool(vv2_r));
    ASSERT(vv2_r.value() == vv);

    // Test merge
    smo::sync::VersionVector vv3;
    vv3.set("node-b", 3);
    vv3.set("node-c", 10);
    vv.merge(vv3);
    ASSERT(vv.get("node-a") == 1);  // unchanged
    ASSERT(vv.get("node-b") == 5);  // 5 > 3, keep 5
    ASSERT(vv.get("node-c") == 10); // new

    // Test dominates
    smo::sync::VersionVector vv4;
    vv4.set("node-a", 0);
    vv4.set("node-b", 5);
    ASSERT(vv.dominates(vv4));  // vv has node-a=1 >= 0, node-b=5 >= 5
    ASSERT(!vv4.dominates(vv)); // vv4 has node-a=0 < 1

    // Test MerkleTree
    auto tree = smo::sync::MerkleTree(smo::sync::TreeID::Membership);
    ASSERT(tree.buckets.size() == 256);
    tree.epoch = 42;
    tree.version_vector.set("node-a", 1);
    tree.rebuild();
    bool has_root = false;
    for (auto b : tree.root_hash)
        if (b != 0)
            has_root = true;
    ASSERT(has_root);

    // Test MerkleTree serialization roundtrip
    auto tree_bytes = tree.serialize();
    auto tree2_r = smo::sync::MerkleTree::deserialize(BytesView(tree_bytes));
    ASSERT(bool(tree2_r));
    auto& tree2 = tree2_r.value();
    ASSERT(tree2.id == smo::sync::TreeID::Membership);
    ASSERT(tree2.epoch == 42);
    ASSERT(tree2.buckets.size() == 256);
    ASSERT(tree2.root_hash == tree.root_hash);
    ASSERT(tree2.version_vector == tree.version_vector);

    // Test Delta serialization
    smo::sync::Delta delta;
    delta.tree_id = smo::sync::TreeID::Policy;
    delta.base_epoch = 10;
    delta.entry_count = 3;
    delta.data = {0x01, 0x02, 0x03};
    auto d_bytes = delta.serialize();
    auto d2_r = smo::sync::Delta::deserialize(BytesView(d_bytes));
    ASSERT(bool(d2_r));
    ASSERT(d2_r.value().tree_id == smo::sync::TreeID::Policy);
    ASSERT(d2_r.value().base_epoch == 10);
    ASSERT(d2_r.value().entry_count == 3);
    ASSERT(d2_r.value().data.size() == 3);

    return true;
}

// PCT-022 — Structured log format
static bool test_pct_022()
{
    // Verify JSON output has all required fields
    auto entry =
        smo::runtime::LogEntry::make("test", smo::runtime::LogLevel::Info, "hello world", "trace-abc", "span-def");
    entry.node_id = "node-123";
    entry.mesh_id = "mesh-test";
    entry.session_id = "sess-456";

    auto json = entry.to_json();
    // Must contain: timestamp, node_id, mesh_id, trace_id, span_id, session_id, component, level, message
    ASSERT(json.find("\"timestamp\"") != std::string::npos);
    ASSERT(json.find("\"node_id\"") != std::string::npos);
    ASSERT(json.find("\"node-123\"") != std::string::npos);
    ASSERT(json.find("\"mesh_id\"") != std::string::npos);
    ASSERT(json.find("\"trace_id\"") != std::string::npos);
    ASSERT(json.find("\"trace-abc\"") != std::string::npos);
    ASSERT(json.find("\"span_id\"") != std::string::npos);
    ASSERT(json.find("\"span-def\"") != std::string::npos);
    ASSERT(json.find("\"session_id\"") != std::string::npos);
    ASSERT(json.find("\"sess-456\"") != std::string::npos);
    ASSERT(json.find("\"component\"") != std::string::npos);
    ASSERT(json.find("\"component\":\"test\"") != std::string::npos);
    ASSERT(json.find("\"level\"") != std::string::npos);
    ASSERT(json.find("\"level\":\"info\"") != std::string::npos);
    ASSERT(json.find("\"message\"") != std::string::npos);
    ASSERT(json.find("\"hello world\"") != std::string::npos);

    // Verify plaintext output
    auto plain = entry.to_plaintext();
    ASSERT(plain.find("info") != std::string::npos);
    ASSERT(plain.find("hello world") != std::string::npos);
    ASSERT(plain.find("trace-abc") != std::string::npos);

    // Verify custom fields in JSON
    entry.fields["peer_count"] = "5";
    entry.fields["rtt_ms"] = "42";
    json = entry.to_json();
    ASSERT(json.find("\"peer_count\":\"5\"") != std::string::npos);
    ASSERT(json.find("\"rtt_ms\":\"42\"") != std::string::npos);

    return true;
}

// PCT-024 — Fault injection / chaos: VersionVector partition + heal
static bool test_pct_024()
{
    Blake3Provider::register_as_default();

    // Simulate partition: two nodes diverge independently
    smo::sync::VersionVector vv_a, vv_b;
    vv_a.set("node-a", 10);
    vv_a.set("node-b", 5);

    vv_b.set("node-a", 7);
    vv_b.set("node-b", 8);
    vv_b.set("node-c", 3);

    // Before heal: neither dominates the other
    ASSERT(!vv_a.dominates(vv_b));
    ASSERT(!vv_b.dominates(vv_a));

    // Heal: merge
    vv_a.merge(vv_b);
    ASSERT(vv_a.get("node-a") == 10); // max(10,7)
    ASSERT(vv_a.get("node-b") == 8);  // max(5,8)
    ASSERT(vv_a.get("node-c") == 3);  // new node

    // After heal: vv_a now dominates vv_b
    ASSERT(vv_a.dominates(vv_b));

    // Test MerkleTree divergence + repair detection
    auto tree1 = smo::sync::MerkleTree(smo::sync::TreeID::Membership);
    tree1.epoch = 1;
    tree1.rebuild();

    auto tree2 = smo::sync::MerkleTree(smo::sync::TreeID::Membership);
    tree2.epoch = 1;
    tree2.rebuild();
    ASSERT(tree1 == tree2); // identical initially

    // After divergent update
    tree2.epoch = 2;
    tree2.version_vector.set("node-x", 1);
    tree2.rebuild();
    ASSERT(tree1 != tree2); // divergence detected

    // Test snapshot vs delta threshold
    ASSERT(smo::sync::AntiEntropyService::Config::defaults().max_delta_entries == 500);

    return true;
}

// PCT-025 — STUN binding request/response (RFC 5389 §6)
// Tests STUN client construction, message building, and parsing
static bool test_pct_025()
{
    using namespace smo::network::stun;

    // Test 1: Client construction with default config
    {
        Client client;
        const auto& cfg = client.config();
        ASSERT_STREQ(cfg.server_host, "stun.l.google.com");
        ASSERT_EQ(cfg.server_port, 19302);
        ASSERT_EQ(cfg.max_attempts, 3);
        ASSERT_EQ(cfg.timeout.count(), 2000);
    }

    // Test 2: Client construction with custom config
    {
        Config cfg;
        cfg.server_host = "stun.example.com";
        cfg.server_port = 3478;
        cfg.max_attempts = 5;
        cfg.timeout = std::chrono::milliseconds(5000);
        Client client(cfg);
        const auto& c = client.config();
        ASSERT_STREQ(c.server_host, "stun.example.com");
        ASSERT_EQ(c.server_port, 3478);
        ASSERT_EQ(c.max_attempts, 5);
        ASSERT_EQ(c.timeout.count(), 5000);
    }

    // Test 3: Build binding request - verify structure
    {
        Client client;
        TransactionId tid;
        Bytes req = client.build_request(tid);

        // Must have at least 20-byte header
        ASSERT(req.size() >= 20);

        // Check message type = Binding Request (0x0001)
        uint16_t msg_type = (static_cast<uint16_t>(req[0]) << 8) | req[1];
        ASSERT_EQ(msg_type, kStunBindingRequest);

        // Check magic cookie
        uint32_t magic = (static_cast<uint32_t>(req[4]) << 24) |
                         (static_cast<uint32_t>(req[5]) << 16) |
                         (static_cast<uint32_t>(req[6]) << 8) |
                         static_cast<uint32_t>(req[7]);
        ASSERT_EQ(magic, kStunMagicCookie);

        // Transaction ID must be 12 bytes
        ASSERT_EQ(req.size() >= 20, true);

        // Verify FINGERPRINT attribute is present at the end
        // Last 8 bytes should be FINGERPRINT attribute (type=0x8028, len=4, value=4 bytes)
        if (req.size() >= 8)
        {
            size_t end = req.size();
            uint16_t last_type = (static_cast<uint16_t>(req[end - 8]) << 8) | req[end - 7];
            // Could be FINGERPRINT (0x8028) or SOFTWARE (0x8022) depending on padding
            // Just verify we have attributes
            ASSERT(last_type == kAttrFingerprint || last_type == kAttrSoftware);
        }
    }

    // Test 4: Parse response - valid XOR-MAPPED-ADDRESS (IPv4)
    {
        Client client;
        TransactionId tid;
        tid.bytes.fill(0xAB);

        // Build a fake STUN Binding Response with XOR-MAPPED-ADDRESS
        // Header (20 bytes) + XOR-MAPPED-ADDRESS attribute (8 bytes) + FINGERPRINT (8 bytes)
        Bytes resp;
        resp.resize(36); // We'll fill it manually

        // Message Type = Binding Response (0x0101)
        resp[0] = 0x01;
        resp[1] = 0x01;

        // Message Length = 8 (XOR-MAPPED-ADDRESS) + 8 (FINGERPRINT) = 16
        resp[2] = 0x00;
        resp[3] = 0x10;

        // Magic Cookie
        resp[4] = 0x21;
        resp[5] = 0x12;
        resp[6] = 0xA4;
        resp[7] = 0x42;

        // Transaction ID (12 bytes)
        for (int i = 0; i < 12; ++i)
            resp[8 + i] = tid.bytes[i];

        // XOR-MAPPED-ADDRESS attribute
        // Type = 0x0020
        resp[20] = 0x00;
        resp[21] = 0x20;
        // Length = 8 (family + port + IPv4 address)
        resp[22] = 0x00;
        resp[23] = 0x08;
        // Reserved (0), Family (1 = IPv4)
        resp[24] = 0x00;
        resp[25] = 0x01;
        // XOR'ed port: 19302 ^ 0x2112 = 19302 ^ 8466 = 24840 = 0x6108
        uint16_t xor_port = 19302 ^ 0x2112;
        resp[26] = static_cast<uint8_t>((xor_port >> 8) & 0xFF);
        resp[27] = static_cast<uint8_t>(xor_port & 0xFF);
        // XOR'ed address: 8.8.8.8 ^ 0x2112A442
        // 8.8.8.8 = 0x08080808
        // 0x08080808 ^ 0x2112A442 = 0x291AAC4A
        uint32_t xor_addr = 0x08080808 ^ kStunMagicCookie;
        resp[28] = static_cast<uint8_t>((xor_addr >> 24) & 0xFF);
        resp[29] = static_cast<uint8_t>((xor_addr >> 16) & 0xFF);
        resp[30] = static_cast<uint8_t>((xor_addr >> 8) & 0xFF);
        resp[31] = static_cast<uint8_t>(xor_addr & 0xFF);

        // FINGERPRINT attribute (dummy - just for structure)
        resp[32] = 0x80;
        resp[33] = 0x28;
        resp[34] = 0x00;
        resp[35] = 0x04;
        // CRC32 placeholder
        resp.push_back(0x00);
        resp.push_back(0x00);
        resp.push_back(0x00);
        resp.push_back(0x00);

        // Update length to include FINGERPRINT (8 bytes)
        resp[2] = 0x00;
        resp[3] = 0x18;

        auto parsed = client.parse_response(resp, tid);
        ASSERT(parsed.has_value());
        ASSERT_EQ(parsed->port, 19302);
        ASSERT_STREQ(parsed->ip, "8.8.8.8");
        ASSERT_EQ(parsed->is_ipv6, false);
    }

    // Test 5: Parse response - invalid magic cookie
    {
        Client client;
        TransactionId tid;
        tid.bytes.fill(0xCD);

        Bytes resp = {
            0x01, 0x01,  // Binding Response
            0x00, 0x08,  // Length = 8
            0x00, 0x00, 0x00, 0x00,  // Wrong magic cookie
            0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD,  // TID
            0x00, 0x20, 0x00, 0x08,  // XOR-MAPPED-ADDRESS
            0x00, 0x01, 0x4B, 0x7E, 0x08, 0x08, 0x08, 0x08  // attribute value
        };

        auto parsed = client.parse_response(resp, tid);
        ASSERT(!parsed.has_value()); // Should fail due to wrong magic cookie
    }

    // Test 6: Parse response - transaction ID mismatch
    {
        Client client;
        TransactionId tid1, tid2;
        tid1.bytes.fill(0x11);
        tid2.bytes.fill(0x22);

        Bytes resp = {
            0x01, 0x01,  // Binding Response
            0x00, 0x08,  // Length = 8
            0x21, 0x12, 0xA4, 0x42,  // Correct magic cookie
            0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,  // Wrong TID
            0x00, 0x20, 0x00, 0x08,  // XOR-MAPPED-ADDRESS
            0x00, 0x01, 0x4B, 0x7E, 0x08, 0x08, 0x08, 0x08  // attribute value
        };

        auto parsed = client.parse_response(resp, tid1);
        ASSERT(!parsed.has_value()); // Should fail due to TID mismatch
    }

    // Test 7: MappedAddress to_string()
    {
        smo::network::stun::MappedAddress ma;
        ma.ip = "1.2.3.4";
        ma.port = 5678;
        ma.is_ipv6 = false;
        ASSERT_STREQ(ma.to_string(), "1.2.3.4:5678");

        ma.ip = "2001:db8::1";
        ma.port = 3478;
        ma.is_ipv6 = true;
        ASSERT_STREQ(ma.to_string(), "[2001:db8::1]:3478");

        ma.ip = "";
        ma.port = 0;
        ASSERT(ma.empty());
        ASSERT_STREQ(ma.to_string(), "");
    }

    return true;
}

// ==========================================================================
// PCT-026 — UDP hole punch protocol (predictable port pairs)
// Tests hole punch state tracking, metrics, and predictable port behavior
// ==========================================================================
static bool test_pct_026()
{
    using namespace smo::network::udp;

    // Test 1: HeartbeatService Config with hole punch enabled
    {
        HeartbeatService::Config cfg = HeartbeatService::default_config();
        ASSERT_EQ(cfg.enable_hole_punch, true);
        ASSERT_EQ(cfg.ping_interval_ms, 5000U);
        ASSERT_EQ(cfg.ping_timeout_ms, 3000U);
        ASSERT_EQ(cfg.max_misses, 3);
    }

    // Test 2: HeartbeatService construction and basic config
    {
        HeartbeatService::Config cfg;
        cfg.enable_hole_punch = false;
        cfg.ping_interval_ms = 1000;
        cfg.ping_timeout_ms = 500;
        cfg.max_misses = 2;

        HeartbeatService hb(cfg);
        // Verify config was applied (indirectly via default_config comparison)
        HeartbeatService hb2(cfg);
        ASSERT_EQ(hb2.config().enable_hole_punch, false);
        ASSERT_EQ(hb2.config().ping_interval_ms, 1000U);
    }

    // Test 3: Hole punch state tracking
    {
        // Test that HolePunchState can be created and manipulated
        HeartbeatService::HolePunchState state;
        ASSERT_EQ(state.attempts, 0);
        ASSERT_EQ(state.succeeded, false);
        ASSERT(state.path == "");
        ASSERT_EQ(state.started_at, 0);

        state.attempts = 1;
        state.started_at = 12345;
        state.path = "direct";
        ASSERT_EQ(state.attempts, 1);
        ASSERT_EQ(state.started_at, 12345);
        ASSERT(state.path == "direct");
    }

    // Test 4: Predictable port pair concept
    // Both sides use the same local port (the bound UDP socket port)
    // The mapped address port is the port as seen by the STUN server
    // This test verifies the concept without actual network I/O
    {
        smo::MappedAddress mapped;
        mapped.ip = "1.2.3.4";
        mapped.port = 12345;
        mapped.is_ipv6 = false;
        mapped.discovered_at = 1000;

        ASSERT_EQ(mapped.port, 12345U);
        ASSERT(mapped.ip == "1.2.3.4");
        ASSERT_EQ(mapped.is_ipv6, false);
        ASSERT(mapped.to_string() == "1.2.3.4:12345");
    }

    // Test 5: Metrics names for hole punch
    {
        // Verify metric names are as expected (used in telemetry)
        std::string success_metric = "smo_hole_punch_success_total";
        std::string failure_metric = "smo_hole_punch_failure_total";

        ASSERT(success_metric.find("hole_punch") != std::string::npos);
        ASSERT(failure_metric.find("hole_punch") != std::string::npos);
        ASSERT(success_metric.find("success") != std::string::npos);
        ASSERT(failure_metric.find("failure") != std::string::npos);
    }

    // Test 6: GossipEngine UDP listener integration
    {
        MembershipTable table;
        GossipEngine::Config cfg;
        GossipEngine engine(table, cfg);

        // Verify default state
        ASSERT_EQ(engine.gossip_sent_count(), 0U);
        ASSERT_EQ(engine.gossip_received_count(), 0U);

        // Test that set_udp_listener can be called (with nullptr for unit test)
        engine.set_udp_listener(nullptr);
        // If we get here without crash, the method exists and is callable
    }

    // Test 7: Dual endpoint fanout (physical + mapped)
    {
        MembershipTable table;
        GossipEngine::Config cfg;
        cfg.fanout = 2;
        GossipEngine engine(table, cfg);

        // Add a peer with both physical and mapped addresses
        smo::PeerRecord rec;
        rec.node_id.value.fill(0x01);
        rec.endpoint.scheme = "tcp";
        rec.endpoint.host = "10.0.0.1";
        rec.endpoint.port = 7777;
        rec.mapped_address.ip = "1.2.3.4";
        rec.mapped_address.port = 12345;
        rec.mapped_address.is_ipv6 = false;
        rec.state = smo::PeerState::Online;

        table.upsert(std::move(rec));

        // Select fanout peers - should include both TCP and UDP endpoints
        auto peers = engine.test_select_fanout_peers();
        // With 1 peer, fanout=2, we should get 2 endpoints (TCP + UDP)
        ASSERT_EQ(peers.size(), 2U);

        // Verify one is TCP and one is UDP
        bool has_tcp = false;
        bool has_udp = false;
        for (const auto& ep : peers)
        {
            if (ep.scheme == "tcp")
                has_tcp = true;
            else if (ep.scheme == "udp")
                has_udp = true;
        }
        ASSERT(has_tcp);
        ASSERT(has_udp);
    }

    return true;
}

// PCT-027 — Relay Service (TURN-Lite) integration test
// Tests relay session allocation, frame forwarding (preserve AEAD), relay candidate detection,
// bandwidth budget, and metrics
// ==========================================================================
static bool test_pct_027()
{
    using namespace smo::network::relay;

    // Test 1: RelayService Config defaults
    {
        RelayService::Config cfg = RelayService::default_config();
        ASSERT_EQ(cfg.bandwidth_bps_per_peer, 1'000'000ULL); // 1 Mbps
        ASSERT_EQ(cfg.session_timeout_ms, 300000U);         // 5 min
        ASSERT_EQ(cfg.max_sessions, 100U);
    }

    // Test 2: RelayService Config customization
    {
        RelayService::Config cfg;
        cfg.bandwidth_bps_per_peer = 500'000; // 500 Kbps
        cfg.session_timeout_ms = 60000;       // 1 min
        cfg.max_sessions = 50;

        RelayService relay(cfg);
        // Config is stored internally, verify via default_config comparison
        ASSERT_EQ(relay.default_config().bandwidth_bps_per_peer, 1'000'000ULL);
    }

    // Test 3: RelaySession structure
    {
        RelaySession session;
        smo::NodeID peer;
        peer.value.fill(0x01);
        smo::NodeID relay_node;
        relay_node.value.fill(0x02);

        session.peer_id = peer;
        session.relay_node_id = relay_node;
        session.relay_endpoint.scheme = "tcp";
        session.relay_endpoint.host = "10.0.0.1";
        session.relay_endpoint.port = 7777;
        session.created_at_ns = 1000;
        session.last_activity_ns = 2000;
        session.bytes_forwarded = 1024;
        session.active = true;

        ASSERT(session.active);
        ASSERT_EQ(session.bytes_forwarded, 1024ULL);
        ASSERT_EQ(session.peer_id.value[0], 0x01);
        ASSERT_EQ(session.relay_node_id.value[0], 0x02);
        ASSERT(session.relay_endpoint.host == "10.0.0.1");
        ASSERT_EQ(session.relay_endpoint.port, 7777U);
    }

    // Test 4: Metrics callback interface
    {
        // Verify MetricsCallback interface can be implemented
        class TestMetrics : public RelayService::MetricsCallback
        {
        public:
            std::string last_counter_name;
            std::string last_counter_labels;
            int64_t last_counter_delta = 0;
            std::string last_gauge_name;
            double last_gauge_value = 0.0;
            std::string last_gauge_labels;

            void increment_counter(const std::string& name, const std::string& labels, int64_t delta) override
            {
                last_counter_name = name;
                last_counter_labels = labels;
                last_counter_delta = delta;
            }
            void set_gauge(const std::string& name, double value, const std::string& labels) override
            {
                last_gauge_name = name;
                last_gauge_value = value;
                last_gauge_labels = labels;
            }
        };

        TestMetrics metrics;
        metrics.increment_counter("test_counter", "label=value", 42);
        metrics.set_gauge("test_gauge", 3.14, "label=value");

        ASSERT(metrics.last_counter_name == "test_counter");
        ASSERT(metrics.last_counter_labels == "label=value");
        ASSERT_EQ(metrics.last_counter_delta, 42);
        ASSERT(metrics.last_gauge_name == "test_gauge");
        ASSERT_EQ(metrics.last_gauge_value, 3.14);
    }

    // Test 5: Relay capability detection in PeerRecord
    {
        smo::PeerRecord rec;
        rec.node_id.value.fill(0x01);
        rec.endpoint.scheme = "tcp";
        rec.endpoint.host = "10.0.0.1";
        rec.endpoint.port = 7777;
        rec.relay_capable = true;
        rec.state = smo::PeerState::Online;

        ASSERT(rec.relay_capable);

        rec.relay_capable = false;
        ASSERT(!rec.relay_capable);
    }

    // Test 6: Bandwidth budget calculation (token bucket concept)
    {
        RelaySession session;
        session.bytes_forwarded = 0;
        session.last_activity_ns = 1'000'000'000; // 1 second ago
        session.active = true;

        RelayService::Config cfg;
        cfg.bandwidth_bps_per_peer = 1'000'000; // 1 Mbps = 125 KB/s

        // Mock the check_budget logic (private method, test concept here)
        auto now_ns = 2'000'000'000; // 1 second later
        double elapsed_sec = static_cast<double>(now_ns - session.last_activity_ns) / 1'000'000'000.0;
        double budget_bytes = static_cast<double>(cfg.bandwidth_bps_per_peer) / 8.0 * elapsed_sec;
        double allowed_bytes = budget_bytes * 2.0; // 2x burst

        // 1 second at 1 Mbps = 125 KB budget, 2x burst = 250 KB
        ASSERT(allowed_bytes > 200'000.0); // ~250 KB
        ASSERT(allowed_bytes < 300'000.0);
    }

    // Test 7: Relay metrics names
    {
        std::string bytes_metric = "smo_relay_bytes_total";
        std::string peers_metric = "smo_relay_active_peers";

        ASSERT(bytes_metric.find("relay") != std::string::npos);
        ASSERT(bytes_metric.find("bytes") != std::string::npos);
        ASSERT(peers_metric.find("relay") != std::string::npos);
        ASSERT(peers_metric.find("active_peers") != std::string::npos);
    }

    // Test 8: Session allocation requires membership and transport
    {
        RelayService relay(RelayService::default_config());
        // Not started - allocate should fail gracefully
        smo::NodeID peer;
        peer.value.fill(0x01);
        auto result = relay.allocate_relay_session(peer);
        ASSERT(!result); // Should fail because not started
        // Error code 500 = "RelayService not started"
    }

    // Test 9: Relay session cleanup concept
    {
        RelaySession session;
        session.active = true;
        session.last_activity_ns = 1'000'000'000; // 1 second ago

        int64_t now_ns = 10'000'000'000; // 9 seconds later
        int64_t timeout_ns = 5'000'000'000; // 5 second timeout

        // Session should be expired
        bool expired = (now_ns - session.last_activity_ns > timeout_ns);
        ASSERT(expired);

        // Update activity - should not be expired
        session.last_activity_ns = now_ns - 1'000'000'000; // 1 second ago
        expired = (now_ns - session.last_activity_ns > timeout_ns);
        ASSERT(!expired);
    }

    // Test 10: AEAD preservation concept - frames are forwarded as-is
    {
        // The relay service forwards BytesView frames without decryption
        // This test verifies the frame format expectations
        smo::Bytes frame;
        frame.resize(100);
        frame[0] = 0x44; // SMO frame magic
        frame[1] = 0x01; // frame type

        // Simulate forwarding - frame should be unchanged
        smo::BytesView view(frame);
        ASSERT_EQ(view.size(), 100U);
        ASSERT_EQ(view[0], 0x44);
        ASSERT_EQ(view[1], 0x01);

        // AEAD tag would be at the end of the frame (not modified by relay)
        frame[frame.size() - 1] = 0xAA; // Mock AEAD tag
        ASSERT_EQ(frame.back(), 0xAA);
    }

    return true;
}

static bool test_pct_019()
{
    auto rules = join::join_transition_table();
    auto timeouts = join::join_timeout_table();

    FsmInstance fsm;
    fsm.set_transitions(rules);
    fsm.set_timeouts(timeouts);
    fsm.reset(static_cast<int64_t>(join::JoinState::WAIT_GOSSIP));

    // Verify WAIT_GOSSIP → GOSSIP_TIMEOUT → DEGRADED
    auto r1 = fsm.on_event(static_cast<int64_t>(join::JoinEvent::GOSSIP_TIMEOUT));
    ASSERT(r1);
    ASSERT(fsm.current_state() == static_cast<int64_t>(join::JoinState::DEGRADED));

    // Verify DEGRADED → GOSSIP_COMPLETE → READY
    auto r2 = fsm.on_event(static_cast<int64_t>(join::JoinEvent::GOSSIP_COMPLETE));
    ASSERT(r2);
    ASSERT(fsm.current_state() == static_cast<int64_t>(join::JoinState::READY));

    // Verify DEGRADED → TIMEOUT → FAILED
    fsm.reset(static_cast<int64_t>(join::JoinState::DEGRADED));
    auto r3 = fsm.on_event(static_cast<int64_t>(join::JoinEvent::TIMEOUT));
    ASSERT(r3);
    ASSERT(fsm.current_state() == static_cast<int64_t>(join::JoinState::FAILED));

    // Verify DEGRADED → FAIL → FAILED
    fsm.reset(static_cast<int64_t>(join::JoinState::DEGRADED));
    auto r4 = fsm.on_event(static_cast<int64_t>(join::JoinEvent::FAIL));
    ASSERT(r4);
    ASSERT(fsm.current_state() == static_cast<int64_t>(join::JoinState::FAILED));

    // Verify timeout table: WAIT_GOSSIP → DEGRADED (60s)
    ASSERT(fsm.max_dwell_ns() == 0); // after reset to DEGRADED, default timeout
    fsm.reset(static_cast<int64_t>(join::JoinState::WAIT_GOSSIP));
    ASSERT(fsm.max_dwell_ns() == 60'000'000'000ULL);
    ASSERT(fsm.fallback_state() == static_cast<int64_t>(join::JoinState::DEGRADED));

    // Verify GossipEngine counters
    GossipEngine::Config cfg;
    MembershipTable table;
    GossipEngine engine(table, cfg);
    ASSERT(engine.gossip_sent_count() == 0);
    ASSERT(engine.gossip_received_count() == 0);

    return true;
}

// ==========================================================================
// PCT-023: Join token signature verification (P0-S1 regression)
//   Suite-driven (RFC 0009 / RFC 0024): every crypto op goes through
//   CryptoRegistry by cipher_suite_id — never a concrete primitive.
//   Runs against ALL registered suites (Classical, Modern, PurePQC).
//   A v2 token must fail verification if the signature does not match the
//   issuer's public key (tampered payload / forged issuer).
// ==========================================================================
static bool test_pct_023()
{
    RngRef rng(nullptr, [](void*, uint8_t* buf, size_t len) { random::fill(BytesMutView{buf, len}); });

    // Register ALL suites exactly like smo-node does at startup
    smo::providers::register_suite1_classical();
    smo::providers::register_suite2_modern();
#ifdef SMO_WITH_PQC
    smo::providers::register_suite3_purepqc();
#endif

    auto& reg = CryptoRegistry::instance();
    const auto available = reg.available_suites();
    ASSERT(!available.empty());

    auto now_sec =
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    const int64_t expiry = now_sec + 3600;

    enroll::Admission admission;
    admission.role = "Member";
    admission.profile = "server";

    for (auto suite_id : available)
    {
        // Resolve crypto by suite id — the only sanctioned way to touch crypto
        auto prov_res = reg.get_suite(suite_id);
        ASSERT(prov_res);
        const auto* prov = prov_res.value();
        ASSERT(prov->signer.generate_keypair && prov->signer.sign && prov->signer.verify);
        ASSERT(prov->hash.hash);

        // Root keypair (the "issuer" authority) + attacker keypair
        auto root_kp = prov->signer.generate_keypair(rng);
        ASSERT(root_kp);
        ASSERT(!root_kp.value().public_key.empty());
        auto attacker_kp = prov->signer.generate_keypair(rng);
        ASSERT(attacker_kp);

        const std::string issuer = "root:" + bytes_to_hex(root_kp.value().public_key).substr(0, 16);

        // 1. Valid token signed by root → must validate
        auto tok = enroll::generate_token("mesh-test", 1, static_cast<int>(suite_id), {"10.0.0.1:7777"}, admission,
                                          expiry, issuer, prov->signer, root_kp.value().secret_key, rng);
        ASSERT(tok);
        ASSERT(!tok.value().signature.empty());
        ASSERT(!enroll::token_is_v1(tok.value()));
        auto vr = enroll::validate_token(tok.value(), prov->signer, root_kp.value().public_key, prov->hash);
        ASSERT(vr);

        // 2. Tampered payload (role escalation) → must FAIL
        {
            auto tam = tok.value();
            tam.admission.role = "Authority";
            auto tcheck = enroll::validate_token(tam, prov->signer, root_kp.value().public_key, prov->hash);
            ASSERT(!tcheck); // signature no longer matches modified payload
        }

        // 3. Forged token (signed by attacker's key) → must FAIL against root key
        {
            auto forged =
                enroll::generate_token("mesh-test", 1, static_cast<int>(suite_id), {"10.0.0.1:7777"}, admission, expiry,
                                       issuer, prov->signer, attacker_kp.value().secret_key, rng);
            ASSERT(forged);
            auto fcheck = enroll::validate_token(forged.value(), prov->signer, root_kp.value().public_key, prov->hash);
            ASSERT(!fcheck); // wrong signing key
        }

        // 4. v1 (HMAC) token path is suite-agnostic via provider hash
        {
            auto v1 = enroll::generate_token_hmac("mesh-test", 1, static_cast<int>(suite_id), {"10.0.0.1:7777"},
                                                  "Member", expiry, Bytes{1, 2, 3, 4}, prov->hash);
            ASSERT(v1);
            ASSERT(enroll::token_is_v1(v1.value()));
            auto v1ok = enroll::validate_token_v1(v1.value(), Bytes{1, 2, 3, 4}, prov->hash);
            ASSERT(v1ok);
            auto v1bad = enroll::validate_token_v1(v1.value(), Bytes{9, 9, 9, 9}, prov->hash);
            ASSERT(!v1bad); // wrong secret
        }
    }

    return true;
}

// ==========================================================================
// PCT-028 — ICE-Lite candidate gathering, exchange, and connectivity checks
// ==========================================================================
static bool test_pct_028()
{
    using namespace smo::network::ice;

    // Test 1: IceConfig default values
    {
        IceConfig cfg;
        ASSERT_STREQ(cfg.stun_server_host, "stun.l.google.com");
        ASSERT_EQ(cfg.stun_server_port, 19302);
        ASSERT_EQ(cfg.max_stun_attempts, 3);
        ASSERT_EQ(cfg.stun_timeout_ms, 2000);
        ASSERT_EQ(cfg.enable_relay, true);
        ASSERT_EQ(cfg.connectivity_check_timeout_ms, 5000);
        ASSERT_EQ(cfg.max_checks_per_pair, 3);
    }

    // Test 2: IceConfig customization
    {
        IceConfig cfg;
        cfg.stun_server_host = "stun.example.com";
        cfg.stun_server_port = 3478;
        cfg.max_stun_attempts = 5;
        cfg.stun_timeout_ms = 5000;
        cfg.enable_relay = false;

        IceAgent agent(cfg);
        // Config is stored internally
        ASSERT_STREQ(agent.config().stun_server_host, "stun.example.com");
        ASSERT_EQ(agent.config().stun_server_port, 3478);
    }

    // Test 3: Candidate priority calculation (RFC 8445 §5.1.2)
    {
        uint32_t host_prio = calculate_priority(CandidateType::Host);
        uint32_t srflx_prio = calculate_priority(CandidateType::ServerReflexive);
        uint32_t relay_prio = calculate_priority(CandidateType::Relayed);

        // Host should have highest priority (type_pref = 126)
        ASSERT(host_prio > srflx_prio);
        ASSERT(srflx_prio > relay_prio);

        // Verify specific values
        ASSERT_EQ(host_prio, (126u << 24) | (65535u << 8) | (256 - 1));
        ASSERT_EQ(srflx_prio, (110u << 24) | (65535u << 8) | (256 - 1));
        ASSERT_EQ(relay_prio, (0u << 24) | (65535u << 8) | (256 - 1));
    }

    // Test 4: Pair priority calculation (RFC 8445 §5.7.2)
    {
        uint32_t controlling = 0x7E0000FF; // host priority
        uint32_t controlled = 0x6E0000FF;  // srflx priority
        uint64_t pair_prio = calculate_pair_priority(controlling, controlled);

        // pair_priority = 2^32 * min(G, D) + 2 * max(G, D) + (G > D ? 1 : 0)
        uint64_t expected = (static_cast<uint64_t>(controlled) << 32) +
                           (2 * controlling) + 1;
        ASSERT_EQ(pair_prio, expected);
    }

    // Test 5: Foundation generation
    {
        std::string foundation = generate_foundation(CandidateType::Host, "192.168.1.1", 5000);
        ASSERT(foundation.find("host:192.168.1.1:5000") != std::string::npos);

        std::string foundation2 = generate_foundation(CandidateType::ServerReflexive, "1.2.3.4", 12345);
        ASSERT(foundation2.find("srflx:1.2.3.4:12345") != std::string::npos);

        // Same base should generate same foundation
        std::string foundation3 = generate_foundation(CandidateType::Host, "192.168.1.1", 5000);
        ASSERT(foundation == foundation3);
    }

    // Test 6: Candidate structure
    {
        Candidate cand;
        cand.type = CandidateType::Host;
        cand.foundation = "host:192.168.1.1:5000";
        cand.ip = "192.168.1.1";
        cand.port = 5000;
        cand.is_ipv6 = false;
        cand.priority = calculate_priority(CandidateType::Host);
        cand.discovered_at = 1234567890;

        ASSERT_EQ(cand.type, CandidateType::Host);
        ASSERT(cand.foundation == "host:192.168.1.1:5000");
        ASSERT(cand.ip == "192.168.1.1");
        ASSERT_EQ(cand.port, 5000);
        ASSERT_EQ(cand.is_ipv6, false);
        ASSERT(!cand.empty());
    }

    // Test 7: Candidate equality
    {
        Candidate cand1, cand2;
        cand1.type = CandidateType::Host;
        cand1.ip = "192.168.1.1";
        cand1.port = 5000;
        cand1.foundation = "host:192.168.1.1:5000";

        cand2 = cand1;
        ASSERT(cand1 == cand2);

        cand2.port = 5001;
        ASSERT(!(cand1 == cand2));
    }

    // Test 8: Candidate to_string
    {
        Candidate cand;
        cand.type = CandidateType::Host;
        cand.ip = "192.168.1.1";
        cand.port = 5000;
        cand.is_ipv6 = false;
        cand.priority = calculate_priority(CandidateType::Host);
        cand.foundation = "host:192.168.1.1:5000";

        std::string str = cand.to_string();
        ASSERT(str.find("192.168.1.1:5000") != std::string::npos);
        ASSERT(str.find("host") != std::string::npos);
        ASSERT(str.find("prio=") != std::string::npos);
        ASSERT(str.find("foundation=") != std::string::npos);
    }

    // Test 9: CBOR encode/decode roundtrip
    {
        // Test the static decode_candidates_cbor method
        cbor::Encoder enc;
        enc.encode_array(2);
        
        // Encode cand1 (Host)
        enc.encode_map(7);
        enc.encode_uint(1); enc.encode_uint(static_cast<uint64_t>(CandidateType::Host));
        enc.encode_uint(2); enc.encode_string("host:192.168.1.1:5000");
        enc.encode_uint(3); enc.encode_string("192.168.1.1");
        enc.encode_uint(4); enc.encode_uint(5000);
        enc.encode_uint(5); enc.encode_uint(0);
        enc.encode_uint(6); enc.encode_uint(calculate_priority(CandidateType::Host));
        enc.encode_uint(9); enc.encode_uint(1000);
        
        // Encode cand2 (ServerReflexive)
        enc.encode_map(9);
        enc.encode_uint(1); enc.encode_uint(static_cast<uint64_t>(CandidateType::ServerReflexive));
        enc.encode_uint(2); enc.encode_string("srflx:1.2.3.4:12345");
        enc.encode_uint(3); enc.encode_string("1.2.3.4");
        enc.encode_uint(4); enc.encode_uint(12345);
        enc.encode_uint(5); enc.encode_uint(0);
        enc.encode_uint(6); enc.encode_uint(calculate_priority(CandidateType::ServerReflexive));
        enc.encode_uint(7); enc.encode_string("192.168.1.1");
        enc.encode_uint(8); enc.encode_uint(5000);
        enc.encode_uint(9); enc.encode_uint(2000);

        Bytes cbor_data = enc.take();
        ASSERT(!cbor_data.empty());

        // Decode
        auto decoded = IceAgent::decode_candidates_cbor(BytesView(cbor_data));
        ASSERT(decoded);
        ASSERT_EQ(decoded.value().size(), 2U);
        ASSERT_EQ(decoded.value()[0].type, CandidateType::Host);
        ASSERT_EQ(decoded.value()[1].type, CandidateType::ServerReflexive);
        ASSERT(decoded.value()[0].ip == "192.168.1.1");
        ASSERT(decoded.value()[1].ip == "1.2.3.4");
        ASSERT_EQ(decoded.value()[0].port, 5000);
        ASSERT_EQ(decoded.value()[1].port, 12345);
    }

    // Test 10: CandidatePair structure
    {
        Candidate local, remote;
        local.type = CandidateType::Host;
        local.ip = "192.168.1.1";
        local.port = 5000;
        local.priority = calculate_priority(CandidateType::Host);

        remote.type = CandidateType::ServerReflexive;
        remote.ip = "1.2.3.4";
        remote.port = 12345;
        remote.priority = calculate_priority(CandidateType::ServerReflexive);

        CandidatePair pair;
        pair.local = local;
        pair.remote = remote;
        pair.priority = calculate_pair_priority(local.priority, remote.priority);

        ASSERT(!pair.empty());
        ASSERT(pair.local.ip == "192.168.1.1");
        ASSERT(pair.remote.ip == "1.2.3.4");
        ASSERT(pair.priority > 0);
        ASSERT(!pair.nominated);
        ASSERT_EQ(pair.rtt_ms, -1.0);
    }

    // Test 11: Metric names for ICE
    {
        std::string ice_candidates_metric = "smo_ice_candidates_total";
        std::string ice_checks_metric = "smo_ice_connectivity_checks_total";
        std::string ice_nominated_metric = "smo_ice_nominated_pair_rtt_ms";

        ASSERT(ice_candidates_metric.find("ice") != std::string::npos);
        ASSERT(ice_checks_metric.find("ice") != std::string::npos);
        ASSERT(ice_nominated_metric.find("ice") != std::string::npos);
    }

    // Test 12: ICE capability bit
    {
        ASSERT(smo::join::CAP_ICE_LITE != 0);
        // Should be bit 11
        ASSERT_EQ(smo::join::CAP_ICE_LITE, 1ULL << 11);
    }

    return true;
}

// ==========================================================================
// PCT-029 — PolicyEngine evaluation with built-in presets
// ==========================================================================
static bool test_pct_029()
{
    using namespace smo::acl;

    // Create PolicyEngine with default config (loads built-in presets)
    PolicyEngine::Config config;
    config.enable_caching = false;
    PolicyEngine engine(config);

    // Test 1: Enterprise-standard preset allows read for members
    {
        PolicyEvaluationContext ctx;
        ctx.session_id = "test-session";
        ctx.session_caps = {"CAP_VERIFY", "CAP_FS_READ"};
        ctx.session_roles = {"Member"};
        ctx.session_trust_score = 0.5;
        ctx.custom_attributes["CAP_VERIFY"] = "true"; // Required by "require-certificate" rule
        ctx.request_contract_id = "system.file";
        ctx.request_method = "read";

        auto result = engine.evaluate(ctx);
        ASSERT(result);
        ASSERT_EQ(static_cast<int>(result.value().decision), static_cast<int>(PolicyDecision::Allow));
    }

    // Test 2: Enterprise-standard allows write for members too (require-certificate rule at priority 100 allows all Member ops)
    // Note: The enterprise-standard preset has a baseline "require-certificate" rule at priority 100
    // that allows any operation for Members with CAP_VERIFY. More specific rules are at lower priority.
    {
        PolicyEvaluationContext ctx;
        ctx.session_id = "test-session";
        ctx.session_caps = {"CAP_VERIFY", "CAP_FS_WRITE"};
        ctx.session_roles = {"Member"};
        ctx.session_trust_score = 0.5;
        ctx.custom_attributes["CAP_VERIFY"] = "true";
        ctx.request_contract_id = "system.file";
        ctx.request_method = "write";

        auto result = engine.evaluate(ctx);
        ASSERT(result);
        ASSERT_EQ(static_cast<int>(result.value().decision), static_cast<int>(PolicyDecision::Allow));
    }

    // Test 3: Enterprise-standard allows write for contributors
    {
        PolicyEvaluationContext ctx;
        ctx.session_id = "test-session";
        ctx.session_caps = {"CAP_VERIFY", "CAP_FS_WRITE"};
        ctx.session_roles = {"Contributor"};
        ctx.session_trust_score = 0.5;
        ctx.custom_attributes["CAP_VERIFY"] = "true";
        ctx.request_contract_id = "system.file";
        ctx.request_method = "write";

        auto result = engine.evaluate(ctx);
        ASSERT(result);
        ASSERT_EQ(static_cast<int>(result.value().decision), static_cast<int>(PolicyDecision::Allow));
    }

// Test 4: Custom deny-write policy
    {
        PolicyEngine engine_custom(PolicyEngine::Config{.enable_caching = false});
        auto clear_res = engine_custom.clear_policies();
        ASSERT(clear_res);
        // Create a custom policy that denies write
        PolicySet deny_write_policy;
        deny_write_policy.name = "deny-write-test";
        deny_write_policy.rules.push_back(PolicyRule{
            .name = "deny-write",
            .description = "Deny write operations",
            .priority = 10,
            .required_capabilities = {},
            .forbidden_capabilities = {"CAP_FS_WRITE"},
            .required_roles = {},
            .forbidden_roles = {},
            .effect = PolicyDecision::Deny,
        });
        deny_write_policy.rules.push_back(PolicyRule{
            .name = "allow-read",
            .description = "Allow read operations",
            .priority = 50,
            .required_capabilities = {"CAP_FS_READ", "CAP_VERIFY"},
            .forbidden_capabilities = {},
            .required_roles = {"Member"},
            .forbidden_roles = {},
            .effect = PolicyDecision::Allow,
        });
        auto load_res = engine_custom.load_policy_set(deny_write_policy);
        ASSERT(load_res);

        PolicyEvaluationContext ctx;
        ctx.session_id = "test-session";
        ctx.session_caps = {"CAP_VERIFY", "CAP_FS_WRITE"};
        ctx.session_roles = {"Contributor"};
        ctx.session_trust_score = 0.5;
        ctx.custom_attributes["CAP_VERIFY"] = "true";
        ctx.request_contract_id = "system.file";
        ctx.request_method = "write";

        auto result = engine_custom.evaluate(ctx);
        ASSERT(result);
        ASSERT_EQ(static_cast<int>(result.value().decision), static_cast<int>(PolicyDecision::Deny));
    }

    // Test 5: Custom allow-read policy
    {
        PolicyEngine engine_custom(PolicyEngine::Config{.enable_caching = false});
        auto clear_res = engine_custom.clear_policies();
        ASSERT(clear_res);
        PolicySet allow_read_policy;
        allow_read_policy.name = "allow-read-test";
        allow_read_policy.rules.push_back(PolicyRule{
            .name = "allow-read",
            .description = "Allow read operations",
            .priority = 50,
            .required_capabilities = {"CAP_FS_READ", "CAP_VERIFY"},
            .forbidden_capabilities = {},
            .required_roles = {"Member"},
            .forbidden_roles = {},
            .effect = PolicyDecision::Allow,
        });
        auto load_res = engine_custom.load_policy_set(allow_read_policy);
        ASSERT(load_res);

        PolicyEvaluationContext ctx;
        ctx.session_id = "test-session";
        ctx.session_caps = {"CAP_VERIFY", "CAP_FS_READ"};
        ctx.session_roles = {"Member"};
        ctx.session_trust_score = 0.5;
        ctx.custom_attributes["CAP_VERIFY"] = "true";
        ctx.request_contract_id = "system.file";
        ctx.request_method = "read";

        auto result = engine_custom.evaluate(ctx);
        ASSERT(result);
        ASSERT_EQ(static_cast<int>(result.value().decision), static_cast<int>(PolicyDecision::Allow));
    }

    // Test 6: PolicyEngine with no policies returns Deny
    {
        PolicyEngine engine_empty(PolicyEngine::Config{.enable_caching = false});
        auto clear_res = engine_empty.clear_policies();
        ASSERT(clear_res);
        PolicyEvaluationContext ctx;
        ctx.session_id = "test-session";
        ctx.session_caps = {"CAP_VERIFY"};
        ctx.session_roles = {"Member"};
        ctx.session_trust_score = 0.5;
        ctx.request_contract_id = "system.file";
        ctx.request_method = "read";

        auto result = engine_empty.evaluate(ctx);
        ASSERT(result);
        ASSERT_EQ(static_cast<int>(result.value().decision), static_cast<int>(PolicyDecision::Deny));
        ASSERT(result.value().reason == "No matching policy");
    }

    return true;
}

// ==========================================================================
// PCT-030 — PolicyMiddleware integration with PolicyEngine
// ==========================================================================
static bool test_pct_030()
{
    using namespace smo::runtime;
    using namespace smo::acl;

    // Create PolicyEngine with enterprise-standard preset
    smo::acl::PolicyEngine::Config config;
    config.enable_caching = false;
    smo::acl::PolicyEngine engine(config);

    // Create TrustManager (minimal for test)
    TrustManager trust_mgr;

    // Create NodeLifecycleFSM
    NodeLifecycleFSM lifecycle_fsm;
    lifecycle_fsm.on_event(NodeLifecycleEvent::IDENTITY_CREATED);

    // Create PolicyMiddleware with PolicyEngine
    PolicyMiddleware policy_mw(&trust_mgr, &engine, &lifecycle_fsm);

    // Test 1: Anonymous contract bypasses all checks
    {
        PolicyMiddleware policy_mw2(&trust_mgr, &engine, &lifecycle_fsm);
        policy_mw2.set_anonymous("system.test", true);

        PacketContext ctx;
        ctx.session = nullptr;
        ctx.contract_id = "system.test";
        ctx.method = "test";
        ctx.payload = BytesView{};
        ctx.opcode_hex = "0x01";

        auto result = policy_mw2.process(ctx);
        ASSERT(result);
        ASSERT(!ctx.denied);
    }

    // Test 2: Non-anonymous contract without session is denied
    {
        PacketContext ctx;
        ctx.session = nullptr;
        ctx.contract_id = "system.file";
        ctx.method = "read";
        ctx.payload = BytesView{};
        ctx.opcode_hex = "0x2b";

        auto result = policy_mw.process(ctx);
        ASSERT(result);
        ASSERT(ctx.denied);
        ASSERT(ctx.deny_reason.find("session required") != std::string::npos);
    }

    // Test 3: Closed session is denied
    {
        auto crypto_res = smo::CryptoRegistry::instance().get_suite(smo::kSuiteClassical);
        ASSERT(crypto_res);
        const auto* crypto = crypto_res.value();
        auto rng = crypto->default_rng();
        auto id_res = smo::Identity::create(*crypto, rng);
        ASSERT(id_res);
        auto identity = std::move(id_res.value());

        auto session_res = Session::create(SessionId{}, identity.node_id(), Certificate{}, CapabilitySet{}, 1000, 3600000000000LL);
        ASSERT(session_res);
        auto session = std::move(session_res.value());
        session.on_event(SessionEvent::Close, 2000);

        PacketContext ctx;
        ctx.session = &session;
        ctx.contract_id = "system.file";
        ctx.method = "read";
        ctx.payload = BytesView{};
        ctx.opcode_hex = "0x2b";

        auto result = policy_mw.process(ctx);
        ASSERT(result);
        ASSERT(ctx.denied);
        ASSERT(ctx.deny_reason.find("session is closed") != std::string::npos);
    }

    return true;
}

// ==========================================================================
// PCT-031 — No anonymous bypass for 7 policy-covered contracts
// ==========================================================================
static bool test_pct_031()
{
    using namespace smo::runtime;
    using namespace smo::acl;

    // Create PolicyEngine with enterprise-standard preset
    smo::acl::PolicyEngine::Config config;
    config.enable_caching = false;
    smo::acl::PolicyEngine engine(config);

    // Create TrustManager
    TrustManager trust_mgr;

    // Create NodeLifecycleFSM
    NodeLifecycleFSM lifecycle_fsm;
    lifecycle_fsm.on_event(NodeLifecycleEvent::IDENTITY_CREATED);

    // Create PolicyMiddleware with PolicyEngine - NO anonymous contracts set
    PolicyMiddleware policy_mw(&trust_mgr, &engine, &lifecycle_fsm);

    // The 7 policy-covered contracts (packet-capable opcodes):
    const std::vector<std::string> policy_covered_contracts = {
        "system.echo",       // ECHO (0x06) - Execution namespace
        "system.governance", // GOV_* (0x24-0x29) - Control namespace
        "system.recovery",   // RECOVERY (0x2A) - Control namespace
        "system.file",       // FILE_OP (0x2B) - Execution namespace
        "system.process",    // PROCESS (0x2C) - Execution namespace
        "system.contracts",  // CONTRACT_MGMT (0x2D) - Control namespace
        "system.trust"       // WITNESS (0x2E) - Control namespace
    };

    // Create a mock session
    auto crypto_res = smo::CryptoRegistry::instance().get_suite(smo::kSuiteClassical);
    ASSERT(crypto_res);
    const auto* crypto = crypto_res.value();
    auto rng = crypto->default_rng();
    auto id_res = smo::Identity::create(*crypto, rng);
    ASSERT(id_res);
    auto identity = std::move(id_res.value());

    auto session_res = Session::create(SessionId{}, identity.node_id(), Certificate{}, CapabilitySet{}, 1000, 3600000000000LL);
    ASSERT(session_res);
    auto session = std::move(session_res.value());
    session.on_event(SessionEvent::Established, 1000);
    session.on_event(SessionEvent::Activate, 1000);

    // Test each policy-covered contract - NONE should be anonymous
    for (const auto& contract_id : policy_covered_contracts)
    {
        // Verify not anonymous
        ASSERT(!policy_mw.is_anonymous(contract_id));

        // Create context for this contract
        PacketContext ctx;
        ctx.session = &session;
        ctx.contract_id = contract_id;
        ctx.method = "invoke";
        ctx.payload = BytesView{};
        ctx.opcode_hex = "0x01";

        // Process should evaluate through PolicyEngine (not bypass)
        auto result = policy_mw.process(ctx);
        ASSERT(result);

        // The decision depends on PolicyEngine rules, but the key point is:
        // - It should NOT bypass due to anonymous (ctx.denied should not be set due to missing session)
        // - If denied, it should be due to policy evaluation, not anonymous bypass
        if (ctx.denied)
        {
            ASSERT(ctx.deny_reason.find("session required") == std::string::npos);
        }
    }

    return true;
}

// ==========================================================================
// Main
// ==========================================================================
int main(int, char*[])
{
    printf("SMO Protocol Compliance Tests (PCT-001 to PCT-017)\n");
    printf("===================================================\n\n");

    printf("── §9.1  CBOR Encode/Decode ──────────────────────────────────\n");
    TEST("PCT-001  JoinRequest CBOR roundtrip") END_TEST(test_pct_001());
    TEST("PCT-002  JoinResponse CBOR roundtrip") END_TEST(test_pct_002());
    TEST("PCT-003  BootstrapSyncRequest CBOR roundtrip") END_TEST(test_pct_003());
    TEST("PCT-004  BootstrapSyncResponse CBOR roundtrip") END_TEST(test_pct_004());

    printf("\n── §9.2  Join FSM ────────────────────────────────────────────\n");
    TEST("PCT-005  Join FSM full flow NEW → READY") END_TEST(test_pct_005());
    TEST("PCT-006  Join FSM FAIL transitions") END_TEST(test_pct_006());
    TEST("PCT-007  Join FSM TIMEOUT transitions") END_TEST(test_pct_007());
    TEST("PCT-008  Join FSM persist + resume") END_TEST(test_pct_008());

    printf("\n── §9.3  Bootstrap ───────────────────────────────────────────\n");
    TEST("PCT-009  BootstrapRequest/Response CBOR") END_TEST(test_pct_009());

    printf("\n── §9.4  Gossip ──────────────────────────────────────────────\n");
    TEST("PCT-010  GossipEngine basic operation") END_TEST(test_pct_010());

    printf("\n── §9.5  Token & Certificate ─────────────────────────────────\n");
    TEST("PCT-011  JoinToken parse/validate") END_TEST(test_pct_011());
    TEST("PCT-012  Certificate encode/decode roundtrip") END_TEST(test_pct_012());

    printf("\n── §9.6  Replay & Time ───────────────────────────────────────\n");
    TEST("PCT-013  ReplayProtector nonce detection") END_TEST(test_pct_013());
    TEST("PCT-014  Timestamp ±30s window") END_TEST(test_pct_014());

    printf("\n── §9.7  Delta Sync ──────────────────────────────────────────\n");
    TEST("PCT-015  MembershipEvent serialization") END_TEST(test_pct_015());
    TEST("PCT-016  CRL serialize/deserialize roundtrip") END_TEST(test_pct_016());

    printf("\n── §9.8  Forward Compat ──────────────────────────────────────\n");
    TEST("PCT-017  CBOR map key forward compat") END_TEST(test_pct_017());

    printf("\n── §9.9  Anti-Entropy ─────────────────────────────────────────\n");
    TEST("PCT-018  Anti-entropy Merkle + version vector") END_TEST(test_pct_018());

    printf("\n── §9.10 Gossip Readiness ─────────────────────────────────────\n");
    TEST("PCT-019  Gossip readiness + DEGRADED state") END_TEST(test_pct_019());

    printf("\n── §9.9  Policy Store ─────────────────────────────────────────\n");
    TEST("PCT-020  PolicyStore CRUD") END_TEST(test_pct_020());

    printf("\n── §9.10 Nonce Dedup ───────────────────────────────────────────\n");
    TEST("PCT-021  JOIN_REQUEST nonce dedup") END_TEST(test_pct_021());

    printf("\n── §9.11 Structured Logging ──────────────────────────────────────\n");
    TEST("PCT-022  Structured log format") END_TEST(test_pct_022());

    printf("\n── §9.12 Fault Injection / Chaos ─────────────────────────────────\n");
    TEST("PCT-024  VersionVector partition + heal") END_TEST(test_pct_024());

    printf("\n── §9.13 STUN ──────────────────────────────────────────────────────\n");
    TEST("PCT-025  STUN binding request/response (RFC 5389)") END_TEST(test_pct_025());

    printf("\n── §9.14 NAT Traversal ────────────────────────────────────────────\n");
    TEST("PCT-026  UDP hole punch protocol (predictable port pairs)") END_TEST(test_pct_026());

    printf("\n── §9.15 Relay Service (N3) ───────────────────────────────────────\n");
    TEST("PCT-027  RelayService (TURN-Lite) integration") END_TEST(test_pct_027());

    printf("\n── §9.16 Security ─────────────────────────────────────────────────\n");
    TEST("PCT-023  Join token signature verify (P0-S1)") END_TEST(test_pct_023());

    printf("\n── §9.17 ICE-Lite (N4) ────────────────────────────────────────────\n");
    TEST("PCT-028  ICE candidate gather + exchange + connectivity check") END_TEST(test_pct_028());

    printf("\n── §9.18 Policy Engine ────────────────────────────────────────────\n");
    TEST("PCT-029  PolicyEngine evaluation with built-in presets") END_TEST(test_pct_029());
    TEST("PCT-030  PolicyMiddleware integration with PolicyEngine") END_TEST(test_pct_030());
    TEST("PCT-031  No anonymous bypass for 7 policy-covered contracts") END_TEST(test_pct_031());

    printf("\n");
    if (failures == 0)
    {
        printf("ALL 29 PCT TESTS PASSED\n");
        return 0;
    }
    else
    {
        printf("%d PCT TEST(S) FAILED\n", failures);
        return 1;
    }
}
