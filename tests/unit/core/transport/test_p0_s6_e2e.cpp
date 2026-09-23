#include <transport/secure_session.hpp>
#include <certificate/certificate.hpp>
#include <crypto/impl.hpp>
#include <providers/suite1_classical/suite1_classical_provider.hpp>
#include <join/join_protocol.hpp>
#include <join/join_service.hpp>
#include <authority/authority.hpp>
#include <mesh/mesh_manager.hpp>
#include <enroll/join_token.hpp>
#include <identity/identity.hpp>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <memory>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

using namespace smo;

// ---------------------------------------------------------------------------
// Minimal test runner
// ---------------------------------------------------------------------------
static int failures = 0;

#define TEST(name)                                                                                                     \
    do                                                                                                                 \
    {                                                                                                                  \
        printf("  TEST %-60s ... ", name);                                                                             \
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static const CryptoProvider& suite1()
{
    static bool registered = []() {
        providers::register_suite1_classical();
        return true;
    }();
    (void)registered;
    return providers::get_suite1_classical_provider();
}

struct KeyPair
{
    Bytes pk;
    Bytes sk;
};

static KeyPair make_identity()
{
    auto rng = suite1().default_rng();
    auto kp = suite1().signer.generate_keypair(rng);
    KeyPair out;
    if (kp)
    {
        out.pk = std::move(kp.value().public_key);
        out.sk = std::move(kp.value().secret_key);
    }
    return out;
}

static Bytes make_cert_blob(BytesView subject_pk, const std::string& mesh, uint64_t epoch = 1)
{
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();

    Certificate cert;
    cert.mesh_id.assign(mesh.begin(), mesh.end());
    cert.subject_pubkey.assign(subject_pk.begin(), subject_pk.end());
    cert.role = Role::Member;
    cert.epoch = epoch;
    cert.not_before = now - 60;
    cert.not_after = now + 3600;
    return cert.serialize();
}

static Bytes hex_to_bytes(const std::string& hex)
{
    Bytes out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2)
    {
        char buf[3] = {hex[i], hex[i + 1], 0};
        out.push_back(static_cast<uint8_t>(std::strtoul(buf, nullptr, 16)));
    }
    return out;
}

// Bring up a client/server pair over a socketpair and complete the handshake.
struct SessionPair
{
    int fds[2] = {-1, -1};
    std::unique_ptr<SecureSession> client;
    std::unique_ptr<SecureSession> server;
    bool client_ok = false;
    bool server_ok = false;

    ~SessionPair()
    {
        if (fds[0] >= 0)
            ::close(fds[0]);
        if (fds[1] >= 0)
            ::close(fds[1]);
    }

    bool establish(uint64_t current_epoch = 1)
    {
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
            return false;

        const std::string mesh = "p0-s6-test-mesh";
        KeyPair client_id = make_identity();
        KeyPair server_id = make_identity();
        if (client_id.pk.empty() || server_id.pk.empty())
            return false;

        SecureSession::Config client_cfg;
        client_cfg.role = SecureSession::Role::Client;
        client_cfg.client_cert = make_cert_blob(client_id.pk, mesh, current_epoch);
        client_cfg.client_signing_secret_key = client_id.sk;
        client_cfg.mesh_id = mesh;
        client_cfg.current_epoch = current_epoch;

        SecureSession::Config server_cfg;
        server_cfg.role = SecureSession::Role::Server;
        server_cfg.server_cert = make_cert_blob(server_id.pk, mesh, current_epoch);
        server_cfg.signing_secret_key = server_id.sk;
        server_cfg.mesh_id = mesh;
        server_cfg.current_epoch = current_epoch;

        client = std::make_unique<SecureSession>(fds[0], std::move(client_cfg), suite1());
        server = std::make_unique<SecureSession>(fds[1], std::move(server_cfg), suite1());

        std::thread t([this]() { server_ok = static_cast<bool>(server->handshake()); });
        client_ok = static_cast<bool>(client->handshake());
        t.join();

        return client_ok && server_ok;
    }
};

// Helper to create a test mesh with authority
static bool setup_test_mesh(const std::string& test_name,
                            const std::string& base_data_dir,
                            MeshManager& mesh_mgr,
                            authority::MeshAuthority& authority,
                            std::unique_ptr<join::JoinService>& join_svc,
                            std::shared_ptr<MeshContext>& mesh_ctx_out,
                            std::string& mesh_id_out)
{
    MeshConfig mesh_cfg;
    mesh_cfg.display_name = test_name;
    mesh_cfg.authority_pubkey = bytes_to_hex(make_identity().pk);
    mesh_cfg.root_pubkey = mesh_cfg.authority_pubkey;
    mesh_cfg.cipher_suite_id = kSuitePurePQC;
    mesh_cfg.bootstrap_endpoints = {"127.0.0.1:7777"};
    auto mm_create = mesh_mgr.create_mesh(mesh_cfg, test_name);
    if (!mm_create)
    {
        printf("\n    create_mesh failed: %s\n", mm_create.error().message.c_str());
        return false;
    }

    auto mesh_ctx = mesh_mgr.get_mesh_by_name(test_name);
    if (!mesh_ctx)
    {
        printf("\n    get_mesh_by_name failed\n");
        return false;
    }

    auto rng = suite1().default_rng();
    auto auth_init = authority.init(suite1(), rng);
    if (!auth_init)
    {
        printf("\n    authority init failed: %s\n", auth_init.error().message.c_str());
        return false;
    }

    authority::MeshAuthority::Config auth_cfg;
    auth_cfg.data_dir = base_data_dir + "/meshes/" + test_name;
    auth_cfg.mesh_id = mesh_ctx.value()->config.mesh_id;
    auth_cfg.registry_path = auth_cfg.data_dir + "/registry.db";

    // Ensure data directory exists
    std::filesystem::create_directories(auth_cfg.data_dir);

    // Create mesh keys
    std::string root_pubkey_out;
    auto create_keys = authority.create_mesh_keys(auth_cfg, suite1(), rng, root_pubkey_out);
    if (!create_keys)
    {
        printf("\n    create_mesh_keys failed: %s\n", create_keys.error().message.c_str());
        return false;
    }
    auto auth_open = authority.open(auth_cfg);
    if (!auth_open)
    {
        printf("\n    authority open failed: %s\n", auth_open.error().message.c_str());
        return false;
    }

    join_svc = std::make_unique<join::JoinService>(mesh_mgr, authority, join::JoinService::Config{auth_cfg.data_dir});
    auto js_init = join_svc->initialize();
    if (!js_init)
    {
        printf("\n    JoinService init failed: %s\n", js_init.error().message.c_str());
        return false;
    }

    mesh_ctx_out = mesh_ctx.value();
    mesh_id_out = mesh_ctx.value()->config.mesh_id;
    return true;
}

// ---------------------------------------------------------------------------
// C1.1: JOIN_REQUEST handler - verify token -> issue cert
// ---------------------------------------------------------------------------

static bool test_join_request_verify_token_issue_cert()
{
    // Create a test mesh authority
    MeshManager::Config mm_cfg;
    mm_cfg.base_data_dir = "/tmp/smo_p0_s6_test_" + std::to_string(getpid());
    MeshManager mesh_mgr(mm_cfg);
    auto mm_init = mesh_mgr.initialize();
    if (!mm_init)
    {
        printf("\n    MeshManager init failed: %s\n", mm_init.error().message.c_str());
        return false;
    }

    authority::MeshAuthority authority;
    std::unique_ptr<join::JoinService> join_svc;
    std::shared_ptr<MeshContext> mesh_ctx;
    std::string mesh_id;

    if (!setup_test_mesh("p0-s6-test", mm_cfg.base_data_dir, mesh_mgr, authority, join_svc, mesh_ctx, mesh_id))
        return false;

    // Generate a v2 join token
    auto rng = suite1().default_rng();
    enroll::Admission admission;
    admission.role = "Member";
    admission.profile = "server";

    auto token_result = enroll::generate_token(
        mesh_id,
        1, // mesh_epoch
        static_cast<int>(kSuitePurePQC),
        mesh_ctx->config.bootstrap_endpoints,
        admission,
        0, // no expiry
        "authority:" + bytes_to_hex(authority.authority_public_key()).substr(0, 16),
        suite1().signer,
        authority.authority_public_key(),
        rng
    );

    if (!token_result)
    {
        printf("\n    generate_token failed: %s\n", token_result.error().message.c_str());
        return false;
    }

    const auto& token = token_result.value();
    std::string token_wire = enroll::encode_token_wire(token);

    // Parse token back (simulates JOIN_REQUEST handler)
    auto parsed = enroll::parse_token(token_wire);
    ASSERT(parsed);
    ASSERT(parsed.value().mesh_id == mesh_id);

    // Verify token signature
    auto validate = enroll::validate_token(parsed.value(), suite1().signer, authority.authority_public_key(), suite1().hash);
    ASSERT(validate);

    // Create a CSR for a new node
    KeyPair new_node = make_identity();
    CertificateSigningRequest csr;
    csr.new_public_key = new_node.pk;
    csr.mesh_id.assign(mesh_id.begin(), mesh_id.end());
    csr.display_name = "test-node";
    csr.platform = "linux";
    csr.version = "0.1.0";
    csr.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count();
    csr.old_cert_hash = Bytes(32, 0);

    auto csr_body = csr.serialize_body();
    auto sig_result = suite1().signer.sign(csr_body, new_node.sk, rng);
    ASSERT(sig_result);
    csr.signature = std::move(sig_result.value());

    // Build JoinRequest
    join::JoinRequest req;
    req.token = token_wire;
    req.csr_pem = bytes_to_hex(csr.serialize());
    req.timestamp = csr.timestamp;
    req.nonce.fill(0);
    rng.fill(BytesMutView(req.nonce.data(), req.nonce.size()));

    auto hash_result = suite1().hash.hash(BytesView(reinterpret_cast<const uint8_t*>(req.csr_pem.data()), req.csr_pem.size()));
    ASSERT(hash_result);
    req.csr_hash = std::move(hash_result.value());

    {
        Bytes sig_payload;
        sig_payload.insert(sig_payload.end(), req.token.begin(), req.token.end());
        sig_payload.push_back(static_cast<uint8_t>((req.timestamp >> 56) & 0xFF));
        sig_payload.push_back(static_cast<uint8_t>((req.timestamp >> 48) & 0xFF));
        sig_payload.push_back(static_cast<uint8_t>((req.timestamp >> 40) & 0xFF));
        sig_payload.push_back(static_cast<uint8_t>((req.timestamp >> 32) & 0xFF));
        sig_payload.push_back(static_cast<uint8_t>((req.timestamp >> 24) & 0xFF));
        sig_payload.push_back(static_cast<uint8_t>((req.timestamp >> 16) & 0xFF));
        sig_payload.push_back(static_cast<uint8_t>((req.timestamp >> 8) & 0xFF));
        sig_payload.push_back(static_cast<uint8_t>(req.timestamp & 0xFF));
        sig_payload.insert(sig_payload.end(), req.nonce.begin(), req.nonce.end());
        sig_payload.insert(sig_payload.end(), req.csr_hash.begin(), req.csr_hash.end());
        auto sig_req_result = suite1().signer.sign(BytesView(sig_payload), new_node.sk, rng);
        ASSERT(sig_req_result);
        req.request_signature = std::move(sig_req_result.value());
    }

    // Process JOIN_REQUEST - this is C1.1
    auto resp_result = join_svc->handle_join_request(req);
    ASSERT(resp_result);
    ASSERT(!resp_result.value().certificate_pem.empty());
    ASSERT(resp_result.value().mesh_id == mesh_id);
    ASSERT(!resp_result.value().bootstrap_ticket.empty());

    return true;
}

// ---------------------------------------------------------------------------
// C1.2: SecureSession handshake requires cert + sig (no empty exception)
// ---------------------------------------------------------------------------

static bool test_secure_session_requires_cert_sig()
{
    // Test that verify_peer_certificate fails with empty cert
    // Use test accessor to access private method
    SecureSession::Config cfg;
    cfg.role = SecureSession::Role::Server;
    cfg.server_cert = make_cert_blob(make_identity().pk, "test-mesh", 1);
    cfg.signing_secret_key = make_identity().sk;
    cfg.mesh_id = "test-mesh";
    cfg.current_epoch = 1;

    // Create a dummy session (fd=-1 won't be used for this test)
    SecureSession server(-1, std::move(cfg), suite1());

    // Test with empty cert - should fail
    Bytes empty_cert;
    auto result = server.test_verify_peer_certificate(BytesView(empty_cert));
    ASSERT(!result);

    // Test with valid cert - should pass
    Bytes valid_cert = make_cert_blob(make_identity().pk, "test-mesh", 1);
    result = server.test_verify_peer_certificate(BytesView(valid_cert));
    ASSERT(result);

    return true;
}

static bool test_secure_session_handshake_with_valid_certs()
{
    SessionPair p;
    ASSERT(p.establish(1)); // current_epoch = 1
    ASSERT(p.client->is_secure());
    ASSERT(p.server->is_secure());
    return true;
}

// ---------------------------------------------------------------------------
// C1.3: Capability Epoch - epoch-based revocation replaces CRL
// ---------------------------------------------------------------------------

static bool test_capability_epoch_revocation()
{
    // Test that verify_peer_certificate rejects cert with epoch < current_epoch
    // Use test accessor to access private method
    SecureSession::Config cfg;
    cfg.role = SecureSession::Role::Server;
    cfg.server_cert = make_cert_blob(make_identity().pk, "test-mesh", 1);
    cfg.signing_secret_key = make_identity().sk;
    cfg.mesh_id = "test-mesh";
    cfg.current_epoch = 2; // current_epoch = 2

    SecureSession server(-1, std::move(cfg), suite1());

    // Test with cert epoch = 1 (< current_epoch 2) - should fail
    Bytes old_cert = make_cert_blob(make_identity().pk, "test-mesh", 1);
    auto result = server.test_verify_peer_certificate(BytesView(old_cert));
    ASSERT(!result);

    // Test with cert epoch = 2 (== current_epoch) - should pass
    Bytes current_cert = make_cert_blob(make_identity().pk, "test-mesh", 2);
    result = server.test_verify_peer_certificate(BytesView(current_cert));
    ASSERT(result);

    // Test with cert epoch = 3 (> current_epoch) - should pass
    Bytes future_cert = make_cert_blob(make_identity().pk, "test-mesh", 3);
    result = server.test_verify_peer_certificate(BytesView(future_cert));
    ASSERT(result);

    // Now test with matching epoch handshake
    SessionPair p2;
    ASSERT(p2.establish(2)); // both at epoch 2
    ASSERT(p2.client->is_secure());
    ASSERT(p2.server->is_secure());

    return true;
}

// ---------------------------------------------------------------------------
// C1.4: E2E - fresh node -> token verify -> cert issue -> SecureSession handshake
// ---------------------------------------------------------------------------

static bool test_e2e_fresh_node_join_session()
{
    // This test simulates the full flow:
    // 1. Fresh node gets join token
    // 2. Node verifies token
    // 3. Node creates CSR, sends JOIN_REQUEST
    // 4. Authority verifies token, issues cert
    // 5. Node receives cert, saves it
    // 6. Node connects to mesh and does SecureSession handshake with cert

    MeshManager::Config mm_cfg;
    mm_cfg.base_data_dir = "/tmp/smo_p0_s6_e2e_test_" + std::to_string(getpid());
    MeshManager mesh_mgr(mm_cfg);
    auto mm_init = mesh_mgr.initialize();
    if (!mm_init)
    {
        printf("\n    MeshManager init failed: %s\n", mm_init.error().message.c_str());
        return false;
    }

    authority::MeshAuthority authority;
    std::unique_ptr<join::JoinService> join_svc;
    std::shared_ptr<MeshContext> mesh_ctx;
    std::string mesh_id;

    if (!setup_test_mesh("e2e-test", mm_cfg.base_data_dir, mesh_mgr, authority, join_svc, mesh_ctx, mesh_id))
        return false;

    auto rng = suite1().default_rng();

    // Generate join token
    enroll::Admission admission;
    admission.role = "Member";
    admission.profile = "server";

    auto token_result = enroll::generate_token(
        mesh_id,
        1, // mesh_epoch
        static_cast<int>(kSuitePurePQC),
        mesh_ctx->config.bootstrap_endpoints,
        admission,
        0,
        "authority:" + bytes_to_hex(authority.authority_public_key()).substr(0, 16),
        suite1().signer,
        authority.authority_public_key(),
        rng
    );

    if (!token_result)
    {
        printf("\n    generate_token failed: %s\n", token_result.error().message.c_str());
        return false;
    }

    const auto& token = token_result.value();
    std::string token_wire = enroll::encode_token_wire(token);

    // --- Node side: parse and verify token ---
    auto parsed = enroll::parse_token(token_wire);
    ASSERT(parsed);

    auto validate = enroll::validate_token(parsed.value(), suite1().signer, authority.authority_public_key(), suite1().hash);
    ASSERT(validate);

    // --- Node side: create CSR and send JOIN_REQUEST ---
    KeyPair new_node = make_identity();
    CertificateSigningRequest csr;
    csr.new_public_key = new_node.pk;
    csr.mesh_id.assign(mesh_id.begin(), mesh_id.end());
    csr.display_name = "e2e-test-node";
    csr.platform = "linux";
    csr.version = "0.1.0";
    csr.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count();
    csr.old_cert_hash = Bytes(32, 0);

    auto csr_body = csr.serialize_body();
    auto sig_result = suite1().signer.sign(csr_body, new_node.sk, rng);
    ASSERT(sig_result);
    csr.signature = std::move(sig_result.value());

    join::JoinRequest req;
    req.token = token_wire;
    req.csr_pem = bytes_to_hex(csr.serialize());
    req.timestamp = csr.timestamp;
    req.nonce.fill(0);
    rng.fill(BytesMutView(req.nonce.data(), req.nonce.size()));

    auto hash_result = suite1().hash.hash(BytesView(reinterpret_cast<const uint8_t*>(req.csr_pem.data()), req.csr_pem.size()));
    ASSERT(hash_result);
    req.csr_hash = std::move(hash_result.value());

    {
        Bytes sig_payload;
        sig_payload.insert(sig_payload.end(), req.token.begin(), req.token.end());
        sig_payload.push_back(static_cast<uint8_t>((req.timestamp >> 56) & 0xFF));
        sig_payload.push_back(static_cast<uint8_t>((req.timestamp >> 48) & 0xFF));
        sig_payload.push_back(static_cast<uint8_t>((req.timestamp >> 40) & 0xFF));
        sig_payload.push_back(static_cast<uint8_t>((req.timestamp >> 32) & 0xFF));
        sig_payload.push_back(static_cast<uint8_t>((req.timestamp >> 24) & 0xFF));
        sig_payload.push_back(static_cast<uint8_t>((req.timestamp >> 16) & 0xFF));
        sig_payload.push_back(static_cast<uint8_t>((req.timestamp >> 8) & 0xFF));
        sig_payload.push_back(static_cast<uint8_t>(req.timestamp & 0xFF));
        sig_payload.insert(sig_payload.end(), req.nonce.begin(), req.nonce.end());
        sig_payload.insert(sig_payload.end(), req.csr_hash.begin(), req.csr_hash.end());
        auto sig_req_result = suite1().signer.sign(BytesView(sig_payload), new_node.sk, rng);
        ASSERT(sig_req_result);
        req.request_signature = std::move(sig_req_result.value());
    }

    // --- Authority side: process JOIN_REQUEST ---
    auto resp_result = join_svc->handle_join_request(req);
    ASSERT(resp_result);
    auto resp = resp_result.value();
    ASSERT(!resp.certificate_pem.empty());
    ASSERT(resp.mesh_id == mesh_id);

    // --- Node side: verify received certificate ---
    Bytes cert_bytes = hex_to_bytes(resp.certificate_pem);
    auto cert_result = Certificate::deserialize(cert_bytes);
    ASSERT(cert_result);
    auto cert = cert_result.value();

    // Verify cert signature
    auto verify_cert = cert.verify(suite1().signer);
    ASSERT(verify_cert && verify_cert.value());

    // Check epoch matches
    ASSERT(cert.epoch == 1);

    // --- Node side: SecureSession handshake with issued cert ---
    int fds[2] = {-1, -1};
    ASSERT(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    SecureSession::Config client_cfg;
    client_cfg.role = SecureSession::Role::Client;
    client_cfg.client_cert = cert_bytes;
    client_cfg.client_signing_secret_key = new_node.sk;
    client_cfg.mesh_id = mesh_id;
    client_cfg.current_epoch = 1; // from token.mesh_epoch

    SecureSession::Config server_cfg;
    server_cfg.role = SecureSession::Role::Server;
    server_cfg.server_cert = make_cert_blob(authority.authority_public_key(), mesh_id, 1);
    server_cfg.signing_secret_key = Bytes(authority.authority_public_key().begin(), authority.authority_public_key().end());
    server_cfg.mesh_id = mesh_id;
    server_cfg.current_epoch = 1;

    SecureSession client(fds[0], std::move(client_cfg), suite1());
    SecureSession server(fds[1], std::move(server_cfg), suite1());

    std::thread t([&server]() { server.handshake(); });
    auto client_ok = client.handshake();
    t.join();

    ASSERT(client_ok);
    ASSERT(client.is_secure());
    ASSERT(client.crypto_context().valid());

    ::close(fds[0]);
    ::close(fds[1]);

    return true;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

int main(int, char*[])
{
    printf("P0-S6 E2E Tests — Session Crypto Handshake + Mesh Auth Separation\n");
    printf("=================================================================\n\n");

    // C1.1
    TEST("C1.1 JOIN_REQUEST verify token -> issue cert") END_TEST(test_join_request_verify_token_issue_cert());

    // C1.2
    TEST("C1.2 SecureSession rejects empty cert") END_TEST(test_secure_session_requires_cert_sig());
    TEST("C1.2 SecureSession handshake with valid certs") END_TEST(test_secure_session_handshake_with_valid_certs());

    // C1.3
    TEST("C1.3 Capability Epoch revocation (epoch < current_epoch rejected)") END_TEST(test_capability_epoch_revocation());

    // C1.4
    TEST("C1.4 E2E fresh node -> token verify -> cert issue -> SecureSession") END_TEST(test_e2e_fresh_node_join_session());

    printf("\n");
    if (failures == 0)
    {
        printf("ALL P0-S6 TESTS PASSED\n");
        return 0;
    }
    else
    {
        printf("%d TEST(S) FAILED\n", failures);
        return 1;
    }
}