#include <transport/secure_session.hpp>
#include <certificate/certificate.hpp>
#include <crypto/impl.hpp>
#include <providers/suite1_classical/suite1_classical_provider.hpp>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

using namespace smo;

// ---------------------------------------------------------------------------
// Minimal test runner (mirrors tests/unit/core/session/test_session_security.cpp)
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
    RngRef rng = suite1().default_rng();
    auto kp = suite1().signer.generate_keypair(rng);
    KeyPair out;
    if (kp)
    {
        out.pk = std::move(kp.value().public_key);
        out.sk = std::move(kp.value().secret_key);
    }
    return out;
}

static Bytes make_cert_blob(BytesView subject_pk, const std::string& mesh)
{
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();

    Certificate cert;
    cert.mesh_id.assign(mesh.begin(), mesh.end());
    cert.subject_pubkey.assign(subject_pk.begin(), subject_pk.end());
    cert.role = Role::Member;
    cert.epoch = 1;
    cert.not_before = now - 60;
    cert.not_after = now + 3600;
    return cert.serialize();
}

static bool read_exact(int fd, uint8_t* buf, size_t n)
{
    size_t off = 0;
    while (off < n)
    {
        ssize_t r = ::read(fd, buf + off, n - off);
        if (r <= 0)
            return false;
        off += static_cast<size_t>(r);
    }
    return true;
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

    bool establish()
    {
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
            return false;

        const std::string mesh = "p2-mesh";
        KeyPair client_id = make_identity();
        KeyPair server_id = make_identity();
        if (client_id.pk.empty() || server_id.pk.empty())
            return false;

        SecureSession::Config client_cfg;
        client_cfg.role = SecureSession::Role::Client;
        client_cfg.client_cert = make_cert_blob(client_id.pk, mesh);
        client_cfg.client_signing_secret_key = client_id.sk;
        client_cfg.mesh_id = mesh;

        SecureSession::Config server_cfg;
        server_cfg.role = SecureSession::Role::Server;
        server_cfg.server_cert = make_cert_blob(server_id.pk, mesh);
        server_cfg.signing_secret_key = server_id.sk;
        server_cfg.mesh_id = mesh;

        client = std::make_unique<SecureSession>(fds[0], std::move(client_cfg), suite1());
        server = std::make_unique<SecureSession>(fds[1], std::move(server_cfg), suite1());

        std::thread t([this]() { server_ok = static_cast<bool>(server->handshake()); });
        client_ok = static_cast<bool>(client->handshake());
        t.join();

        return client_ok && server_ok;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

static bool test_handshake_establishes_both_sides()
{
    SessionPair p;
    ASSERT(p.establish());
    ASSERT(p.client->is_secure());
    ASSERT(p.server->is_secure());
    ASSERT(p.client->crypto_context().valid());
    ASSERT(p.server->crypto_context().valid());
    return true;
}

static bool test_shared_session_id()
{
    SessionPair p;
    ASSERT(p.establish());
    const SessionId& cid = p.client->crypto_context().session_id();
    const SessionId& sid = p.server->crypto_context().session_id();
    ASSERT(!cid.is_zero());
    ASSERT(cid == sid);
    return true;
}

static bool test_key_orientation()
{
    SessionPair p;
    ASSERT(p.establish());

    const auto& ct = p.client->crypto_context().packet_tx_key();
    const auto& cr = p.client->crypto_context().packet_rx_key();
    const auto& st = p.server->crypto_context().packet_tx_key();
    const auto& sr = p.server->crypto_context().packet_rx_key();

    // Cross directions agree...
    ASSERT(ct.matches(sr));
    ASSERT(st.matches(cr));
    ASSERT(sr.matches(ct));
    ASSERT(cr.matches(st));

    // ...but a session's own TX/RX are distinct.
    ASSERT(!ct.matches(cr));
    ASSERT(!st.matches(sr));
    return true;
}

static bool test_cbor_send_recv_still_aead()
{
    SessionPair p;
    ASSERT(p.establish());

    const Bytes c2s = {'h', 'e', 'l', 'l', 'o'};
    ASSERT(p.client->send(BytesView(c2s)));
    auto r1 = p.server->recv();
    ASSERT(static_cast<bool>(r1));
    ASSERT(r1.value() == c2s);

    const Bytes s2c = {'w', 'o', 'r', 'l', 'd'};
    ASSERT(p.server->send(BytesView(s2c)));
    auto r2 = p.client->recv();
    ASSERT(static_cast<bool>(r2));
    ASSERT(r2.value() == s2c);
    return true;
}

static bool test_send_recv_framed_roundtrip()
{
    SessionPair p;
    ASSERT(p.establish());

    const Bytes payload = {'p', 'a', 'c', 'k', 'e', 't'};
    ASSERT(p.client->send_framed(BytesView(payload)));
    auto r = p.server->recv_framed();
    ASSERT(static_cast<bool>(r));
    ASSERT(r.value() == payload);
    return true;
}

static bool test_send_framed_is_plaintext()
{
    SessionPair p;
    ASSERT(p.establish());

    const Bytes payload = {'n', 'o', 't', 'e', 'n', 'c'};
    ASSERT(p.client->send_framed(BytesView(payload)));

    // Read the raw transport bytes on the far side: framing only, no AEAD.
    uint8_t hdr[4];
    ASSERT(read_exact(p.server->fd(), hdr, 4));
    const uint32_t len = (static_cast<uint32_t>(hdr[0]) << 24) | (static_cast<uint32_t>(hdr[1]) << 16) |
                         (static_cast<uint32_t>(hdr[2]) << 8) | static_cast<uint32_t>(hdr[3]);
    ASSERT(len == payload.size());

    Bytes raw(len);
    ASSERT(read_exact(p.server->fd(), raw.data(), len));
    ASSERT(raw == payload);
    return true;
}

static bool test_before_handshake_rejected()
{
    int fds[2] = {-1, -1};
    ASSERT(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    SecureSession::Config cfg;
    cfg.role = SecureSession::Role::Client;
    SecureSession s(fds[0], std::move(cfg), suite1());

    ASSERT(!s.crypto_context().valid());
    ASSERT(!s.send(BytesView{}));
    ASSERT(!s.send_framed(BytesView{}));

    ::close(fds[0]);
    ::close(fds[1]);
    return true;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

int main(int, char*[])
{
    printf("SMO SecureSession — P2 Tests\n");
    printf("============================\n\n");

    TEST("Handshake establishes both sides") END_TEST(test_handshake_establishes_both_sides());
    TEST("Shared session_id across endpoints") END_TEST(test_shared_session_id());
    TEST("Packet key orientation (tx/rx)") END_TEST(test_key_orientation());
    TEST("CBOR send/recv still AEAD") END_TEST(test_cbor_send_recv_still_aead());
    TEST("send_framed/recv_framed roundtrip") END_TEST(test_send_recv_framed_roundtrip());
    TEST("send_framed is framing-only") END_TEST(test_send_framed_is_plaintext());
    TEST("Rejected before handshake") END_TEST(test_before_handshake_rejected());

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
