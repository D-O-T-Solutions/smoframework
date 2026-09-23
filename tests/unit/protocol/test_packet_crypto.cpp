#include <packet/packet.h>
#include <packet/packet_crypto.hpp>
#include <packet/packet_route.hpp>

#include <cstdio>
#include <cstring>
#include <string>

using namespace smo;

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
            printf("\n    ASSERTION FAILED at %s:%d: %s == %s\n", __FILE__, __LINE__, #a, #b);                         \
            return false;                                                                                              \
        }                                                                                                              \
    } while (false)

// ---------------------------------------------------------------------------
static SessionCryptoContext make_ctx(uint8_t tx_seed, uint8_t rx_seed, uint8_t sid_seed)
{
    Bytes tx(32, tx_seed);
    Bytes rx(32, rx_seed);
    SessionId sid;
    sid.bytes.fill(sid_seed);
    return SessionCryptoContext::create(sid, BytesView(tx), BytesView(rx));
}

static Packet make_packet(const SessionId& sid, const std::string& payload)
{
    Packet p;
    p.header.protocol_version = kPacketProtocolVersion;
    p.header.suite_id = 1;
    p.header.ns = packet_route::kNamespaceExecution;
    p.header.message_id = 0x0201;  // EXEC in Execution namespace per RFC 0020
    p.header.session_id = sid.bytes;
    p.header.timestamp = 1234567890;
    p.payload.assign(payload.begin(), payload.end());
    return p;
}

// ==========================================================================
// Tests
// ==========================================================================
static bool test_seal_open_roundtrip_via_wire()
{
    auto sender = make_ctx(0xAA, 0xBB, 0x33);
    auto receiver = make_ctx(0xBB, 0xAA, 0x33);
    SessionId sid;
    sid.bytes.fill(0x33);

    Packet p = make_packet(sid, "hello-data");
    ASSERT(packet_seal_data(p, sender.packet_tx_key(), 1));
    ASSERT_EQ(p.header.nonce, 1U);
    ASSERT_EQ(p.header.payload_length, 10U);
    ASSERT_EQ(p.auth.size(), 16U); // AEAD tag
    ASSERT_EQ(p.payload.size(), 10U); // stream cipher: ct len == pt len

    std::vector<uint8_t> wire;
    ASSERT(packet_to_buffer(p, wire));
    ASSERT_EQ(wire.size(), 39U + 10U + 16U);

    auto parsed = packet_from_buffer(wire);
    ASSERT(parsed);

    Packet rx = std::move(parsed.value());
    ASSERT(packet_open_data(rx, receiver.packet_rx_key()));
    ASSERT(rx.auth.empty());
    ASSERT_EQ(rx.payload.size(), 10U);
    ASSERT(std::memcmp(rx.payload.data(), "hello-data", 10) == 0);

    return true;
}

static bool test_open_tampered_payload_fails()
{
    auto sender = make_ctx(0xAA, 0xBB, 0x33);
    auto receiver = make_ctx(0xBB, 0xAA, 0x33);
    SessionId sid;
    sid.bytes.fill(0x33);

    Packet p = make_packet(sid, "secret-payload");
    ASSERT(packet_seal_data(p, sender.packet_tx_key(), 7));

    Packet rx = p;
    rx.payload[0] = static_cast<uint8_t>(rx.payload[0] ^ 0xFF);
    ASSERT(!packet_open_data(rx, receiver.packet_rx_key()));
    // Failure must not mutate the packet.
    ASSERT_EQ(rx.payload.size(), p.payload.size());
    ASSERT_EQ(rx.payload[0], static_cast<uint8_t>(p.payload[0] ^ 0xFF));

    return true;
}

static bool test_open_tampered_header_aad_fails()
{
    auto sender = make_ctx(0xAA, 0xBB, 0x33);
    auto receiver = make_ctx(0xBB, 0xAA, 0x33);
    SessionId sid;
    sid.bytes.fill(0x33);

    Packet p = make_packet(sid, "aad-bound");
    ASSERT(packet_seal_data(p, sender.packet_tx_key(), 7));

    // Header is the AAD — flipping timestamp must break authentication.
    Packet ts_tampered = p;
    ts_tampered.header.timestamp += 1;
    ASSERT(!packet_open_data(ts_tampered, receiver.packet_rx_key()));

    // message_id is likewise part of the canonical header/AAD.
    Packet mid_tampered = p;
    mid_tampered.header.message_id = static_cast<uint16_t>(Opcode::PUT);
    ASSERT(!packet_open_data(mid_tampered, receiver.packet_rx_key()));

    return true;
}

static bool test_open_wrong_key_fails()
{
    SessionId sid;
    sid.bytes.fill(0x33);

    auto sender = make_ctx(0xAA, 0xBB, 0x33);
    auto receiver = make_ctx(0xBB, 0xAA, 0x33);
    auto other = make_ctx(0xCC, 0xDD, 0x33);

    Packet p = make_packet(sid, "key-bound");
    ASSERT(packet_seal_data(p, sender.packet_tx_key(), 3));

    Packet rx = p;
    ASSERT(!packet_open_data(rx, other.packet_rx_key()));

    // Correct key still opens.
    Packet ok = p;
    ASSERT(packet_open_data(ok, receiver.packet_rx_key()));
    ASSERT(std::memcmp(ok.payload.data(), "key-bound", 9) == 0);

    return true;
}

static bool test_seal_rejects_zero_sequence_and_zero_session()
{
    auto ctx = make_ctx(0x11, 0x22, 0x33);

    SessionId sid;
    sid.bytes.fill(0x33);
    Packet p = make_packet(sid, "x");
    ASSERT(!packet_seal_data(p, ctx.packet_tx_key(), 0)); // zero sequence

    SessionId zero_sid;
    Packet p2 = make_packet(zero_sid, "x");
    ASSERT(!packet_seal_data(p2, ctx.packet_tx_key(), 5)); // zero session_id

    return true;
}

static bool test_open_rejects_bad_tag_length()
{
    auto sender = make_ctx(0xAA, 0xBB, 0x33);
    auto receiver = make_ctx(0xBB, 0xAA, 0x33);
    SessionId sid;
    sid.bytes.fill(0x33);

    Packet p = make_packet(sid, "tag-len");
    ASSERT(packet_seal_data(p, sender.packet_tx_key(), 4));

    Packet short_tag = p;
    short_tag.auth.pop_back();
    ASSERT(!packet_open_data(short_tag, receiver.packet_rx_key()));

    Packet long_tag = p;
    long_tag.auth.push_back(0x00);
    ASSERT(!packet_open_data(long_tag, receiver.packet_rx_key()));

    return true;
}

static bool test_derive_aead_nonce()
{
    std::array<uint8_t, 16> sid;
    sid.fill(0x33);

    Bytes n1 = derive_aead_nonce(BytesView(sid.data(), sid.size()), 1024);
    Bytes n2 = derive_aead_nonce(BytesView(sid.data(), sid.size()), 1024);
    Bytes n3 = derive_aead_nonce(BytesView(sid.data(), sid.size()), 1025);

    ASSERT_EQ(n1.size(), 24U);
    ASSERT(n1 == n2); // deterministic → both ends derive the same nonce
    ASSERT(n1 != n3); // sequence is bound into the nonce

    std::array<uint8_t, 16> sid2;
    sid2.fill(0x44);
    Bytes n4 = derive_aead_nonce(BytesView(sid2.data(), sid2.size()), 1024);
    ASSERT(n1 != n4); // session_id is bound into the nonce

    return true;
}

// ==========================================================================
// Main
// ==========================================================================
int main(int, char*[])
{
    printf("SMO Packet Crypto (P4) — Unit Tests\n");
    printf("===================================\n\n");

    TEST("seal→open roundtrip via wire") END_TEST(test_seal_open_roundtrip_via_wire());
    TEST("open tampered payload fails") END_TEST(test_open_tampered_payload_fails());
    TEST("open tampered header (AAD) fails") END_TEST(test_open_tampered_header_aad_fails());
    TEST("open wrong key fails") END_TEST(test_open_wrong_key_fails());
    TEST("seal rejects zero seq / zero session") END_TEST(test_seal_rejects_zero_sequence_and_zero_session());
    TEST("open rejects bad tag length") END_TEST(test_open_rejects_bad_tag_length());
    TEST("derive_aead_nonce deterministic + bound") END_TEST(test_derive_aead_nonce());

    printf("\n");
    if (failures == 0)
    {
        printf("ALL TESTS PASSED\n");
        return 0;
    }
    printf("%d TEST(S) FAILED\n", failures);
    return 1;
}
