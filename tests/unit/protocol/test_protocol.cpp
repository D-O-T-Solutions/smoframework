#include <packet/packet.h>
#include <packet/packet_route.hpp>
#include <signing/signing.h>
#include <encryption/encryption.h>
#include <replay/replay.h>
#include <schema/schema.h>

#include <cstdio>
#include <cstring>

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
// Tests — Packet (RFC 0019 39B canonical)
// ==========================================================================
namespace {

// Build a valid packet wire buffer via public serializer.
std::vector<uint8_t> make_valid_wire(uint8_t ns, uint16_t message_id, uint8_t suite_id,
                                     size_t payload_len, size_t auth_len)
{
    Packet pkt;
    pkt.header.protocol_version = kPacketProtocolVersion;
    pkt.header.suite_id = suite_id;
    pkt.header.ns = ns;
    pkt.header.message_id = message_id;
    pkt.session_id().fill(0xA5);
    pkt.header.timestamp = 1234567890;
    pkt.header.nonce = 42;
    pkt.payload.assign(payload_len, 0x11);
    pkt.auth.assign(auth_len, 0x22);

    std::vector<uint8_t> out;
    auto res = packet_to_buffer(pkt, out);
    if (!res)
        return {};
    return out;
}

// Build an INVALID packet wire buffer manually (bypassing packet_to_buffer validation).
std::vector<uint8_t> make_invalid_wire(uint8_t ns, uint16_t message_id, uint8_t suite_id,
                                       size_t payload_len, size_t auth_len)
{
    PacketHeader hdr;
    hdr.protocol_version = kPacketProtocolVersion;
    hdr.suite_id = suite_id;
    hdr.ns = ns;
    hdr.message_id = message_id;
    hdr.session_id.fill(0xA5);
    hdr.timestamp = 1234567890;
    hdr.nonce = 42;
    hdr.payload_length = static_cast<uint16_t>(payload_len);

    auto header_bytes = serialize_packet_header(hdr);

    std::vector<uint8_t> out;
    out.reserve(39 + payload_len + auth_len);
    out.insert(out.end(), header_bytes.begin(), header_bytes.end());
    out.insert(out.end(), payload_len, 0x11);
    out.insert(out.end(), auth_len, 0x22);
    return out;
}

} // anonymous namespace

static bool test_packet_roundtrip_39b()
{
    Packet pkt;
    pkt.header.protocol_version = kPacketProtocolVersion;
    pkt.header.suite_id = 1;
    pkt.header.ns = packet_route::kNamespaceDiscovery;  // PUT is in Discovery namespace
    pkt.header.message_id = 0x0102;  // PUT message_id per RFC 0020
    pkt.session_id().fill(0xAA);
    pkt.intent_id.fill(0xBB);
    pkt.timestamp() = 1234567890;
    pkt.header.nonce = 7;
    pkt.payload = {0x01, 0x02, 0x03};
    pkt.auth.assign(16, 0xDD);

    std::vector<uint8_t> buf;
    ASSERT(packet_to_buffer(pkt, buf));
    ASSERT_EQ(buf.size(), 39U + 3U + 16U);
    ASSERT_EQ(buf[0], kPacketProtocolVersion);

    auto parsed = packet_from_buffer(buf);
    ASSERT(parsed);
    ASSERT_EQ(parsed.value().header.protocol_version, kPacketProtocolVersion);
    ASSERT_EQ(parsed.value().header.suite_id, 1);
    ASSERT_EQ(parsed.value().header.ns, packet_route::kNamespaceDiscovery);
    ASSERT_EQ(parsed.value().header.message_id, 0x0102U);
    ASSERT_EQ(parsed.value().session_id()[0], 0xAA);
    ASSERT_EQ(parsed.value().timestamp(), 1234567890);
    ASSERT_EQ(parsed.value().header.nonce, 7U);
    ASSERT_EQ(parsed.value().payload.size(), 3U);
    ASSERT_EQ(parsed.value().payload[2], 0x03);
    ASSERT_EQ(parsed.value().auth.size(), 16U);
    ASSERT_EQ(parsed.value().opcode_id, static_cast<uint32_t>(Opcode::PUT));
    // Shim không lên wire: intent_id luôn rỗng sau khi parse.
    ASSERT_EQ(parsed.value().intent_id[0], 0x00);

    return true;
}

static bool test_packet_too_short()
{
    std::vector<uint8_t> buf(10, 0);
    ASSERT(!packet_from_buffer(buf));
    return true;
}

static bool test_packet_bad_version()
{
    Packet pkt;
    pkt.header.protocol_version = 99;
    pkt.session_id().fill(0xAA);
    pkt.header.nonce = 1;
    std::vector<uint8_t> buf;
    ASSERT(!packet_to_buffer(pkt, buf));

    auto wire = make_valid_wire(packet_route::kNamespaceDiscovery, 0x0102,
                                1, 0, 16);
    ASSERT(!wire.empty());
    wire[0] = 99;
    ASSERT(!packet_from_buffer(wire));
    return true;
}

static bool test_packet_zero_nonce_payload_len_mismatch()
{
    auto wire = make_valid_wire(packet_route::kNamespaceDiscovery, 0x0102,
                                1, 0, 16);
    ASSERT(!wire.empty());

    // payload_length quá lớn so với buffer (offset 37..38)
    auto big_len = wire;
    big_len[37] = 0xFF;
    big_len[38] = 0xFF;
    ASSERT(!packet_from_buffer(big_len));

    // nonce == 0 (offset 29..36)
    auto zero_nonce = wire;
    for (size_t i = 29; i < 37; ++i)
        zero_nonce[i] = 0;
    ASSERT(!packet_from_buffer(zero_nonce));

    return true;
}

static bool test_packet_zero_session_id()
{
    auto wire = make_valid_wire(packet_route::kNamespaceDiscovery, 0x0102,
                                1, 0, 16);
    ASSERT(!wire.empty());
    for (size_t i = 5; i < 21; ++i)
        wire[i] = 0;
    ASSERT(!packet_from_buffer(wire));
    return true;
}

static bool test_packet_auth_length()
{
    // CONTROL + suite 1 (Ed25519) = 64B auth → hợp lệ.
    auto ctrl = make_valid_wire(packet_route::kNamespaceControl,
                                0x0050, 1, 4, 64);  // CONTRACT_MGMT
    ASSERT(!ctrl.empty());
    ASSERT(packet_from_buffer(ctrl));
    ASSERT_EQ(ctrl.size(), 39U + 4U + 64U);

    // Thiếu auth byte → reject.
    auto truncated = ctrl;
    truncated.pop_back();
    ASSERT(!packet_from_buffer(truncated));

    // Thừa auth byte → reject.
    auto extended = ctrl;
    extended.push_back(0x33);
    ASSERT(!packet_from_buffer(extended));

    // Namespace không hỗ trợ Packet (DISCOVERY 0x01 with invalid message_id) → reject.
    // 0x0199 is not a valid message_id in Discovery namespace
    auto exec = make_invalid_wire(packet_route::kNamespaceDiscovery, 0x0199,
                                  1, 0, 16);
    ASSERT(!exec.empty());
    // This should fail validation since 0x0199 is not valid in Discovery namespace
    ASSERT(!packet_from_buffer(exec));

    return true;
}

static bool test_packet_route_mapping()
{
    using smo::packet_route::PacketRoute;
    using smo::Opcode;

    struct TestCase {
        Opcode op;
        uint8_t expected_ns;
        uint16_t expected_mid;
    };

    const TestCase cases[] = {
        // Discovery namespace (0x01)
        {Opcode::LS,        0x01, 0x0101},
        {Opcode::PUT,       0x01, 0x0102},
        {Opcode::GET,       0x01, 0x0103},
        {Opcode::ECHO,      0x01, 0x0104},

        // Control namespace (0x02) - session
        {Opcode::SESSION_OPEN,  0x02, 0x0010},
        {Opcode::SESSION_CLOSE, 0x02, 0x0011},
        {Opcode::SESSION_RENEW, 0x02, 0x0012},

        // Control namespace (0x02) - governance
        {Opcode::GOV_PROPOSE,  0x02, 0x0020},
        {Opcode::GOV_VOTE,     0x02, 0x0021},
        {Opcode::GOV_COMMIT,   0x02, 0x0022},
        {Opcode::GOV_LIST,     0x02, 0x0023},
        {Opcode::GOV_STATUS,   0x02, 0x0024},
        {Opcode::GOV_INFO,     0x02, 0x0025},

        // Control namespace (0x02) - certificate
        {Opcode::REVOKE_CERT,     0x02, 0x0030},
        {Opcode::EPOCH_INCREMENT, 0x02, 0x0031},
        {Opcode::CRL_SYNC,        0x02, 0x0032},

        // Control namespace (0x02) - recovery
        {Opcode::RECOVERY_SESSION, 0x02, 0x0040},
        {Opcode::RECOVERY,         0x02, 0x0041},

        // Control namespace (0x02) - contract_mgmt
        {Opcode::CONTRACT_MGMT, 0x02, 0x0050},
        {Opcode::WITNESS,       0x02, 0x0051},

        // Execution namespace (0x03)
        {Opcode::EXEC,      0x03, 0x0201},
        {Opcode::QUARANTINE, 0x03, 0x0202},
        {Opcode::MKDIR,     0x03, 0x0203},
        {Opcode::RM,        0x03, 0x0204},
        {Opcode::CP,        0x03, 0x0205},
        {Opcode::FILE_OP,   0x03, 0x0206},
        {Opcode::PROCESS,   0x03, 0x0207},
        {Opcode::CUSTOM,    0x03, 0x02FF},
    };

    for (const auto& tc : cases)
    {
        ASSERT(packet_route::is_packet_capable(tc.op));
        auto route = packet_route::to_packet_route(tc.op);
        ASSERT(route);
        ASSERT_EQ(route->ns, tc.expected_ns);
        ASSERT_EQ(route->message_id, tc.expected_mid);
        auto back = packet_route::from_packet_route(route->ns, route->message_id);
        ASSERT(back);
        ASSERT(*back == tc.op);
    }

    const Opcode non_packet[] = {Opcode::BOOTSTRAP_SNAPSHOT, Opcode::BOOTSTRAP_INFO, Opcode::JOIN,
                                 Opcode::LEAVE, Opcode::JOIN_INFO};
    for (const auto op : non_packet)
    {
        ASSERT(!packet_route::is_packet_capable(op));
        ASSERT(!packet_route::to_packet_route(op));
    }

    // Serialize reject non-Packet opcode khi header route chưa set.
    Packet pkt;
    pkt.opcode_id = static_cast<uint32_t>(Opcode::JOIN);
    pkt.session_id().fill(0xAA);
    std::vector<uint8_t> buf;
    ASSERT(!packet_to_buffer(pkt, buf));

    return true;
}

// ==========================================================================
// Tests — Schema
// ==========================================================================
static bool test_schema_message_type_to_string()
{
    ASSERT(std::strcmp(to_string(MessageType::CONTRACT_PROPOSAL), "CONTRACT_PROPOSAL") == 0);
    ASSERT(std::strcmp(to_string(MessageType::HEARTBEAT), "HEARTBEAT") == 0);
    ASSERT(std::strcmp(to_string(MessageType::SESSION_OPEN), "SESSION_OPEN") == 0);
    ASSERT(std::strcmp(to_string(static_cast<MessageType>(0xFF)), "UNKNOWN") == 0);

    return true;
}

static bool test_schema_message_classification()
{
    ASSERT(is_control_message(MessageType::HEARTBEAT));
    ASSERT(is_control_message(MessageType::SESSION_OPEN));
    ASSERT(is_control_message(MessageType::SESSION_CLOSE));
    ASSERT(!is_control_message(MessageType::CONTRACT_PROPOSAL));

    ASSERT(is_contract_message(MessageType::CONTRACT_PROPOSAL));
    ASSERT(is_contract_message(MessageType::CONTRACT_RESULT));
    ASSERT(!is_contract_message(MessageType::WITNESS_REQUEST));

    ASSERT(is_witness_message(MessageType::WITNESS_REQUEST));
    ASSERT(is_witness_message(MessageType::WITNESS_RESPONSE));
    ASSERT(!is_witness_message(MessageType::HEARTBEAT));

    return true;
}

static bool test_schema_protocol_version()
{
    auto v = current_protocol_version();
    ASSERT_EQ(v.major, 1);
    ASSERT_EQ(v.minor, 0);

    ASSERT(is_compatible({1, 5}, v));  // same major
    ASSERT(!is_compatible({2, 0}, v)); // different major

    return true;
}

// ==========================================================================
// Tests — ReplayProtector
// ==========================================================================
static bool test_replay_accept_fresh()
{
    ReplayProtector rp({5000, 100});

    std::array<uint8_t, 8> nonce = {0, 0, 0, 0, 0, 0, 0, 1};
    ASSERT(rp.accept(nonce, 1000, 1500)); // delta 500ms < 5s
    ASSERT_EQ(rp.size(), 1U);

    return true;
}

static bool test_replay_reject_duplicate()
{
    ReplayProtector rp({5000, 100});

    std::array<uint8_t, 8> nonce = {0, 0, 0, 0, 0, 0, 0, 1};
    ASSERT(rp.accept(nonce, 1000, 1500));
    ASSERT(!rp.accept(nonce, 1000, 1500)); // same nonce → reject

    return true;
}

static bool test_replay_reject_outside_window()
{
    ReplayProtector rp({5000, 100});

    std::array<uint8_t, 8> nonce = {0, 0, 0, 0, 0, 0, 0, 1};
    ASSERT(!rp.accept(nonce, 1000, 20000)); // delta 19s > 5s

    return true;
}

static bool test_replay_eviction()
{
    ReplayProtector rp({50000, 3}); // capacity 3

    for (uint8_t i = 0; i < 5; ++i)
    {
        std::array<uint8_t, 8> nonce = {0, 0, 0, 0, 0, 0, 0, i};
        ASSERT(rp.accept(nonce, 1000, 1500));
    }

    ASSERT_EQ(rp.size(), 3U); // evicted 2

    // First nonce (0) should be evicted and re-usable
    std::array<uint8_t, 8> old = {0, 0, 0, 0, 0, 0, 0, 0};
    ASSERT(rp.accept(old, 1000, 1500)); // was evicted, so accepted again

    return true;
}

static bool test_replay_clear()
{
    ReplayProtector rp({5000, 100});

    std::array<uint8_t, 8> nonce = {0, 0, 0, 0, 0, 0, 0, 1};
    ASSERT(rp.accept(nonce, 1000, 1500));
    ASSERT_EQ(rp.size(), 1U);

    rp.clear();
    ASSERT_EQ(rp.size(), 0U);
    ASSERT(rp.accept(nonce, 1000, 1500)); // accepted again after clear

    return true;
}

// ==========================================================================
// Main
// ==========================================================================

int main(int, char*[])
{
    printf("SMO Protocol — Unit Tests\n");
    printf("==========================\n\n");

    TEST("Packet roundtrip 39B") END_TEST(test_packet_roundtrip_39b());
    TEST("Packet too short") END_TEST(test_packet_too_short());
    TEST("Packet bad version") END_TEST(test_packet_bad_version());
    TEST("Packet zero nonce / payload length") END_TEST(test_packet_zero_nonce_payload_len_mismatch());
    TEST("Packet zero session_id") END_TEST(test_packet_zero_session_id());
    TEST("Packet auth length") END_TEST(test_packet_auth_length());
    TEST("Packet route mapping") END_TEST(test_packet_route_mapping());
    TEST("Schema MessageType to_string") END_TEST(test_schema_message_type_to_string());
    TEST("Schema message classification") END_TEST(test_schema_message_classification());
    TEST("Schema protocol version") END_TEST(test_schema_protocol_version());
    TEST("Replay accept fresh") END_TEST(test_replay_accept_fresh());
    TEST("Replay reject duplicate") END_TEST(test_replay_reject_duplicate());
    TEST("Reject outside time window") END_TEST(test_replay_reject_outside_window());
    TEST("Replay eviction") END_TEST(test_replay_eviction());
    TEST("Replay clear") END_TEST(test_replay_clear());

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
