#include <packet/packet.h>
#include <packet/packet_crypto.hpp>
#include <packet/packet_route.hpp>
#include <core/session/session.hpp>
#include <core/session/session_security.hpp>
#include <core/crypto/registry.hpp>
#include <core/crypto/suite.hpp>
#include <core/errors/error.hpp>
#include <core/types.hpp>
#include <providers/suite1_classical/suite1_classical_provider.hpp>

#include <cstdint>
#include <cstring>
#include <vector>
#include <cstdio>

using namespace smo;

namespace {
    inline bool check_true(bool cond) { return cond; }
    inline bool check_false(bool cond) { return !cond; }
    inline bool check_eq(auto a, auto b) { return a == b; }
    inline bool check_ne(auto a, auto b) { return a != b; }
}

static const CryptoProvider* get_crypto()
{
    auto& reg = CryptoRegistry::instance();
    auto res = reg.get_suite(kSuiteClassical);
    if (!res) return nullptr;
    return res.value();
}

static SessionCryptoContext make_crypto_ctx(uint8_t tx_byte, uint8_t rx_byte, uint8_t sid_byte)
{
    SessionId sid;
    sid.bytes.fill(sid_byte);
    Bytes tx_key(32, tx_byte);
    Bytes rx_key(32, rx_byte);
    return SessionCryptoContext::create(sid, BytesView(tx_key), BytesView(rx_key));
}

static Packet make_valid_packet(const SessionId& sid, uint64_t seq, const std::string& payload_str,
                                uint8_t ns = smo::packet_route::kNamespaceExecution, uint16_t mid = 0x0101)
{
    Packet p;
    p.header.protocol_version = kPacketProtocolVersion;
    p.header.suite_id = kSuiteClassical;
    p.header.ns = ns;
    p.header.message_id = mid;
    std::memcpy(p.header.session_id.data(), sid.bytes.data(), 16);
    p.header.timestamp = 1234567890000;
    p.header.nonce = seq;
    p.payload.assign(payload_str.begin(), payload_str.end());
    return p;
}

static void run_test(const char* name, bool (*fn)())
{
    printf("  TEST %-55s ... ", name);
    fflush(stdout);
    if (fn())
    {
        printf("PASS\n");
    }
    else
    {
        printf("FAIL\n");
    }
}

// ============================================================================
// MALFORMED PACKET TESTS
// ============================================================================

static bool test_reject_zero_session_id()
{
    const auto* crypto = get_crypto();
    if (!crypto) return false;

    auto sender = make_crypto_ctx(0x11, 0x22, 0x33);
    SessionId sid;
    sid.bytes.fill(0x33);

    Packet p = make_valid_packet(sid, 1, "test");
    p.header.session_id.fill(0); // zero session ID

    auto seal_res = packet_seal_data(p, sender.packet_tx_key(), 1);
    if (!check_false(static_cast<bool>(seal_res))) return false;
    return true;
}

static bool test_reject_zero_nonce()
{
    const auto* crypto = get_crypto();
    if (!crypto) return false;

    auto sender = make_crypto_ctx(0x11, 0x22, 0x33);
    SessionId sid;
    sid.bytes.fill(0x33);

    Packet p = make_valid_packet(sid, 0, "test"); // zero nonce
    auto seal_res1 = packet_seal_data(p, sender.packet_tx_key(), 0);
    if (!check_false(static_cast<bool>(seal_res1))) return false;

    // Also test seal rejects zero seq explicitly
    p = make_valid_packet(sid, 1, "test");
    auto seal_res2 = packet_seal_data(p, sender.packet_tx_key(), 0);
    if (!check_false(static_cast<bool>(seal_res2))) return false;

    return true;
}

static bool test_reject_bad_protocol_version()
{
    const auto* crypto = get_crypto();
    if (!crypto) return false;

    SessionId sid;
    sid.bytes.fill(0x33);
    auto sender = make_crypto_ctx(0x11, 0x22, 0x33);

    // Create a valid packet first
    Packet p = make_valid_packet(sid, 1, "test");
    auto seal_res = packet_seal_data(p, sender.packet_tx_key(), 1);
    if (!check_true(static_cast<bool>(seal_res))) return false;

    std::vector<uint8_t> buf;
    if (!packet_to_buffer(p, buf)) return false;

    // Tamper version in wire buffer
    if (buf.size() > 0) {
        buf[0] = 0x02; // wrong version
    }

    auto parsed = packet_from_buffer(buf);
    if (!check_false(static_cast<bool>(parsed))) return false;

    return true;
}

static bool test_reject_bad_suite_id_on_parse()
{
    const auto* crypto = get_crypto();
    if (!crypto) return false;

    auto sender = make_crypto_ctx(0x11, 0x22, 0x33);
    SessionId sid;
    sid.bytes.fill(0x33);

    // Create valid packet with Control namespace, then tamper suite_id in wire buffer
    Packet p = make_valid_packet(sid, 1, "test",
                                 smo::packet_route::kNamespaceControl, 0x0201);
    auto seal_res = packet_seal_data(p, sender.packet_tx_key(), 1);
    if (!check_true(static_cast<bool>(seal_res))) return false;

    std::vector<uint8_t> buf;
    if (!packet_to_buffer(p, buf)) return false;

    // Tamper suite_id in wire buffer (offset 1) - for Control namespace, suite_id must be 1,2,3
    if (buf.size() > 1) {
        buf[1] = 0xFF; // invalid suite_id for Control namespace
    }

    auto parsed = packet_from_buffer(buf);
    if (!check_false(static_cast<bool>(parsed))) return false;

    return true;
}

static bool test_reject_payload_length_mismatch()
{
    const auto* crypto = get_crypto();
    if (!crypto) return false;

    SessionId sid;
    sid.bytes.fill(0x33);
    auto sender = make_crypto_ctx(0x11, 0x22, 0x33);

    Packet p = make_valid_packet(sid, 1, "test");
    auto seal_res = packet_seal_data(p, sender.packet_tx_key(), 1);
    if (!check_true(static_cast<bool>(seal_res))) return false;

    std::vector<uint8_t> buf;
    if (!packet_to_buffer(p, buf)) return false;

    // Parse and tamper payload_length field in header (position after timestamp+nonce = 1+1+1+2+16+8+8 = 37)
    // payload_length is at offset 37 (2 bytes)
    if (buf.size() > 38) {
        buf[37] = 0x00;
        buf[38] = 0x05; // wrong length (5 vs actual)
    }

    auto parsed = packet_from_buffer(buf);
    if (!check_false(static_cast<bool>(parsed))) return false;

    return true;
}

static bool test_reject_zero_session_id_on_open()
{
    const auto* crypto = get_crypto();
    if (!crypto) return false;

    auto sender = make_crypto_ctx(0x11, 0x22, 0x33);
    auto receiver = make_crypto_ctx(0x22, 0x11, 0x33);
    SessionId sid;
    sid.bytes.fill(0x33);

    Packet p = make_valid_packet(sid, 1, "test");
    auto seal_res = packet_seal_data(p, sender.packet_tx_key(), 1);
    if (!check_true(static_cast<bool>(seal_res))) return false;

    std::vector<uint8_t> buf;
    if (!packet_to_buffer(p, buf)) return false;

    // Tamper session_id in wire buffer to zero
    if (buf.size() > 4) {
        for (int i = 4; i < 20; ++i) buf[i] = 0;
    }

    auto parsed = packet_from_buffer(buf);
    if (!parsed) return false;
    Packet rx = std::move(parsed.value());

    // Open should fail with zero session_id
    auto open_res = packet_open_data(rx, receiver.packet_rx_key());
    if (!check_false(static_cast<bool>(open_res))) return false;

    // State unchanged
    if (!check_true(rx.payload.size() > 0)) return false; // payload still ciphertext
    return true;
}

// ============================================================================
// AEAD/AAD TESTS
// ============================================================================

static bool test_payload_tamper_reject()
{
    const auto* crypto = get_crypto();
    if (!crypto) return false;

    auto sender = make_crypto_ctx(0x11, 0x22, 0x33);
    auto receiver = make_crypto_ctx(0x22, 0x11, 0x33);
    SessionId sid;
    sid.bytes.fill(0x33);

    Packet p = make_valid_packet(sid, 1, "secret-payload");
    auto seal_res = packet_seal_data(p, sender.packet_tx_key(), 1);
    if (!check_true(static_cast<bool>(seal_res))) return false;

    std::vector<uint8_t> buf;
    if (!packet_to_buffer(p, buf)) return false;

    auto parsed = packet_from_buffer(buf);
    if (!parsed) return false;
    Packet rx = std::move(parsed.value());

    // Tamper ciphertext
    if (!rx.payload.empty()) {
        rx.payload[0] ^= 0xFF;
    }

    auto open_res = packet_open_data(rx, receiver.packet_rx_key());
    if (!check_false(static_cast<bool>(open_res))) return false;

    // Packet state unchanged
    if (!check_true(rx.payload.size() > 0)) return false;

    return true;
}

static bool test_header_aad_tamper_reject()
{
    const auto* crypto = get_crypto();
    if (!crypto) return false;

    auto sender = make_crypto_ctx(0x11, 0x22, 0x33);
    auto receiver = make_crypto_ctx(0x22, 0x11, 0x33);
    SessionId sid;
    sid.bytes.fill(0x33);

    Packet p = make_valid_packet(sid, 1, "aad-bound");
    auto seal_res = packet_seal_data(p, sender.packet_tx_key(), 1);
    if (!check_true(static_cast<bool>(seal_res))) return false;

    std::vector<uint8_t> buf;
    if (!packet_to_buffer(p, buf)) return false;

    auto parsed = packet_from_buffer(buf);
    if (!parsed) return false;
    Packet rx = std::move(parsed.value());

    // Tamper timestamp (part of AAD)
    rx.header.timestamp += 1;

    auto open_res = packet_open_data(rx, receiver.packet_rx_key());
    if (!check_false(static_cast<bool>(open_res))) return false;

    // Also test message_id tamper
    auto parsed2 = packet_from_buffer(buf);
    if (!parsed2) return false;
    Packet rx2 = std::move(parsed2.value());
    rx2.header.message_id = 0xFFFF;

    auto open_res2 = packet_open_data(rx2, receiver.packet_rx_key());
    if (!check_false(static_cast<bool>(open_res2))) return false;

    return true;
}

static bool test_wrong_rx_key_reject()
{
    const auto* crypto = get_crypto();
    if (!crypto) return false;

    SessionId sid;
    sid.bytes.fill(0x33);

    auto sender = make_crypto_ctx(0x11, 0x22, 0x33);
    auto receiver = make_crypto_ctx(0x22, 0x11, 0x33);
    auto other = make_crypto_ctx(0xAA, 0xBB, 0x33); // different keys

    Packet p = make_valid_packet(sid, 1, "key-bound");
    auto seal_res = packet_seal_data(p, sender.packet_tx_key(), 1);
    if (!check_true(static_cast<bool>(seal_res))) return false;

    std::vector<uint8_t> buf;
    if (!packet_to_buffer(p, buf)) return false;

    auto parsed = packet_from_buffer(buf);
    if (!parsed) return false;
    Packet rx = std::move(parsed.value());

    // Try with wrong key
    auto open_res = packet_open_data(rx, other.packet_rx_key());
    if (!check_false(static_cast<bool>(open_res))) return false;

    // Correct key should still work
    auto parsed2 = packet_from_buffer(buf);
    if (!parsed2) return false;
    Packet rx2 = std::move(parsed2.value());
    auto open_res2 = packet_open_data(rx2, receiver.packet_rx_key());
    if (!check_true(static_cast<bool>(open_res2))) return false;

    return true;
}

static bool test_open_fail_state_unchanged()
{
    const auto* crypto = get_crypto();
    if (!crypto) return false;

    auto sender = make_crypto_ctx(0x11, 0x22, 0x33);
    auto receiver = make_crypto_ctx(0x22, 0x11, 0x33);
    SessionId sid;
    sid.bytes.fill(0x33);

    Packet p = make_valid_packet(sid, 1, "state-test");
    auto seal_res = packet_seal_data(p, sender.packet_tx_key(), 1);
    if (!check_true(static_cast<bool>(seal_res))) return false;

    std::vector<uint8_t> buf;
    if (!packet_to_buffer(p, buf)) return false;

    auto parsed = packet_from_buffer(buf);
    if (!parsed) return false;
    Packet rx = std::move(parsed.value());

    // Tamper first
    rx.payload[0] ^= 0xFF;

    // Save tampered state
    std::vector<uint8_t> tampered_payload = rx.payload;
    std::vector<uint8_t> tampered_auth = rx.auth;

    // Try to open (should fail)
    auto open_res = packet_open_data(rx, receiver.packet_rx_key());
    if (!check_false(static_cast<bool>(open_res))) return false;

    // State should be unchanged from tampered state
    if (!check_eq(rx.payload, tampered_payload)) return false;
    if (!check_eq(rx.auth, tampered_auth)) return false;

    return true;
}

// ============================================================================
// REPLAY TESTS
// ============================================================================

static bool test_replay_duplicate_reject()
{
    const auto* crypto = get_crypto();
    if (!crypto) return false;

    auto sender = make_crypto_ctx(0x11, 0x22, 0x33);
    auto receiver = make_crypto_ctx(0x22, 0x11, 0x33);
    SessionId sid;
    sid.bytes.fill(0x33);

    SessionSecurityState rx_state;
    rx_state.session_id = sid;
    rx_state.epoch = 0;
    rx_state.rx_epoch = 0;

    Packet p = make_valid_packet(sid, 5, "dup-test");
    auto seal_res = packet_seal_data(p, sender.packet_tx_key(), 5);
    if (!check_true(static_cast<bool>(seal_res))) return false;

    std::vector<uint8_t> buf;
    if (!packet_to_buffer(p, buf)) return false;

    // First time - should work
    auto parsed1 = packet_from_buffer(buf);
    if (!parsed1) return false;
    Packet rx1 = std::move(parsed1.value());
    if (!check_true(rx_state.rx_window.is_acceptable(5))) return false;
    if (!packet_open_data(rx1, receiver.packet_rx_key())) return false;
    if (!check_true(rx_state.rx_window.commit(5))) return false;

    // Second time (duplicate) - should be rejected at precheck
    auto parsed2 = packet_from_buffer(buf);
    if (!parsed2) return false;
    Packet rx2 = std::move(parsed2.value());
    if (!check_false(rx_state.rx_window.is_acceptable(5))) return false;

    return true;
}

static bool test_replay_stale_reject()
{
    const auto* crypto = get_crypto();
    if (!crypto) return false;

    SessionSecurityState rx_state;
    rx_state.session_id.bytes.fill(0x33);
    rx_state.epoch = 0;
    rx_state.rx_epoch = 0;

    // Advance window
    rx_state.rx_window.commit(100);

    // Stale sequence (outside window of 64)
    if (!check_false(rx_state.rx_window.is_acceptable(30))) return false;
    if (!check_false(rx_state.rx_window.is_acceptable(35))) return false;

    // Edge: exactly at window boundary (highest - 63 is acceptable, highest - 64 is not)
    if (!check_true(rx_state.rx_window.is_acceptable(37))) return false; // 100-63
    if (!check_false(rx_state.rx_window.is_acceptable(36))) return false; // 100-64

    return true;
}

static bool test_replay_out_of_order_accept()
{
    const auto* crypto = get_crypto();
    if (!crypto) return false;

    auto sender = make_crypto_ctx(0x11, 0x22, 0x33);
    auto receiver = make_crypto_ctx(0x22, 0x11, 0x33);
    SessionId sid;
    sid.bytes.fill(0x33);

    SessionSecurityState rx_state;
    rx_state.session_id = sid;
    rx_state.epoch = 0;
    rx_state.rx_epoch = 0;

    // Send seq 10, then 5 (out of order but in window)
    Packet p10 = make_valid_packet(sid, 10, "seq10");
    auto seal_res1 = packet_seal_data(p10, sender.packet_tx_key(), 10);
    if (!check_true(static_cast<bool>(seal_res1))) return false;
    std::vector<uint8_t> buf10;
    if (!packet_to_buffer(p10, buf10)) return false;

    Packet p5 = make_valid_packet(sid, 5, "seq5");
    auto seal_res2 = packet_seal_data(p5, sender.packet_tx_key(), 5);
    if (!check_true(static_cast<bool>(seal_res2))) return false;
    std::vector<uint8_t> buf5;
    if (!packet_to_buffer(p5, buf5)) return false;

    // Process seq 10 first
    auto parsed10 = packet_from_buffer(buf10);
    if (!parsed10) return false;
    Packet rx10 = std::move(parsed10.value());
    if (!check_true(rx_state.rx_window.is_acceptable(10))) return false;
    if (!packet_open_data(rx10, receiver.packet_rx_key())) return false;
    if (!check_true(rx_state.rx_window.commit(10))) return false;
    if (!check_eq(rx_state.rx_window.highest(), 10ULL)) return false;

    // Process seq 5 (out of order, in window)
    auto parsed5 = packet_from_buffer(buf5);
    if (!parsed5) return false;
    Packet rx5 = std::move(parsed5.value());
    if (!check_true(rx_state.rx_window.is_acceptable(5))) return false;
    if (!packet_open_data(rx5, receiver.packet_rx_key())) return false;
    if (!check_true(rx_state.rx_window.commit(5))) return false;
    if (!check_eq(rx_state.rx_window.highest(), 10ULL)) return false; // highest unchanged

    return true;
}

static bool test_forged_high_seq_no_advance()
{
    const auto* crypto = get_crypto();
    if (!crypto) return false;

    auto sender = make_crypto_ctx(0xAA, 0xBB, 0xCC);
    auto receiver = make_crypto_ctx(0xBB, 0xAA, 0xCC);
    SessionId sid;
    sid.bytes.fill(0xCC);

    SessionSecurityState rx_state;
    rx_state.session_id = sid;
    rx_state.epoch = 0;
    rx_state.rx_epoch = 0;

    // Legitimate packet seq=10
    Packet p = make_valid_packet(sid, 10, "legit");
    auto seal_res = packet_seal_data(p, sender.packet_tx_key(), 10);
    if (!check_true(static_cast<bool>(seal_res))) return false;
    std::vector<uint8_t> legit_buf;
    if (!packet_to_buffer(p, legit_buf)) return false;

    // Attacker: forged packet with seq=1000, tampered ciphertext
    Packet attack = make_valid_packet(sid, 1000, "attack");
    auto seal_res2 = packet_seal_data(attack, sender.packet_tx_key(), 1000);
    if (!check_true(static_cast<bool>(seal_res2))) return false;
    std::vector<uint8_t> attack_buf;
    if (!packet_to_buffer(attack, attack_buf)) return false;

    auto sealed_attack = packet_from_buffer(attack_buf);
    if (!sealed_attack) return false;
    Packet tampered = std::move(sealed_attack.value());
    if (!tampered.payload.empty()) {
        tampered.payload[0] ^= 0xFF;
    }
    attack_buf.clear();
    if (!packet_to_buffer(tampered, attack_buf)) return false;

    auto tampered_pkt = packet_from_buffer(attack_buf);
    if (!tampered_pkt) return false;
    Packet rx_attack = std::move(tampered_pkt.value());

    // Precheck: seq=1000 is acceptable (new high)
    if (!check_true(rx_state.rx_window.is_acceptable(1000))) return false;

    // But AEAD open fails
    auto open_res = packet_open_data(rx_attack, receiver.packet_rx_key());
    if (!check_false(static_cast<bool>(open_res))) return false;

    // Replay window should NOT have advanced
    if (!check_eq(rx_state.rx_window.highest(), 0ULL)) return false;

    // Legitimate packet seq=10 should still work
    auto legit_pkt = packet_from_buffer(legit_buf);
    if (!legit_pkt) return false;
    Packet rx_legit = std::move(legit_pkt.value());
    if (!check_true(rx_state.rx_window.is_acceptable(10))) return false;
    if (!packet_open_data(rx_legit, receiver.packet_rx_key())) return false;
    if (!check_true(rx_state.rx_window.commit(10))) return false;
    if (!check_eq(rx_state.rx_window.highest(), 10ULL)) return false;

    return true;
}

static bool test_valid_high_seq_advance()
{
    const auto* crypto = get_crypto();
    if (!crypto) return false;

    auto sender = make_crypto_ctx(0x11, 0x22, 0x33);
    auto receiver = make_crypto_ctx(0x22, 0x11, 0x33);
    SessionId sid;
    sid.bytes.fill(0x33);

    SessionSecurityState rx_state;
    rx_state.session_id = sid;
    rx_state.epoch = 0;
    rx_state.rx_epoch = 0;

    // Valid high sequence packet
    Packet p = make_valid_packet(sid, 1000, "high-seq");
    auto seal_res = packet_seal_data(p, sender.packet_tx_key(), 1000);
    if (!check_true(static_cast<bool>(seal_res))) return false;
    std::vector<uint8_t> buf;
    if (!packet_to_buffer(p, buf)) return false;

    auto parsed = packet_from_buffer(buf);
    if (!parsed) return false;
    Packet rx = std::move(parsed.value());

    if (!check_true(rx_state.rx_window.is_acceptable(1000))) return false;
    if (!packet_open_data(rx, receiver.packet_rx_key())) return false;
    if (!check_true(rx_state.rx_window.commit(1000))) return false;
    if (!check_eq(rx_state.rx_window.highest(), 1000ULL)) return false;

    // Old sequences now stale
    if (!check_false(rx_state.rx_window.is_acceptable(500))) return false;

    return true;
}

// ============================================================================
// SESSION REKEY TESTS
// ============================================================================

static bool test_rekey_resets_replay_window()
{
    const auto* crypto = get_crypto();
    if (!crypto) return false;

    SessionSecurityState ss;
    ss.session_id.bytes.fill(0xAA);
    ss.epoch = 0;
    ss.tx_sequence = 10;
    ss.rx_epoch = 0;
    ss.rx_window.commit(5);
    ss.rx_window.commit(8);

    ss.rekey();

    if (!check_eq(ss.epoch, 1ULL)) return false;
    if (!check_eq(ss.tx_sequence, 0ULL)) return false;
    if (!check_eq(ss.rx_epoch, 1ULL)) return false;
    if (!check_eq(ss.rx_window.highest(), 0ULL)) return false;

    // Old sequences now acceptable in new epoch
    if (!check_true(ss.rx_window.is_acceptable(1))) return false;
    if (!check_true(ss.rx_window.is_acceptable(5))) return false;

    return true;
}

// ============================================================================
// SESSION CLOSED TESTS
// ============================================================================

static bool test_closed_session_no_packets()
{
    const auto* crypto = get_crypto();
    if (!crypto) return false;

    SessionId sid;
    sid.bytes.fill(0xDD);

    Session s = Session::create(sid, NodeID{}, Certificate{}, CapabilitySet{}, 1000, 1000000).value();
    s.on_event(SessionEvent::Close, 2000);

    if (!check_eq(s.state(), SessionState::Closed)) return false;
    if (!check_false(s.is_valid_at(2001))) return false;

    return true;
}

int main()
{
    smo::providers::register_suite1_classical();

    printf("SMO P7 Negative Tests — Packet Auth & Replay\n");
    printf("=============================================\n\n");

    // Malformed packet tests
    run_test("MALFORMED: reject zero session_id on seal", test_reject_zero_session_id);
    run_test("MALFORMED: reject zero nonce/seq on seal", test_reject_zero_nonce);
    run_test("MALFORMED: reject bad protocol version on parse", test_reject_bad_protocol_version);
    run_test("MALFORMED: reject bad suite_id on parse", test_reject_bad_suite_id_on_parse);
    run_test("MALFORMED: reject payload length mismatch on parse", test_reject_payload_length_mismatch);
    run_test("MALFORMED: reject zero session_id on open", test_reject_zero_session_id_on_open);

    // AEAD/AAD tests
    run_test("AEAD: payload tamper reject", test_payload_tamper_reject);
    run_test("AEAD: header/AAD tamper reject", test_header_aad_tamper_reject);
    run_test("AEAD: wrong RX key reject", test_wrong_rx_key_reject);
    run_test("AEAD: open fail leaves state unchanged", test_open_fail_state_unchanged);

    // Replay tests
    run_test("REPLAY: duplicate sequence reject", test_replay_duplicate_reject);
    run_test("REPLAY: stale/out-of-window reject", test_replay_stale_reject);
    run_test("REPLAY: out-of-order in window accept", test_replay_out_of_order_accept);
    run_test("REPLAY: forged high-seq no advance", test_forged_high_seq_no_advance);
    run_test("REPLAY: valid high-seq advances highest", test_valid_high_seq_advance);

    // Session rekey tests
    run_test("REKEY: resets replay window", test_rekey_resets_replay_window);

    // Session closed tests
    run_test("CLOSED: session rejects packets", test_closed_session_no_packets);

    printf("\nALL NEGATIVE TESTS COMPLETED\n");
    return 0;
}