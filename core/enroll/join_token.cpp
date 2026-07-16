#include "join_token.hpp"
#include "core/types.hpp"

#include <chrono>
#include <cstring>
#include <random>
#include <sstream>
#include <vector>

namespace smo::enroll {

// =========================================================================
// CBOR encoder/decoder (RFC 7049 — minimal subset for Join Token)
// =========================================================================
namespace cbor {

// Major types — 3 high bits
enum Major : uint8_t {
    Uint    = 0 << 5,
    Bstr    = 2 << 5,
    Text    = 3 << 5,
    Array   = 4 << 5,
    Map     = 5 << 5,
};

// Write the initial byte + (optional) extended length
static void write_head(Bytes& out, Major mt, uint64_t val) {
    if (val <= 23) {
        out.push_back(static_cast<uint8_t>(mt) | static_cast<uint8_t>(val));
    } else if (val <= 0xFF) {
        out.push_back(static_cast<uint8_t>(mt) | 24);
        out.push_back(static_cast<uint8_t>(val));
    } else if (val <= 0xFFFF) {
        out.push_back(static_cast<uint8_t>(mt) | 25);
        uint16_t n = static_cast<uint16_t>(val);
        out.push_back(static_cast<uint8_t>(n >> 8));
        out.push_back(static_cast<uint8_t>(n));
    } else if (val <= 0xFFFFFFFFULL) {
        out.push_back(static_cast<uint8_t>(mt) | 26);
        uint32_t n = static_cast<uint32_t>(val);
        for (int i = 3; i >= 0; --i) out.push_back(static_cast<uint8_t>((n >> (i * 8)) & 0xFF));
    } else {
        out.push_back(static_cast<uint8_t>(mt) | 27);
        for (int i = 7; i >= 0; --i) out.push_back(static_cast<uint8_t>((val >> (i * 8)) & 0xFF));
    }
}

// Read the initial byte, return value (or length), advance offset
// Helper: reads a CBOR integer after the initial byte
static uint64_t read_int(BytesView data, size_t& off, uint8_t ib) {
    uint8_t extra = ib & 0x1F;
    if (extra <= 23) return extra;
    if (off + (1ULL << (extra - 24)) > data.size()) return 0;
    uint64_t val = 0;
    size_t nbytes = 1ULL << (extra - 24);
    for (size_t i = 0; i < nbytes; ++i)
        val = (val << 8) | data[off++];
    return val;
}

void encode_uint(Bytes& out, uint64_t val) {
    write_head(out, Uint, val);
}

void encode_text(Bytes& out, const std::string& s) {
    write_head(out, Text, s.size());
    out.insert(out.end(), s.begin(), s.end());
}

void encode_array(Bytes& out, size_t n) {
    write_head(out, Array, n);
}

void encode_map(Bytes& out, size_t n) {
    write_head(out, Map, n);
}

uint64_t decode_uint(BytesView data, size_t& off) {
    if (off >= data.size()) return 0;
    uint8_t ib = data[off++];
    if ((ib >> 5) != 0) return 0; // not unsigned int
    return read_int(data, off, ib);
}

std::string decode_text(BytesView data, size_t& off) {
    if (off >= data.size()) return {};
    uint8_t ib = data[off++];
    if ((ib >> 5) != 3) return {}; // not text
    uint64_t len = read_int(data, off, ib);
    if (off + len > data.size()) return {};
    std::string s(reinterpret_cast<const char*>(data.data() + off), static_cast<size_t>(len));
    off += static_cast<size_t>(len);
    return s;
}

size_t decode_array(BytesView data, size_t& off) {
    if (off >= data.size()) return 0;
    uint8_t ib = data[off++];
    if ((ib >> 5) != 4) return 0; // not array
    return static_cast<size_t>(read_int(data, off, ib));
}

size_t decode_map(BytesView data, size_t& off) {
    if (off >= data.size()) return 0;
    uint8_t ib = data[off++];
    if ((ib >> 5) != 5) return 0; // not map
    return static_cast<size_t>(read_int(data, off, ib));
}

} // namespace cbor

// =========================================================================
// Base64url
// =========================================================================
namespace {

std::string base64url_encode(BytesView data) {
    static const char kEnc[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                               "abcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    for (size_t i = 0; i < data.size(); i += 3) {
        uint32_t v = (uint32_t)data[i] << 16;
        if (i + 1 < data.size()) v |= (uint32_t)data[i + 1] << 8;
        if (i + 2 < data.size()) v |= (uint32_t)data[i + 2];
        out += kEnc[(v >> 18) & 0x3f];
        out += kEnc[(v >> 12) & 0x3f];
        out += kEnc[(v >> 6) & 0x3f];
        out += kEnc[v & 0x3f];
    }
    return out;
}

static uint8_t kDec[256] = {};
static const bool kDecInit = []() {
    std::memset(kDec, 0xFF, 256);
    for (int i = 0; i < 26; ++i) {
        kDec[(uint8_t)('A' + i)] = i;
        kDec[(uint8_t)('a' + i)] = 26 + i;
    }
    for (int i = 0; i < 10; ++i) kDec[(uint8_t)('0' + i)] = 52 + i;
    kDec[(uint8_t)'-'] = 62;
    kDec[(uint8_t)'_'] = 63;
    return true;
}();

Bytes base64url_decode(const std::string& s) {
    Bytes out;
    out.reserve(s.size() * 3 / 4);
    uint32_t buf = 0;
    int bits = 0;
    for (uint8_t c : s) {
        if (c == '=') break;
        uint8_t val = kDec[c];
        if (val == 0xFF) continue;
        buf = (buf << 6) | val;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((buf >> bits) & 0xFF));
        }
    }
    return out;
}

std::string generate_nonce() {
    std::array<uint8_t, 16> nonce;
    std::random_device rd;
    for (auto& b : nonce) b = static_cast<uint8_t>(rd());
    std::ostringstream oss;
    for (uint8_t b : nonce) oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return oss.str();
}

} // anonymous namespace

// =========================================================================
// JoinToken serialization (CBOR map)
// =========================================================================
Bytes JoinToken::serialize_payload() const {
    using namespace cbor;

    Bytes out;
    // Map: key → value
    // Keys: 1=version, 2=mesh_id, 3=mesh_epoch, 4=cipher_suite_id,
    //       5=endpoints, 6=role, 7=expiry, 8=nonce
    // Count only non-default fields (omit empty endpoints, empty role, etc.)
    size_t count = 4; // version, mesh_id, mesh_epoch, cipher_suite_id
    if (!bootstrap_endpoints.empty()) ++count;
    if (!role.empty()) ++count;
    if (expiry_unix_sec > 0) ++count;
    if (!nonce.empty()) ++count;

    encode_map(out, count);

    // 1: version
    encode_uint(out, 1);
    encode_uint(out, version);

    // 2: mesh_id
    encode_uint(out, 2);
    encode_text(out, mesh_id);

    // 3: mesh_epoch
    encode_uint(out, 3);
    encode_uint(out, static_cast<uint64_t>(mesh_epoch));

    // 4: cipher_suite_id
    encode_uint(out, 4);
    encode_uint(out, static_cast<uint64_t>(cipher_suite_id));

    // 5: endpoints (array of text)
    if (!bootstrap_endpoints.empty()) {
        encode_uint(out, 5);
        encode_array(out, bootstrap_endpoints.size());
        for (auto& ep : bootstrap_endpoints)
            encode_text(out, ep);
    }

    // 6: role
    if (!role.empty()) {
        encode_uint(out, 6);
        encode_text(out, role);
    }

    // 7: expiry
    if (expiry_unix_sec > 0) {
        encode_uint(out, 7);
        encode_uint(out, static_cast<uint64_t>(expiry_unix_sec));
    }

    // 8: nonce
    if (!nonce.empty()) {
        encode_uint(out, 8);
        encode_text(out, nonce);
    }

    return out;
}

Result<JoinToken> JoinToken::deserialize_payload(BytesView data) {
    using namespace cbor;

    JoinToken token;

    size_t off = 0;
    size_t pairs = decode_map(data, off);
    if (pairs == 0) {
        return SMO_ERR_CERT(212, Error, NoRetry, ManualIntervention,
                            "Join Token: expected CBOR map");
    }

    // Saved endpoints vector (needs move into token at the end)
    std::vector<std::string> endpoints;

    for (size_t i = 0; i < pairs; ++i) {
        uint64_t key = decode_uint(data, off);
        if (off > data.size()) break;

        switch (key) {
            case 1: // version
                token.version = static_cast<uint8_t>(decode_uint(data, off));
                break;
            case 2: // mesh_id
                token.mesh_id = decode_text(data, off);
                break;
            case 3: // mesh_epoch
                token.mesh_epoch = static_cast<int64_t>(decode_uint(data, off));
                break;
            case 4: // cipher_suite_id
                token.cipher_suite_id = static_cast<int>(decode_uint(data, off));
                break;
            case 5: { // endpoints
                size_t n = decode_array(data, off);
                endpoints.clear();
                for (size_t j = 0; j < n; ++j)
                    endpoints.push_back(decode_text(data, off));
                break;
            }
            case 6: // role
                token.role = decode_text(data, off);
                break;
            case 7: // expiry
                token.expiry_unix_sec = static_cast<int64_t>(decode_uint(data, off));
                break;
            case 8: // nonce
                token.nonce = decode_text(data, off);
                break;
            default: {
                // Unknown key — skip value by peeking at major type
                if (off >= data.size()) break;
                uint8_t ib = data[off];
                uint8_t mt = ib >> 5;
                if (mt == 0 || mt == 1) { // uint / nint — same length encoding
                    decode_uint(data, off);
                } else if (mt == 3 || mt == 2) { // text / bytes — skip string
                    decode_text(data, off);
                } else if (mt == 4) { // array — skip all items
                    size_t n = cbor::decode_array(data, off);
                    for (size_t j = 0; j < n; ++j) {
                        // Recursive skip: re-read ib
                        if (off >= data.size()) break;
                        uint8_t ib2 = data[off];
                        uint8_t mt2 = ib2 >> 5;
                        if (mt2 == 0 || mt2 == 1) decode_uint(data, off);
                        else if (mt2 == 3 || mt2 == 2) decode_text(data, off);
                        else break;
                    }
                } else {
                    // Cannot skip — break to avoid infinite loop
                    break;
                }
                break;
            }
        }
    }

    token.bootstrap_endpoints = std::move(endpoints);
    return token;
}

// =========================================================================
// Token generation
// =========================================================================
Result<JoinToken> generate_token(
    const std::string& mesh_id,
    int64_t mesh_epoch,
    int cipher_suite_id,
    const std::vector<std::string>& bootstrap_endpoints,
    const std::string& role,
    int64_t expiry_unix_sec,
    const Bytes& hmac_secret,
    const HashImpl& hash
) {
    JoinToken token;
    token.version = 1;
    token.mesh_id = mesh_id;
    token.mesh_epoch = mesh_epoch;
    token.cipher_suite_id = cipher_suite_id;
    token.bootstrap_endpoints = bootstrap_endpoints;
    token.role = role;
    token.expiry_unix_sec = expiry_unix_sec;
    token.nonce = generate_nonce();

    auto payload = token.serialize_payload();
    auto hmac_result = hash.hmac(BytesView(hmac_secret), BytesView(payload));
    if (!hmac_result) {
        return SMO_ERR_CERT(212, Error, NoRetry, RetryOperation,
                            "HMAC computation failed");
    }
    token.hmac_hex = smo::bytes_to_hex(hmac_result.value());
    return token;
}

// =========================================================================
// Parse wire format
// =========================================================================
Result<JoinToken> parse_token(const std::string& token_str) {
    const char kPrefix[] = "SMO-JOIN-";
    if (token_str.size() < 9 || token_str.compare(0, 9, kPrefix) != 0) {
        return SMO_ERR_CERT(212, Error, NoRetry, ManualIntervention,
                            "Invalid Join Token: missing SMO-JOIN- prefix");
    }

    Bytes raw = base64url_decode(token_str.substr(9));

    // Need at least 1 byte of CBOR + 32 bytes HMAC
    if (raw.size() < 33) {
        return SMO_ERR_CERT(212, Error, NoRetry, ManualIntervention,
                            "Join Token too short");
    }

    // Split at the last 32 bytes (HMAC is always 32 bytes raw)
    size_t payload_len = raw.size() - 32;
    BytesView payload(raw.data(), payload_len);
    BytesView hmac_raw(raw.data() + payload_len, 32);

    auto token_result = JoinToken::deserialize_payload(payload);
    if (!token_result) return token_result.error();

    token_result.value().hmac_hex = smo::bytes_to_hex(hmac_raw);
    return token_result;
}

// =========================================================================
// Validate
// =========================================================================
Result<void> validate_token(const JoinToken& token, const Bytes& hmac_secret, const HashImpl& hash) {
    if (token.expiry_unix_sec > 0) {
        auto now_sec = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        if (now_sec > token.expiry_unix_sec) {
            return SMO_ERR_CERT(213, Warn, NoRetry, ManualIntervention,
                                "Join Token has expired");
        }
    }

    auto payload = token.serialize_payload();
    auto hmac_result = hash.hmac(BytesView(hmac_secret), BytesView(payload));
    if (!hmac_result) {
        return SMO_ERR_CERT(212, Error, NoRetry, RetryOperation,
                            "HMAC computation failed");
    }

    auto expected_hex = smo::bytes_to_hex(hmac_result.value());
    if (token.hmac_hex != expected_hex) {
        return SMO_ERR_CERT(212, Error, NoRetry, ManualIntervention,
                            "Join Token HMAC mismatch");
    }

    return {};
}

// =========================================================================
// Encode wire format
// =========================================================================
std::string encode_token_wire(const JoinToken& token) {
    auto payload = token.serialize_payload();

    Bytes hmac_raw;
    for (size_t i = 0; i + 1 < token.hmac_hex.size(); i += 2) {
        char buf[3] = {token.hmac_hex[i], token.hmac_hex[i+1], 0};
        hmac_raw.push_back(static_cast<uint8_t>(std::strtoul(buf, nullptr, 16)));
    }

    Bytes full;
    full.insert(full.end(), payload.begin(), payload.end());
    full.insert(full.end(), hmac_raw.begin(), hmac_raw.end());

    return "SMO-JOIN-" + base64url_encode(full);
}

} // namespace smo::enroll
