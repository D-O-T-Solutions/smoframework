#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include "core/types.hpp"
#include "core/errors/error.hpp"
#include "core/crypto/impl.hpp"

namespace smo::enroll {

// ---------------------------------------------------------------------------
// Join Token v1 — CBOR-encoded bootstrap credential
//
// Wire format:
//   SMO-JOIN-<base64url(CBOR(payload) || HMAC)>
//
// CBOR payload (map, keyed):
//   1: version         (uint)
//   2: mesh_id         (tstr)
//   3: mesh_epoch      (uint)
//   4: cipher_suite_id (uint)
//   5: endpoints       (array of tstr)
//   6: role            (tstr)
//   7: expiry          (uint — unix seconds, 0 = no expiry)
//   8: nonce           (tstr — 32 hex chars)
//
// HMAC is computed over the CBOR payload bytes, then appended as raw 32 bytes
// before base64url encoding.
// ---------------------------------------------------------------------------

struct JoinToken {
    uint8_t     version = 1;
    std::string mesh_id;
    int64_t     mesh_epoch = 0;
    int         cipher_suite_id = 0;
    std::vector<std::string> bootstrap_endpoints;
    std::string role;
    int64_t     expiry_unix_sec = 0;  // 0 = no expiry
    std::string nonce;                // 32 hex chars (16 random bytes)

    // Computed (set after generate/parse)
    std::string hmac_hex;

    Bytes serialize_payload() const;
    static Result<JoinToken> deserialize_payload(BytesView data);
};

// ---- CBOR helpers (internal) -------------------------------------------
namespace cbor {

void encode_uint(Bytes& out, uint64_t val);
void encode_text(Bytes& out, const std::string& s);
void encode_array(Bytes& out, size_t n);
void encode_map(Bytes& out, size_t n);

uint64_t     decode_uint(BytesView data, size_t& off);
std::string  decode_text(BytesView data, size_t& off);
size_t       decode_array(BytesView data, size_t& off);
size_t       decode_map(BytesView data, size_t& off);

} // namespace cbor

// ---- Token API -----------------------------------------------------------

Result<JoinToken> generate_token(
    const std::string& mesh_id,
    int64_t mesh_epoch,
    int cipher_suite_id,
    const std::vector<std::string>& bootstrap_endpoints,
    const std::string& role,
    int64_t expiry_unix_sec,
    const Bytes& hmac_secret,
    const HashImpl& hash
);

Result<JoinToken> parse_token(const std::string& token_str);
Result<void> validate_token(const JoinToken& token, const Bytes& hmac_secret, const HashImpl& hash);
std::string encode_token_wire(const JoinToken& token);

} // namespace smo::enroll
