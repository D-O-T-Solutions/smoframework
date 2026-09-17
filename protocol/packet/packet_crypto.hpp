#pragma once

#include "packet.h"
#include "../../core/session/session_crypto_context.hpp"

namespace smo {

// RFC 0019 DATA-plane AEAD nonce: BLAKE3(session_id || wire_nonce_be8)[0:24].
// `wire_nonce` is the canonical 8-byte sequence from the packet header.
Bytes derive_aead_nonce(BytesView session_id, uint64_t wire_nonce);

// Seal a DATA-plane packet. Sets the canonical header fields (protocol_version,
// nonce = sequence, payload_length), derives nonce24 from
// header.session_id + sequence, encrypts payload with AAD = canonical 39B
// header, then splits ciphertext||tag into packet.payload / packet.auth (16B).
//
// `key` is the opaque TX capability only — an RX key cannot be passed (B2a).
Result<void> packet_seal_data(Packet& packet, const PacketTxKey& key, uint64_t sequence);

// Verify + decrypt a DATA-plane packet using AAD = canonical 39B header.
// On failure `packet` is left unchanged and replay state MUST NOT be committed.
// On success packet.payload holds the plaintext and packet.auth is cleared.
Result<void> packet_open_data(Packet& packet, const PacketRxKey& key);

} // namespace smo
