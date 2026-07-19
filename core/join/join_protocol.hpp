#pragma once

#include "core/types.hpp"
#include "core/errors/error.hpp"
#include "core/bootstrap/cbor.hpp"
#include "core/mesh/mesh_manager.hpp"
#include "core/enroll/join_token.hpp"
#include "core/bootstrap/bootstrap_snapshot.hpp"
#include "core/network/packet_dispatcher.hpp"

#include <cstdint>
#include <vector>
#include <array>
#include <string>

namespace smo::join {

// ── Protocol constants ────────────────────────────────────────────────

// JOIN namespace (RFC 0020 - 0x06 reserved for JOIN)
inline constexpr uint8_t kNamespaceJoin = 0x06;

// Message IDs within JOIN namespace
inline constexpr uint16_t kMsgJoinRequest       = 0x0001;
inline constexpr uint16_t kMsgJoinResponse      = 0x0002;
inline constexpr uint16_t kMsgBootstrapSyncReq  = 0x0003;
inline constexpr uint16_t kMsgBootstrapSyncResp = 0x0004;

// Combined opcode_id for Packet (namespace << 8 | message_id)
inline constexpr uint32_t kOpcodeJoinRequest        = 0x0601;
inline constexpr uint32_t kOpcodeJoinResponse       = 0x0602;
inline constexpr uint32_t kOpcodeBootstrapSyncReq   = 0x0603;
inline constexpr uint32_t kOpcodeBootstrapSyncResp  = 0x0604;

// ── JoinRequest ──────────────────────────────────────────────────────
// Sent by joining node to bootstrap endpoint.
// CBOR keys (per DISCUSSION_0039 §5.17):
//   1: token_wire      (string — SMO-JOIN-xxxx token)
//   2: csr_cbor        (bytes — CSR)
//   3: timestamp       (uint — UNIX seconds)
//   4: nonce           (bytes — 64-bit random per-request)
//   5: csr_hash        (bytes — sha256(csr_cbor))
//   6: request_signature (bytes — sign(token_wire || timestamp || nonce || csr_hash))
struct JoinRequest {
    uint8_t version = 1;
    std::string token;              // SMO-JOIN-xxxx token wire format
    std::string csr_pem;            // PEM-encoded CSR
    int64_t timestamp = 0;          // UNIX seconds (±30s window)
    std::array<uint8_t, 8> nonce{}; // 64-bit random per-request
    Bytes csr_hash;                 // sha256(csr_pem)
    Bytes request_signature;        // signature over (token || timestamp || nonce || csr_hash)

    Bytes encode_cbor() const;
    static Result<JoinRequest> decode_cbor(BytesView data);
};

// ── JoinResponse ─────────────────────────────────────────────────────
// Lightweight response: JOIN gives identity, not world state.
// CBOR keys (per DISCUSSION_0039 §5.1):
//   1: certificate      (string — PEM-encoded certificate)
//   2: mesh_id          (string — mesh identifier)
//   3: manifest_digest  (bytes — sha256 of current manifest)
//   4: manifest_epoch   (uint — current manifest epoch)
//   5: bootstrap_nodes  (array of string — seed endpoints)
struct JoinResponse {
    uint8_t version = 1;
    std::array<uint8_t, 8> nonce{};    // echoes request nonce
    std::string certificate_pem;        // PEM-encoded certificate
    std::string mesh_id;                // assigned mesh_id
    Bytes manifest_digest;              // sha256 of current manifest (optional)
    uint64_t manifest_epoch = 0;        // current manifest epoch
    std::vector<std::string> bootstrap_nodes; // seed endpoints to start gossip

    Bytes encode_cbor() const;
    static Result<JoinResponse> decode_cbor(BytesView data);
};

// ── BootstrapSync Request/Response ───────────────────────────────────

// Epoch-based delta sync request.
// CBOR keys (per DISCUSSION_0039 §5.2):
//   1: mesh_id           (string)
//   2: node_id           (string)
//   3: manifest_epoch    (uint — known manifest epoch, 0 = none)
//   4: crl_epoch         (uint — known CRL epoch, 0 = none)
//   5: membership_epoch  (uint — known membership epoch, 0 = none)
//   6: policy_version    (uint — known policy version, 0 = none)
struct BootstrapSyncRequest {
    uint8_t version = 1;
    std::array<uint8_t, 8> nonce{};
    std::string mesh_id;
    std::string node_id;
    uint64_t manifest_epoch = 0;
    uint64_t crl_epoch = 0;
    uint64_t membership_epoch = 0;
    uint64_t policy_version = 0;

    Bytes encode_cbor() const;
    static Result<BootstrapSyncRequest> decode_cbor(BytesView data);
};

// Delta sync response: only send changed components.
// CBOR keys (per DISCUSSION_0039 §5.4):
//   1: manifest_delta    (bytes — present if manifest_epoch > known)
//   2: membership_delta  (bytes — present if membership_epoch > known)
//   3: policy_delta      (bytes — present if policy_version > known)
//   4: crl_delta         (bytes — present if crl_epoch > known)
//   5: manifest_epoch    (uint — current manifest epoch)
//   6: membership_epoch  (uint — current membership epoch)
//   7: crl_epoch         (uint — current CRL epoch)
//   8: policy_version    (uint — current policy version)
struct BootstrapSyncResponse {
    uint8_t version = 1;
    std::array<uint8_t, 8> nonce{};   // echoes request nonce
    Bytes manifest_delta;             // manifest CBOR if changed
    Bytes membership_delta;           // membership delta if changed
    Bytes policy_delta;               // policy delta if changed
    Bytes crl_delta;                  // CRL entries since known epoch
    uint64_t manifest_epoch = 0;
    uint64_t membership_epoch = 0;
    uint64_t crl_epoch = 0;
    uint64_t policy_version = 0;

    Bytes encode_cbor() const;
    static Result<BootstrapSyncResponse> decode_cbor(BytesView data);
};

// ── Handler declarations ─────────────────────────────────────────────

Result<void> handle_join_request(
    const JoinRequest& req,
    smo::MeshManager& mesh_mgr,
    const std::string& home);

Result<void> handle_bootstrap_sync(
    const BootstrapSyncRequest& req,
    const std::string& home);

void register_join_handler(
    network::PacketDispatcher& dispatcher,
    const std::string& home);

} // namespace smo::join

// ── CBOR helpers ─────────────────────────────────────────────────────
namespace smo {
    inline void cbor_encode_string_array(cbor::Encoder& enc, const std::vector<std::string>& vec) {
        enc.encode_array(vec.size());
        for (auto& s : vec) enc.encode_string(s);
    }

    inline std::vector<std::string> cbor_decode_string_array(cbor::Decoder& dec, size_t n) {
        std::vector<std::string> vec;
        vec.reserve(n);
        for (size_t i = 0; i < n; ++i) {
            auto s = dec.decode_string();
            if (!s) return std::vector<std::string>();
            vec.push_back(std::move(s.value()));
        }
        return vec;
    }
}
