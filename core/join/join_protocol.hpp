#pragma once

#include "core/types.hpp"
#include "core/errors/error.hpp"
#include "core/bootstrap/cbor.hpp"
#include "core/mesh/mesh_manager.hpp"
#include "core/enroll/join_token.hpp"
#include "core/bootstrap/bootstrap_snapshot.hpp"
#include "core/network/packet_dispatcher.hpp"
#include "core/authority/authority.hpp"
#include "core/recovery/crl.hpp"

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
// Capability bitmap bits (uint64) for JOIN_REQUEST/JoinResponse
// negotiation and runtime capability discovery.
inline constexpr uint64_t CAP_DELTA_SYNC       = 1ULL << 0;
inline constexpr uint64_t CAP_COMPRESSION      = 1ULL << 1;
inline constexpr uint64_t CAP_CRT              = 1ULL << 2;
inline constexpr uint64_t CAP_CONTRACT_SYNC    = 1ULL << 3;
inline constexpr uint64_t CAP_ANTI_ENTROPY     = 1ULL << 4;
// Runtime capability negotiation bits (change 6)
inline constexpr uint64_t CAP_COMPRESSION_ZSTD = 1ULL << 5;  // supports zstd compression
inline constexpr uint64_t CAP_COMPRESSION_BROTLI = 1ULL << 6; // supports brotli compression
inline constexpr uint64_t CAP_STREAM_CONTRACT  = 1ULL << 7;  // supports stream contracts
inline constexpr uint64_t CAP_FILE_VAULT       = 1ULL << 8;  // supports file vault
inline constexpr uint64_t CAP_GPU_COMPUTE      = 1ULL << 9;  // supports GPU compute
inline constexpr uint64_t CAP_RUNTIME_NEGOTIATE = 1ULL << 10; // node supports extended runtime negotiation

struct JoinRequest {
    uint8_t version = 1;
    uint8_t protocol_version = 1;   // JOIN protocol version for future compat
    uint64_t capability_bitmap = 0;  // supported feature bits (CAP_*)
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
// Lightweight response: JOIN gives identity + bootstrap ticket, not world state.
// Full mesh sync (manifest, policy, seeds) is done via BOOTSTRAP_SYNC.
// CBOR keys:
//   1: certificate      (string — PEM-encoded certificate)
//   2: mesh_id          (string — mesh identifier)
//   3: bootstrap_ticket (bytes — opaque ticket for BOOTSTRAP_SYNC auth)

struct JoinResponse {
    uint8_t version = 1;
    std::array<uint8_t, 8> nonce{};    // echoes request nonce
    std::string certificate_pem;        // PEM-encoded certificate
    std::string mesh_id;                // assigned mesh_id
    Bytes bootstrap_ticket;             // opaque ticket for BOOTSTRAP_SYNC
    int64_t server_time = 0;            // UNIX ms — Authority's clock (for drift correction)
    uint64_t capability_bitmap = 0;     // echoed from request, filtered by Authority

    Bytes encode_cbor() const;
    static Result<JoinResponse> decode_cbor(BytesView data);
};

// ── BootstrapSync Request/Response ───────────────────────────────────

// Revision-based delta sync request.
// CBOR keys:
//   1: mesh_id           (string)
//   2: node_id           (string)
//   3: manifest_revision (uint — known manifest revision, 0 = none)
//   4: crl_revision      (uint — known CRL revision, 0 = none)
//   5: membership_revision (uint — known membership revision, 0 = none)
//   6: policy_revision   (uint — known policy revision, 0 = none)
//   9: bootstrap_ticket  (bytes — opaque ticket from JoinResponse)
struct BootstrapSyncRequest {
    uint8_t version = 1;
    uint8_t protocol_version = 1;
    std::array<uint8_t, 8> nonce{};
    std::string mesh_id;
    std::string node_id;
    Bytes bootstrap_ticket;           // opaque ticket from JoinResponse
    uint64_t manifest_revision = 0;
    uint64_t crl_revision = 0;
    uint64_t membership_revision = 0;
    uint64_t policy_revision = 0;

    Bytes encode_cbor() const;
    static Result<BootstrapSyncRequest> decode_cbor(BytesView data);
};

// Delta sync response: only send changed components.
// CBOR keys:
//   1: manifest_delta    (bytes — present if manifest_revision > known)
//   2: membership_delta  (bytes — present if membership_revision > known)
//   3: policy_delta      (bytes — present if policy_revision > known)
//   4: crl_delta         (bytes — present if crl_revision > known)
//   5: manifest_revision (uint — current manifest revision)
//   6: membership_revision (uint — current membership revision)
//   7: crl_revision      (uint — current CRL revision)
//   8: policy_revision   (uint — current policy revision)
// Plus seed info for gossip bootstrap.
//  11: seeds            (array — SeedInfo with endpoint/region/weight/health_score)
struct BootstrapSyncResponse {
    uint8_t version = 1;
    std::array<uint8_t, 8> nonce{};   // echoes request nonce
    Bytes manifest_delta;             // manifest CBOR if changed
    Bytes membership_delta;           // membership delta if changed
    Bytes policy_delta;               // policy delta if changed
    Bytes crl_delta;                  // CRL entries since known revision
    uint64_t manifest_revision = 0;
    uint64_t membership_revision = 0;
    uint64_t crl_revision = 0;
    uint64_t policy_revision = 0;
    std::vector<SeedInfo> seeds;      // seed endpoints for gossip (moved from JOIN_RESPONSE)
    int64_t server_time = 0;          // UNIX ms — server's clock

    Bytes encode_cbor() const;
    static Result<BootstrapSyncResponse> decode_cbor(BytesView data);
};

// ── Join State Machine ────────────────────────────────────────────────
// States per DISCUSSION_0039 §5.21

enum class JoinState : int64_t {
    NEW             = 0,
    TOKEN_RECEIVED  = 1,
    CSR_CREATED     = 2,
    JOIN_SENT       = 3,
    WAIT_RESPONSE   = 4,
    CERT_RECEIVED   = 5,
    CERT_VERIFY     = 6,
    BOOTSTRAP_SYNC  = 7,
    WAIT_SYNC       = 8,
    GOSSIP_SYNC     = 9,
    WAIT_GOSSIP     = 10,
    READY           = 11,
    FAILED          = -1,
};

enum class JoinEvent : int64_t {
    TOKEN_PARSED    = 100,
    CSR_BUILT       = 101,
    MSG_SENT        = 102,
    RESPONSE_RCVD   = 103,
    CERT_VERIFIED   = 104,
    CERT_INVALID    = 105,
    SYNC_REQUESTED  = 106,
    SYNC_COMPLETE   = 107,
    GOSSIP_STARTED  = 108,
    GOSSIP_COMPLETE = 109,
    TIMEOUT         = 110,
    RETRY           = 111,
    FAIL            = 112,
};

// Build transition table for the join FSM
std::vector<smo::TransitionRule> join_transition_table();
std::vector<smo::StateTimeout> join_timeout_table();

// ── Handler declarations ─────────────────────────────────────────────

// Process a JoinRequest (raw CBOR protocol) — validates token, verifies
// CSR, issues certificate, returns JoinResponse.
Result<JoinResponse> process_join_request(
    const JoinRequest& req,
    MeshManager& mesh_mgr,
    authority::MeshAuthority& authority);

// Process a BootstrapSyncRequest — builds delta sync response from
// current mesh state (manifest/membership/policy/CRL deltas).
Result<BootstrapSyncResponse> process_bootstrap_sync(
    const BootstrapSyncRequest& req,
    MeshManager& mesh_mgr,
    authority::MeshAuthority& authority,
    recovery::CRL* crl);

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
