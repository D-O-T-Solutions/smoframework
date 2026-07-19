#include "join_protocol.hpp"

#include "core/bootstrap/cbor.hpp"
#include "core/opcode/opcode.h"
#include "core/crypto/suite.hpp"
#include "core/crypto/impl.hpp"
#include "core/enroll/join_token.hpp"
#include "core/errors/error.hpp"

#include <random>
#include <chrono>

namespace smo::join {

// ── CBOR key constants ──────────────────────────────────────────────
namespace {
// JoinRequest keys (DISCUSSION_0039 §5.17)
constexpr uint64_t K_REQ_TOKEN     = 1;
constexpr uint64_t K_REQ_CSR       = 2;
constexpr uint64_t K_REQ_TIMESTAMP = 3;
constexpr uint64_t K_REQ_NONCE     = 4;
constexpr uint64_t K_REQ_CSR_HASH  = 5;
constexpr uint64_t K_REQ_SIG       = 6;

// JoinResponse keys (DISCUSSION_0039 §5.1)
constexpr uint64_t K_RESP_CERT     = 1;
constexpr uint64_t K_RESP_MESH_ID  = 2;
constexpr uint64_t K_RESP_MF_DIGEST = 3;
constexpr uint64_t K_RESP_MF_EPOCH = 4;
constexpr uint64_t K_RESP_BOOT_NODES = 5;
constexpr uint64_t K_RESP_NONCE    = 6;

// BootstrapSyncRequest keys (DISCUSSION_0039 §5.2)
constexpr uint64_t K_SYNC_REQ_MESH_ID = 1;
constexpr uint64_t K_SYNC_REQ_NODE_ID = 2;
constexpr uint64_t K_SYNC_REQ_MF_EPOCH = 3;
constexpr uint64_t K_SYNC_REQ_CRL_EPOCH = 4;
constexpr uint64_t K_SYNC_REQ_MEMBER_EPOCH = 5;
constexpr uint64_t K_SYNC_REQ_POLICY_VER = 6;

// BootstrapSyncResponse keys (DISCUSSION_0039 §5.4)
constexpr uint64_t K_SYNC_RESP_MF_DELTA   = 1;
constexpr uint64_t K_SYNC_RESP_MEMBER_DELTA = 2;
constexpr uint64_t K_SYNC_RESP_POLICY_DELTA = 3;
constexpr uint64_t K_SYNC_RESP_CRL_DELTA   = 4;
constexpr uint64_t K_SYNC_RESP_MF_EPOCH    = 5;
constexpr uint64_t K_SYNC_RESP_MEMBER_EPOCH = 6;
constexpr uint64_t K_SYNC_RESP_CRL_EPOCH   = 7;
constexpr uint64_t K_SYNC_RESP_POLICY_VER  = 8;
} // anonymous namespace

// ── JoinRequest ──────────────────────────────────────────────────────
Bytes JoinRequest::encode_cbor() const {
    cbor::Encoder enc;
    int fields = 2; // token + csr
    if (timestamp > 0) fields++;
    if (csr_hash.size() > 0) fields++;
    if (request_signature.size() > 0) fields++;
    fields++; // nonce always present
    enc.encode_map(fields);
    enc.encode_uint(K_REQ_TOKEN); enc.encode_string(token);
    enc.encode_uint(K_REQ_CSR); enc.encode_string(csr_pem);
    if (timestamp > 0) { enc.encode_uint(K_REQ_TIMESTAMP); enc.encode_int(timestamp); }
    enc.encode_uint(K_REQ_NONCE); enc.encode_bytes(BytesView(nonce.data(), nonce.size()));
    if (csr_hash.size() > 0) { enc.encode_uint(K_REQ_CSR_HASH); enc.encode_bytes(BytesView(csr_hash)); }
    if (request_signature.size() > 0) { enc.encode_uint(K_REQ_SIG); enc.encode_bytes(BytesView(request_signature)); }
    return enc.take();
}

Result<JoinRequest> JoinRequest::decode_cbor(BytesView data) {
    cbor::Decoder dec(data);
    JoinRequest req;
    auto map_sz = dec.decode_map_size();
    if (!map_sz) return map_sz.error();

    for (size_t i = 0; i < map_sz.value(); ++i) {
        auto key = dec.decode_uint();
        if (!key) return key.error();
        switch (key.value()) {
            case K_REQ_TOKEN: {
                auto v = dec.decode_string(); if (!v) return v.error();
                req.token = std::move(v.value()); break;
            }
            case K_REQ_CSR: {
                auto v = dec.decode_string(); if (!v) return v.error();
                req.csr_pem = std::move(v.value()); break;
            }
            case K_REQ_TIMESTAMP: {
                auto v = dec.decode_int(); if (!v) return v.error();
                req.timestamp = v.value(); break;
            }
            case K_REQ_NONCE: {
                auto v = dec.decode_bytes(); if (!v) return v.error();
                if (v.value().size() == 8) std::memcpy(req.nonce.data(), v.value().data(), 8);
                break;
            }
            case K_REQ_CSR_HASH: {
                auto v = dec.decode_bytes(); if (!v) return v.error();
                req.csr_hash = Bytes(v.value().begin(), v.value().end()); break;
            }
            case K_REQ_SIG: {
                auto v = dec.decode_bytes(); if (!v) return v.error();
                req.request_signature = Bytes(v.value().begin(), v.value().end()); break;
            }
            default: {
                auto r = dec.skip(); if (!r) return r.error();
            }
        }
    }
    return req;
}

// ── JoinResponse ────────────────────────────────────────────────────
Bytes JoinResponse::encode_cbor() const {
    cbor::Encoder enc;
    int fields = 0;
    if (!certificate_pem.empty()) fields++;
    if (!mesh_id.empty()) fields++;
    if (!manifest_digest.empty()) fields++;
    if (manifest_epoch > 0) fields++;
    if (!bootstrap_nodes.empty()) fields++;
    fields++; // nonce always present
    if (fields == 0) fields = 1; // at least empty map
    enc.encode_map(fields);
    if (!certificate_pem.empty()) { enc.encode_uint(K_RESP_CERT); enc.encode_string(certificate_pem); }
    if (!mesh_id.empty()) { enc.encode_uint(K_RESP_MESH_ID); enc.encode_string(mesh_id); }
    if (!manifest_digest.empty()) { enc.encode_uint(K_RESP_MF_DIGEST); enc.encode_bytes(BytesView(manifest_digest)); }
    if (manifest_epoch > 0) { enc.encode_uint(K_RESP_MF_EPOCH); enc.encode_uint(manifest_epoch); }
    if (!bootstrap_nodes.empty()) {
        enc.encode_uint(K_RESP_BOOT_NODES);
        enc.encode_array(bootstrap_nodes.size());
        for (auto& ep : bootstrap_nodes) enc.encode_string(ep);
    }
    enc.encode_uint(K_RESP_NONCE); enc.encode_bytes(BytesView(nonce.data(), nonce.size()));
    return enc.take();
}

Result<JoinResponse> JoinResponse::decode_cbor(BytesView data) {
    cbor::Decoder dec(data);
    JoinResponse resp;
    auto map_sz = dec.decode_map_size();
    if (!map_sz) return map_sz.error();

    for (size_t i = 0; i < map_sz.value(); ++i) {
        auto key = dec.decode_uint();
        if (!key) return key.error();
        switch (key.value()) {
            case K_RESP_CERT: {
                auto v = dec.decode_string(); if (!v) return v.error();
                resp.certificate_pem = std::move(v.value()); break;
            }
            case K_RESP_MESH_ID: {
                auto v = dec.decode_string(); if (!v) return v.error();
                resp.mesh_id = std::move(v.value()); break;
            }
            case K_RESP_MF_DIGEST: {
                auto v = dec.decode_bytes(); if (!v) return v.error();
                resp.manifest_digest = Bytes(v.value().begin(), v.value().end()); break;
            }
            case K_RESP_MF_EPOCH: {
                auto v = dec.decode_uint(); if (!v) return v.error();
                resp.manifest_epoch = v.value(); break;
            }
            case K_RESP_BOOT_NODES: {
                auto arr_sz = dec.decode_array_size(); if (!arr_sz) return arr_sz.error();
                for (size_t j = 0; j < arr_sz.value(); ++j) {
                    auto s = dec.decode_string(); if (!s) return s.error();
                    resp.bootstrap_nodes.push_back(std::move(s.value()));
                }
                break;
            }
            case K_RESP_NONCE: {
                auto v = dec.decode_bytes(); if (!v) return v.error();
                if (v.value().size() == 8) std::memcpy(resp.nonce.data(), v.value().data(), 8);
                break;
            }
            default: {
                auto r = dec.skip(); if (!r) return r.error();
            }
        }
    }
    return resp;
}

// ── BootstrapSyncRequest ───────────────────────────────────────────
Bytes BootstrapSyncRequest::encode_cbor() const {
    cbor::Encoder enc;
    int fields = 0;
    if (!mesh_id.empty()) fields++;
    if (!node_id.empty()) fields++;
    if (manifest_epoch > 0) fields++;
    if (crl_epoch > 0) fields++;
    if (membership_epoch > 0) fields++;
    if (policy_version > 0) fields++;
    enc.encode_map(fields);
    if (!mesh_id.empty()) { enc.encode_uint(K_SYNC_REQ_MESH_ID); enc.encode_string(mesh_id); }
    if (!node_id.empty()) { enc.encode_uint(K_SYNC_REQ_NODE_ID); enc.encode_string(node_id); }
    if (manifest_epoch > 0) { enc.encode_uint(K_SYNC_REQ_MF_EPOCH); enc.encode_uint(manifest_epoch); }
    if (crl_epoch > 0) { enc.encode_uint(K_SYNC_REQ_CRL_EPOCH); enc.encode_uint(crl_epoch); }
    if (membership_epoch > 0) { enc.encode_uint(K_SYNC_REQ_MEMBER_EPOCH); enc.encode_uint(membership_epoch); }
    if (policy_version > 0) { enc.encode_uint(K_SYNC_REQ_POLICY_VER); enc.encode_uint(policy_version); }
    return enc.take();
}

Result<BootstrapSyncRequest> BootstrapSyncRequest::decode_cbor(BytesView data) {
    cbor::Decoder dec(data);
    BootstrapSyncRequest req;
    auto map_sz = dec.decode_map_size();
    if (!map_sz) return map_sz.error();

    for (size_t i = 0; i < map_sz.value(); ++i) {
        auto key = dec.decode_uint();
        if (!key) return key.error();
        switch (key.value()) {
            case K_SYNC_REQ_MESH_ID: {
                auto v = dec.decode_string(); if (!v) return v.error();
                req.mesh_id = std::move(v.value()); break;
            }
            case K_SYNC_REQ_NODE_ID: {
                auto v = dec.decode_string(); if (!v) return v.error();
                req.node_id = std::move(v.value()); break;
            }
            case K_SYNC_REQ_MF_EPOCH: {
                auto v = dec.decode_uint(); if (!v) return v.error();
                req.manifest_epoch = v.value(); break;
            }
            case K_SYNC_REQ_CRL_EPOCH: {
                auto v = dec.decode_uint(); if (!v) return v.error();
                req.crl_epoch = v.value(); break;
            }
            case K_SYNC_REQ_MEMBER_EPOCH: {
                auto v = dec.decode_uint(); if (!v) return v.error();
                req.membership_epoch = v.value(); break;
            }
            case K_SYNC_REQ_POLICY_VER: {
                auto v = dec.decode_uint(); if (!v) return v.error();
                req.policy_version = v.value(); break;
            }
            default: {
                auto r = dec.skip(); if (!r) return r.error();
            }
        }
    }
    return req;
}

// ── BootstrapSyncResponse ───────────────────────────────────────────
Bytes BootstrapSyncResponse::encode_cbor() const {
    cbor::Encoder enc;
    int fields = 0;
    if (!manifest_delta.empty()) fields++;
    if (!membership_delta.empty()) fields++;
    if (!policy_delta.empty()) fields++;
    if (!crl_delta.empty()) fields++;
    if (manifest_epoch > 0) fields++;
    if (membership_epoch > 0) fields++;
    if (crl_epoch > 0) fields++;
    if (policy_version > 0) fields++;
    if (fields == 0) fields = 1;
    enc.encode_map(fields);
    if (!manifest_delta.empty()) { enc.encode_uint(K_SYNC_RESP_MF_DELTA); enc.encode_bytes(BytesView(manifest_delta)); }
    if (!membership_delta.empty()) { enc.encode_uint(K_SYNC_RESP_MEMBER_DELTA); enc.encode_bytes(BytesView(membership_delta)); }
    if (!policy_delta.empty()) { enc.encode_uint(K_SYNC_RESP_POLICY_DELTA); enc.encode_bytes(BytesView(policy_delta)); }
    if (!crl_delta.empty()) { enc.encode_uint(K_SYNC_RESP_CRL_DELTA); enc.encode_bytes(BytesView(crl_delta)); }
    if (manifest_epoch > 0) { enc.encode_uint(K_SYNC_RESP_MF_EPOCH); enc.encode_uint(manifest_epoch); }
    if (membership_epoch > 0) { enc.encode_uint(K_SYNC_RESP_MEMBER_EPOCH); enc.encode_uint(membership_epoch); }
    if (crl_epoch > 0) { enc.encode_uint(K_SYNC_RESP_CRL_EPOCH); enc.encode_uint(crl_epoch); }
    if (policy_version > 0) { enc.encode_uint(K_SYNC_RESP_POLICY_VER); enc.encode_uint(policy_version); }
    return enc.take();
}

Result<BootstrapSyncResponse> BootstrapSyncResponse::decode_cbor(BytesView data) {
    cbor::Decoder dec(data);
    BootstrapSyncResponse resp;
    auto map_sz = dec.decode_map_size();
    if (!map_sz) return map_sz.error();

    for (size_t i = 0; i < map_sz.value(); ++i) {
        auto key = dec.decode_uint();
        if (!key) return key.error();
        switch (key.value()) {
            case K_SYNC_RESP_MF_DELTA: {
                auto v = dec.decode_bytes(); if (!v) return v.error();
                resp.manifest_delta = Bytes(v.value().begin(), v.value().end()); break;
            }
            case K_SYNC_RESP_MEMBER_DELTA: {
                auto v = dec.decode_bytes(); if (!v) return v.error();
                resp.membership_delta = Bytes(v.value().begin(), v.value().end()); break;
            }
            case K_SYNC_RESP_POLICY_DELTA: {
                auto v = dec.decode_bytes(); if (!v) return v.error();
                resp.policy_delta = Bytes(v.value().begin(), v.value().end()); break;
            }
            case K_SYNC_RESP_CRL_DELTA: {
                auto v = dec.decode_bytes(); if (!v) return v.error();
                resp.crl_delta = Bytes(v.value().begin(), v.value().end()); break;
            }
            case K_SYNC_RESP_MF_EPOCH: {
                auto v = dec.decode_uint(); if (!v) return v.error();
                resp.manifest_epoch = v.value(); break;
            }
            case K_SYNC_RESP_MEMBER_EPOCH: {
                auto v = dec.decode_uint(); if (!v) return v.error();
                resp.membership_epoch = v.value(); break;
            }
            case K_SYNC_RESP_CRL_EPOCH: {
                auto v = dec.decode_uint(); if (!v) return v.error();
                resp.crl_epoch = v.value(); break;
            }
            case K_SYNC_RESP_POLICY_VER: {
                auto v = dec.decode_uint(); if (!v) return v.error();
                resp.policy_version = v.value(); break;
            }
            default: {
                auto r = dec.skip(); if (!r) return r.error();
            }
        }
    }
    return resp;
}

} // namespace smo::join
