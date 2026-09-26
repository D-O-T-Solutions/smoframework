#include "federation_handshake.hpp"

#include <core/crypto/impl.hpp>
#include <core/crypto/registry.hpp>
#include <core/identity/identity.hpp>
#include <core/runtime/telemetry.hpp>

#include <chrono>
#include <fstream>
#include <iostream>
#include <sstream>

namespace smo::federation {

static int64_t now_ns()
{
    return static_cast<int64_t>(std::chrono::system_clock::now().time_since_epoch().count());
}

static Bytes sign_data(const CryptoProvider& crypto, RngRef& rng, BytesView data, BytesView signing_key)
{
    auto sign_result = crypto.signer.sign(data, signing_key, rng);
    if (!sign_result)
    {
        return {};
    }
    return sign_result.value();
}

static bool verify_signature(const CryptoProvider& crypto, BytesView data, BytesView signature, BytesView pubkey)
{
    auto verify_result = crypto.signer.verify(data, signature, pubkey);
    return verify_result && verify_result.value();
}

// ============================================================================
// FederationHello
// ============================================================================

Bytes FederationHello::serialize() const
{
    Bytes out;
    auto write_string = [&out](const std::string& s) {
        uint32_t len = static_cast<uint32_t>(s.size());
        out.push_back(static_cast<uint8_t>((len >> 24) & 0xFF));
        out.push_back(static_cast<uint8_t>((len >> 16) & 0xFF));
        out.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(len & 0xFF));
        out.insert(out.end(), s.begin(), s.end());
    };

    auto write_bytes = [&out](const Bytes& b) {
        uint32_t len = static_cast<uint32_t>(b.size());
        out.push_back(static_cast<uint8_t>((len >> 24) & 0xFF));
        out.push_back(static_cast<uint8_t>((len >> 16) & 0xFF));
        out.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(len & 0xFF));
        out.insert(out.end(), b.begin(), b.end());
    };

    write_string(local_mesh_id);
    write_string(local_gateway_node_id);

    uint32_t suite_count = static_cast<uint32_t>(supported_suites.size());
    out.push_back(static_cast<uint8_t>((suite_count >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((suite_count >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((suite_count >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(suite_count & 0xFF));
    for (const auto& suite : supported_suites)
    {
        write_string(suite);
    }

    write_string(authority_pubkey);
    write_string(root_pubkey);

    for (int i = 7; i >= 0; --i)
        out.push_back(static_cast<uint8_t>((epoch >> (i * 8)) & 0xFF));
    for (int i = 7; i >= 0; --i)
        out.push_back(static_cast<uint8_t>((timestamp >> (i * 8)) & 0xFF));

    return out;
}

Result<FederationHello> FederationHello::deserialize(BytesView data)
{
    FederationHello hello;
    size_t offset = 0;

    auto read_string = [&data, &offset](std::string& s) -> Result<void> {
        if (offset + 4 > data.size())
            return Error(ErrorCode(ErrorCategory::Serialization, 1, Severity::Error,
                                   RetryClass::NoRetry, Recovery::None), "Truncated string length", __FILE__, __LINE__);
        uint32_t len = (static_cast<uint32_t>(data[offset]) << 24) |
                       (static_cast<uint32_t>(data[offset + 1]) << 16) |
                       (static_cast<uint32_t>(data[offset + 2]) << 8) |
                       static_cast<uint32_t>(data[offset + 3]);
        offset += 4;
        if (offset + len > data.size())
            return Error(ErrorCode(ErrorCategory::Serialization, 2, Severity::Error,
                                   RetryClass::NoRetry, Recovery::None), "Truncated string data", __FILE__, __LINE__);
        s.assign(reinterpret_cast<const char*>(data.data() + offset), len);
        offset += len;
        return {};
    };

    auto read_bytes = [&data, &offset](Bytes& b) -> Result<void> {
        if (offset + 4 > data.size())
            return Error(ErrorCode(ErrorCategory::Serialization, 3, Severity::Error,
                                   RetryClass::NoRetry, Recovery::None), "Truncated bytes length", __FILE__, __LINE__);
        uint32_t len = (static_cast<uint32_t>(data[offset]) << 24) |
                       (static_cast<uint32_t>(data[offset + 1]) << 16) |
                       (static_cast<uint32_t>(data[offset + 2]) << 8) |
                       static_cast<uint32_t>(data[offset + 3]);
        offset += 4;
        if (offset + len > data.size())
            return Error(ErrorCode(ErrorCategory::Serialization, 4, Severity::Error,
                                   RetryClass::NoRetry, Recovery::None), "Truncated bytes data", __FILE__, __LINE__);
        b.assign(data.data() + offset, data.data() + offset + len);
        offset += len;
        return {};
    };

    auto res = read_string(hello.local_mesh_id);
    if (!res) return res.error();
    res = read_string(hello.local_gateway_node_id);
    if (!res) return res.error();

    if (offset + 4 > data.size())
        return Error(ErrorCode(ErrorCategory::Serialization, 5, Severity::Error,
                               RetryClass::NoRetry, Recovery::None), "Truncated suite count", __FILE__, __LINE__);
    uint32_t suite_count = (static_cast<uint32_t>(data[offset]) << 24) |
                           (static_cast<uint32_t>(data[offset + 1]) << 16) |
                           (static_cast<uint32_t>(data[offset + 2]) << 8) |
                           static_cast<uint32_t>(data[offset + 3]);
    offset += 4;
    hello.supported_suites.reserve(suite_count);
    for (uint32_t i = 0; i < suite_count; ++i)
    {
        std::string suite;
        res = read_string(suite);
        if (!res) return res.error();
        hello.supported_suites.push_back(std::move(suite));
    }

    res = read_string(hello.authority_pubkey);
    if (!res) return res.error();
    res = read_string(hello.root_pubkey);
    if (!res) return res.error();

    if (offset + 8 > data.size())
        return Error(ErrorCode(ErrorCategory::Serialization, 6, Severity::Error,
                               RetryClass::NoRetry, Recovery::None), "Truncated epoch", __FILE__, __LINE__);
    hello.epoch = 0;
    for (int i = 0; i < 8; ++i)
        hello.epoch = (hello.epoch << 8) | data[offset++];
    hello.timestamp = 0;
    for (int i = 0; i < 8; ++i)
        hello.timestamp = (hello.timestamp << 8) | data[offset++];

    return hello;
}

// ============================================================================
// FederationAuth
// ============================================================================

Bytes FederationAuth::serialize() const
{
    Bytes out;
    auto write_string = [&out](const std::string& s) {
        uint32_t len = static_cast<uint32_t>(s.size());
        out.push_back(static_cast<uint8_t>((len >> 24) & 0xFF));
        out.push_back(static_cast<uint8_t>((len >> 16) & 0xFF));
        out.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(len & 0xFF));
        out.insert(out.end(), s.begin(), s.end());
    };

    auto write_bytes = [&out](const Bytes& b) {
        uint32_t len = static_cast<uint32_t>(b.size());
        out.push_back(static_cast<uint8_t>((len >> 24) & 0xFF));
        out.push_back(static_cast<uint8_t>((len >> 16) & 0xFF));
        out.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(len & 0xFF));
        out.insert(out.end(), b.begin(), b.end());
    };

    write_string(remote_mesh_id);
    write_string(local_mesh_id);
    write_bytes(signature);

    auto cert_data = local_certificate.serialize();
    write_bytes(cert_data);

    uint32_t anchor_count = static_cast<uint32_t>(trust_anchors.size());
    out.push_back(static_cast<uint8_t>((anchor_count >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((anchor_count >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((anchor_count >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(anchor_count & 0xFF));
    for (const auto& anchor : trust_anchors)
    {
        auto anchor_data = anchor.serialize();
        write_bytes(anchor_data);
    }

    for (int i = 7; i >= 0; --i)
        out.push_back(static_cast<uint8_t>((timestamp >> (i * 8)) & 0xFF));

    return out;
}

Result<FederationAuth> FederationAuth::deserialize(BytesView data)
{
    FederationAuth auth;
    size_t offset = 0;

    auto read_string = [&data, &offset](std::string& s) -> Result<void> {
        if (offset + 4 > data.size())
            return Error(ErrorCode(ErrorCategory::Serialization, 1, Severity::Error,
                                   RetryClass::NoRetry, Recovery::None), "Truncated string length", __FILE__, __LINE__);
        uint32_t len = (static_cast<uint32_t>(data[offset]) << 24) |
                       (static_cast<uint32_t>(data[offset + 1]) << 16) |
                       (static_cast<uint32_t>(data[offset + 2]) << 8) |
                       static_cast<uint32_t>(data[offset + 3]);
        offset += 4;
        if (offset + len > data.size())
            return Error(ErrorCode(ErrorCategory::Serialization, 2, Severity::Error,
                                   RetryClass::NoRetry, Recovery::None), "Truncated string data", __FILE__, __LINE__);
        s.assign(reinterpret_cast<const char*>(data.data() + offset), len);
        offset += len;
        return {};
    };

    auto read_bytes = [&data, &offset](Bytes& b) -> Result<void> {
        if (offset + 4 > data.size())
            return Error(ErrorCode(ErrorCategory::Serialization, 3, Severity::Error,
                                   RetryClass::NoRetry, Recovery::None), "Truncated bytes length", __FILE__, __LINE__);
        uint32_t len = (static_cast<uint32_t>(data[offset]) << 24) |
                       (static_cast<uint32_t>(data[offset + 1]) << 16) |
                       (static_cast<uint32_t>(data[offset + 2]) << 8) |
                       static_cast<uint32_t>(data[offset + 3]);
        offset += 4;
        if (offset + len > data.size())
            return Error(ErrorCode(ErrorCategory::Serialization, 4, Severity::Error,
                                   RetryClass::NoRetry, Recovery::None), "Truncated bytes data", __FILE__, __LINE__);
        b.assign(data.data() + offset, data.data() + offset + len);
        offset += len;
        return {};
    };

    auto res = read_string(auth.remote_mesh_id);
    if (!res) return res.error();
    res = read_string(auth.local_mesh_id);
    if (!res) return res.error();
    res = read_bytes(auth.signature);
    if (!res) return res.error();

    Bytes cert_blob;
    res = read_bytes(cert_blob);
    if (!res) return res.error();
    auto cert_result = Certificate::deserialize(cert_blob);
    if (!cert_result) return cert_result.error();
    auth.local_certificate = std::move(cert_result.value());

    if (offset + 4 > data.size())
        return Error(ErrorCode(ErrorCategory::Serialization, 5, Severity::Error,
                               RetryClass::NoRetry, Recovery::None), "Truncated anchor count", __FILE__, __LINE__);
    uint32_t anchor_count = (static_cast<uint32_t>(data[offset]) << 24) |
                            (static_cast<uint32_t>(data[offset + 1]) << 16) |
                            (static_cast<uint32_t>(data[offset + 2]) << 8) |
                            static_cast<uint32_t>(data[offset + 3]);
    offset += 4;
    auth.trust_anchors.reserve(anchor_count);
    for (uint32_t i = 0; i < anchor_count; ++i)
    {
        Bytes anchor_blob;
        res = read_bytes(anchor_blob);
        if (!res) return res.error();
        auto anchor_result = Certificate::deserialize(anchor_blob);
        if (!anchor_result) return anchor_result.error();
        auth.trust_anchors.push_back(std::move(anchor_result.value()));
    }

    if (offset + 8 > data.size())
        return Error(ErrorCode(ErrorCategory::Serialization, 6, Severity::Error,
                               RetryClass::NoRetry, Recovery::None), "Truncated timestamp", __FILE__, __LINE__);
    auth.timestamp = 0;
    for (int i = 0; i < 8; ++i)
        auth.timestamp = (auth.timestamp << 8) | data[offset++];

    return auth;
}

// ============================================================================
// FederationAck
// ============================================================================

Bytes FederationAck::serialize() const
{
    Bytes out;
    auto write_string = [&out](const std::string& s) {
        uint32_t len = static_cast<uint32_t>(s.size());
        out.push_back(static_cast<uint8_t>((len >> 24) & 0xFF));
        out.push_back(static_cast<uint8_t>((len >> 16) & 0xFF));
        out.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(len & 0xFF));
        out.insert(out.end(), s.begin(), s.end());
    };

    auto write_bytes = [&out](const Bytes& b) {
        uint32_t len = static_cast<uint32_t>(b.size());
        out.push_back(static_cast<uint8_t>((len >> 24) & 0xFF));
        out.push_back(static_cast<uint8_t>((len >> 16) & 0xFF));
        out.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(len & 0xFF));
        out.insert(out.end(), b.begin(), b.end());
    };

    write_string(remote_mesh_id);
    write_string(local_mesh_id);
    out.push_back(accepted ? 1 : 0);
    write_string(rejection_reason);
    write_bytes(signature);

    for (int i = 7; i >= 0; --i)
        out.push_back(static_cast<uint8_t>((timestamp >> (i * 8)) & 0xFF));

    return out;
}

Result<FederationAck> FederationAck::deserialize(BytesView data)
{
    FederationAck ack;
    size_t offset = 0;

    auto read_string = [&data, &offset](std::string& s) -> Result<void> {
        if (offset + 4 > data.size())
            return Error(ErrorCode(ErrorCategory::Serialization, 1, Severity::Error,
                                   RetryClass::NoRetry, Recovery::None), "Truncated string length", __FILE__, __LINE__);
        uint32_t len = (static_cast<uint32_t>(data[offset]) << 24) |
                       (static_cast<uint32_t>(data[offset + 1]) << 16) |
                       (static_cast<uint32_t>(data[offset + 2]) << 8) |
                       static_cast<uint32_t>(data[offset + 3]);
        offset += 4;
        if (offset + len > data.size())
            return Error(ErrorCode(ErrorCategory::Serialization, 2, Severity::Error,
                                   RetryClass::NoRetry, Recovery::None), "Truncated string data", __FILE__, __LINE__);
        s.assign(reinterpret_cast<const char*>(data.data() + offset), len);
        offset += len;
        return {};
    };

    auto read_bytes = [&data, &offset](Bytes& b) -> Result<void> {
        if (offset + 4 > data.size())
            return Error(ErrorCode(ErrorCategory::Serialization, 3, Severity::Error,
                                   RetryClass::NoRetry, Recovery::None), "Truncated bytes length", __FILE__, __LINE__);
        uint32_t len = (static_cast<uint32_t>(data[offset]) << 24) |
                       (static_cast<uint32_t>(data[offset + 1]) << 16) |
                       (static_cast<uint32_t>(data[offset + 2]) << 8) |
                       static_cast<uint32_t>(data[offset + 3]);
        offset += 4;
        if (offset + len > data.size())
            return Error(ErrorCode(ErrorCategory::Serialization, 4, Severity::Error,
                                   RetryClass::NoRetry, Recovery::None), "Truncated bytes data", __FILE__, __LINE__);
        b.assign(data.data() + offset, data.data() + offset + len);
        offset += len;
        return {};
    };

    auto res = read_string(ack.remote_mesh_id);
    if (!res) return res.error();
    res = read_string(ack.local_mesh_id);
    if (!res) return res.error();

    if (offset >= data.size())
        return Error(ErrorCode(ErrorCategory::Serialization, 5, Severity::Error,
                               RetryClass::NoRetry, Recovery::None), "Truncated accepted flag", __FILE__, __LINE__);
    ack.accepted = data[offset++] != 0;

    res = read_string(ack.rejection_reason);
    if (!res) return res.error();
    res = read_bytes(ack.signature);
    if (!res) return res.error();

    if (offset + 8 > data.size())
        return Error(ErrorCode(ErrorCategory::Serialization, 6, Severity::Error,
                               RetryClass::NoRetry, Recovery::None), "Truncated timestamp", __FILE__, __LINE__);
    ack.timestamp = 0;
    for (int i = 0; i < 8; ++i)
        ack.timestamp = (ack.timestamp << 8) | data[offset++];

    return ack;
}

// ============================================================================
// FederationHandshake
// ============================================================================

FederationHandshake::FederationHandshake(const Config& config, const CryptoProvider& crypto, RngRef& rng)
    : config_(config), crypto_(crypto), rng_(rng), start_time_(now_ns())
{
}

Result<void> FederationHandshake::start_as_initiator(SendFn send_fn, OnCompleteFn on_complete)
{
    if (state_ != FederationHandshakeState::Init)
    {
        return Error(ErrorCode(ErrorCategory::Federation, 1, Severity::Error,
                               RetryClass::NoRetry, Recovery::None),
                     "Handshake already started", __FILE__, __LINE__);
    }

    on_complete_ = std::move(on_complete);
    start_time_ = now_ns();
    state_ = FederationHandshakeState::SentHello;

    return send_hello(send_fn);
}

Result<void> FederationHandshake::handle_message(BytesView data, SendFn send_fn)
{
    if (is_timed_out(now_ns()))
    {
        return complete_handshake(Error(ErrorCode(ErrorCategory::Federation, 2, Severity::Error,
                                                  RetryClass::NoRetry, Recovery::None),
                                        "Handshake timed out", __FILE__, __LINE__));
    }

    if (data.empty())
    {
        return Error(ErrorCode(ErrorCategory::Federation, 3, Severity::Error,
                               RetryClass::NoRetry, Recovery::None),
                     "Empty message", __FILE__, __LINE__);
    }

    uint8_t msg_type = data[0];
    BytesView payload = data.subspan(1);

    switch (msg_type)
    {
        case 0x01: // Hello
            return handle_hello(payload, send_fn);
        case 0x02: // Auth
            return handle_auth(payload, send_fn);
        case 0x03: // Ack
            return handle_ack(payload);
        default:
            return Error(ErrorCode(ErrorCategory::Federation, 4, Severity::Error,
                                   RetryClass::NoRetry, Recovery::None),
                         "Unknown federation message type", __FILE__, __LINE__);
    }
}

Result<void> FederationHandshake::send_hello(SendFn send_fn)
{
    FederationHello hello;
    hello.local_mesh_id = config_.local_mesh_id;
    hello.local_gateway_node_id = config_.local_gateway_node_id;
    hello.supported_suites = {"suite3_purepqc", "suite2_modern", "suite1_classical"};
    hello.authority_pubkey = ""; // Load from config
    hello.root_pubkey = ""; // Load from config
    hello.epoch = 1;
    hello.timestamp = now_ns();

    Bytes msg;
    msg.push_back(0x01);
    auto hello_data = hello.serialize();
    msg.insert(msg.end(), hello_data.begin(), hello_data.end());

    return send_fn(msg);
}

Result<void> FederationHandshake::handle_hello(BytesView data, SendFn send_fn)
{
    if (state_ != FederationHandshakeState::Init && state_ != FederationHandshakeState::SentHello)
    {
        return Error(ErrorCode(ErrorCategory::Federation, 5, Severity::Error,
                               RetryClass::NoRetry, Recovery::None),
                     "Unexpected Hello message", __FILE__, __LINE__);
    }

    auto hello_result = FederationHello::deserialize(data);
    if (!hello_result)
    {
        return hello_result.error();
    }

    const auto& hello = hello_result.value();
    peer_mesh_id_ = hello.local_mesh_id;
    peer_gateway_node_id_ = hello.local_gateway_node_id;

    state_ = FederationHandshakeState::ReceivedHello;

    return send_auth(send_fn);
}

Result<void> FederationHandshake::send_auth(SendFn send_fn)
{
    FederationAuth auth;
    auth.remote_mesh_id = peer_mesh_id_;
    auth.local_mesh_id = config_.local_mesh_id;
    auth.timestamp = now_ns();

    Bytes local_cert_data;
    if (!config_.local_certificate_data.empty())
    {
        local_cert_data = config_.local_certificate_data;
    }
    else
    {
        local_cert_data = load_file_binary(config_.local_certificate_path);
    }
    if (local_cert_data.empty())
    {
        return Error(ErrorCode(ErrorCategory::Federation, 6, Severity::Error,
                               RetryClass::NoRetry, Recovery::None),
                     "Failed to load local certificate", __FILE__, __LINE__);
    }

    auto cert_result = Certificate::deserialize(local_cert_data);
    if (!cert_result)
    {
        return cert_result.error();
    }
    auth.local_certificate = std::move(cert_result.value());

    auth.trust_anchors = load_trust_anchors();

    Bytes to_sign = auth.local_certificate.serialize();
    for (const auto& anchor : auth.trust_anchors)
    {
        auto anchor_data = anchor.serialize();
        to_sign.insert(to_sign.end(), anchor_data.begin(), anchor_data.end());
    }

    auth.signature = sign_data(crypto_, rng_, to_sign, config_.local_identity_key);
    if (auth.signature.empty())
    {
        return Error(ErrorCode(ErrorCategory::Federation, 7, Severity::Error,
                               RetryClass::NoRetry, Recovery::None),
                     "Failed to sign auth message", __FILE__, __LINE__);
    }

    Bytes msg;
    msg.push_back(0x02);
    auto auth_data = auth.serialize();
    msg.insert(msg.end(), auth_data.begin(), auth_data.end());

    state_ = FederationHandshakeState::SentAuth;
    return send_fn(msg);
}

Result<void> FederationHandshake::handle_auth(BytesView data, SendFn send_fn)
{
    if (state_ != FederationHandshakeState::SentHello && state_ != FederationHandshakeState::ReceivedHello)
    {
        return Error(ErrorCode(ErrorCategory::Federation, 8, Severity::Error,
                               RetryClass::NoRetry, Recovery::None),
                     "Unexpected Auth message", __FILE__, __LINE__);
    }

    auto auth_result = FederationAuth::deserialize(data);
    if (!auth_result)
    {
        return auth_result.error();
    }

    const auto& auth = auth_result.value();
    peer_mesh_id_ = auth.remote_mesh_id;
    peer_trust_anchors_ = auth.trust_anchors;

    auto verify_res = verify_peer_certificate(auth.local_certificate);
    if (!verify_res)
    {
        FederationAck ack;
        ack.remote_mesh_id = auth.remote_mesh_id;
        ack.local_mesh_id = config_.local_mesh_id;
        ack.accepted = false;
        ack.rejection_reason = "Certificate verification failed: " + verify_res.error().message;
        ack.timestamp = now_ns();

        Bytes to_sign = Bytes(reinterpret_cast<const uint8_t*>(&ack.accepted), reinterpret_cast<const uint8_t*>(&ack.accepted) + 1);
        auto reason_bytes = Bytes(ack.rejection_reason.begin(), ack.rejection_reason.end());
        to_sign.insert(to_sign.end(), reason_bytes.begin(), reason_bytes.end());
        ack.signature = sign_data(crypto_, rng_, to_sign, config_.local_identity_key);

        Bytes msg;
        msg.push_back(0x03);
        auto ack_data = ack.serialize();
        msg.insert(msg.end(), ack_data.begin(), ack_data.end());

        send_fn(msg);
        return complete_handshake(verify_res.error());
    }

    auto anchor_res = verify_trust_anchors(auth.trust_anchors);
    if (!anchor_res)
    {
        FederationAck ack;
        ack.remote_mesh_id = auth.remote_mesh_id;
        ack.local_mesh_id = config_.local_mesh_id;
        ack.accepted = false;
        ack.rejection_reason = "Trust anchor verification failed: " + anchor_res.error().message;
        ack.timestamp = now_ns();

        Bytes msg;
        msg.push_back(0x03);
        auto ack_data = ack.serialize();
        msg.insert(msg.end(), ack_data.begin(), ack_data.end());

        send_fn(msg);
        return complete_handshake(anchor_res.error());
    }

    FederationAck ack;
    ack.remote_mesh_id = auth.remote_mesh_id;
    ack.local_mesh_id = config_.local_mesh_id;
    ack.accepted = true;
    ack.timestamp = now_ns();

    Bytes to_sign = Bytes{1};
    ack.signature = sign_data(crypto_, rng_, to_sign, config_.local_identity_key);

    Bytes msg;
    msg.push_back(0x03);
    auto ack_data = ack.serialize();
    msg.insert(msg.end(), ack_data.begin(), ack_data.end());

    state_ = FederationHandshakeState::Completed;
    send_fn(msg);

    return complete_handshake({});
}

Result<void> FederationHandshake::handle_ack(BytesView data)
{
    if (state_ != FederationHandshakeState::SentAuth)
    {
        return Error(ErrorCode(ErrorCategory::Federation, 9, Severity::Error,
                               RetryClass::NoRetry, Recovery::None),
                     "Unexpected Ack message", __FILE__, __LINE__);
    }

    auto ack_result = FederationAck::deserialize(data);
    if (!ack_result)
    {
        return ack_result.error();
    }

    const auto& ack = ack_result.value();

    if (!ack.accepted)
    {
        return complete_handshake(Error(ErrorCode(ErrorCategory::Federation, 10, Severity::Error,
                                                  RetryClass::NoRetry, Recovery::None),
                                        "Handshake rejected: " + ack.rejection_reason, __FILE__, __LINE__));
    }

    state_ = FederationHandshakeState::Completed;
    return complete_handshake({});
}

Result<void> FederationHandshake::verify_peer_certificate(const Certificate& cert)
{
    return {};
}

Result<void> FederationHandshake::verify_trust_anchors(const std::vector<Certificate>& anchors)
{
    return {};
}

Result<void> FederationHandshake::complete_handshake(Result<void> result)
{
    if (on_complete_)
    {
        on_complete_(result);
    }
    return result;
}

bool FederationHandshake::is_timed_out(int64_t now) const
{
    return (now - start_time_) > config_.handshake_timeout_ns;
}

std::vector<smo::Certificate> FederationHandshake::load_trust_anchors() const
{
    std::vector<smo::Certificate> anchors;
    return anchors;
}

smo::Bytes FederationHandshake::load_file_binary(const std::string& path)
{
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f)
        return {};
    auto size = f.tellg();
    f.seekg(0);
    smo::Bytes data(static_cast<size_t>(size));
    f.read(reinterpret_cast<char*>(data.data()), size);
    return data;
}

} // namespace smo::federation