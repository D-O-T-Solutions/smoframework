#pragma once

#include <core/errors/error.hpp>
#include <core/types.hpp>
#include <core/certificate/certificate.hpp>
#include <core/session/session.hpp>

#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <functional>

namespace smo::federation {

enum class FederationHandshakeState : uint8_t
{
    Init = 0,
    SentHello = 1,
    ReceivedHello = 2,
    SentAuth = 3,
    ReceivedAuth = 4,
    Completed = 5,
    Failed = 6,
};

struct FederationHello
{
    std::string local_mesh_id;
    std::string local_gateway_node_id;
    std::vector<std::string> supported_suites;
    std::string authority_pubkey;
    std::string root_pubkey;
    int64_t epoch = 1;
    int64_t timestamp = 0;

    smo::Bytes serialize() const;
    static smo::Result<FederationHello> deserialize(smo::BytesView data);
};

struct FederationAuth
{
    std::string remote_mesh_id;
    std::string local_mesh_id;
    smo::Bytes signature;
    smo::Certificate local_certificate;
    std::vector<smo::Certificate> trust_anchors;
    int64_t timestamp = 0;

    smo::Bytes serialize() const;
    static smo::Result<FederationAuth> deserialize(smo::BytesView data);
};

struct FederationAck
{
    std::string remote_mesh_id;
    std::string local_mesh_id;
    bool accepted = true;
    std::string rejection_reason;
    smo::Bytes signature;
    int64_t timestamp = 0;

    smo::Bytes serialize() const;
    static smo::Result<FederationAck> deserialize(smo::BytesView data);
};

class FederationHandshake
{
public:
    struct Config
    {
        std::string local_mesh_id;
        std::string local_gateway_node_id;
        smo::Bytes local_identity_key;
        std::string local_certificate_path;
        smo::Bytes local_certificate_data; // Optional: pre-loaded certificate data for testing
        std::string trust_anchors_dir;
        int64_t handshake_timeout_ns = 30'000'000'000LL;
    };

    using SendFn = std::function<smo::Result<void>(smo::BytesView)>;
    using OnCompleteFn = std::function<void(smo::Result<void>)>;

    FederationHandshake(const Config& config, const smo::CryptoProvider& crypto, smo::RngRef& rng);
    ~FederationHandshake() = default;

    smo::Result<void> start_as_initiator(SendFn send_fn, OnCompleteFn on_complete);
    smo::Result<void> handle_message(smo::BytesView data, SendFn send_fn);

    FederationHandshakeState state() const noexcept { return state_; }
    const std::string& peer_mesh_id() const noexcept { return peer_mesh_id_; }
    const std::vector<smo::Certificate>& peer_trust_anchors() const noexcept { return peer_trust_anchors_; }

private:
    Config config_;
    const smo::CryptoProvider& crypto_;
    smo::RngRef& rng_;
    FederationHandshakeState state_ = FederationHandshakeState::Init;
    std::string peer_mesh_id_;
    std::string peer_gateway_node_id_;
    std::vector<smo::Certificate> peer_trust_anchors_;
    OnCompleteFn on_complete_;
    int64_t start_time_ = 0;

    smo::Result<void> send_hello(SendFn send_fn);
    smo::Result<void> handle_hello(smo::BytesView data, SendFn send_fn);
    smo::Result<void> send_auth(SendFn send_fn);
    smo::Result<void> handle_auth(smo::BytesView data, SendFn send_fn);
    smo::Result<void> handle_ack(smo::BytesView data);
    smo::Result<void> verify_peer_certificate(const smo::Certificate& cert);
    smo::Result<void> verify_trust_anchors(const std::vector<smo::Certificate>& anchors);
    smo::Result<void> complete_handshake(smo::Result<void> result);
    bool is_timed_out(int64_t now) const;

    // Helper functions
    static smo::Bytes load_file_binary(const std::string& path);
    std::vector<smo::Certificate> load_trust_anchors() const;
};

} // namespace smo::federation