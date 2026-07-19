#include "auto_enroll.hpp"

#include "core/crypto/registry.hpp"
#include "core/enroll/join_token.hpp"
#include "core/join/join_protocol.hpp"
#include "core/errors/error.hpp"
#include "core/types.hpp"
#include "core/identity/identity.hpp"
#include "core/certificate/certificate.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

namespace smo {
namespace enroll {

// ── Hex helper ────────────────────────────────────────────────────────

static Bytes hex_to_bytes(const std::string& hex) {
    Bytes out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        char buf[3] = {hex[i], hex[i+1], 0};
        out.push_back(static_cast<uint8_t>(std::strtoul(buf, nullptr, 16)));
    }
    return out;
}

// ── TCP send/receive (raw CBOR, no HTTP) ──────────────────────────────

static int tcp_connect(const std::string& host, uint16_t port, int timeout_sec = 10) {
    struct addrinfo hints, *res = nullptr;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    std::string port_str = std::to_string(port);
    int gai_err = ::getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res);
    if (gai_err != 0 || !res) {
        return -1;
    }

    int fd = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        ::freeaddrinfo(res);
        return -1;
    }

    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (::connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
        ::close(fd);
        ::freeaddrinfo(res);
        return -1;
    }
    ::freeaddrinfo(res);
    return fd;
}

// ── CBOR transport: 4-byte length prefix + CBOR payload ──────────────

static Result<Bytes> tcp_cbor_exchange(int fd, BytesView send_cbor) {
    // Send: 4-byte big-endian length + CBOR payload
    uint32_t send_len = static_cast<uint32_t>(send_cbor.size());
    uint8_t header[4];
    header[0] = static_cast<uint8_t>((send_len >> 24) & 0xFF);
    header[1] = static_cast<uint8_t>((send_len >> 16) & 0xFF);
    header[2] = static_cast<uint8_t>((send_len >> 8) & 0xFF);
    header[3] = static_cast<uint8_t>(send_len & 0xFF);

    size_t total = 0;
    while (total < sizeof(header)) {
        ssize_t n = ::send(fd, header + total, sizeof(header) - total, 0);
        if (n <= 0) return SMO_ERR_TRANSPORT(400, Error, RetrySafe, None, "Failed to send CBOR header");
        total += static_cast<size_t>(n);
    }
    total = 0;
    while (total < send_cbor.size()) {
        ssize_t n = ::send(fd, send_cbor.data() + total, send_cbor.size() - total, 0);
        if (n <= 0) return SMO_ERR_TRANSPORT(400, Error, RetrySafe, None, "Failed to send CBOR payload");
        total += static_cast<size_t>(n);
    }

    // Receive: 4-byte big-endian length
    uint8_t resp_header[4];
    total = 0;
    while (total < sizeof(resp_header)) {
        ssize_t n = ::recv(fd, resp_header + total, sizeof(resp_header) - total, 0);
        if (n <= 0) return SMO_ERR_TRANSPORT(400, Error, RetrySafe, None, "Failed to receive response header");
        total += static_cast<size_t>(n);
    }
    uint32_t resp_len = (static_cast<uint32_t>(resp_header[0]) << 24) |
                        (static_cast<uint32_t>(resp_header[1]) << 16) |
                        (static_cast<uint32_t>(resp_header[2]) << 8)  |
                         static_cast<uint32_t>(resp_header[3]);
    if (resp_len > 1024 * 1024) { // 1MB max
        return SMO_ERR_TRANSPORT(400, Error, NoRetry, None, "Response too large");
    }

    Bytes resp(resp_len);
    total = 0;
    while (total < resp_len) {
        ssize_t n = ::recv(fd, resp.data() + total, resp_len - total, 0);
        if (n <= 0) return SMO_ERR_TRANSPORT(400, Error, RetrySafe, None, "Failed to receive response payload");
        total += static_cast<size_t>(n);
    }
    ::close(fd);
    return resp;
}

// ── Directory helpers ────────────────────────────────────────────────

static Result<void> ensure_dir(const std::string& path) {
    namespace fs = std::filesystem;
    std::error_code ec;
    fs::create_directories(path, ec);
    if (ec) {
        return SMO_ERR_CERT(200, Error, RetrySafe, None,
                            "Failed to create directory: " + ec.message());
    }
    return {};
}

// ── Main join command ────────────────────────────────────────────────

Result<void> run_join_command(const std::string& token_str,
                               const std::string& data_dir,
                               const std::string& node_name,
                               uint16_t port,
                               const std::string& mesh_dir) {
    (void)mesh_dir;

    // Parse token
    auto token_result = enroll::parse_token(token_str);
    if (!token_result) return token_result.error();
    const auto& token = token_result.value();

    // Validate expiry
    if (token.expiry_unix_sec > 0) {
        auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        if (now > token.expiry_unix_sec) {
            return SMO_ERR_CERT(213, Error, NoRetry, None, "Join token expired");
        }
    }

    // Setup data directory
    std::string actual_data_dir = data_dir.empty() ? "/tmp/smo-node-" + std::to_string(getpid()) : data_dir;
    auto dir_result = ensure_dir(actual_data_dir);
    if (!dir_result) return dir_result.error();

    // Get crypto once and reuse
    auto& reg = CryptoRegistry::instance();
    auto crypto_result = reg.get_suite(token.cipher_suite_id);
    if (!crypto_result) return crypto_result.error();
    const auto* crypto = crypto_result.value();
    auto rng = crypto->default_rng();

    // 1. Initialize identity (or load existing)
    std::string identity_path = actual_data_dir + "/identity.json";
    bool identity_exists = std::filesystem::exists(identity_path);

    std::shared_ptr<Identity> identity;
    if (identity_exists) {
        auto id_result = Identity::load_from_file(identity_path, *crypto);
        if (!id_result) return id_result.error();
        identity = std::make_shared<Identity>(std::move(id_result.value()));
        std::printf("Loaded existing identity: %s\n", identity->node_id().to_string().c_str());
    } else {
        auto id_result = Identity::create(*crypto, rng);
        if (!id_result) return id_result.error();
        identity = std::make_shared<Identity>(std::move(id_result.value()));
        auto save_result = identity->save_to_file(identity_path);
        if (!save_result) return save_result.error();
        std::printf("Identity created: %s\n", identity->node_id().to_string().c_str());
    }

    // 2. Build CSR
    CertificateSigningRequest csr;
    csr.new_public_key = Bytes(identity->public_key().begin(), identity->public_key().end());
    csr.mesh_id = hex_to_bytes(token.mesh_id);
    csr.display_name = node_name.empty() ? identity->node_id().to_string() : node_name;
    csr.platform = "linux";
    csr.version = "0.1.0";
    csr.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    csr.old_cert_hash = Bytes(32, 0);

    // Sign CSR with node's secret key
    auto csr_body = csr.serialize_body();
    auto sig_result = crypto->signer.sign(csr_body, identity->secret_key(), rng);
    if (!sig_result) return sig_result.error();
    csr.signature = std::move(sig_result.value());

    // Serialize CSR to PEM
    Bytes csr_bytes = csr.serialize();
    std::string csr_pem = bytes_to_hex(csr_bytes); // Use hex as PEM placeholder

    // 3. Build JoinRequest (TCP/CBOR — no HTTP)
    auto now_sec = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    join::JoinRequest req;
    req.token = token_str;
    req.csr_pem = csr_pem;
    req.timestamp = now_sec;
    // Generate 64-bit random nonce
    std::array<uint8_t, 8> nonce{};
    for (auto& b : nonce) b = static_cast<uint8_t>(rand());
    req.nonce = nonce;
    // csr_hash = sha256(csr_pem)
    auto hash_result = crypto->hash.hash(BytesView(reinterpret_cast<const uint8_t*>(csr_pem.data()), csr_pem.size()));
    if (!hash_result) return hash_result.error();
    req.csr_hash = std::move(hash_result.value());
    // request_signature = sign(token || timestamp || nonce || csr_hash) using node key
    {
        Bytes sig_payload;
        sig_payload.insert(sig_payload.end(), token_str.begin(), token_str.end());
        sig_payload.push_back(static_cast<uint8_t>((now_sec >> 56) & 0xFF));
        sig_payload.push_back(static_cast<uint8_t>((now_sec >> 48) & 0xFF));
        sig_payload.push_back(static_cast<uint8_t>((now_sec >> 40) & 0xFF));
        sig_payload.push_back(static_cast<uint8_t>((now_sec >> 32) & 0xFF));
        sig_payload.push_back(static_cast<uint8_t>((now_sec >> 24) & 0xFF));
        sig_payload.push_back(static_cast<uint8_t>((now_sec >> 16) & 0xFF));
        sig_payload.push_back(static_cast<uint8_t>((now_sec >> 8) & 0xFF));
        sig_payload.push_back(static_cast<uint8_t>(now_sec & 0xFF));
        sig_payload.insert(sig_payload.end(), nonce.begin(), nonce.end());
        sig_payload.insert(sig_payload.end(), req.csr_hash.begin(), req.csr_hash.end());
        auto sig_req_result = crypto->signer.sign(BytesView(sig_payload), identity->secret_key(), rng);
        if (!sig_req_result) return sig_req_result.error();
        req.request_signature = std::move(sig_req_result.value());
    }

    Bytes req_cbor = req.encode_cbor();

    // 4. Try to enroll via TCP/CBOR to bootstrap endpoints
    std::string last_error;
    bool success = false;
    join::JoinResponse resp;

    std::printf("Attempting to join mesh via TCP/CBOR...\n");

    for (const auto& endpoint : token.bootstrap_endpoints) {
        size_t colon = endpoint.rfind(':');
        if (colon == std::string::npos) continue;
        std::string host = endpoint.substr(0, colon);
        uint16_t ep_port = static_cast<uint16_t>(std::stoi(endpoint.substr(colon + 1)));

        std::printf("  Trying endpoint: %s:%u ... ", host.c_str(), ep_port);

        int fd = tcp_connect(host, ep_port);
        if (fd < 0) {
            std::printf("FAIL (connection refused)\n");
            last_error = "Connection refused: " + host + ":" + std::to_string(ep_port);
            continue;
        }

        auto resp_result = tcp_cbor_exchange(fd, BytesView(req_cbor));
        if (!resp_result) {
            std::printf("FAIL (%s)\n", resp_result.error().message.c_str());
            last_error = resp_result.error().message;
            continue;
        }

        auto decode_result = join::JoinResponse::decode_cbor(BytesView(resp_result.value()));
        if (!decode_result) {
            std::printf("FAIL (invalid response: %s)\n", decode_result.error().message.c_str());
            last_error = "Invalid CBOR response";
            continue;
        }

        resp = std::move(decode_result.value());
        success = true;
        std::printf("OK\n");
        break;
    }

    if (!success) {
        return SMO_ERR_CERT(214, Error, RetrySafe, None,
                            "All bootstrap endpoints unreachable. Last error: " + last_error);
    }

    // 5. Process response
    if (resp.certificate_pem.empty()) {
        return SMO_ERR_CERT(215, Error, NoRetry, None, "No certificate in response");
    }

    // Deserialize certificate (PEM is hex-encoded for now)
    Bytes cert_bytes;
    if (resp.certificate_pem.find("BEGIN") != std::string::npos) {
        // Real PEM — strip headers and decode base64
        // For now assume hex-encoded binary
        cert_bytes = hex_to_bytes(resp.certificate_pem);
    } else {
        cert_bytes = hex_to_bytes(resp.certificate_pem);
    }

    auto cert_result = Certificate::deserialize(cert_bytes);
    if (!cert_result) {
        return SMO_ERR_CERT(216, Error, NoRetry, None,
                            "Failed to parse certificate: " + cert_result.error().message);
    }

    // Save certificate
    std::string cert_path = actual_data_dir + "/cert.smoc";
    {
        std::ofstream f(cert_path, std::ios::binary);
        if (!f) {
            return SMO_ERR_STORAGE(900, Error, RetrySafe, None,
                                   "Failed to write certificate to " + cert_path);
        }
        f.write(reinterpret_cast<const char*>(cert_bytes.data()), cert_bytes.size());
    }

    std::string node_id_str = resp.mesh_id.empty() ? token.mesh_id : resp.mesh_id;

    std::printf("\n✓ Successfully enrolled!\n");
    std::printf("  Mesh:         %s\n", token.mesh_id.c_str());
    std::printf("  Role:         %s\n", token.admission.role.c_str());
    std::printf("  Profile:      %s\n", token.admission.profile.empty() ? "default" : token.admission.profile.c_str());
    std::printf("  Certificate:  %s\n", cert_path.c_str());
    if (!resp.manifest_digest.empty()) {
        std::printf("  Manifest:     epoch=%llu digest=", (unsigned long long)resp.manifest_epoch);
        for (auto b : resp.manifest_digest) std::printf("%02x", b);
        std::printf("\n");
    }
    if (!resp.bootstrap_nodes.empty()) {
        std::printf("  Bootstrap:    %zu seed(s)\n", resp.bootstrap_nodes.size());
        for (auto& ep : resp.bootstrap_nodes) {
            std::printf("    %s\n", ep.c_str());
        }
    }

    // Update identity state to Enrolled
    (void)identity->transition_to(IdentityState::Enrolled);
    (void)identity->save_to_file(identity_path);

    // 6. Save config for daemon
    std::string config_path = actual_data_dir + "/config.json";
    {
        std::ofstream f(config_path);
        if (f) {
            f << "{\n";
            f << "  \"mesh_id\": \"" << token.mesh_id << "\",\n";
            f << "  \"role\": \"" << token.admission.role << "\",\n";
            f << "  \"profile\": \"" << (token.admission.profile.empty() ? "server" : token.admission.profile) << "\",\n";
            f << "  \"listen_port\": " << port << ",\n";
            f << "  \"bootstrap_endpoints\": [\n";
            // Use bootstrap_nodes from response if available, else fallback to token endpoints
            const auto& endpoints = !resp.bootstrap_nodes.empty() ? resp.bootstrap_nodes : token.bootstrap_endpoints;
            for (size_t i = 0; i < endpoints.size(); ++i) {
                if (i > 0) f << ",\n";
                f << "    \"" << endpoints[i] << "\"";
            }
            f << "\n  ],\n";
            f << "  \"node_name\": \"" << (node_name.empty() ? identity->node_id().to_string() : node_name) << "\"\n";
            f << "}\n";
        }
    }

    std::printf("\nRun 'smo-node --daemon --data %s --port %d' to start the node.\n",
                actual_data_dir.c_str(), port);

    return {};
}

} // namespace enroll
} // namespace smo
