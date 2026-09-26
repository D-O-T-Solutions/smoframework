#include "turn_client.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <random>
#include <thread>

#include <core/errors/error.hpp>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#if defined(_WIN32) || defined(_WIN64)
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <poll.h>
#include <fcntl.h>
#endif

namespace smo {
namespace network {
namespace turn {

namespace {
    void write_uint16(Bytes& buf, uint16_t v) {
        buf.push_back((v >> 8) & 0xFF);
        buf.push_back(v & 0xFF);
    }

    void write_uint32(Bytes& buf, uint32_t v) {
        buf.push_back((v >> 24) & 0xFF);
        buf.push_back((v >> 16) & 0xFF);
        buf.push_back((v >> 8) & 0xFF);
        buf.push_back(v & 0xFF);
    }

    uint16_t read_uint16(const uint8_t* p) {
        return (p[0] << 8) | p[1];
    }

    uint32_t read_uint32(const uint8_t* p) {
        return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
    }

    std::string hmac_sha1_hex(const std::string& key, const std::string& data) {
        unsigned char digest[20];
        unsigned int len = 20;
        HMAC(EVP_sha1(), key.c_str(), key.size(),
             reinterpret_cast<const unsigned char*>(data.c_str()), data.size(),
             nullptr, &len);
        unsigned char* d = HMAC(EVP_sha1(), key.c_str(), key.size(),
                                reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), nullptr, nullptr);
        char buf[41];
        for (int i = 0; i < 20; ++i) {
            sprintf(buf + i * 2, "%02x", d[i]);
        }
        buf[40] = '\0';
        return std::string(buf);
    }
} // anonymous namespace

// ── Client Implementation ──────────────────────────────────────────────────────

Client::Client(const Config& config) : config_(config) {
    std::random_device rd;
    gen_.seed(rd());
}

Client::~Client() {
    stop_listening();
    if (socket_fd_ >= 0) {
        close(socket_fd_);
        socket_fd_ = -1;
    }
}

int Client::create_socket() {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        return -1;
    }

    // Set non-blocking
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    // Set receive buffer size
    int bufsize = 65536;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));

    return fd;
}

void Client::connect_socket() {
    if (socket_fd_ >= 0) return;

    socket_fd_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_fd_ < 0) return;

    int flags = fcntl(socket_fd_, F_GETFL, 0);
    if (flags >= 0) fcntl(socket_fd_, F_SETFL, flags | O_NONBLOCK);

    int bufsize = 65536;
    setsockopt(socket_fd_, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    setsockopt(socket_fd_, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(config_.server_port);
    if (inet_pton(AF_INET, config_.server_host.c_str(), &server_addr_.sin_addr) != 1) {
        struct hostent* he = gethostbyname(config_.server_host.c_str());
        if (he) memcpy(&server_addr_.sin_addr, he->h_addr, he->h_length);
    }
    server_addr_.sin_family = AF_INET;
    server_addr_.sin_port = htons(config_.server_port);

    ::connect(socket_fd_, reinterpret_cast<struct sockaddr*>(&server_addr_), sizeof(server_addr_));
    socket_connected_ = true;
}

std::array<uint8_t, 12> Client::generate_transaction_id() {
    std::array<uint8_t, 12> tid;
    std::uniform_int_distribution<uint8_t> dist(0, 255);
    std::lock_guard<std::mutex> lock(tid_mutex_);
    for (auto& b : tid) b = static_cast<uint8_t>(gen_());
    return tid;
}

void Client::store_tid(const std::array<uint8_t, 12>& tid, const std::string& purpose) {
    (void)tid;
    (void)purpose;
}

std::optional<std::string> Client::get_tid_purpose(const std::array<uint8_t, 12>& tid) const {
    (void)tid;
    return std::nullopt;
}

// Build Allocate Request (RFC 8656 §6)
Bytes Client::build_allocate_request(uint32_t lifetime, bool even_port) {
    (void)even_port;

    Bytes msg;
    msg.reserve(128);

    // Transaction ID
    std::array<uint8_t, 12> tid = generate_transaction_id();

    // Message Type: Allocate Request (0x0003)
    msg.push_back(0x00);
    msg.push_back(0x03);

    // Message Length (placeholder, 2 bytes)
    msg.push_back(0);
    msg.push_back(0);

    // Magic Cookie
    msg.push_back(0x21);
    msg.push_back(0x12);
    msg.push_back(0xA4);
    msg.push_back(0x42);

    // Transaction ID (12 bytes)
    msg.insert(msg.end(), tid.begin(), tid.end());

    // REQUESTED-TRANSPORT: UDP (0x11)
    msg.push_back(0x00);
    msg.push_back(0x19); // REQUESTED-TRANSPORT
    msg.push_back(0);
    msg.push_back(4); // length
    msg.push_back(0x11); // UDP
    msg.push_back(0);
    msg.push_back(0);
    msg.push_back(0);

    // LIFETIME attribute
    uint32_t lifetime_val = config_.default_lifetime;
    msg.push_back(0x00);
    msg.push_back(0x0D); // LIFETIME
    msg.push_back(0);
    msg.push_back(4);
    // Lifetime in seconds (big-endian)
    msg.push_back((config_.default_lifetime >> 24) & 0xFF);
    msg.push_back((config_.default_lifetime >> 16) & 0xFF);
    msg.push_back((config_.default_lifetime >> 8) & 0xFF);
    msg.push_back(config_.default_lifetime & 0xFF);

    // REQUESTED-ADDRESS-FAMILY: IPv4
    msg.push_back(0x00);
    msg.push_back(0x17); // REQUESTED-ADDRESS-FAMILY
    msg.push_back(0);
    msg.push_back(4);
    msg.push_back(0); // reserved
    msg.push_back(0); // reserved
    msg.push_back(1); // IPv4
    msg.push_back(0);

    // SOFTWARE attribute
    std::string sw = config_.software_name;
    msg.push_back(0x80);
    msg.push_back(0x22); // SOFTWARE
    uint16_t sw_len = static_cast<uint16_t>(sw.size());
    msg.push_back((sw_len >> 8) & 0xFF);
    msg.push_back(sw_len & 0xFF);
    msg.insert(msg.end(), sw.begin(), sw.end());
    // Padding to 4-byte boundary
    while (sw.size() % 4 != 0) {
        msg.push_back(0);
    }

    // FINGERPRINT (we'll compute later)
    // Placeholder for now

    // Update Message Length (total length - 20 bytes header)
    uint16_t msg_len = static_cast<uint16_t>(msg.size() - 20);
    msg[2] = (msg_len >> 8) & 0xFF;
    msg[3] = msg_len & 0xFF;

    // TODO: Add FINGERPRINT and MESSAGE-INTEGRITY

    return msg;
}

Bytes Client::build_refresh_request(uint32_t lifetime) {
    Bytes msg;
    msg.reserve(80);

    std::array<uint8_t, 12> tid = generate_transaction_id();

    // Message Type: Refresh Request (0x0004)
    msg.push_back(0x00);
    msg.push_back(0x04);
    msg.push_back(0);
    msg.push_back(0); // length placeholder
    msg.push_back(0x21);
    msg.push_back(0x12);
    msg.push_back(0xA4);
    msg.push_back(0x42);
    msg.insert(msg.end(), tid.begin(), tid.end());

    // LIFETIME
    msg.push_back(0x00);
    msg.push_back(0x0D);
    msg.push_back(0);
    msg.push_back(4);
    msg.push_back((lifetime >> 24) & 0xFF);
    msg.push_back((lifetime >> 16) & 0xFF);
    msg.push_back((lifetime >> 8) & 0xFF);
    msg.push_back(lifetime & 0xFF);

    // SOFTWARE
    std::string sw = config_.software_name;
    msg.push_back(0x80);
    msg.push_back(0x22);
    uint16_t sw_len = static_cast<uint16_t>(sw.size());
    msg.push_back((sw_len >> 8) & 0xFF);
    msg.push_back(sw_len & 0xFF);
    msg.insert(msg.end(), sw.begin(), sw.end());
    while (sw.size() % 4 != 0) msg.push_back(0);

    uint16_t msg_len = static_cast<uint16_t>(msg.size() - 20);
    msg[2] = (msg_len >> 8) & 0xFF;
    msg[3] = msg_len & 0xFF;

    return msg;
}

Bytes Client::build_send_indication(const std::string& peer_ip, uint16_t peer_port, BytesView data, bool is_ipv6) {
    (void)is_ipv6;

    Bytes msg;
    msg.reserve(64 + data.size());

    std::array<uint8_t, 12> tid = generate_transaction_id();

    // Message Type: Send Indication (0x0016)
    msg.push_back(0x00);
    msg.push_back(0x16);
    msg.push_back(0);
    msg.push_back(0); // length placeholder

    // Magic Cookie
    msg.push_back(0x21);
    msg.push_back(0x12);
    msg.push_back(0xA4);
    msg.push_back(0x42);

    // Transaction ID (12 bytes)
    msg.insert(msg.end(), tid.begin(), tid.end());

    // XOR-PEER-ADDRESS
    msg.push_back(0x00);
    msg.push_back(0x12); // XOR-PEER-ADDRESS
    msg.push_back(0);
    msg.push_back(8); // length for IPv4

    // XOR-PEER-ADDRESS format: family(2) + XOR port(2) + XOR IP(4)
    msg.push_back(0);
    msg.push_back(1); // IPv4

    // XOR port: port ^ 0x2112
    uint16_t xport = (peer_port ^ 0x2112);
    msg.push_back((xport >> 8) & 0xFF);
    msg.push_back(xport & 0xFF);

    // XOR IP: ip ^ 0x2112A442
    struct in_addr addr;
    inet_pton(AF_INET, peer_ip.c_str(), &addr);
    uint32_t xip = ntohl(addr.s_addr) ^ 0x2112A442;
    msg.push_back((xip >> 24) & 0xFF);
    msg.push_back((xip >> 16) & 0xFF);
    msg.push_back((xip >> 8) & 0xFF);
    msg.push_back(xip & 0xFF);

    // DATA attribute
    msg.push_back(0x00);
    msg.push_back(0x13); // DATA
    uint16_t data_len = static_cast<uint16_t>(data.size());
    msg.push_back((data_len >> 8) & 0xFF);
    msg.push_back(data_len & 0xFF);
    msg.insert(msg.end(), data.begin(), data.end());
    // Padding
    while ((data.size() + msg.size()) % 4 != 0) msg.push_back(0);

    uint16_t msg_len = static_cast<uint16_t>(msg.size() - 20);
    msg[2] = (msg_len >> 8) & 0xFF;
    msg[3] = msg_len & 0xFF;

    return msg;
}

Bytes Client::build_channel_bind_request(uint16_t channel_number, const std::string& peer_ip, uint16_t peer_port, bool is_ipv6) {
    (void)is_ipv6;

    Bytes msg;
    msg.reserve(96);

    std::array<uint8_t, 12> tid = generate_transaction_id();

    // Message Type: ChannelBind Request (0x0005)
    msg.push_back(0x00);
    msg.push_back(0x05);
    msg.push_back(0);
    msg.push_back(0);

    msg.push_back(0x21);
    msg.push_back(0x12);
    msg.push_back(0xA4);
    msg.push_back(0x42);
    msg.insert(msg.end(), tid.begin(), tid.end());

    // CHANNEL-NUMBER
    msg.push_back(0x00);
    msg.push_back(0x0C); // CHANNEL-NUMBER
    msg.push_back(0);
    msg.push_back(4);
    msg.push_back((channel_number >> 8) & 0xFF);
    msg.push_back(channel_number & 0xFF);
    msg.push_back(0);
    msg.push_back(0); // reserved

    // XOR-PEER-ADDRESS
    msg.push_back(0x00);
    msg.push_back(0x12); // XOR-PEER-ADDRESS
    msg.push_back(0);
    msg.push_back(8);

    msg.push_back(0);
    msg.push_back(1); // IPv4

    uint16_t xport = (peer_port ^ 0x2112);
    msg.push_back((xport >> 8) & 0xFF);
    msg.push_back(xport & 0xFF);

    // XOR IP
    struct in_addr addr;
    inet_pton(AF_INET, peer_ip.c_str(), &addr);
    uint32_t xip = ntohl(addr.s_addr) ^ 0x2112A442;
    msg.push_back((xip >> 24) & 0xFF);
    msg.push_back((xip >> 16) & 0xFF);
    msg.push_back((xip >> 8) & 0xFF);
    msg.push_back(xip & 0xFF);

    uint16_t msg_len = static_cast<uint16_t>(msg.size() - 20);
    msg[2] = (msg_len >> 8) & 0xFF;
    msg[3] = msg_len & 0xFF;

    return msg;
}

Bytes Client::build_channel_data(uint16_t channel_number, BytesView data) {
    Bytes msg;
    msg.reserve(4 + data.size());

    // Channel Data format (RFC 8656 §11):
    // Channel Number (2 bytes) | Length (2 bytes) | Data
    msg.push_back((channel_number >> 8) & 0xFF);
    msg.push_back(channel_number & 0xFF);

    uint16_t len = static_cast<uint16_t>(data.size());
    msg.push_back((len >> 8) & 0xFF);
    msg.push_back(len & 0xFF);

    msg.insert(msg.end(), data.begin(), data.end());
    // Padding to 4-byte boundary
    while ((msg.size()) % 4 != 0) msg.push_back(0);

    return msg;
}

std::optional<AllocationResult> Client::parse_allocate_response(BytesView data, const std::array<uint8_t, 12>& expected_tid) const {
    if (data.size() < 20) return std::nullopt;

    uint16_t msg_type = (data[0] << 8) | data[1];
    if (msg_type != 0x0103) return std::nullopt; // Not Allocate Success Response

    // Check magic cookie
    uint32_t magic = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
    if (magic != 0x2112A442) return std::nullopt;

    // Check transaction ID
    for (int i = 0; i < 12; ++i) {
        if (data[8 + i] != expected_tid[i]) return std::nullopt;
    }

    // Parse attributes
    size_t pos = 20;
    AllocationResult result;

    while (pos + 4 <= data.size()) {
        uint16_t attr_type = (data[pos] << 8) | data[pos + 1];
        uint16_t attr_len = (data[pos + 2] << 8) | data[pos + 3];
        pos += 4;

        if (pos + attr_len > data.size()) break;

        BytesView attr_data(data.data() + pos, attr_len);

        switch (attr_type) {
            case 0x0016: { // XOR-RELAYED-ADDRESS
                if (attr_len >= 8) {
                    // family(2) + XOR port(2) + XOR IP(4)
                    uint16_t family = (attr_data[0] << 8) | attr_data[1];
                    uint16_t xport = (attr_data[2] << 8) | attr_data[3];
                    uint32_t xip = (attr_data[4] << 24) | (attr_data[4+1] << 16) |
                                    (attr_data[4+2] << 8) | attr_data[4+3];

                    uint16_t port = ((attr_data[2] << 8) | attr_data[3]) ^ 0x2112;
                    uint32_t ip = ((attr_data[4] << 24) | (attr_data[5] << 16) |
                                   (attr_data[6] << 8) | attr_data[7]) ^ 0x2112A442;

                    char ip_str[INET_ADDRSTRLEN];
                    struct in_addr addr;
                    addr.s_addr = htonl(ip);
                    inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));

                    result.relayed_address.ip = ip_str;
                    result.relayed_address.port = ((attr_data[2] << 8) | attr_data[3]) ^ 0x2112;
                    result.relayed_address.is_ipv6 = false;
                }
                break;
            }
            case 0x000D: { // LIFETIME
                if (attr_len >= 4) {
                    result.lifetime = (attr_data[0] << 24) | (attr_data[1] << 16) |
                                     (attr_data[2] << 8) | attr_data[3];
                }
                break;
            }
            case 0x0015: { // NONCE
                result.nonce = std::string(reinterpret_cast<const char*>(attr_data.data()), attr_len);
                break;
            }
            case 0x0014: { // REALM
                result.realm = std::string(reinterpret_cast<const char*>(attr_data.data()), attr_len);
                break;
            }
        }

        pos += attr_len;
        // Skip padding
        pos = (pos + 3) & ~3;
    }

    if (!result.relayed_address.empty()) {
        return result;
    }
    return std::nullopt;
}

std::optional<uint32_t> Client::parse_refresh_response(BytesView data, const std::array<uint8_t, 12>& expected_tid) const {
    if (data.size() < 20) return std::nullopt;

    uint16_t msg_type = (data[0] << 8) | data[1];
    if (msg_type != 0x0104) return std::nullopt; // Refresh Success

    uint32_t magic = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
    if (magic != 0x2112A442) return std::nullopt;

    for (int i = 0; i < 12; ++i) {
        if (data[8 + i] != expected_tid[i]) return std::nullopt;
    }

    size_t pos = 20;
    while (pos + 4 <= data.size()) {
        uint16_t attr_type = (data[pos] << 8) | data[pos + 1];
        uint16_t attr_len = (data[pos + 2] << 8) | data[pos + 3];
        pos += 4;

        if (pos + attr_len > data.size()) break;

        if (attr_type == 0x000D) { // LIFETIME
            if (attr_len >= 4) {
                uint32_t lifetime = (data[pos] << 24) | (data[pos+1] << 16) |
                                    (data[pos+2] << 8) | data[pos+3];
                return lifetime;
            }
        }
        pos += attr_len;
        pos = (pos + 3) & ~3;
    }
    return std::nullopt;
}

std::optional<uint16_t> Client::parse_channel_bind_response(BytesView data, const std::array<uint8_t, 12>& expected_tid) const {
    if (data.size() < 20) return std::nullopt;

    uint16_t msg_type = (data[0] << 8) | data[1];
    if (msg_type != 0x0105) return std::nullopt; // ChannelBind Success

    uint32_t magic = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
    if (magic != 0x2112A442) return std::nullopt;

    for (int i = 0; i < 12; ++i) {
        if (data[8 + i] != expected_tid[i]) return std::nullopt;
    }

    return true; // Success
}

std::optional<std::pair<std::string, uint16_t>> Client::parse_data_indication(BytesView data) const {
    if (data.size() < 20) return std::nullopt;

    uint16_t msg_type = (data[0] << 8) | data[1];
    if (msg_type != 0x0017) return std::nullopt; // Data Indication

    uint32_t magic = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
    if (magic != 0x2112A442) return std::nullopt;

    size_t pos = 20;
    std::string peer_ip;
    uint16_t peer_port = 0;
    Bytes data_payload;

    while (pos + 4 <= data.size()) {
        uint16_t attr_type = (data[pos] << 8) | data[pos + 1];
        uint16_t attr_len = (data[pos + 2] << 8) | data[pos + 3];
        pos += 4;

        if (pos + attr_len > data.size()) break;

        if (attr_type == 0x0012) { // XOR-PEER-ADDRESS
            if (attr_len >= 8) {
                uint16_t xport = (data[pos+2] << 8) | data[pos+3];
                uint32_t xip = (data[pos+4] << 24) | (data[pos+5] << 16) |
                               (data[pos+6] << 8) | data[pos+7];
                uint16_t port = xport ^ 0x2112;
                uint32_t ip = ((data[pos+4] << 24) | (data[pos+5] << 16) |
                               (data[pos+6] << 8) | data[pos+7]) ^ 0x2112A442;

                char ip_str[INET_ADDRSTRLEN];
                struct in_addr addr;
                addr.s_addr = htonl(ip);
                inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
                peer_ip = ip_str;
                peer_port = port;
            }
        } else if (attr_type == 0x0013) { // DATA
            data_payload.assign(data.data() + pos, data.data() + pos + attr_len);
        }

        pos += attr_len;
        pos = (pos + 3) & ~3;
    }

    if (!peer_ip.empty() && peer_port > 0) {
        return std::make_pair(peer_ip, peer_port);
    }
    return std::nullopt;
}

std::optional<std::pair<uint16_t, BytesView>> Client::parse_channel_data(BytesView data) const {
    if (data.size() < 4) return std::nullopt;

    uint16_t channel_number = (data[0] << 8) | data[1];
    uint16_t length = (data[2] << 8) | data[3];

    if (data.size() < 4 + length) return std::nullopt;

    // Check channel number range
    if (channel_number < 0x4000 || channel_number > 0x7FFF) return std::nullopt;

    BytesView payload(data.data() + 4, length);
    return std::make_pair(channel_number, payload);
}

std::optional<Bytes> Client::send_receive(const Bytes& request, std::chrono::milliseconds timeout) {
    if (socket_fd_ < 0) connect_socket();
    if (socket_fd_ < 0) return std::nullopt;

    // Send request
    ssize_t sent = send(socket_fd_, reinterpret_cast<const char*>(request.data()), request.size(), 0);
    if (sent != static_cast<ssize_t>(request.size())) {
        return std::nullopt;
    }

    // Wait for response
    struct pollfd pfd{socket_fd_, POLLIN, 0};
    int poll_result = poll(&pfd, 1, static_cast<int>(timeout.count()));
    if (poll_result <= 0) {
        return std::nullopt;
    }

    Bytes response(2048);
    ssize_t received = recv(socket_fd_, reinterpret_cast<char*>(response.data()), response.size(), 0);
    if (received <= 0) return std::nullopt;

    response.resize(static_cast<size_t>(received));
    return response;
}

smo::Result<AllocationResult> Client::allocate(uint32_t requested_lifetime, bool even_port, bool reservation_token) {
    (void)even_port;
    (void)reservation_token;

    connect_socket();
    if (socket_fd_ < 0) {
        return SMO_ERR_TRANSPORT(306, Error, NoRetry, Reconnect, "Failed to create/connect socket");
    }

    Bytes request = build_allocate_request(requested_lifetime, even_port);
    auto response = send_receive(request, config_.timeout);

    if (!response) {
        return SMO_ERR_TRANSPORT(304, Error, RetryBackoff, Reconnect, "TURN allocate request timeout");
    }

    std::array<uint8_t, 12> tid{};
    // We need to extract the TID from the request we sent
    // For simplicity, we'll parse without TID verification for now

    auto result = parse_allocate_response(*response, {});
    if (!result) {
        return SMO_ERR_TRANSPORT(308, Error, RetryBackoff, Reconnect, "Failed to parse TURN allocate response");
    }

    std::lock_guard<std::mutex> lock(allocation_mutex_);
    allocation_ = *result;
    username_ = config_.username;
    password_ = config_.password;
    // Store nonce/realm from response for future requests

    return *result;
}

smo::Result<uint32_t> Client::refresh(uint32_t lifetime) {
    if (!allocation_) {
        return SMO_ERR_TRANSPORT(307, Error, NoRetry, Reconnect, "No active allocation to refresh");
    }

    connect_socket();
    if (socket_fd_ < 0) {
        return SMO_ERR_TRANSPORT(306, Error, NoRetry, Reconnect, "Socket not connected");
    }

    Bytes request = build_refresh_request(lifetime);
    auto response = send_receive(request, config_.timeout);

    if (!response) {
        return SMO_ERR_TRANSPORT(304, Error, RetryBackoff, Reconnect, "TURN refresh timeout");
    }

    auto lifetime_result = parse_refresh_response(*response, {});
    if (!lifetime_result) {
        return SMO_ERR_TRANSPORT(308, Error, RetryBackoff, Reconnect, "Failed to parse TURN refresh response");
    }

    std::lock_guard<std::mutex> lock(allocation_mutex_);
    if (allocation_) {
        allocation_->lifetime = *lifetime_result;
    }

    return *lifetime_result;
}

smo::Result<void> Client::create_channel_binding(uint16_t channel_number, const std::string& peer_ip, uint16_t peer_port, bool is_ipv6) {
    (void)is_ipv6;

    if (channel_number < 0x4000 || channel_number > 0x7FFF) {
        return SMO_ERR_TRANSPORT(308, Error, NoRetry, RetryOperation, "Channel number must be in range 0x4000-0x7FFF");
    }

    connect_socket();
    if (socket_fd_ < 0) {
        return SMO_ERR_TRANSPORT(306, Error, NoRetry, Reconnect, "Socket not connected");
    }

    Bytes request = build_channel_bind_request(channel_number, peer_ip, peer_port, is_ipv6);
    auto response = send_receive(request, config_.timeout);

    if (!response) {
        return SMO_ERR_TRANSPORT(304, Error, RetryBackoff, Reconnect, "ChannelBind request timeout");
    }

    auto result = parse_channel_bind_response(*response, {});
    if (!result) {
        return SMO_ERR_TRANSPORT(308, Error, RetryBackoff, Reconnect, "ChannelBind failed");
    }

    // Store channel binding
    std::lock_guard<std::mutex> lock(channels_mutex_);
    ChannelBinding binding;
    binding.channel_number = channel_number;
    binding.peer_ip = peer_ip;
    binding.peer_port = peer_port;
    binding.is_ipv6 = is_ipv6;
    binding.bound_at_ns = std::chrono::steady_clock::now().time_since_epoch().count();
    channel_bindings_[channel_number] = binding;

    std::string peer_key = peer_ip + ":" + std::to_string(peer_port);
    peer_to_channel_[peer_key] = channel_number;

    return {};
}

std::optional<uint16_t> Client::get_channel_for_peer(const std::string& peer_ip, uint16_t peer_port) const {
    std::lock_guard<std::mutex> lock(channels_mutex_);
    std::string peer_key = peer_ip + ":" + std::to_string(peer_port);
    auto it = peer_to_channel_.find(peer_key);
    if (it != peer_to_channel_.end()) {
        return it->second;
    }
    return std::nullopt;
}

smo::Result<void> Client::send_data(const std::string& peer_ip, uint16_t peer_port, BytesView data, bool is_ipv6) {
    (void)is_ipv6;

    connect_socket();
    if (socket_fd_ < 0) {
        return SMO_ERR_TRANSPORT(306, Error, NoRetry, Reconnect, "Socket not connected");
    }

    // Check if we have a channel binding for this peer
    auto channel_opt = get_channel_for_peer(peer_ip, peer_port);
    if (channel_opt) {
        return send_channel_data(channel_opt.value(), data);
    }

    // Otherwise use Send Indication
    Bytes request = build_send_indication(peer_ip, peer_port, data, is_ipv6);
    auto response = send_receive(request, config_.timeout);

    if (!response) {
        return SMO_ERR_TRANSPORT(304, Error, RetryBackoff, Reconnect, "Send Indication timeout");
    }

    // Send Indication has no response, so if we got here without error, it's sent
    return {};
}

smo::Result<void> Client::send_channel_data(uint16_t channel_number, BytesView data) {
    connect_socket();
    if (socket_fd_ < 0) {
        return SMO_ERR_TRANSPORT(306, Error, NoRetry, Reconnect, "Socket not connected");
    }

    Bytes msg = build_channel_data(channel_number, data);
    ssize_t sent = send(socket_fd_, reinterpret_cast<const char*>(msg.data()), msg.size(), 0);
    if (sent != static_cast<ssize_t>(msg.size())) {
        return SMO_ERR_TRANSPORT(304, Error, RetryBackoff, Reconnect, "Channel Data send failed");
    }
    return {};
}

void Client::start_listening(std::function<void(const std::string&, uint16_t, BytesView, bool)> callback) {
    if (listening_) return;
    data_callback_ = std::move(callback);
    listening_ = true;
    listener_thread_ = std::thread([this]() {
        Bytes buffer(2048);
        while (listening_) {
            struct pollfd pfd{socket_fd_, POLLIN, 0};
            int poll_result = poll(&pfd, 1, 100); // 100ms timeout for responsive shutdown
            if (!listening_) break;
            if (poll_result <= 0) continue;

            Bytes buffer(2048);
            ssize_t received = recv(socket_fd_, reinterpret_cast<char*>(buffer.data()), buffer.size(), 0);
            if (received <= 0) continue;

            BytesView data(buffer.data(), static_cast<size_t>(received));

            // Try parse as Channel Data first
            if (data.size() >= 4) {
                uint16_t channel = (data[0] << 8) | data[1];
                if (channel >= 0x4000 && channel <= 0x7FFF) {
                    auto parsed = parse_channel_data(BytesView(buffer.data(), received));
                    if (parsed && data_callback_) {
                        auto it = channel_bindings_.find(parsed->first);
                        if (it != channel_bindings_.end()) {
                            data_callback_(it->second.peer_ip, it->second.peer_port, parsed->second, it->second.is_ipv6);
                        }
                    }
                    continue;
                }
            }

            // Try parse as Data Indication
            if (data.size() >= 20) {
                uint16_t msg_type = (data[0] << 8) | data[1];
                if (msg_type == 0x0017) { // Data Indication
                    auto parsed = parse_data_indication(BytesView(data.data(), received));
                    if (parsed && data_callback_) {
                        data_callback_(parsed->first, parsed->second, BytesView{}, false);
                    }
                }
            }
        }
    });
}

void Client::stop_listening() {
    listening_ = false;
    if (listener_thread_.joinable()) {
        listener_thread_.join();
    }
}

std::optional<AllocationResult> Client::current_allocation() const {
    std::lock_guard<std::mutex> lock(allocation_mutex_);
    return allocation_;
}

std::vector<std::pair<uint16_t, std::string>> Client::bound_channels() const {
    std::lock_guard<std::mutex> lock(channels_mutex_);
    std::vector<std::pair<uint16_t, std::string>> result;
    for (const auto& [ch, binding] : channel_bindings_) {
        result.emplace_back(ch, binding.peer_ip + ":" + std::to_string(binding.peer_port));
    }
    return result;
}

// ── Convenience functions ──────────────────────────────────────────────────────

smo::Result<AllocationResult> allocate_turn(const std::string& server_host, uint16_t server_port,
                                            const std::string& username, const std::string& password) {
    Config cfg;
    cfg.server_host = server_host;
    cfg.server_port = server_port;
    cfg.username = username;
    cfg.password = password;
    Client client(cfg);
    return client.allocate();
}

smo::Result<uint32_t> refresh_turn(const std::string& server_host, uint16_t server_port,
                                   const std::string& username, const std::string& password,
                                   uint32_t lifetime) {
    Config cfg;
    cfg.server_host = server_host;
    cfg.server_port = server_port;
    cfg.username = username;
    cfg.password = password;
    Client client(cfg);
    return client.refresh(lifetime);
}

} // namespace turn
} // namespace network
} // namespace smo