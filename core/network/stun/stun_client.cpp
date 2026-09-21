#include "stun_client.hpp"

#include <cstdio>
#include <cstring>
#include <random>
#include <chrono>

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
#include <fcntl.h>
#include <poll.h>
#define SOCKET int
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#define closesocket(fd) ::close(fd)
#endif

namespace smo {
namespace network {
namespace stun {

    // ── Client Implementation ────────────────────────────────────────────────

    Client::Client(const Config& config) : config_(config) {}

    smo::Result<Result> Client::discover()
    {
        Result result;
        result.attempts_used = 0;
        result.server_used = config_.server_host + ":" + std::to_string(config_.server_port);

        // Resolve server address once
        sockaddr_in server_addr;
        int sock = create_socket(config_.server_host, config_.server_port, server_addr);
        if (sock == INVALID_SOCKET)
        {
            return smo::Error(smo::ErrorCode(smo::ErrorCategory::Transport, 308, smo::Severity::Error,
                                             smo::RetryClass::NoRetry, smo::Recovery::None),
                              "Failed to create/resolve socket for STUN server: " + config_.server_host);
        }

        std::optional<MappedAddress> mapped_addr;
        auto start_overall = std::chrono::steady_clock::now();

        for (int attempt = 1; attempt <= config_.max_attempts; ++attempt)
        {
            result.attempts_used = attempt;

            TransactionId tid;
            Bytes request = build_request(tid);

            auto attempt_start = std::chrono::steady_clock::now();
            auto response_opt = send_receive(sock, reinterpret_cast<const sockaddr*>(&server_addr), sizeof(server_addr), request);
            auto attempt_end = std::chrono::steady_clock::now();

            if (response_opt)
            {
                auto parsed = parse_response(*response_opt, tid);
                if (parsed)
                {
                    mapped_addr = parsed;
                    result.latency = std::chrono::duration_cast<std::chrono::milliseconds>(attempt_end - attempt_start);
                    break;
                }
            }

            // Wait before retry (except on last attempt)
            if (attempt < config_.max_attempts)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }

        closesocket(sock);

        if (!mapped_addr)
        {
            return smo::Error(smo::ErrorCode(smo::ErrorCategory::Transport, 301, smo::Severity::Error,
                                             smo::RetryClass::RetryBackoff, smo::Recovery::Reconnect),
                              "STUN binding failed after " + std::to_string(config_.max_attempts) + " attempts");
        }

        result.mapped_address = *mapped_addr;
        return result;
    }

    // ── Build STUN Binding Request ───────────────────────────────────────────
    Bytes Client::build_request(TransactionId& out_tid) const
    {
        // Generate random transaction ID
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint8_t> dist(0, 255);
        for (auto& b : out_tid.bytes)
        {
            b = dist(gen);
        }

        // STUN Message Header: 20 bytes
        // 0-1: Message Type (Binding Request = 0x0001)
        // 2-3: Message Length (0 for now, will update after building body)
        // 4-7: Magic Cookie (0x2112A442)
        // 8-19: Transaction ID (12 bytes)

        Bytes msg;
        msg.reserve(64);

        // Message Type
        msg.push_back(static_cast<uint8_t>((kStunBindingRequest >> 8) & 0xFF));
        msg.push_back(static_cast<uint8_t>(kStunBindingRequest & 0xFF));

        // Message Length (placeholder, 2 bytes)
        msg.push_back(0);
        msg.push_back(0);

        // Magic Cookie
        msg.push_back(static_cast<uint8_t>((kStunMagicCookie >> 24) & 0xFF));
        msg.push_back(static_cast<uint8_t>((kStunMagicCookie >> 16) & 0xFF));
        msg.push_back(static_cast<uint8_t>((kStunMagicCookie >> 8) & 0xFF));
        msg.push_back(static_cast<uint8_t>(kStunMagicCookie & 0xFF));

        // Transaction ID (12 bytes)
        msg.insert(msg.end(), out_tid.bytes.begin(), out_tid.bytes.end());

        // Attributes
        // SOFTWARE attribute (optional but good practice)
        std::string software = config_.software_name;
        if (!software.empty())
        {
            uint16_t attr_type = kAttrSoftware;
            uint16_t attr_len = static_cast<uint16_t>(software.size());

            // Type (2 bytes)
            msg.push_back(static_cast<uint8_t>((attr_type >> 8) & 0xFF));
            msg.push_back(static_cast<uint8_t>(attr_type & 0xFF));
            // Length (2 bytes)
            msg.push_back(static_cast<uint8_t>((attr_len >> 8) & 0xFF));
            msg.push_back(static_cast<uint8_t>(attr_len & 0xFF));
            // Value
            msg.insert(msg.end(), software.begin(), software.end());

            // Padding to 4-byte boundary
            while (msg.size() % 4 != 0)
            {
                msg.push_back(0);
            }
        }

        // FINGERPRINT attribute (CRC32 of message up to this point, XOR 0x5354554E)
        // We'll compute and append it at the end

        // Update Message Length (total length - 20 bytes header)
        uint16_t msg_len = static_cast<uint16_t>(msg.size() - 20);
        msg[2] = static_cast<uint8_t>((msg_len >> 8) & 0xFF);
        msg[3] = static_cast<uint8_t>(msg_len & 0xFF);

        // Compute FINGERPRINT (CRC32 of message so far, XOR 0x5354554E)
        uint32_t crc = 0xFFFFFFFF;
        for (uint8_t byte : msg)
        {
            crc ^= byte;
            for (int i = 0; i < 8; ++i)
            {
                crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
            }
        }
        crc ^= 0xFFFFFFFF;
        crc ^= 0x5354554E; // XOR with "STUN"

        // Append FINGERPRINT attribute
        uint16_t fp_type = kAttrFingerprint;
        uint16_t fp_len = 4;
        msg.push_back(static_cast<uint8_t>((fp_type >> 8) & 0xFF));
        msg.push_back(static_cast<uint8_t>(fp_type & 0xFF));
        msg.push_back(static_cast<uint8_t>((fp_len >> 8) & 0xFF));
        msg.push_back(static_cast<uint8_t>(fp_len & 0xFF));
        msg.push_back(static_cast<uint8_t>((crc >> 24) & 0xFF));
        msg.push_back(static_cast<uint8_t>((crc >> 16) & 0xFF));
        msg.push_back(static_cast<uint8_t>((crc >> 8) & 0xFF));
        msg.push_back(static_cast<uint8_t>(crc & 0xFF));

        // Update Message Length again to include FINGERPRINT (8 bytes)
        msg_len = static_cast<uint16_t>(msg.size() - 20);
        msg[2] = static_cast<uint8_t>((msg_len >> 8) & 0xFF);
        msg[3] = static_cast<uint8_t>(msg_len & 0xFF);

        return msg;
    }

    // ── Parse STUN Binding Response ──────────────────────────────────────────
    std::optional<MappedAddress> Client::parse_response(BytesView data, const TransactionId& expected_tid) const
    {
        if (data.size() < 20)
        {
            return std::nullopt;
        }

        // Check Message Type
        uint16_t msg_type = (static_cast<uint16_t>(data[0]) << 8) | data[1];
        if (msg_type != kStunBindingResponse && msg_type != kStunBindingErrorResponse)
        {
            return std::nullopt;
        }

        // Check Magic Cookie
        uint32_t magic = (static_cast<uint32_t>(data[4]) << 24) |
                         (static_cast<uint32_t>(data[5]) << 16) |
                         (static_cast<uint32_t>(data[6]) << 8) |
                         static_cast<uint32_t>(data[7]);
        if (magic != kStunMagicCookie)
        {
            return std::nullopt;
        }

        // Check Transaction ID
        TransactionId recv_tid;
        std::copy(data.begin() + 8, data.begin() + 20, recv_tid.bytes.begin());
        if (recv_tid.bytes != expected_tid.bytes)
        {
            return std::nullopt;
        }

        // Parse attributes (start after 20-byte header)
        size_t offset = 20;
        uint16_t msg_len = (static_cast<uint16_t>(data[2]) << 8) | data[3];
        size_t attrs_end = 20 + msg_len;

        MappedAddress mapped;

        while (offset + 4 <= attrs_end && offset + 4 <= data.size())
        {
            if (offset + 4 > data.size())
                break;

            uint16_t attr_type = (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
            uint16_t attr_len = (static_cast<uint16_t>(data[offset + 2]) << 8) | data[offset + 3];
            offset += 4;

            if (offset + attr_len > data.size() || offset + attr_len > attrs_end)
                break;

            BytesView attr_value(data.data() + offset, attr_len);

            if (attr_type == kAttrXorMappedAddress || attr_type == kAttrMappedAddress)
            {
                if (attr_value.size() >= 8)
                {
                    // XOR-MAPPED-ADDRESS format:
                    // 0: reserved (0)
                    // 1: family (0x01 = IPv4, 0x02 = IPv6)
                    // 2-3: XOR'ed port
                    // 4-7: XOR'ed address (IPv4) or 4-19 (IPv6)
                    uint8_t family = attr_value[1];
                    uint16_t xport = (static_cast<uint16_t>(attr_value[2]) << 8) | attr_value[3];

                    if (attr_type == kAttrXorMappedAddress)
                    {
                        // XOR with magic cookie for port
                        xport ^= static_cast<uint16_t>((kStunMagicCookie >> 16) & 0xFFFF);
                    }

                    mapped.port = xport;

                    if (family == 0x01) // IPv4
                    {
                        mapped.is_ipv6 = false;
                        if (attr_value.size() >= 8)
                        {
                            uint32_t xaddr = (static_cast<uint32_t>(attr_value[4]) << 24) |
                                             (static_cast<uint32_t>(attr_value[5]) << 16) |
                                             (static_cast<uint32_t>(attr_value[6]) << 8) |
                                             static_cast<uint32_t>(attr_value[7]);

                            if (attr_type == kAttrXorMappedAddress)
                            {
                                xaddr ^= kStunMagicCookie;
                            }

                            char ip_str[INET_ADDRSTRLEN];
                            struct in_addr addr;
                            addr.s_addr = htonl(xaddr);
                            if (inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str)))
                            {
                                mapped.ip = ip_str;
                            }
                        }
                    }
                    else if (family == 0x02) // IPv6
                    {
                        mapped.is_ipv6 = true;
                        if (attr_value.size() >= 20)
                        {
                            // For IPv6, XOR with magic cookie + transaction ID
                            std::array<uint8_t, 16> xaddr_bytes;
                            for (int i = 0; i < 16; ++i)
                            {
                                xaddr_bytes[i] = attr_value[4 + i];
                            }

                            if (attr_type == kAttrXorMappedAddress)
                            {
                                // XOR first 4 bytes with magic cookie
                                xaddr_bytes[0] ^= static_cast<uint8_t>((kStunMagicCookie >> 24) & 0xFF);
                                xaddr_bytes[1] ^= static_cast<uint8_t>((kStunMagicCookie >> 16) & 0xFF);
                                xaddr_bytes[2] ^= static_cast<uint8_t>((kStunMagicCookie >> 8) & 0xFF);
                                xaddr_bytes[3] ^= static_cast<uint8_t>(kStunMagicCookie & 0xFF);
                                // XOR next 12 bytes with transaction ID
                                for (int i = 0; i < 12; ++i)
                                {
                                    xaddr_bytes[4 + i] ^= expected_tid.bytes[i];
                                }
                            }

                            char ip_str[INET6_ADDRSTRLEN];
                            struct in6_addr addr;
                            std::copy(xaddr_bytes.begin(), xaddr_bytes.end(), addr.s6_addr);
                            if (inet_ntop(AF_INET6, &addr, ip_str, sizeof(ip_str)))
                            {
                                mapped.ip = ip_str;
                            }
                        }
                    }
                }
            }

            offset += attr_len;
            // Padding to 4-byte boundary
            offset = (offset + 3) & ~3;
        }

        if (!mapped.ip.empty() && mapped.port != 0)
        {
            return mapped;
        }
        return std::nullopt;
    }

    // ── Send Request and Receive Response ────────────────────────────────────
    std::optional<Bytes> Client::send_receive(int fd, const sockaddr* addr, socklen_t addrlen, const Bytes& request) const
    {
        // Send request
        ssize_t sent = sendto(fd, reinterpret_cast<const char*>(request.data()), request.size(), 0, addr, addrlen);
        if (sent != static_cast<ssize_t>(request.size()))
        {
            return std::nullopt;
        }

        // Wait for response with timeout
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLIN;

        int poll_result = poll(&pfd, 1, static_cast<int>(config_.timeout.count()));
        if (poll_result <= 0)
        {
            return std::nullopt; // Timeout or error
        }

        // Receive response
        Bytes response(1500); // Max UDP packet size
        ssize_t received = recvfrom(fd, reinterpret_cast<char*>(response.data()), response.size(), 0, nullptr, nullptr);
        if (received <= 0)
        {
            return std::nullopt;
        }
        response.resize(static_cast<size_t>(received));
        return response;
    }

    // ── Create and Connect UDP Socket ────────────────────────────────────────
    int Client::create_socket(const std::string& host, uint16_t port, sockaddr_in& out_addr) const
    {
        // Resolve hostname
        struct addrinfo hints{}, *res = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;

        std::string port_str = std::to_string(port);
        int gai_err = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res);
        if (gai_err != 0 || !res)
        {
            return INVALID_SOCKET;
        }

        // Create socket
        int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (sock == INVALID_SOCKET)
        {
            freeaddrinfo(res);
            return INVALID_SOCKET;
        }

        // Copy address for return
        if (res->ai_addrlen == sizeof(sockaddr_in))
        {
            std::memcpy(&out_addr, res->ai_addr, sizeof(sockaddr_in));
        }

        // Set non-blocking
#if defined(_WIN32) || defined(_WIN64)
        u_long mode = 1;
        ioctlsocket(sock, FIONBIO, &mode);
#else
        int flags = fcntl(sock, F_GETFL, 0);
        if (flags >= 0)
        {
            fcntl(sock, F_SETFL, flags | O_NONBLOCK);
        }
#endif

        freeaddrinfo(res);
        return sock;
    }

    // ── Convenience Functions ────────────────────────────────────────────────

    smo::Result<MappedAddress> discover_mapped_address()
    {
        Client client;
        auto result = client.discover();
        if (!result)
        {
            return result.error();
        }
        return result.value().mapped_address;
    }

    smo::Result<MappedAddress> discover_mapped_address(const Config& config)
    {
        Client client(config);
        auto result = client.discover();
        if (!result)
        {
            return result.error();
        }
        return result.value().mapped_address;
    }

} // namespace stun
} // namespace network
} // namespace smo