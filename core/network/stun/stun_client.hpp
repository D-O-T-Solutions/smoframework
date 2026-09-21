#pragma once

#include <core/errors/error.hpp>
#include <core/types.hpp>

#include <chrono>
#include <functional>
#include <optional>
#include <string>
#include <thread>

#if defined(_WIN32) || defined(_WIN64)
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <poll.h>
#endif

namespace smo {
namespace network {
namespace stun {

    // ── STUN Message Types (RFC 5389) ────────────────────────────────────────
    inline constexpr uint16_t kStunBindingRequest = 0x0001;
    inline constexpr uint16_t kStunBindingResponse = 0x0101;
    inline constexpr uint16_t kStunBindingErrorResponse = 0x0111;

    // ── STUN Attributes ──────────────────────────────────────────────────────
    inline constexpr uint16_t kAttrXorMappedAddress = 0x0020;
    inline constexpr uint16_t kAttrMappedAddress = 0x0001;
    inline constexpr uint16_t kAttrXorMappedAddressAlt = 0x8020; // RFC 5389 uses 0x0020
    inline constexpr uint16_t kAttrSoftware = 0x8022;
    inline constexpr uint16_t kAttrFingerprint = 0x8028;

    // ── Magic Cookie (RFC 5389) ──────────────────────────────────────────────
    inline constexpr uint32_t kStunMagicCookie = 0x2112A442;

    // ── STUN Transaction ID (96 bits) ────────────────────────────────────────
    struct TransactionId
    {
        std::array<uint8_t, 12> bytes{};
    };

    // ── Mapped Address (result of STUN binding) ──────────────────────────────
    struct MappedAddress
    {
        std::string ip;       // IPv4 or IPv6
        uint16_t port = 0;
        bool is_ipv6 = false;
        int64_t discovered_at = 0; // timestamp when discovered

        bool empty() const noexcept { return ip.empty() || port == 0; }
        std::string to_string() const
        {
            if (empty())
                return "";
            if (is_ipv6)
                return "[" + ip + "]:" + std::to_string(port);
            return ip + ":" + std::to_string(port);
        }
    };

    // ── STUN Client Configuration ────────────────────────────────────────────
    struct Config
    {
        std::string server_host = "stun.l.google.com";
        uint16_t server_port = 19302;
        int max_attempts = 3;
        std::chrono::milliseconds timeout = std::chrono::milliseconds(2000);
        std::string software_name = "smo-node/0.0.4";
    };

    // ── STUN Client Result ───────────────────────────────────────────────────
    struct Result
    {
        MappedAddress mapped_address;
        std::chrono::milliseconds latency;
        int attempts_used = 0;
        std::string server_used;
    };

    // ── STUN Client ──────────────────────────────────────────────────────────
    class Client
    {
    public:
        explicit Client(const Config& config = Config());
        ~Client() = default;

        Client(const Client&) = delete;
        Client& operator=(const Client&) = delete;
        Client(Client&&) = default;
        Client& operator=(Client&&) = default;

        // Perform STUN binding request to discover mapped address
        // Returns Result with mapped address on success, Error on failure
        smo::Result<Result> discover();

        // Get current config (for inspection)
        const Config& config() const noexcept { return config_; }

    public:
        // Parse STUN Binding Response and extract XOR-MAPPED-ADDRESS
        // Returns mapped address on success, empty optional on parse failure
        std::optional<MappedAddress> parse_response(BytesView data, const TransactionId& expected_tid) const;

        // Build STUN Binding Request packet (public for testing)
        Bytes build_request(TransactionId& out_tid) const;

private:
        Config config_;

        // Send request and receive response with timeout
        // Returns response bytes on success, empty on timeout/error
        std::optional<Bytes> send_receive(int fd, const sockaddr* addr, socklen_t addrlen, const Bytes& request) const;

        // Create and connect UDP socket to STUN server
        int create_socket(const std::string& host, uint16_t port, sockaddr_in& out_addr) const;
    };

    // ── Convenience function for one-shot STUN discovery ─────────────────────
    // Uses default config (stun.l.google.com:19302, 3 retries, 2s timeout)
    smo::Result<MappedAddress> discover_mapped_address();

    // ── Run STUN discovery with custom config ────────────────────────────────
    smo::Result<MappedAddress> discover_mapped_address(const Config& config);

} // namespace stun
} // namespace network
} // namespace smo