#pragma once

#include <core/errors/error.hpp>
#include <core/types.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <string>
#include <thread>
#include <vector>

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
#include <fcntl.h>
#endif

namespace smo {
namespace network {
namespace turn {

// ── TURN Message Types (RFC 8656 §6) ───────────────────────────────────────────
inline constexpr uint16_t kTurnAllocateRequest = 0x0003;
inline constexpr uint16_t kTurnAllocateResponse = 0x0103;
inline constexpr uint16_t kTurnAllocateErrorResponse = 0x0113;

inline constexpr uint16_t kTurnRefreshRequest = 0x0004;
inline constexpr uint16_t kTurnRefreshResponse = 0x0104;
inline constexpr uint16_t kTurnRefreshErrorResponse = 0x0114;

inline constexpr uint16_t kTurnSendIndication = 0x0016;
inline constexpr uint16_t kTurnDataIndication = 0x0017;

inline constexpr uint16_t kTurnChannelBindRequest = 0x0005;
inline constexpr uint16_t kTurnChannelBindResponse = 0x0105;
inline constexpr uint16_t kTurnChannelBindErrorResponse = 0x0115;

// ── TURN Attributes (RFC 8656 §14) ─────────────────────────────────────────────
inline constexpr uint16_t kAttrLifetime = 0x000D;
inline constexpr uint16_t kAttrXorRelayedAddress = 0x0016;
inline constexpr uint16_t kAttrXorPeerAddress = 0x0012;
inline constexpr uint16_t kAttrData = 0x0013;
inline constexpr uint16_t kAttrChannelNumber = 0x000C;
inline constexpr uint16_t kAttrRequestedTransport = 0x0019;
inline constexpr uint16_t kAttrDontFragment = 0x001A;
inline constexpr uint16_t kAttrReservationToken = 0x0022;
inline constexpr uint16_t kAttrEvenPort = 0x000A;
inline constexpr uint16_t kAttrRequestedAddressFamily = 0x0017;
inline constexpr uint16_t kAttrXorPeerAddressAlt = 0x8012;

// ── TURN Error Codes (RFC 8656 §15) ───────────────────────────────────────────
inline constexpr uint16_t kErrTryAlternate = 300;
inline constexpr uint16_t kErrBadRequest = 400;
inline constexpr uint16_t kErrUnauthorized = 401;
inline constexpr uint16_t kErrForbidden = 403;
inline constexpr uint16_t kErrAllocationMismatch = 437;
inline constexpr uint16_t kErrStaleNonce = 438;
inline constexpr uint16_t kErrWrongCredentials = 441;
inline constexpr uint16_t kErrUnsupportedTransport = 442;
inline constexpr uint16_t kErrAllocationQuotaReached = 486;
inline constexpr uint16_t kErrInsufficientCapacity = 508;

// ── TURN Transaction ID (96 bits) ──────────────────────────────────────────────
struct TransactionId
{
    std::array<uint8_t, 12> bytes{};
};

// ── Relayed Address (result of TURN Allocate) ──────────────────────────────────
struct RelayedAddress
{
    std::string ip;          // Relayed transport address (IPv4 or IPv6)
    uint16_t port = 0;       // Relayed port
    bool is_ipv6 = false;

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

// ── Channel Data (for TURN Channel Data mechanism) ─────────────────────────────
struct ChannelData
{
    uint16_t channel_number = 0;  // 0x4000-0x7FFF
    Bytes data;
};

// ── TURN Client Configuration ──────────────────────────────────────────────────
struct Config
{
    std::string server_host = "turn.example.com";
    uint16_t server_port = 3478;
    std::string username = "";
    std::string password = "";
    std::string realm = "";
    int max_attempts = 3;
    std::chrono::milliseconds timeout = std::chrono::milliseconds(5000);
    uint32_t default_lifetime = 600; // seconds, default 10 min
    std::string software_name = "smo-node/0.0.7";
};

// ── TURN Allocation Result ─────────────────────────────────────────────────────
struct AllocationResult
{
    RelayedAddress relayed_address;
    uint32_t lifetime = 0;              // Granted lifetime in seconds
    std::string nonce;                   // For digest auth
    std::string realm;                   // Realm from server
    std::vector<uint16_t> channel_numbers; // Bound channels
};

// ── Channel Binding ────────────────────────────────────────────────────────────
struct ChannelBinding
{
    uint16_t channel_number = 0;  // 0x4000-0x7FFF
    std::string peer_ip;
    uint16_t peer_port = 0;
    bool is_ipv6 = false;
    int64_t bound_at_ns = 0;
};

// ── TURN Client ────────────────────────────────────────────────────────────────
class Client
{
public:
    explicit Client(const Config& config = Config());
    ~Client();

    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;
    Client(Client&&) = default;
    Client& operator=(Client&&) = default;

    // ── Allocation (RFC 8656 §6) ───────────────────────────────────────────────

    // Request allocation on TURN server
    // Returns allocated relayed address on success
    smo::Result<AllocationResult> allocate(
        uint32_t requested_lifetime = 0,
        bool even_port = false,
        bool reservation_token = false);

    // Refresh allocation to extend lifetime (RFC 8656 §7)
    // lifetime = 0 means delete allocation
    smo::Result<uint32_t> refresh(uint32_t lifetime);

    // ── Channel Bindings (RFC 8656 §11) ────────────────────────────────────────

    // Create channel binding to a peer
    // channel_number must be in range 0x4000-0x7FFF
    smo::Result<void> create_channel_binding(uint16_t channel_number,
                                             const std::string& peer_ip,
                                             uint16_t peer_port,
                                             bool is_ipv6 = false);

    // Get channel binding for a peer
    std::optional<uint16_t> get_channel_for_peer(const std::string& peer_ip, uint16_t peer_port) const;

    // ── Send/Receive Data (RFC 8656 §10-11) ────────────────────────────────────

    // Send data via Send Indication (no channel binding required)
    smo::Result<void> send_data(const std::string& peer_ip, uint16_t peer_port, BytesView data, bool is_ipv6 = false);

    // Send data via Channel Data (requires channel binding)
    smo::Result<void> send_channel_data(uint16_t channel_number, BytesView data);

    // Start listening for incoming data (runs in background thread)
    // callback receives (peer_ip, peer_port, data)
    void start_listening(std::function<void(const std::string&, uint16_t, BytesView, bool)> callback);
    void stop_listening();

    // ── Configuration ──────────────────────────────────────────────────────────

    const Config& config() const noexcept { return config_; }

    // Get current allocation info
    std::optional<AllocationResult> current_allocation() const;

    // Get bound channels
    std::vector<std::pair<uint16_t, std::string>> bound_channels() const;

private:
    Config config_;

    // Socket handling
    int socket_fd_ = -1;
    struct sockaddr_in server_addr_;
    bool socket_connected_ = false;

    // Authentication state
    std::string nonce_;
    std::string realm_;
    std::string username_;
    std::string password_;

    // Allocation state
    std::optional<AllocationResult> allocation_;
    mutable std::mutex allocation_mutex_;

    // Channel bindings
    mutable std::mutex channels_mutex_;
    std::map<uint16_t, ChannelBinding> channel_bindings_; // channel_number -> binding
    std::map<std::string, uint16_t> peer_to_channel_;     // peer_key -> channel_number

    // Listening thread
    std::thread listener_thread_;
    std::atomic<bool> listening_{false};
    std::function<void(const std::string&, uint16_t, BytesView, bool)> data_callback_;

    // Transaction ID generator
    mutable std::mutex tid_mutex_;
    std::mt19937 gen_;

    // ── Internal Methods ──────────────────────────────────────────────────────

    int create_socket();
    void connect_socket();

    // STUN/TURN message building
    Bytes build_allocate_request(uint32_t lifetime, bool even_port);
    Bytes build_refresh_request(uint32_t lifetime);
    Bytes build_send_indication(const std::string& peer_ip, uint16_t peer_port, BytesView data, bool is_ipv6);
    Bytes build_channel_bind_request(uint16_t channel_number, const std::string& peer_ip, uint16_t peer_port, bool is_ipv6);
    Bytes build_channel_data(uint16_t channel_number, BytesView data);

    // STUN/TURN message parsing
    std::optional<AllocationResult> parse_allocate_response(BytesView data, const std::array<uint8_t, 12>& expected_tid) const;
    std::optional<uint32_t> parse_refresh_response(BytesView data, const std::array<uint8_t, 12>& expected_tid) const;
    std::optional<uint16_t> parse_channel_bind_response(BytesView data, const std::array<uint8_t, 12>& expected_tid) const;
    std::optional<std::pair<std::string, uint16_t>> parse_data_indication(BytesView data) const;
    std::optional<std::pair<uint16_t, BytesView>> parse_channel_data(BytesView data) const;

    // Transaction ID handling
    std::array<uint8_t, 12> generate_transaction_id();
    void store_tid(const std::array<uint8_t, 12>& tid, const std::string& purpose);
    std::optional<std::string> get_tid_purpose(const std::array<uint8_t, 12>& tid) const;

    // Long-term credential mechanism (RFC 5389 §10.2)
    std::string compute_message_integrity(BytesView data) const;
    bool verify_message_integrity(BytesView data, const std::string& expected_integrity) const;

    // Socket I/O with timeout
    std::optional<Bytes> send_receive(const Bytes& request, std::chrono::milliseconds timeout);
    std::optional<Bytes> receive_with_timeout(std::chrono::milliseconds timeout);

    // Message integrity attributes
    inline static constexpr uint16_t kAttrMessageIntegrity = 0x0008;
    inline static constexpr uint16_t kAttrUsername = 0x0006;
    inline static constexpr uint16_t kAttrNonce = 0x0015;
    inline static constexpr uint16_t kAttrRealm = 0x0014;
    inline static constexpr uint16_t kAttrSoftware = 0x8022;
    inline static constexpr uint16_t kAttrFingerprint = 0x8028;

    // Long-term credential mechanism
    inline static constexpr uint32_t kStunMagicCookie = 0x2112A442;
    inline static constexpr uint16_t kAttrPasswordAlgorithm = 0x801E;

    // Message types
    inline static constexpr uint16_t kStunAllocateRequest = 0x0003;
    inline static constexpr uint16_t kStunAllocateResponse = 0x0103;
    inline static constexpr uint16_t kStunAllocateErrorResponse = 0x0113;
    inline static constexpr uint16_t kStunRefreshRequest = 0x0004;
    inline static constexpr uint16_t kStunRefreshResponse = 0x0104;
    inline static constexpr uint16_t kStunRefreshErrorResponse = 0x0114;
    inline static constexpr uint16_t kStunSendIndication = 0x0016;
    inline static constexpr uint16_t kStunDataIndication = 0x0017;
    inline static constexpr uint16_t kStunChannelBindRequest = 0x0005;
    inline static constexpr uint16_t kStunChannelBindResponse = 0x0105;
    inline static constexpr uint16_t kStunChannelBindErrorResponse = 0x0115;

    // Attributes
    inline static constexpr uint16_t kAttrLifetime = 0x000D;
    inline static constexpr uint16_t kAttrXorRelayedAddress = 0x0016;
    inline static constexpr uint16_t kAttrXorPeerAddress = 0x0012;
    inline static constexpr uint16_t kAttrData = 0x0013;
    inline static constexpr uint16_t kAttrChannelNumber = 0x000C;
    inline static constexpr uint16_t kAttrRequestedTransport = 0x0019;
    inline static constexpr uint16_t kAttrDontFragment = 0x001A;
    inline static constexpr uint16_t kAttrXorRelayedAddressAlt = 0x8016;
    inline static constexpr uint16_t kAttrXorPeerAddressAlt = 0x8012;

    // Error codes
    inline static constexpr uint16_t kErrUnauthorized = 401;
    inline static constexpr uint16_t kErrStaleNonce = 438;
    inline static constexpr uint16_t kErrAllocationMismatch = 437;

    // UDP transport
    inline static constexpr uint8_t kTransportUdp = 0x11;

    // Channel number range (RFC 8656 §11)
    inline static constexpr uint16_t kChannelNumberMin = 0x4000;
    inline static constexpr uint16_t kChannelNumberMax = 0x7FFF;

    // Transport protocol
    inline static constexpr uint8_t kTransportUdpProtocol = 0x11;

    // SHA-1 for message integrity
    std::string hmac_sha1(const std::string& key, const std::string& data) const;
};

// ── Convenience functions ──────────────────────────────────────────────────────

// Perform TURN allocation with default config
smo::Result<AllocationResult> allocate_turn(
    const std::string& server_host,
    uint16_t server_port,
    const std::string& username,
    const std::string& password);

// Refresh allocation
smo::Result<uint32_t> refresh_turn(
    const std::string& server_host,
    uint16_t server_port,
    const std::string& username,
    const std::string& password,
    uint32_t lifetime);

} // namespace turn
} // namespace network
} // namespace smo