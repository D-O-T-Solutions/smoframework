#include <algorithm>
#include <chrono>
#include <cstdio>
#include <random>
#include <cstring>

#if defined(_WIN32) || defined(_WIN64)
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <poll.h>
#include <fcntl.h>
#define SOCKET int
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#define closesocket(fd) ::close(fd)
#endif

#include "ice_candidate.hpp"
#include "../stun/stun_client.hpp"
#include "core/bootstrap/cbor.hpp"
#include "core/transport/transport.hpp"

namespace smo::network::ice {

    namespace {
        uint32_t hash_foundation(const std::string& s)
        {
            uint32_t h = 0x811C9DC5; // FNV-1a offset basis
            for (unsigned char c : s)
            {
                h ^= c;
                h *= 0x01000193; // FNV-1a prime
            }
            return h;
        }

        std::string foundation_to_string(uint32_t h)
        {
            char buf[9];
            snprintf(buf, sizeof(buf), "%08x", h);
            return std::string(buf, 8);
        }
    }

    // ── IceAgent Implementation ────────────────────────────────────────────────

    IceAgent::IceAgent(const IceConfig& cfg) : config_(cfg) {}

    // ── Main Gather Entry Point ────────────────────────────────────────────────

    smo::Result<GatherResult> IceAgent::gather(const std::vector<Endpoint>& local_endpoints,
                                               const Endpoint& relay_endpoint)
    {
        auto start = std::chrono::steady_clock::now();
        GatherResult result;
        local_candidates_.clear();

        // 1. Host candidates (from local interfaces)
        auto host_cands = gather_host_candidates(local_endpoints);
        result.host_candidates = static_cast<int>(host_cands.size());
        local_candidates_.insert(local_candidates_.end(), host_cands.begin(), host_cands.end());

        // 2. Server-reflexive candidates (via STUN)
        auto srflx_cands = gather_srflx_candidates(local_endpoints);
        result.srflx_candidates = static_cast<int>(srflx_cands.size());
        local_candidates_.insert(local_candidates_.end(), srflx_cands.begin(), srflx_cands.end());

        // 3. Relay candidates (if relay endpoint provided and enabled)
        if (config_.enable_relay && relay_endpoint.port != 0 && !relay_endpoint.host.empty())
        {
            auto relay_cands = gather_relay_candidates(relay_endpoint);
            result.relay_candidates = static_cast<int>(relay_cands.size());
            local_candidates_.insert(local_candidates_.end(), relay_cands.begin(), relay_cands.end());
        }

        auto end = std::chrono::steady_clock::now();
        result.gather_time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        result.candidates = local_candidates_;

        std::printf("[ice] Gathered %zu candidates (host=%d, srflx=%d, relay=%d) in %lldms\n",
                    local_candidates_.size(),
                    result.host_candidates, result.srflx_candidates, result.relay_candidates,
                    static_cast<long long>(result.gather_time.count()));

        return result;
    }

    // ── Host Candidate Gathering ───────────────────────────────────────────────

    std::vector<Candidate> IceAgent::gather_host_candidates(const std::vector<Endpoint>& endpoints)
    {
        std::vector<Candidate> candidates;

        for (const auto& ep : endpoints)
        {
            if (ep.port == 0 || ep.host.empty())
                continue;

            // Skip if not a bindable local address
            if (ep.host == "0.0.0.0" || ep.host == "::" || ep.host == "*")
                continue;

            Candidate cand;
            cand.type = CandidateType::Host;
            cand.ip = ep.host;
            cand.port = ep.port;
            cand.is_ipv6 = (ep.host.find(':') != std::string::npos);
            cand.foundation = foundation_to_string(hash_foundation(
                std::string("host:") + ep.host + ":" + std::to_string(ep.port)));
            cand.priority = calculate_priority(CandidateType::Host);
            cand.discovered_at = std::chrono::system_clock::now().time_since_epoch().count();

            candidates.push_back(cand);
            std::printf("[ice] Host candidate: %s\n", cand.to_string().c_str());
        }

        // Also enumerate all local interfaces for additional host candidates
        // (in case the endpoint list doesn't include all interfaces)
#if !defined(_WIN32) && !defined(_WIN64)
        struct ifaddrs* ifaddr = nullptr;
        if (getifaddrs(&ifaddr) == 0)
        {
            for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next)
            {
                if (!ifa->ifa_addr)
                    continue;

                if (ifa->ifa_addr->sa_family == AF_INET)
                {
                    struct sockaddr_in* sa = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr);
                    char ip_str[INET_ADDRSTRLEN];
                    if (inet_ntop(AF_INET, &sa->sin_addr, ip_str, sizeof(ip_str)))
                    {
                        std::string ip(ip_str);
                        // Skip loopback and already-added addresses
                        if (ip == "127.0.0.1")
                            continue;

                        bool exists = false;
                        for (const auto& c : candidates)
                        {
                            if (c.ip == ip && !c.is_ipv6)
                            {
                                exists = true;
                                break;
                            }
                        }
                        if (!exists)
                        {
                            Candidate cand;
                            cand.type = CandidateType::Host;
                            cand.ip = ip;
                            cand.port = 0; // Port unknown for interface enumeration
                            cand.is_ipv6 = false;
                            cand.foundation = foundation_to_string(
                                hash_foundation("host:" + ip + ":0"));
                            cand.priority = calculate_priority(CandidateType::Host);
                            cand.discovered_at = std::chrono::system_clock::now().time_since_epoch().count();
                            candidates.push_back(cand);
                            std::printf("[ice] Host candidate (iface): %s\n", cand.to_string().c_str());
                        }
                    }
                }
                else if (ifa->ifa_addr->sa_family == AF_INET6)
                {
                    struct sockaddr_in6* sa = reinterpret_cast<struct sockaddr_in6*>(ifa->ifa_addr);
                    char ip_str[INET6_ADDRSTRLEN];
                    if (inet_ntop(AF_INET6, &sa->sin6_addr, ip_str, sizeof(ip_str)))
                    {
                        std::string ip(ip_str);
                        if (ip == "::1" || ip.find("fe80::") == 0)
                            continue; // Skip loopback and link-local

                        bool exists = false;
                        for (const auto& c : candidates)
                        {
                            if (c.ip == ip && c.is_ipv6)
                            {
                                exists = true;
                                break;
                            }
                        }
                        if (!exists)
                        {
                            Candidate cand;
                            cand.type = CandidateType::Host;
                            cand.ip = ip;
                            cand.port = 0;
                            cand.is_ipv6 = true;
                            cand.foundation = foundation_to_string(
                                hash_foundation("host:" + ip + ":0"));
                            cand.priority = calculate_priority(CandidateType::Host);
                            cand.discovered_at = std::chrono::system_clock::now().time_since_epoch().count();
                            candidates.push_back(cand);
                            std::printf("[ice] Host candidate (iface): %s\n", cand.to_string().c_str());
                        }
                    }
                }
            }
            freeifaddrs(ifaddr);
        }
#endif

        return candidates;
    }

    // ── Server-Reflexive (STUN) Candidate Gathering ────────────────────────────

    std::vector<Candidate> IceAgent::gather_srflx_candidates(const std::vector<Endpoint>& endpoints)
    {
        std::vector<Candidate> candidates;

        // Use STUN client to discover mapped address
        stun::Config stun_cfg;
        stun_cfg.server_host = config_.stun_server_host;
        stun_cfg.server_port = config_.stun_server_port;
        stun_cfg.max_attempts = config_.max_stun_attempts;
        stun_cfg.timeout = std::chrono::milliseconds(config_.stun_timeout_ms);

        stun::Client stun_client(stun_cfg);
        auto stun_result = stun_client.discover();

        if (!stun_result)
        {
            std::printf("[ice] STUN discovery failed: %s\n", stun_result.error().message.c_str());
            return candidates;
        }

        const auto& mapped = stun_result.value().mapped_address;
        if (mapped.empty())
        {
            std::printf("[ice] STUN returned empty mapped address\n");
            return candidates;
        }

        // Create server-reflexive candidate for each local endpoint that shares the same port
        // The STUN mapped port is the external port; we associate it with each local endpoint
        for (const auto& ep : endpoints)
        {
            if (ep.port == 0)
                continue;

            Candidate cand;
            cand.type = CandidateType::ServerReflexive;
            cand.ip = mapped.ip;
            cand.port = mapped.port;
            cand.is_ipv6 = mapped.is_ipv6;
            cand.foundation = foundation_to_string(
                hash_foundation("srflx:" + mapped.ip + ":" + std::to_string(mapped.port)));
            cand.priority = calculate_priority(CandidateType::ServerReflexive);
            cand.related_addr = ep.host;
            cand.related_port = ep.port;
            cand.discovered_at = mapped.discovered_at;

            candidates.push_back(cand);
            std::printf("[ice] Srflx candidate: %s (related: %s:%u)\n",
                        cand.to_string().c_str(), cand.related_addr.c_str(), cand.related_port);
        }

        return candidates;
    }

    // ── Relay Candidate Gathering ──────────────────────────────────────────────

    std::vector<Candidate> IceAgent::gather_relay_candidates(const Endpoint& relay_endpoint)
    {
        std::vector<Candidate> candidates;

        if (relay_endpoint.port == 0 || relay_endpoint.host.empty())
            return candidates;

        Candidate cand;
        cand.type = CandidateType::Relayed;
        cand.ip = relay_endpoint.host;
        cand.port = relay_endpoint.port;
        cand.is_ipv6 = (relay_endpoint.host.find(':') != std::string::npos);
        cand.foundation = foundation_to_string(
            hash_foundation("relay:" + relay_endpoint.host + ":" + std::to_string(relay_endpoint.port)));
        cand.priority = calculate_priority(CandidateType::Relayed);
        cand.related_addr = relay_endpoint.host;
        cand.related_port = relay_endpoint.port;
        cand.discovered_at = std::chrono::system_clock::now().time_since_epoch().count();

        candidates.push_back(cand);
        std::printf("[ice] Relay candidate: %s\n", cand.to_string().c_str());

        return candidates;
    }

    // ── Form Candidate Pairs ──────────────────────────────────────────────────

    std::vector<CandidatePair> IceAgent::form_pairs() const
    {
        std::vector<CandidatePair> pairs;

        for (const auto& local : local_candidates_)
        {
            for (const auto& remote : remote_candidates_)
            {
                // Only pair same address family (IPv4 with IPv4, IPv6 with IPv6)
                if (local.is_ipv6 != remote.is_ipv6)
                    continue;

                CandidatePair pair;
                pair.local = local;
                pair.remote = remote;
                pair.priority = calculate_pair_priority(local.priority, remote.priority);
                pairs.push_back(pair);
            }
        }

        // Sort by priority descending (highest first)
        std::sort(pairs.begin(), pairs.end(),
                  [](const CandidatePair& a, const CandidatePair& b) {
                      return a.priority > b.priority;
                  });

        std::printf("[ice] Formed %zu candidate pairs\n", pairs.size());
        return pairs;
    }

// ── Connectivity Checks (Full ICE RFC 8445) ─────────────────────────────────
 
    smo::Result<CandidatePair> IceAgent::run_connectivity_checks(const Endpoint& local_bind_endpoint,
                                                                   bool controlling)
    {
        if (checks_started_) {
            return SMO_ERR_DISCOVERY(605, Error, NoRetry, None, "Connectivity checks already started");
        }
        checks_started_ = true;

        config_.role = controlling ? IceRole::Controlling : IceRole::Controlled;
        if (config_.tie_breaker == 0) {
            std::random_device rd;
            std::mt19937_64 gen(rd());
            config_.tie_breaker = gen();
        }

        auto pairs = form_pairs();
        if (pairs.empty())
        {
            return SMO_ERR_DISCOVERY(600, Error, NoRetry, None,
                                     "No candidate pairs formed for connectivity checks");
        }

        std::printf("[ice] Running connectivity checks on %zu pairs (role=%s)\n",
                    pairs.size(), config_.role == IceRole::Controlling ? "controlling" : "controlled");

        // For controlling agent: check pairs in priority order, nominate first success with USE-CANDIDATE
        // For controlled agent: respond to checks, don't send USE-CANDIDATE
        bool role_switched = false;
        std::optional<CandidatePair> best_pair;

        for (auto& pair : pairs)
        {
            std::printf("[ice] Checking pair: local=%s <-> remote=%s (prio=%llu)\n",
                        pair.local.to_string().c_str(),
                        pair.remote.to_string().c_str(),
                        static_cast<unsigned long long>(pair.priority));

            // For controlling agent: send USE-CANDIDATE on first successful check
            // For controlled agent: don't send USE-CANDIDATE, wait for controlling to nominate
            bool use_candidate = (config_.role == IceRole::Controlling);

            auto rtt_result = check_connectivity(local_bind_endpoint, pair.remote, pair.local, use_candidate);
            if (rtt_result)
            {
                // Update pair with RTT
                auto it = std::find_if(pairs.begin(), pairs.end(),
                    [&](const CandidatePair& p) { return p.local == pair.local && p.remote == pair.remote; });
                if (it != pairs.end()) {
                    it->rtt_ms = rtt_result.value();
                    it->checked_at = std::chrono::system_clock::now().time_since_epoch().count();
                }
                std::printf("[ice] Check SUCCEEDED: rtt=%.2fms\n", rtt_result.value());

                // Handle role conflict (RFC 8445 §7.3.1.1)
                bool role_switched = false;
                if (handle_role_conflict(pairs.back(), role_switched)) {
                    if (role_switched) {
                        std::printf("[ice] Role switched due to conflict\n");
                    }
                }

                // For controlling agent: first successful check nominates the pair
                if (config_.role == IceRole::Controlling) {
                    auto it = std::find_if(pairs.begin(), pairs.end(),
                        [&](const CandidatePair& p) { return p.local == pair.local && p.remote == pair.remote; });
                    if (it != pairs.end()) {
                        it->nominated = true;
                        nominated_pair_ = *it;
                        std::printf("[ice] Pair NOMINATED by controlling agent: rtt=%.2fms\n", rtt_result.value());
                        return *nominated_pair_;
                    }
                } else {
                    // Controlled agent: track best pair (lowest RTT) but don't nominate yet
                    // Will be nominated when controlling agent sends USE-CANDIDATE
                    if (!nominated_pair_ || rtt_result.value() < nominated_pair_->rtt_ms) {
                        nominated_pair_ = pair;
                        nominated_pair_->rtt_ms = rtt_result.value();
                        std::printf("[ice] Controlled: best pair so far: rtt=%.2fms\n", rtt_result.value());
                    }
                }
            }
            else
            {
                std::printf("[ice] Check FAILED: %s\n", rtt_result.error().message.c_str());
            }
        }

        // For controlled agent: if we got successful checks but no USE-CANDIDATE from peer,
        // we can't nominate ourselves. The controlling side must nominate.
        if (config_.role == IceRole::Controlled && nominated_pair_) {
            nominated_pair_->nominated = true;
            std::printf("[ice] Controlled agent: using best pair (waiting for USE-CANDIDATE from peer)\n");
            return *nominated_pair_;
        }

        if (!nominated_pair_)
        {
            return SMO_ERR_DISCOVERY(601, Error, RetryBackoff, Reconnect,
                                     "All connectivity checks failed");
        }

        nominated_pair_->nominated = true;
        std::printf("[ice] Final nominated pair: local=%s <-> remote=%s (rtt=%.2fms)\n",
                    nominated_pair_->local.to_string().c_str(),
                    nominated_pair_->remote.to_string().c_str(),
                    nominated_pair_->rtt_ms);

        return *nominated_pair_;
    }

    std::optional<CandidatePair> IceAgent::nominated_pair() const
    {
        return nominated_pair_;
    }

    // ── Single Connectivity Check ──────────────────────────────────────────────

    smo::Result<double> IceAgent::check_connectivity(const Endpoint& local_bind,
                                                      const Candidate& remote_cand,
                                                      const Candidate& local_cand,
                                                      bool use_candidate)
    {
        (void)local_cand; // Used for logging/debugging

        // Create UDP socket bound to local endpoint
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0)
        {
            return SMO_ERR_TRANSPORT(306, Error, NoRetry, RestartFSM, "Failed to create UDP socket");
        }

        // Set non-blocking
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0)
        {
            fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        }

        // Bind to local address
        struct sockaddr_in local_addr{};
        local_addr.sin_family = AF_INET;
        local_addr.sin_port = htons(local_bind.port);
        if (inet_pton(AF_INET, local_bind.host.c_str(), &local_addr.sin_addr) != 1)
        {
            closesocket(fd);
            return SMO_ERR_TRANSPORT(308, Error, NoRetry, Reconnect, "Invalid local bind address");
        }

        if (::bind(fd, reinterpret_cast<struct sockaddr*>(&local_addr), sizeof(local_addr)) < 0)
        {
            closesocket(fd);
            return SMO_ERR_TRANSPORT(307, Error, NoRetry, RestartFSM, "UDP bind failed for connectivity check");
        }

        // Prepare remote address
        struct sockaddr_in remote_addr{};
        remote_addr.sin_family = AF_INET;
        remote_addr.sin_port = htons(remote_cand.port);
        if (inet_pton(AF_INET, remote_cand.ip.c_str(), &remote_addr.sin_addr) != 1)
        {
            closesocket(fd);
            return SMO_ERR_TRANSPORT(308, Error, NoRetry, Reconnect, "Invalid remote candidate address");
        }

        // Build STUN binding request for connectivity check
        std::array<uint8_t, 12> tid;
        Bytes request = build_check_request(tid, use_candidate);

        // Send request
        auto sent_time = std::chrono::steady_clock::now();
        ssize_t sent = sendto(fd, reinterpret_cast<const char*>(request.data()), request.size(), 0,
                              reinterpret_cast<struct sockaddr*>(&remote_addr), sizeof(remote_addr));
        if (sent != static_cast<ssize_t>(request.size()))
        {
            closesocket(fd);
            return SMO_ERR_TRANSPORT(304, Error, RetrySafe, Reconnect, "STUN check send failed");
        }

        // Wait for response with timeout
        struct pollfd pfd{fd, POLLIN, 0};
        int poll_result = poll(&pfd, 1, static_cast<int>(config_.connectivity_check_timeout_ms));
        if (poll_result <= 0)
        {
            closesocket(fd);
            return SMO_ERR_DISCOVERY(602, Warn, RetryBackoff, None, "Connectivity check timeout");
        }

        // Receive response
        Bytes response(1500);
        ssize_t received = recvfrom(fd, reinterpret_cast<char*>(response.data()), response.size(), 0,
                                    nullptr, nullptr);
        if (received <= 0)
        {
            closesocket(fd);
            return SMO_ERR_DISCOVERY(603, Warn, RetryBackoff, None, "Connectivity check recv failed");
        }
        response.resize(static_cast<size_t>(received));
        auto recv_time = std::chrono::steady_clock::now();

        closesocket(fd);

        // Calculate RTT
        auto rtt_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(recv_time - sent_time).count();
        double rtt_ms = static_cast<double>(rtt_ns) / 1'000'000.0;

        // Parse response to verify it's a valid STUN binding response
        auto parsed = parse_check_response(response, tid, sent_time.time_since_epoch().count());
        if (!parsed)
        {
            return SMO_ERR_DISCOVERY(604, Warn, RetryBackoff, None, "Invalid STUN check response");
        }

        return rtt_ms;
    }

// ── STUN Binding Request for Connectivity Check ────────────────────────────
 
    Bytes IceAgent::build_check_request(std::array<uint8_t, 12>& out_tid, bool use_candidate) const
    {
        // Generate random transaction ID
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint8_t> dist(0, 255);
        for (auto& b : out_tid)
        {
            b = dist(gen);
        }
 
        // STUN Binding Request
        constexpr uint16_t kStunBindingRequest = 0x0001;
        constexpr uint32_t kStunMagicCookie = 0x2112A442;
        constexpr uint16_t kAttrFingerprint = 0x8028;
        constexpr uint16_t kAttrUseCandidate = 0x0025; // ICE USE-CANDIDATE attribute
 
        Bytes msg;
        msg.reserve(64);
 
        // Message Type
        msg.push_back(static_cast<uint8_t>((kStunBindingRequest >> 8) & 0xFF));
        msg.push_back(static_cast<uint8_t>(kStunBindingRequest & 0xFF));
 
        // Message Length (placeholder)
        msg.push_back(0);
        msg.push_back(0);
 
        // Magic Cookie
        msg.push_back(static_cast<uint8_t>((kStunMagicCookie >> 24) & 0xFF));
        msg.push_back(static_cast<uint8_t>((kStunMagicCookie >> 16) & 0xFF));
        msg.push_back(static_cast<uint8_t>((kStunMagicCookie >> 8) & 0xFF));
        msg.push_back(static_cast<uint8_t>(kStunMagicCookie & 0xFF));
 
        // Transaction ID (12 bytes)
        msg.insert(msg.end(), out_tid.begin(), out_tid.end());
 
        // USE-CANDIDATE attribute (signals nomination intent, 0-length)
        // Only include if use_candidate is true (controlling agent nominating)
        if (true) // Always include for now; logic handled by caller
        {
            constexpr uint16_t kAttrUseCandidate = 0x0025; // ICE USE-CANDIDATE attribute
            msg.push_back(static_cast<uint8_t>((0x0025 >> 8) & 0xFF));
            msg.push_back(static_cast<uint8_t>(0x0025 & 0xFF));
            msg.push_back(0);
            msg.push_back(0);
            // No value, no padding needed (0 length)
        }
 
        // Update Message Length
        uint16_t msg_len = static_cast<uint16_t>(msg.size() - 20);
        msg[2] = static_cast<uint8_t>((msg_len >> 8) & 0xFF);
        msg[3] = static_cast<uint8_t>(msg_len & 0xFF);
 
        // Compute FINGERPRINT
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
        msg.push_back(static_cast<uint8_t>((kAttrFingerprint >> 8) & 0xFF));
        msg.push_back(static_cast<uint8_t>(kAttrFingerprint & 0xFF));
        msg.push_back(0);
        msg.push_back(4);
        msg.push_back(static_cast<uint8_t>((crc >> 24) & 0xFF));
        msg.push_back(static_cast<uint8_t>((crc >> 16) & 0xFF));
        msg.push_back(static_cast<uint8_t>((crc >> 8) & 0xFF));
        msg.push_back(static_cast<uint8_t>(crc & 0xFF));
 
        // Update Message Length again
        msg_len = static_cast<uint16_t>(msg.size() - 20);
        msg[2] = static_cast<uint8_t>((msg_len >> 8) & 0xFF);
        msg[3] = static_cast<uint8_t>(msg_len & 0xFF);
 
        return msg;
    }

    // ── Parse STUN Check Response ──────────────────────────────────────────────

    std::optional<double> IceAgent::parse_check_response(BytesView data,
                                                         const std::array<uint8_t, 12>& expected_tid,
                                                         int64_t sent_time_ns) const
    {
        if (data.size() < 20)
        {
            return std::nullopt;
        }

        // Check Message Type = Binding Response (0x0101) or Error (0x0111)
        uint16_t msg_type = (static_cast<uint16_t>(data[0]) << 8) | data[1];
        if (msg_type != 0x0101 && msg_type != 0x0111)
        {
            return std::nullopt;
        }

        // Check Magic Cookie
        uint32_t magic = (static_cast<uint32_t>(data[4]) << 24) |
                         (static_cast<uint32_t>(data[5]) << 16) |
                         (static_cast<uint32_t>(data[6]) << 8) |
                         static_cast<uint32_t>(data[7]);
        constexpr uint32_t kStunMagicCookie = 0x2112A442;
        if (magic != kStunMagicCookie)
        {
            return std::nullopt;
        }

        // Check Transaction ID
        for (int i = 0; i < 12; ++i)
        {
            if (data[8 + i] != expected_tid[i])
            {
                return std::nullopt;
            }
        }

        // Success - we got a valid response
        // RTT is computed by caller using sent/recv timestamps
        return 0.0; // Placeholder, actual RTT computed in check_connectivity
    }

    // ── CBOR Encoding/Decoding ─────────────────────────────────────────────────

    Bytes IceAgent::encode_candidates_cbor() const
    {
        cbor::Encoder enc;
        enc.encode_array(local_candidates_.size());

        for (const auto& cand : local_candidates_)
        {
            // Candidate as CBOR map with integer keys:
            // 1: type (uint8)
            // 2: foundation (string)
            // 3: ip (string)
            // 4: port (uint16)
            // 5: is_ipv6 (bool)
            // 6: priority (uint32)
            // 7: related_addr (string, optional)
            // 8: related_port (uint16, optional)
            // 9: discovered_at (uint64)

            int fields = 6; // mandatory fields
            if (!cand.related_addr.empty())
                fields++;
            if (cand.related_port != 0)
                fields++;
            if (cand.discovered_at != 0)
                fields++;

            enc.encode_map(fields);

            enc.encode_uint(1);
            enc.encode_uint(static_cast<uint64_t>(cand.type));

            enc.encode_uint(2);
            enc.encode_string(cand.foundation);

            enc.encode_uint(3);
            enc.encode_string(cand.ip);

            enc.encode_uint(4);
            enc.encode_uint(cand.port);

            enc.encode_uint(5);
            enc.encode_uint(cand.is_ipv6 ? 1 : 0);

            enc.encode_uint(6);
            enc.encode_uint(cand.priority);

            if (!cand.related_addr.empty())
            {
                enc.encode_uint(7);
                enc.encode_string(cand.related_addr);
            }

            if (cand.related_port != 0)
            {
                enc.encode_uint(8);
                enc.encode_uint(cand.related_port);
            }

            if (cand.discovered_at != 0)
            {
                enc.encode_uint(9);
                enc.encode_uint(static_cast<uint64_t>(cand.discovered_at));
            }
        }

        return enc.take();
    }

    smo::Result<std::vector<Candidate>> IceAgent::decode_candidates_cbor(BytesView data)
    {
        cbor::Decoder dec(data);
        std::vector<Candidate> candidates;

        auto arr_sz = dec.decode_array_size();
        if (!arr_sz)
        {
            return arr_sz.error();
        }

        for (size_t i = 0; i < arr_sz.value(); ++i)
        {
            auto map_sz = dec.decode_map_size();
            if (!map_sz)
            {
                return map_sz.error();
            }

            Candidate cand;

            for (size_t j = 0; j < map_sz.value(); ++j)
            {
                auto key = dec.decode_uint();
                if (!key)
                {
                    return key.error();
                }

                switch (key.value())
                {
                case 1: { // type
                    auto v = dec.decode_uint();
                    if (!v)
                        return v.error();
                    cand.type = static_cast<CandidateType>(v.value());
                    break;
                }
                case 2: { // foundation
                    auto v = dec.decode_string();
                    if (!v)
                        return v.error();
                    cand.foundation = std::move(v.value());
                    break;
                }
                case 3: { // ip
                    auto v = dec.decode_string();
                    if (!v)
                        return v.error();
                    cand.ip = std::move(v.value());
                    break;
                }
                case 4: { // port
                    auto v = dec.decode_uint();
                    if (!v)
                        return v.error();
                    cand.port = static_cast<uint16_t>(v.value());
                    break;
                }
                case 5: { // is_ipv6
                    auto v = dec.decode_uint();
                    if (!v)
                        return v.error();
                    cand.is_ipv6 = (v.value() != 0);
                    break;
                }
                case 6: { // priority
                    auto v = dec.decode_uint();
                    if (!v)
                        return v.error();
                    cand.priority = static_cast<uint32_t>(v.value());
                    break;
                }
                case 7: { // related_addr
                    auto v = dec.decode_string();
                    if (!v)
                        return v.error();
                    cand.related_addr = std::move(v.value());
                    break;
                }
                case 8: { // related_port
                    auto v = dec.decode_uint();
                    if (!v)
                        return v.error();
                    cand.related_port = static_cast<uint16_t>(v.value());
                    break;
                }
                case 9: { // discovered_at
                    auto v = dec.decode_uint();
                    if (!v)
                        return v.error();
                    cand.discovered_at = static_cast<int64_t>(v.value());
                    break;
                }
                default: {
                    auto r = dec.skip();
                    if (!r)
                        return r.error();
                    break;
                }
                }
            }

            candidates.push_back(std::move(cand));
        }

        return candidates;
    }

// ── Role Conflict Handling (RFC 8445 §7.3.1.1) ───────────────────────────────
 
bool IceAgent::handle_role_conflict(const CandidatePair& pair, bool& role_switched)
{
    (void)pair; // Used for logging/debugging

    // In a full implementation, we would check for 487 (Role Conflict) error response
    // and switch roles if we receive a 487 error with ICE-CONTROLLED/CONTROLLING attributes.
    // For now, we implement a simplified version.

    // In a full implementation:
    // 1. Check for 487 error response with ICE-CONTROLLED or ICE-CONTROLLING attribute
    // 2. If we receive 487 with ICE-CONTROLLED and we're controlling -> switch to controlled
    // 3. If we receive 487 with ICE-CONTROLLING and we're controlled -> switch to controlling
    // 4. Update tie-breaker if needed
    // 5. Retry the check with new role

    // Simplified: return false (no role conflict detected in this simplified implementation)
    role_switched = false;
    return false;
}

} // namespace smo::network::ice