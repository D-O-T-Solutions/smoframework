#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <core/errors/error.hpp>
#include <core/types.hpp>
#include <core/transport/transport.hpp>

namespace smo::network::ice {

    // ── Candidate Type (ICE RFC 8445 §5.1.1) ───────────────────────────────────
    enum class CandidateType : uint8_t
    {
        Host = 0,         // Local interface address (highest priority)
        ServerReflexive = 1, // STUN-mapped address (medium priority)
        Relayed = 2,      // Relay/TURN address (lowest priority)
    };

    inline const char* to_string(CandidateType t) noexcept
    {
        switch (t)
        {
        case CandidateType::Host:
            return "host";
        case CandidateType::ServerReflexive:
            return "srflx";
        case CandidateType::Relayed:
            return "relay";
        default:
            return "unknown";
        }
    }

    // ── ICE Candidate (RFC 8445 §5.1) ─────────────────────────────────────────
    struct Candidate
    {
        CandidateType type = CandidateType::Host;
        std::string foundation;  // Unique identifier for this candidate's base
        std::string ip;          // IP address (IPv4 or IPv6)
        uint16_t port = 0;       // Port
        bool is_ipv6 = false;
        uint32_t priority = 0;   // RFC 8445 priority formula
        std::string related_addr; // For srflx/relay: the base address
        uint16_t related_port = 0;
        int64_t discovered_at = 0; // Timestamp when discovered

        bool empty() const noexcept { return ip.empty() || port == 0; }

        std::string to_string() const
        {
            if (empty())
                return "";
            std::string base = (is_ipv6 ? "[" + ip + "]" : ip) + ":" + std::to_string(port);
            return base + " " + ::smo::network::ice::to_string(type) + " prio=" + std::to_string(priority)
                 + " foundation=" + foundation;
        }

        // Equality for deduplication
        bool operator==(const Candidate& other) const noexcept
        {
            return type == other.type && ip == other.ip && port == other.port
                 && is_ipv6 == other.is_ipv6 && foundation == other.foundation;
        }
    };

    // ── Candidate Pair (local + remote) ───────────────────────────────────────
    struct CandidatePair
    {
        Candidate local;
        Candidate remote;
        uint64_t priority = 0; // Combined priority (RFC 8445 §5.7.2)
        bool nominated = false;
        double rtt_ms = -1.0; // Measured RTT, -1 = not measured
        int64_t checked_at = 0;

        bool empty() const noexcept { return local.empty() || remote.empty(); }
    };

    // ── ICE Configuration ─────────────────────────────────────────────────────
    struct IceConfig
    {
        std::string stun_server_host = "stun.l.google.com";
        uint16_t stun_server_port = 19302;
        int max_stun_attempts = 3;
        uint32_t stun_timeout_ms = 2000;
        bool enable_relay = true;
        uint32_t connectivity_check_timeout_ms = 5000;
        uint32_t max_checks_per_pair = 3;
    };

    // ── Priority Calculation (RFC 8445 §5.1.2) ────────────────────────────────
    // priority = (2^24 * type_preference) + (2^8 * local_preference) + (256 - component_id)
    // type_preference: host=126, srflx=110, relay=0
    // local_preference: 65535 (unused for single component)
    // component_id: 1 (RTP), 2 (RTCP) - we use 1
    inline uint32_t calculate_priority(CandidateType type, uint16_t local_preference = 65535, uint8_t component_id = 1)
    {
        uint32_t type_pref = 0;
        switch (type)
        {
        case CandidateType::Host:
            type_pref = 126;
            break;
        case CandidateType::ServerReflexive:
            type_pref = 110;
            break;
        case CandidateType::Relayed:
            type_pref = 0;
            break;
        }
        return (type_pref << 24) | ((local_preference & 0xFFFF) << 8) | (256 - component_id);
    }

    // ── Pair Priority (RFC 8445 §5.7.2) ───────────────────────────────────────
    // pair_priority = 2^32 * min(G, D) + 2 * max(G, D) + (G > D ? 1 : 0)
    // G = controlling agent's candidate priority, D = controlled agent's candidate priority
    inline uint64_t calculate_pair_priority(uint32_t controlling_prio, uint32_t controlled_prio)
    {
        uint64_t min_prio = std::min<uint32_t>(controlling_prio, controlled_prio);
        uint64_t max_prio = std::max<uint32_t>(controlling_prio, controlled_prio);
        uint64_t tie_breaker = (controlling_prio > controlled_prio) ? 1 : 0;
        return (min_prio << 32) + (2 * max_prio) + tie_breaker;
    }

    // ── Generate Foundation String ────────────────────────────────────────────
    // Foundation = hash of (type + base_ip + base_port + transport_protocol)
    // Used to group candidates that share the same base
    inline std::string generate_foundation(CandidateType type, const std::string& base_ip, uint16_t base_port)
    {
        // Simple foundation: type:base_ip:base_port
        // In production, this could be a hash (e.g., first 8 bytes of SHA-256)
        return std::string(to_string(type)) + ":" + base_ip + ":" + std::to_string(base_port);
    }

    // ── Candidate Gathering Result ────────────────────────────────────────────
    struct GatherResult
    {
        std::vector<Candidate> candidates;
        std::chrono::milliseconds gather_time;
        int host_candidates = 0;
        int srflx_candidates = 0;
        int relay_candidates = 0;
    };

    // ── ICE Agent Interface ──────────────────────────────────────────────────
    class IceAgent
    {
    public:
        explicit IceAgent(const IceConfig& cfg = IceConfig());
        ~IceAgent() = default;

        IceAgent(const IceAgent&) = delete;
        IceAgent& operator=(const IceAgent&) = delete;
        IceAgent(IceAgent&&) = default;
        IceAgent& operator=(IceAgent&&) = default;

        // Gather all local candidates: host → STUN srflx → relay
        // Returns gathered candidates on success
        smo::Result<GatherResult> gather(const std::vector<Endpoint>& local_endpoints,
                                         const Endpoint& relay_endpoint = Endpoint{});

        // Get gathered local candidates
        const std::vector<Candidate>& local_candidates() const noexcept { return local_candidates_; }

        // Set remote candidates (received via Join protocol CBOR)
        void set_remote_candidates(const std::vector<Candidate>& remote) { remote_candidates_ = remote; }

        // Get remote candidates
        const std::vector<Candidate>& remote_candidates() const noexcept { return remote_candidates_; }

        // Form candidate pairs and sort by priority (highest first)
        std::vector<CandidatePair> form_pairs() const;

        // Perform connectivity checks on pairs (STUN binding requests)
        // Returns nominated pair on success
        smo::Result<CandidatePair> run_connectivity_checks(const Endpoint& local_bind_endpoint,
                                                           bool controlling = true);

        // Get nominated pair (after connectivity checks)
        std::optional<CandidatePair> nominated_pair() const;

        // Get current config (for inspection)
        const IceConfig& config() const noexcept { return config_; }

        // Serialize local candidates to CBOR for Join protocol exchange
        Bytes encode_candidates_cbor() const;

        // Deserialize candidates from CBOR
        static smo::Result<std::vector<Candidate>> decode_candidates_cbor(BytesView data);

    private:
        IceConfig config_;
        std::vector<Candidate> local_candidates_;
        std::vector<Candidate> remote_candidates_;
        std::optional<CandidatePair> nominated_pair_;

        // Gather host candidates from local interfaces
        std::vector<Candidate> gather_host_candidates(const std::vector<Endpoint>& endpoints);

        // Gather server-reflexive candidates via STUN
        std::vector<Candidate> gather_srflx_candidates(const std::vector<Endpoint>& endpoints);

        // Gather relay candidates
        std::vector<Candidate> gather_relay_candidates(const Endpoint& relay_endpoint);

        // Perform a single STUN binding check to a remote candidate
        smo::Result<double> check_connectivity(const Endpoint& local_bind,
                                               const Candidate& remote_cand,
                                               const Candidate& local_cand);

        // Build STUN binding request for connectivity check
        Bytes build_check_request(std::array<uint8_t, 12>& out_tid) const;

        // Parse STUN binding response
        std::optional<double> parse_check_response(BytesView data,
                                                   const std::array<uint8_t, 12>& expected_tid,
                                                   int64_t sent_time_ns) const;
    };

} // namespace smo::network::ice