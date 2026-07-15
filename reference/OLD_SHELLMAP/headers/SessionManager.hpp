#ifndef SESSION_MANAGER_HPP
#define SESSION_MANAGER_HPP

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <cstdint>
#include "Protocol.hpp"
#include "CryptoCore.hpp"

/**
 * @class SessionManager
 * @brief Quản lý encryption/decryption sessions
 * 
 * Trách nhiệm:
 * - Lưu trữ session state (AES key, nonce, handshake state)
 * - Xử lý hybrid key derivation (Kyber + X25519)
 * - Encrypt/decrypt messages qua AES-256-GCM
 * - Track session lifecycle (initiated -> handshaking -> established -> closed)
 */
class SessionManager {
public:
    enum class SessionState {
        NONE,              // No session
        INITIATED,         // Step 1: HELLO sent, waiting WELCOME
        HELLO_SENT,        // (Alias for INITIATED, tracking linear flow)
        WELCOME_RECEIVED,  // Step 2: Received WELCOME, waiting AUTH
        WELCOME_SENT,      // Step 2b: Responder sent WELCOME, waiting AUTH
        ESTABLISHED,       // Step 3: AUTH received/verified, ready to use
        CLOSED             // Session closed
    };

    struct Session {
        std::string node_id;                // 32-byte hex string (full SHA-256)
        std::string peer_ip;
        uint16_t peer_port;
        
        // Handshake temporary state
        std::string temp_kyber_ss_responder;  // Kyber SS when we act as responder (encaps from peer)
        std::string temp_kyber_ss_initiator;  // Kyber SS when we act as initiator (decaps peer's CT)
        std::string temp_ecdh_priv;         // ECDH private key (our X25519 priv in current role)
        std::string temp_ecdh_pub;          // ECDH public key (our X25519 pub in current role)
        std::string temp_ecdh_priv_initiator;  // OUR private key when WE are the initiator (saved from initiate_handshake)
        std::string temp_ecdh_pub_initiator;   // OUR public key when WE are the initiator
        std::string temp_ecdh_peer_pub;     // Peer's ECDH public key
        std::string temp_ecdh_ss;           // ECDH shared secret (computed from initiator perspective)
        
        // Final session keys (after KDF)
        std::vector<uint8_t> aes_key;       // AES-256 key (32 bytes)
        std::vector<uint8_t> aes_iv;        // GCM nonce (12 bytes)
        
        // CRITICAL: Separate counters for crypto vs packet nonce!
        uint64_t crypto_nonce_counter = 0;  // Counter for AES-GCM nonce derivation (independent)
        uint64_t packet_nonce_counter = 0;  // Counter for packet anti-replay (must be monotonic across ALL opcodes)
        
        // Session state
        SessionState state = SessionState::NONE;
        uint64_t created_time;              // Timestamp khi session được tạo
        uint64_t last_activity;             // Lần giao tiếp cuối cùng
        uint64_t ping_sent_ts;              // Timestamp of last PING sent (for latency calc)
        uint8_t ping_sent_count = 0;        // CRITICAL: Track consecutive PING sent (max 3, then timeout)
        uint16_t dynamic_peer_port = 0;     // CRITICAL: Track latest peer port from recvfrom (NAT dynamic)
         
         // File system state per session
         std::string current_remote_dir = "";  // Current remote directory (empty = root)
         std::string pending_cd_path = "";     // Path waiting for CD response (set by cmd_cd, cleared by handle_fs_meta_res)
         bool pending_cd_request = false;      // Flag to track if CD request is pending (handles empty string case)
         
        // Peer info (lưu sau khi verify)
        std::string peer_falcon_pub;        // Peer's Falcon-512 public key
        bool is_server = false;             // Peer is reachable server
        bool is_relayed = false;            // Session thông qua relay
        
        // Message tracking for Phase 3
        uint32_t next_msg_id = 1;           // Next message ID to assign
        
        // Pending messages (awaiting ACK)
        struct PendingMessage {
            uint32_t msg_id;
            std::vector<uint8_t> payload;
            uint64_t sent_time;             // For timeout detection
        };
        std::map<uint32_t, PendingMessage> pending_messages;  // msg_id -> message
        
        // Fragmented message reassembly
        struct FragmentedMessage {
            std::vector<std::vector<uint8_t>> fragments;  // fragment_seq -> data
            uint16_t total_fragments = 0;
            uint64_t first_fragment_time = 0;  // For timeout cleanup
        };
        std::map<uint32_t, FragmentedMessage> reassembly_buffer;  // msg_id -> fragments
    };

    /**
     * @brief Tạo hoặc lấy session cho node
     */
    std::shared_ptr<Session> get_or_create_session(const std::string& node_id);

    /**
     * @brief Lấy session tồn tại
     */
    std::shared_ptr<Session> get_session(const std::string& node_id);

    /**
     * @brief Xóa session
     */
    void destroy_session(const std::string& node_id);

    /**
     * @brief Lưu temporary state từ HELLO
     */
    void set_handshake_state(
        const std::string& node_id,
        const std::string& kyber_ss,
        const std::string& ecdh_priv
    );

    /**
     * @brief Lưu peer's ECDH public key từ WELCOME
     */
    void set_peer_ecdh(const std::string& node_id, const std::string& ecdh_pub);

    /**
     * @brief Derive final session keys từ Kyber SS + ECDH SS
     */
    bool establish_session(const std::string& node_id);

    /**
     * @brief Migrate session from placeholder ID to real peer ID
     * When initiating handshake, we use placeholder ID. When we receive WELCOME,
     * we learn the real peer ID. This function migrates the session.
     */
    bool migrate_session(const std::string& placeholder_id, const std::string& real_id);

    /**
     * @brief Find any INITIATED session with placeholder ID (all zeros)
     * @return Pair of (map_key, session_ptr). Returns {"", nullptr} if not found
     */
    std::pair<std::string, std::shared_ptr<Session>> find_placeholder_session();

    /**
     * @brief Encrypt data sử dụng AES-256-GCM with packet_nonce-derived IV
     * @param node_id Target node ID
     * @param plaintext Data to encrypt
     * @param packet_nonce Packet nonce from header (used to derive IV deterministically)
     */
    std::vector<uint8_t> encrypt_message(
        const std::string& node_id,
        const std::vector<uint8_t>& plaintext,
        uint64_t packet_nonce
    );

    /**
     * @brief Decrypt data sử dụng AES-256-GCM with packet_nonce-derived IV
     * @param node_id Sender node ID
     * @param ciphertext Encrypted data with tag
     * @param packet_nonce Packet nonce from header (used to derive IV deterministically)
     */
    std::vector<uint8_t> decrypt_message(
        const std::string& node_id,
        const std::vector<uint8_t>& ciphertext,
        uint64_t packet_nonce
    );

    /**
     * @brief Kiểm tra session còn hợp lệ không
     */
    bool is_session_active(const std::string& node_id);

    /**
     * @brief Lấy tất cả active sessions
     */
    std::map<std::string, std::shared_ptr<Session>> get_all_sessions();

    /**
     * @brief Cleanup expired sessions (>30 min no activity)
     */
    void cleanup_expired_sessions(uint64_t timeout_ms = 1800000);

private:
    std::map<std::string, std::shared_ptr<Session>> sessions_;
    
    /**
     * @brief KDF: Derive AES key từ Kyber SS + ECDH SS
     * @param kyber_ss Kyber shared secret
     * @param ecdh_ss ECDH shared secret
     * @param out_key Output AES-256 key (32 bytes)
     * @param out_iv Output GCM IV (12 bytes)
     */
    void kdf_derive_keys(
        const std::string& kyber_ss,
        const std::string& ecdh_ss,
        std::vector<uint8_t>& out_key,
        std::vector<uint8_t>& out_iv
    );

    /**
     * @brief Generate GCM nonce from packet_nonce (12-byte IV for AES-256-GCM)
     * @param packet_nonce 64-bit packet nonce from header
     * @return 12-byte nonce deterministically derived from packet_nonce
     */
    std::vector<uint8_t> derive_nonce_from_packet_nonce(uint64_t packet_nonce);

    /**
     * @brief Generate next nonce cho GCM mode (DEPRECATED - kept for reference)
     */
    std::vector<uint8_t> generate_next_nonce(uint64_t& counter);
};

#endif // SESSION_MANAGER_HPP
