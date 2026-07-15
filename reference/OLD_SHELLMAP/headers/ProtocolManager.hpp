#ifndef PROTOCOL_MANAGER_HPP
#define PROTOCOL_MANAGER_HPP

#include <cstdint>
#include <vector>
#include <string>
#include <map>
#include <memory>
#include <sys/socket.h>
#include <netinet/in.h>
#include "Protocol.hpp"
#include "NetworkEngine.hpp"
#include "CryptoCore.hpp"
#include "RoutingTable.hpp"

// Forward declarations
class SessionManager;
class VerificationManager;
class RelayManager;
class Web3Manager;
class FileManager;
class CommandHandler;
struct NodeContext;

/**
 * @class ProtocolManager
 * @brief Quản lý toàn bộ packet dispatch và xử lý protocol
 * 
 * Trách nhiệm:
 * - Dispatch incoming packets theo OpCode
 * - Quản lý state transitions (Handshake -> Established)
 * - Gọi các manager chuyên biệt (Session, Verification, Relay, Web3, File, Command)
 * - Xử lý anti-replay (nonce checking)
 */
class ProtocolManager {
public:
    ProtocolManager(
        std::shared_ptr<SessionManager> session_mgr,
        std::shared_ptr<VerificationManager> verify_mgr,
        std::shared_ptr<RelayManager> relay_mgr,
        std::shared_ptr<Web3Manager> web3_mgr,
        FileManager* file_mgr,
        std::shared_ptr<CommandHandler> cmd_handler,
        NetworkEngine& net_engine,
        RoutingTable& route_table,
        NodeContext* my_node  // NEW: Our node identity
    );

    /**
     * @brief Dispatch incoming packet dựa trên OpCode
     * @param hdr PacketHeader từ network
     * @param payload Payload data
     * @param sender_addr Actual address từ kernel recvfrom()
     */
    void dispatch_packet(
        PacketHeader& hdr,
        std::vector<uint8_t>& payload,
        const sockaddr_in& sender_addr
    );

    /**
     * @brief Kiểm tra nonce anti-replay
     * @param sender_id ID của người gửi
     * @param nonce Packet nonce
     * @return true nếu nonce hợp lệ (chưa thấy trước đó)
     */
    bool verify_nonce(const uint8_t* sender_id, uint64_t nonce);

    /**
     * @brief Clear nonce tracking for a specific sender (used during session reset/reconnect)
     * @param sender_id_str Hex string ID của người gửi
     */
    void clear_nonce_for_peer(const std::string& sender_id_str);

    /**
     * @brief Initiate handshake with remote peer
     * @param target_ip Target IP address
     * @param target_port Target port
     * @return true if HELLO packet sent successfully
     */
    bool initiate_handshake(const std::string& target_ip, int target_port);

     /**
      * @brief Send PING packet to remote peer
      * @param target_ip Target IP address
      * @param target_port Target port
      * @return true if PING packet sent successfully
      */
     bool send_ping(const std::string& target_ip, int target_port);

     /**
      * @brief Update peer's IP/port dynamically from kernel recvfrom()
      * CRITICAL: Called after EVERY recv_packet() to detect NAT port changes
      * @param node_id Session node ID
      * @param new_ip New peer IP from kernel
      * @param new_port New peer port from kernel
      * @return true if peer address was updated
      */
     bool update_peer_address(const std::string& node_id, const std::string& new_ip, uint16_t new_port);

     /**
      * @brief Heartbeat worker: Send PING to keep NAT hole open
      * Called periodically (~15s interval) to prevent NAT timeout
      * CRITICAL: Must be called in main event loop
      * @return number of PING packets sent
      */
     int send_heartbeat_pings();

     /**
      * @brief Relay fallback detector: Check if direct connection timeout occurred
      * If HELLO sent but no WELCOME after 5s, mark for relay fallback
      * @return number of sessions switched to relay
      */
     int detect_relay_fallback_timeout();

     /**
      * @brief Send PING_ACK response to keep-alive request
      * @param node_id Peer node ID
      */
     void send_ping_ack(const std::string& node_id);

     /**
      * @brief Send encrypted message to established session
      * @param node_id Recipient node ID (hex string)
      * @param message Message content (plaintext)
      * @return true if message sent successfully
      */
     bool send_message(const std::string& node_id, const std::string& message);

      /**
       * @brief Send ACK for received message
       * @param node_id Sender node ID
       * @param msg_id Message ID to acknowledge
       */
      void send_ack(const std::string& node_id, uint32_t msg_id);

      /**
       * @brief Utility: Convert binary node ID to hex string
       * @param id 32-byte binary node ID
       * @return 64-character hex string representation
       */
      std::string sender_id_to_string(const uint8_t* id);

      /**
       * @brief Utility: Convert hex string to binary node ID
       * @param hex_str 64-character hex string representation
       * @param out_id Output buffer for 32-byte binary ID
       */
      void hex_string_to_node_id(const std::string& hex_str, uint8_t* out_id);

private:
    // Dependencies
    std::shared_ptr<SessionManager> session_mgr_;
    std::shared_ptr<VerificationManager> verify_mgr_;
    std::shared_ptr<RelayManager> relay_mgr_;
    std::shared_ptr<Web3Manager> web3_mgr_;
    FileManager* file_mgr_;
    std::shared_ptr<CommandHandler> cmd_handler_;
    NetworkEngine& net_engine_;
    RoutingTable& route_table_;
    NodeContext* my_node_;  // NEW: Our node identity

    // Nonce tracking: map<sender_id, last_nonce> để anti-replay
    std::map<std::string, uint64_t> nonce_map_;

    // --- Handlers cho từng OpCode ---
    
    /// Handshake phase (HELLO, WELCOME, AUTH)
    void handle_hello(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender);
    void handle_welcome(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender);
    void handle_auth(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender);

    /// Discovery phase (WHO_ARE_YOU, IAM)
    void handle_who_are_you(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender);
    void handle_iam(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender);

     /// Session phase (PING, GET_PUBKEY, PUBKEY, DATA, ACK)
     void handle_ping(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender);
     void handle_get_pubkey(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender);
     void handle_pubkey(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender);
     void handle_data(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender);  // NEW
     void handle_ack(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender);   // NEW
     void handle_session_rst(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender);

    /// File system operations
    void handle_fs_list_req(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender);
    void handle_fs_list_res(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender);
    void handle_fs_meta_req(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender);
    void handle_fs_meta_res(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender);
    void handle_fs_data_req(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender);
    void handle_fs_data_res(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender);
    void handle_fs_put_meta_req(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender);
    void handle_fs_put_meta_res(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender);
    void handle_fs_put_data(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender);

    /// P2P discovery & hole punching
    void handle_p2p_find_node_req(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender);
    void handle_p2p_find_node_res(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender);
    void handle_p2p_assist_req(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender);
    void handle_p2p_hole_punch(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender);

    /// Relay operations
    void handle_relay_req(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender);
    void handle_relay_fwd(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender);

    /// Server verification (3-step)
    void handle_verify_req(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender);
    void handle_probe(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender);
    void handle_probe_ack(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender);

    /// Web3 features (MML, Virtual Shell, ACL)
    void handle_mml_index_req(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender);
    void handle_mml_index_res(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender);
    void handle_cmd_shell_req(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender);
    void handle_cmd_shell_res(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender);

     /// Error handling
    void handle_error(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender);

    // Private utility: send_packet
    void send_packet(
        const uint8_t* target_id,
        uint8_t opcode,
        uint8_t flags,
        const std::vector<uint8_t>& payload,
        const std::string& target_ip,
        int target_port
    );
};

#endif // PROTOCOL_MANAGER_HPP
