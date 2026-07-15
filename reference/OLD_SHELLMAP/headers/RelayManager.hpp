#ifndef RELAY_MANAGER_HPP
#define RELAY_MANAGER_HPP

#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <memory>
#include <queue>
#include "Protocol.hpp"

/**
 * @class RelayManager
 * @brief Quản lý relay operations và identity preservation
 * 
 * Trách nhiệm:
 * - Xử lý RELAY_REQ từ client (A) muốn relay qua bootstrap
 * - Xử lý RELAY_FWD từ bootstrap gửi tới target (B)
 * - Giữ nguyên sender identity khi relay (không thay đổi sender_id)
 * - Route responses cho relayed sessions qua relay node
 * - Track relay sessions để gửi response đúng cách
 * 
 * Fix for relay ambiguity:
 * - Khi nhận gói relay từ A (qua bootstrap), giữ sender_id=A
 * - Khi response cho relayed session, gắp IS_RELAYED flag
 * - Bootstrap phải forward response lại cho A (original sender)
 */
class RelayManager {
public:
    struct RelaySession {
        std::string sender_id;          // ID của người gửi ban đầu (A)
        std::string relay_via_id;       // ID của relay node (bootstrap)
        std::string relay_via_ip;       // IP của relay node
        uint16_t relay_via_port;        // Port của relay node
        
        uint64_t created_time;          // Timestamp khi relay được tạo
        uint64_t last_activity;         // Lần giao tiếp cuối
    };

    /**
     * @brief Process RELAY_REQ từ client
     * @param sender_id ID của người gửi (A)
     * @param target_id ID của mục tiêu (B)
     * @param relay_via_id ID của relay node (bootstrap)
     * @param relay_via_ip IP của relay node
     * @param relay_via_port Port của relay node
     * @return true nếu relay session được tạo
     */
    bool create_relay_session(
        const std::string& sender_id,
        const std::string& target_id,
        const std::string& relay_via_id,
        const std::string& relay_via_ip,
        uint16_t relay_via_port
    );

    /**
     * @brief Process RELAY_FWD từ bootstrap
     * @param inner_packet Gói tin được relay (header + payload)
     * @param sender_addr Address của relay node
     * @return Parsed inner packet (header + payload)
     */
    std::pair<PacketHeader, std::vector<uint8_t>> unpack_relay_packet(
        const std::vector<uint8_t>& relay_payload
    );

    /**
     * @brief Kiểm tra nếu session này là relayed
     */
    bool is_relayed_session(const std::string& sender_id, const std::string& target_id);

    /**
     * @brief Lấy relay info để gửi response
     */
    std::shared_ptr<RelaySession> get_relay_session(const std::string& sender_id);

    /**
     * @brief Xóa relay session
     */
    void destroy_relay_session(const std::string& sender_id);

    /**
     * @brief Cleanup expired relay sessions (>30 min no activity)
     */
    void cleanup_expired_sessions(uint64_t timeout_ms = 1800000);

    /**
     * @brief Pack packet cho relay
     * @param target_id ID của mục tiêu cuối cùng
     * @param hdr Header của gói tin gốc
     * @param payload Payload của gói tin gốc
     * @return Packed relay payload (JSON format)
     */
    std::vector<uint8_t> pack_relay_request(
        const std::string& target_id,
        const PacketHeader& hdr,
        const std::vector<uint8_t>& payload
    );

    /**
     * @brief Get all active relay sessions
     */
    std::map<std::string, std::shared_ptr<RelaySession>> get_all_relay_sessions();

private:
    // Key: sender_id, Value: RelaySession info
    std::map<std::string, std::shared_ptr<RelaySession>> relay_sessions_;
    
    // Track relayed packets để detect loops
    std::map<std::string, uint64_t> packet_timestamps_;
};

#endif // RELAY_MANAGER_HPP
