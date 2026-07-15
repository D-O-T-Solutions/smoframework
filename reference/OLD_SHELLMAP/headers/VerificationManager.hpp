#ifndef VERIFICATION_MANAGER_HPP
#define VERIFICATION_MANAGER_HPP

#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <memory>

/**
 * @class VerificationManager
 * @brief 3-step server verification system
 * 
 * Flow:
 * 1. Node sends VERIFY_REQ with declared IP:Port
 * 2. SuperNode sends PROBE to that address
 * 3. Node responds with PROBE_ACK if reachable
 * 
 * Trách nhiệ:
 * - Lưu trữ verification state
 * - Track pending verifications
 * - Mark nodes as server/client based on reachability
 * - Manage probe timeouts
 */
class VerificationManager {
public:
    enum class VerificationState {
        PENDING,    // Waiting for PROBE response
        VERIFIED,   // PROBE_ACK received, node is reachable
        FAILED,     // Timeout or no response
        TIMEOUT     // Verification timed out
    };

    struct VerificationRequest {
        std::string node_id;            // 32-byte hex string
        std::string declared_ip;        // IP mà node khai báo
        uint16_t declared_port;         // Port mà node khai báo
        
        uint64_t probe_id;              // Unique ID cho probe packet
        uint32_t probe_checksum;        // Checksum để verify integrity
        
        VerificationState state = VerificationState::PENDING;
        uint64_t sent_time;             // Timestamp khi PROBE được gửi
        uint64_t attempts = 0;          // Số lần retry
        
        bool is_server = false;         // true nếu verified reachable
    };

    /**
     * @brief Initiate verification process
     * @param node_id Node ID (32 bytes hex)
     * @param declared_ip IP address node khai báo
     * @param declared_port Port node khai báo
     * @return probe_id để tracking
     */
    uint64_t initiate_verification(
        const std::string& node_id,
        const std::string& declared_ip,
        uint16_t declared_port
    );

    /**
     * @brief Nhận PROBE_ACK từ node
     * @param node_id Node ID
     * @param probe_id Echo của probe_id
     * @param checksum Echo của checksum
     * @return true nếu match, false nếu invalid
     */
    bool handle_probe_ack(
        const std::string& node_id,
        uint64_t probe_id,
        uint32_t checksum
    );

    /**
     * @brief Lấy verification status
     */
    VerificationState get_verification_state(const std::string& node_id);

    /**
     * @brief Kiểm tra node có verified là server không
     */
    bool is_server(const std::string& node_id);

    /**
     * @brief Cleanup expired verification requests
     * @param timeout_ms Timeout duration (mặc định 5000ms)
     */
    void cleanup_expired_verifications(uint64_t timeout_ms = 5000);

    /**
     * @brief Get all pending verifications
     */
    std::map<std::string, std::shared_ptr<VerificationRequest>> get_pending_verifications();

    /**
     * @brief Generate probe_id và checksum
     */
    std::pair<uint64_t, uint32_t> generate_probe_credentials();

private:
    std::map<std::string, std::shared_ptr<VerificationRequest>> verifications_;
    uint64_t next_probe_id_ = 1;
};

#endif // VERIFICATION_MANAGER_HPP
