#ifndef PROTOCOL_HPP
#define PROTOCOL_HPP

#include <cstdint>
#include <vector>

// --- OPCODES (Mã lệnh) ---
namespace OpCode {
    // --- GIAI ĐOẠN 1: HANDSHAKE (Bắt tay 3 bước) ---
    const uint8_t HELLO       = 0x01; // Client gửi Kyber CT + ECDHE Pub
    const uint8_t WELCOME     = 0x02; // Server trả ECDHE Pub + Sig
    const uint8_t AUTH        = 0x03; // Client gửi Sig xác nhận

    // --- DISCOVERY (Tìm người & Trao đổi Key) ---
    const uint8_t WHO_ARE_YOU = 0x90; // "Bạn là ai?"
    const uint8_t IAM         = 0x91; // "Tôi là X, Public Key tôi đây"

     // --- GIAI ĐOẠN 2: SESSION (Đã mã hóa AES) ---
      const uint8_t PING        = 0x04;
      const uint8_t PING_ACK    = 0x04; // CRITICAL: Same opcode as PING (responder sends ACK back)
      const uint8_t GET_PUBKEY  = 0x05; // "Cho xin cái Key"
      const uint8_t PUBKEY      = 0x06; // "Key đây"
      const uint8_t DATA        = 0x07; // Encrypted message payload
      const uint8_t ACK         = 0x08; // Message acknowledgment
      const uint8_t SESSION_RST = 0x0F; // Session reset / kill signal (Gửi khi node ko recognize session)
     
     // File System Ops
    // File System Ops
    const uint8_t FS_LIST_REQ = 0x10; 
    const uint8_t FS_LIST_RES = 0x11; 
    const uint8_t FS_META_REQ = 0x12; 
    const uint8_t FS_META_RES = 0x13; 
    const uint8_t FS_DATA_REQ = 0x20; 
    const uint8_t FS_DATA_RES = 0x21; 
    const uint8_t FS_PUT_META_REQ = 0x30; // "Tôi muốn up file X, nặng Y bytes, cho không?"
    const uint8_t FS_PUT_META_RES = 0x31; // "Ok triển đi / hoặc Cút (Lỗi)"
    const uint8_t FS_PUT_DATA     = 0x32; // "Dữ liệu đây (Chunk)"

    const uint8_t P2P_FIND_NODE_REQ = 0x60; // A hỏi B: "Tìm giúp tao thằng C"
    const uint8_t P2P_FIND_NODE_RES = 0x61; // B trả lời A: "IP thằng C đây"
    const uint8_t P2P_ASSIST_REQ    = 0x62; // B ra lệnh cho C: "Mày đấm lỗ cho thằng A đi"
    const uint8_t P2P_HOLE_PUNCH    = 0x63; // C gửi gói rác cho A để mở NAT
    const uint8_t RELAY_REQ = 0x70; // A -> Admin: "Chuyển cái này đi hộ tao"
    const uint8_t RELAY_FWD = 0x71; // Admin -> B: "Hàng của thằng A gửi mày nè"
    
    // --- SERVER VERIFICATION (3-step) ---
    const uint8_t VERIFY_REQ  = 0x80; // Node gửi IP/Port tự khai báo
    const uint8_t PROBE       = 0x81; // SuperNode gửi kiểm tra
    const uint8_t PROBE_ACK   = 0x82; // Node phản hồi, xác nhận reachable
    
    // --- WEB3 (MML, Virtual Shell, ACL) ---
    const uint8_t MML_INDEX_REQ = 0x40; // Lấy file index.mml
    const uint8_t MML_INDEX_RES = 0x41; // Trả file index.mml
    const uint8_t CMD_SHELL_REQ = 0x42; // Lệnh shell (ls, cd, ...)
    const uint8_t CMD_SHELL_RES = 0x43; // Kết quả shell
    
    const uint8_t ERROR       = 0xFF; 
}

// --- FLAGS ---
namespace PacketFlag {
    const uint8_t NONE        = 0x00;
    const uint8_t ENCRYPTED   = 0x01; 
    const uint8_t IS_RELAY    = 0x02; 
    const uint8_t RELAY_ERR   = 0x04; 
    const uint8_t IS_RELAYED  = 0x08; // Node này đã được relay (phải gửi response qua relay)
    const uint8_t ACK_REQUIRED = 0x10; // Sender expects ACK for this message
}

// --- UDP HEADER (Binary - Cố định 86 bytes) ---
// Size = 2(magic) + 1(op) + 1(flag) + 8(seq) + 32(sender) + 32(target) + 8(nonce) + 2(len) = 86 bytes
#pragma pack(push, 1) 
struct PacketHeader {
    uint8_t  magic[2] = {'S', 'M'}; 
    uint8_t  op_code;               
    uint8_t  flags;                 
    uint64_t seq;                   
    uint8_t  sender_id[32];         // Mở rộng lên 32 bytes (full SHA-256)
    uint8_t  target_id[32];         // Mở rộng lên 32 bytes (full SHA-256)
    uint64_t packet_nonce;          // Anti-replay nonce
    uint16_t payload_len;           
};

// --- CẤU TRÚC PAYLOAD ---

// 1. HELLO (~800 bytes)
struct Payload_Hello {
    uint8_t kyber_ct[768];  // Kyber-512 Ciphertext
    uint8_t ecdh_pub[32];   // X25519 Public Key
};

// 2. WELCOME (~698 bytes)
struct Payload_Welcome {
    uint8_t ecdh_pub[32];
    uint16_t sig_len;   
    uint8_t signature[666]; // Falcon-512 Signature
};

// 3. AUTH (~666 bytes)
struct Payload_Auth {
    uint8_t signature[666]; 
};

// 4. IAM (Trả lời Discovery - 800 bytes)
// Kyber-512 Public Key size chuẩn là 800 bytes
struct Payload_Iam_Kyber512 {
    uint8_t kyber_pub[800]; 
};

struct Payload_PubKey {
    uint8_t falcon_pub[897]; // Key Falcon-512
};

struct Payload_FindNode {
    uint8_t target_id[32]; // ID của thằng muốn tìm (C) - 32 bytes
};

// Cấu trúc gói tin "Trả kết quả" & "Hỗ trợ"
struct Payload_NodeInfo {
    uint8_t target_id[32];
    char ip[46];    // INET6_ADDRSTRLEN = 46 for IPv6
    uint16_t port;  // Port của mục tiêu
};

struct Payload_RelayHeader {
    uint8_t target_id[32]; // ID người nhận (32 bytes)
    // Sau struct này sẽ là toàn bộ gói tin gốc (Raw Data)
};

// --- SERVER VERIFICATION PAYLOADS ---
struct Payload_VerifyReq {
    char ip[46];        // IPv4/IPv6 address
    uint16_t port;
    uint8_t padding[8]; // Padding để đều size
};

struct Payload_Probe {
    uint64_t probe_id;  // Unique ID để verify phản hồi
    uint32_t checksum;  // Checksum để verify packet integrity
};

struct Payload_ProbeAck {
    uint64_t probe_id;  // Echo lại probe_id
    uint32_t checksum;  // Echo lại checksum
};

// --- WEB3 PAYLOADS ---
struct Payload_MmlIndex {
    // MML file content (variable length)
    // Format: JSON hoặc binary list của files trong folder
};

struct Payload_ShellCmd {
    char cmd[256];      // Shell command (ls, cd, pwd, ...)
    char current_dir[256]; // Current working directory
};

#pragma pack(pop)

// Hằng số kích thước
const size_t PACKET_HEADER_SIZE = 86;  // Updated header size
const size_t UDP_MTU = 1400; 
const size_t MAX_PAYLOAD = UDP_MTU - PACKET_HEADER_SIZE - 8; // 1306 bytes

// Node ID size
const size_t NODE_ID_SIZE = 32; // Full SHA-256

// Verification timeout
const int VERIFY_TIMEOUT_MS = 5000; // 5 seconds 

#endif