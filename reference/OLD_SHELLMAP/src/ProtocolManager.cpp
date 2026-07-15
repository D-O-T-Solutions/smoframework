#include "ProtocolManager.hpp"
#include "SessionManager.hpp"
#include "VerificationManager.hpp"
#include "RelayManager.hpp"
#include "Web3Manager.hpp"
#include "FileManager.hpp"
#include "CommandHandler.hpp"
#include "NodeInitializer.hpp"
#include "SecurityUtils.hpp"
#include <iostream>
#include <chrono>
#include <arpa/inet.h>
#include <cstdio>
#include <iomanip>
#include <sstream>
#include <filesystem>
#include <fstream>

ProtocolManager::ProtocolManager(
    std::shared_ptr<SessionManager> session_mgr,
    std::shared_ptr<VerificationManager> verify_mgr,
    std::shared_ptr<RelayManager> relay_mgr,
    std::shared_ptr<Web3Manager> web3_mgr,
    FileManager* file_mgr,
    std::shared_ptr<CommandHandler> cmd_handler,
    NetworkEngine& net_engine,
    RoutingTable& route_table,
    NodeContext* my_node
) : session_mgr_(session_mgr),
    verify_mgr_(verify_mgr),
    relay_mgr_(relay_mgr),
    web3_mgr_(web3_mgr),
    file_mgr_(file_mgr),
    cmd_handler_(cmd_handler),
    net_engine_(net_engine),
    route_table_(route_table),
    my_node_(my_node) {
//     std::cout << "[PROTOCOL] ProtocolManager initialized" << std::endl;
}

void ProtocolManager::dispatch_packet(
    PacketHeader& hdr,
    std::vector<uint8_t>& payload,
    const sockaddr_in& sender_addr
) {
    // CRITICAL: Update peer address from kernel recvfrom() BEFORE processing any packet
    // This handles NAT port changes (Symmetric NAT) dynamically
    std::string sender_id_str = sender_id_to_string(hdr.sender_id);
    char sender_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &sender_addr.sin_addr, sender_ip, INET_ADDRSTRLEN);
    uint16_t sender_port = ntohs(sender_addr.sin_port);
    
     // Update peer address (returns true if changed)
    bool addr_changed = update_peer_address(sender_id_str, std::string(sender_ip), sender_port);
    if (addr_changed && (hdr.op_code != OpCode::HELLO && hdr.op_code != OpCode::WELCOME && hdr.op_code != OpCode::AUTH)) {
        // Only log address changes for non-handshake packets (SUPPRESSED - causes prompt rendering issues)
        // std::cout << "[DISPATCH] Peer address updated (possibly Symmetric NAT)" << std::endl;
    }
    
      // Check nonce first (anti-replay)
      if (!verify_nonce(hdr.sender_id, hdr.packet_nonce)) {
          // Log replay drop with opcode and nonce for debugging
          std::cout << COLOR_RED << "[REPLAY-DROP] Packet from " << sender_id_str.substr(0, 8) 
                    << "... (OpCode=0x" << std::hex << (int)hdr.op_code << std::dec 
                    << ", nonce=" << hdr.packet_nonce << ")" << COLOR_RESET << std::endl;
          return;
      }

    // Dispatch based on OpCode
    switch (hdr.op_code) {
        // Handshake
        case OpCode::HELLO:
            handle_hello(hdr, payload, sender_addr);
            break;
        case OpCode::WELCOME:
            handle_welcome(hdr, payload, sender_addr);
            break;
        case OpCode::AUTH:
            handle_auth(hdr, payload, sender_addr);
            break;

        // Discovery
        case OpCode::WHO_ARE_YOU:
            handle_who_are_you(hdr, payload, sender_addr);
            break;
        case OpCode::IAM:
            handle_iam(hdr, payload, sender_addr);
            break;

        // Session
         case OpCode::PING:
             handle_ping(hdr, payload, sender_addr);
             break;
         case OpCode::GET_PUBKEY:
             handle_get_pubkey(hdr, payload, sender_addr);
             break;
         case OpCode::PUBKEY:
             handle_pubkey(hdr, payload, sender_addr);
             break;
         case OpCode::DATA:
             handle_data(hdr, payload, sender_addr);
             break;
          case OpCode::ACK:
              handle_ack(hdr, payload, sender_addr);
              break;
          case OpCode::SESSION_RST:
              handle_session_rst(hdr, payload, sender_addr);
              break;

        // File system
        case OpCode::FS_LIST_REQ:
            handle_fs_list_req(hdr, payload, sender_addr);
            break;
        case OpCode::FS_LIST_RES:
            handle_fs_list_res(hdr, payload, sender_addr);
            break;
        case OpCode::FS_META_REQ:
            handle_fs_meta_req(hdr, payload, sender_addr);
            break;
        case OpCode::FS_META_RES:
            handle_fs_meta_res(hdr, payload, sender_addr);
            break;
        case OpCode::FS_DATA_REQ:
            handle_fs_data_req(hdr, payload, sender_addr);
            break;
        case OpCode::FS_DATA_RES:
            handle_fs_data_res(hdr, payload, sender_addr);
            break;
        case OpCode::FS_PUT_META_REQ:
            handle_fs_put_meta_req(hdr, payload, sender_addr);
            break;
        case OpCode::FS_PUT_META_RES:
            handle_fs_put_meta_res(hdr, payload, sender_addr);
            break;
        case OpCode::FS_PUT_DATA:
            handle_fs_put_data(hdr, payload, sender_addr);
            break;

        // P2P discovery
        case OpCode::P2P_FIND_NODE_REQ:
            handle_p2p_find_node_req(hdr, payload, sender_addr);
            break;
        case OpCode::P2P_FIND_NODE_RES:
            handle_p2p_find_node_res(hdr, payload, sender_addr);
            break;
        case OpCode::P2P_ASSIST_REQ:
            handle_p2p_assist_req(hdr, payload, sender_addr);
            break;
        case OpCode::P2P_HOLE_PUNCH:
            handle_p2p_hole_punch(hdr, payload, sender_addr);
            break;

        // Relay
        case OpCode::RELAY_REQ:
            handle_relay_req(hdr, payload, sender_addr);
            break;
        case OpCode::RELAY_FWD:
            handle_relay_fwd(hdr, payload, sender_addr);
            break;

        // Server verification
        case OpCode::VERIFY_REQ:
            handle_verify_req(hdr, payload, sender_addr);
            break;
        case OpCode::PROBE:
            handle_probe(hdr, payload, sender_addr);
            break;
        case OpCode::PROBE_ACK:
            handle_probe_ack(hdr, payload, sender_addr);
            break;

        // Web3
        case OpCode::MML_INDEX_REQ:
            handle_mml_index_req(hdr, payload, sender_addr);
            break;
        case OpCode::MML_INDEX_RES:
            handle_mml_index_res(hdr, payload, sender_addr);
            break;
        case OpCode::CMD_SHELL_REQ:
            handle_cmd_shell_req(hdr, payload, sender_addr);
            break;
        case OpCode::CMD_SHELL_RES:
            handle_cmd_shell_res(hdr, payload, sender_addr);
            break;

        case OpCode::ERROR:
            handle_error(hdr, payload, sender_addr);
            break;

        default:
            std::cout << "[PROTOCOL] Unknown OpCode: 0x" << std::hex << (int)hdr.op_code << std::dec << std::endl;
            break;
    }
}

bool ProtocolManager::verify_nonce(const uint8_t* sender_id, uint64_t nonce) {
    std::string id_str = sender_id_to_string(sender_id);
    
    // Check if we've seen this nonce before
    auto it = nonce_map_.find(id_str);
    if (it != nonce_map_.end() && it->second >= nonce) {
        return false;  // Replay detected
    }

    // Update nonce map
    nonce_map_[id_str] = nonce;
    return true;
}

void ProtocolManager::clear_nonce_for_peer(const std::string& sender_id_str) {
    auto it = nonce_map_.find(sender_id_str);
    if (it != nonce_map_.end()) {
        nonce_map_.erase(it);
    }
}

std::string ProtocolManager::sender_id_to_string(const uint8_t* id) {
    std::string result;
    for (int i = 0; i < NODE_ID_SIZE; i++) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", id[i]);
        result += buf;
    }
    return result;
}

// NEW HELPER: Convert 64-char hex string to 32-byte binary ID
void ProtocolManager::hex_string_to_node_id(const std::string& hex_str, uint8_t* out_id) {
    memset(out_id, 0, 32);
    if (hex_str.length() < 64) return;
    
    for (int i = 0; i < 32; i++) {
        std::string hex_byte = hex_str.substr(i * 2, 2);
        out_id[i] = (uint8_t)strtol(hex_byte.c_str(), nullptr, 16);
    }
}

// Helper to convert bytes to hex string for logging
static std::string bytes_to_hex_short(const std::string& bytes, size_t len = 16) {
    std::stringstream ss;
    for (size_t i = 0; i < std::min(len, bytes.size()); i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)(unsigned char)bytes[i];
    }
    return ss.str();
}

// ============= REAL HANDSHAKE IMPLEMENTATION =============
// ============= CLASSIC 3-WAY HANDSHAKE - LINEAR FLOW =============
// Step 2: Node B receives HELLO from Node A
// Responder (Node B) generates its X25519 key pair, sends back WELCOME
void ProtocolManager::handle_hello(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender) {
    std::string peer_id_str = sender_id_to_string(hdr.sender_id);
    // std::cout << "\n[HANDSHAKE-2] === RESPOND: Received HELLO from " << peer_id_str.substr(0, 8) << "... ===" << std::endl;
    
    if (payload.size() < 832) {  // 800B Kyber + 32B X25519 (NO port field!)
        std::cout << "[PROTOCOL] Invalid HELLO payload size: " << payload.size() << " (need >= 832)" << std::endl;
        return;
    }
    
    // Get or create session
    auto session = session_mgr_->get_or_create_session(peer_id_str);
    if (!session) {
        std::cout << "[PROTOCOL] Failed to create session" << std::endl;
        return;
    }
    
    // Extract peer's keys from HELLO payload
    std::string peer_kyber_pub((const char*)payload.data(), 800);
    std::string peer_x25519_pub((const char*)payload.data() + 800, 32);
    
    // std::cout << "[HANDSHAKE-2] Peer X25519 Pub: " << bytes_to_hex_short(peer_x25519_pub) << "..." << std::endl;
    
    // CRITICAL: Use sender address DIRECTLY from kernel recvfrom()
    // This is TRUE SOURCE from the network stack - NEVER trust peer's reported port!
    // NAT Hole Punching: Reply to exact IP:port that sent the packet
    char sender_ip_cstr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &sender.sin_addr, sender_ip_cstr, INET_ADDRSTRLEN);
    int sender_port = ntohs(sender.sin_port);
    
    std::string sender_ip_str(sender_ip_cstr);
    // std::cout << "[HANDSHAKE-2] Using kernel source address: " << sender_ip_str << ":" << sender_port << std::endl;
    
    // STEP 2A: Respond generates OUR X25519 key pair (only once!)
    // CRITICAL: If we're also an initiator, we already have a priv key set. Don't overwrite!
    std::string our_x25519_pub, our_x25519_priv;
    
    if (session->temp_ecdh_priv.empty()) {
        // We haven't initiated, so generate a new key pair as responder
        if (!CryptoCore::generate_x25519_keypair(our_x25519_pub, our_x25519_priv)) {
            std::cout << "[PROTOCOL] Failed to generate X25519 keypair" << std::endl;
            return;
        }
        // Store both priv and pub (CRITICAL - never regenerate!)
        session->temp_ecdh_priv = our_x25519_priv;
        session->temp_ecdh_pub = our_x25519_pub;
        // std::cout << "[HANDSHAKE-2] Generated new X25519 Pub (as responder): " << bytes_to_hex_short(our_x25519_pub) << "..." << std::endl;
    } else {
        // We already initiated! Reuse our priv key from initiation
        our_x25519_priv = session->temp_ecdh_priv;
        our_x25519_pub = session->temp_ecdh_pub;
        // std::cout << "[HANDSHAKE-2] Reusing X25519 Pub (already initiated): " << bytes_to_hex_short(our_x25519_pub) << "..." << std::endl;
    }
    
    // STEP 2B: Calculate ECDH with peer's pub
    std::string ecdh_ss;
    if (!CryptoCore::compute_x25519_secret(our_x25519_priv, peer_x25519_pub, ecdh_ss)) {
        std::cout << "[PROTOCOL] Failed to compute ECDH" << std::endl;
        return;
    }
    // std::cout << "[HANDSHAKE-2] ECDH_SS: " << bytes_to_hex_short(ecdh_ss) << "..." << std::endl;
    
    // STEP 2C: Kyber encapsulate to peer's pub
    std::string kyber_ct, kyber_ss;
    if (!CryptoCore::kyber_encaps(peer_kyber_pub, kyber_ct, kyber_ss)) {
        std::cout << "[PROTOCOL] Kyber encaps failed" << std::endl;
        return;
    }
    // std::cout << "[HANDSHAKE-2] Kyber_SS (from encaps): " << bytes_to_hex_short(kyber_ss) << "..." << std::endl;
    
    // Store Kyber SS and ECDH_SS (this is responder's contribution)
    session->temp_kyber_ss_responder = kyber_ss;
    session->temp_ecdh_ss = ecdh_ss;  // CRITICAL: Store ECDH_SS from responder perspective
    session->temp_ecdh_peer_pub = peer_x25519_pub;
    
    // STEP 2D: Derive final AES key NOW (if this is mutual handshake, we can establish early)
    // For now, just send WELCOME. Will establish when we receive AUTH or initiate AUTH ourselves
    
     // Build WELCOME: [Kyber CT (768B)] [Our Kyber SS (32B)] [Our X25519 Pub (32B)]
     // NOTE: Responder's Kyber_Pub is NOT needed - Initiator already has it from HELLO!
     // In KEM: Responder only needs to return Kyber_CT (encapsulation result)
     // This reduces WELCOME size from 1718B to ~918B, safely under MTU 1500
     std::vector<uint8_t> welcome_payload;
     welcome_payload.insert(welcome_payload.end(), (uint8_t*)kyber_ct.data(), (uint8_t*)kyber_ct.data() + kyber_ct.size());
     welcome_payload.insert(welcome_payload.end(), (uint8_t*)kyber_ss.data(), (uint8_t*)kyber_ss.data() + kyber_ss.size());  // CRITICAL: Include our Kyber SS
     welcome_payload.insert(welcome_payload.end(), (uint8_t*)our_x25519_pub.data(), (uint8_t*)our_x25519_pub.data() + 32);
    
    // Send WELCOME
    PacketHeader hdr_welcome;
    hdr_welcome.magic[0] = 'S'; hdr_welcome.magic[1] = 'M';
    hdr_welcome.op_code = OpCode::WELCOME;
    hdr_welcome.flags = 0;
    hdr_welcome.seq = 1;
    hdr_welcome.payload_len = welcome_payload.size();
    hdr_welcome.packet_nonce = session->packet_nonce_counter++;  // Monotonic counter
     hex_string_to_node_id(my_node_->node_id, hdr_welcome.sender_id);
     memcpy(hdr_welcome.target_id, hdr.sender_id, 32);
     
     // CRITICAL: Store peer's IP/port for future communication
     // (sender_ip_cstr, sender_port, sender_ip_str already declared above)
    session->peer_ip = sender_ip_str;
    session->peer_port = sender_port;
    // std::cout << "[HANDSHAKE-2] Stored peer IP:port = " << sender_ip_str << ":" << sender_port << std::endl;
    
    net_engine_.send_packet(hdr_welcome, welcome_payload, sender_ip_str, sender_port);
    // std::cout << "[HANDSHAKE-2] WELCOME sent!" << std::endl;
    
    session->state = SessionManager::SessionState::WELCOME_SENT;
}

// Step 3: Node A receives WELCOME from Node B
// Initiator (Node A) completes ECDH, sends AUTH
void ProtocolManager::handle_welcome(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender) {
    std::string peer_id_str = sender_id_to_string(hdr.sender_id);
    // std::cout << "\n[HANDSHAKE-3] === FINALIZE: Received WELCOME from " << peer_id_str.substr(0, 8) << "... ===" << std::endl;
    
    if (payload.size() < 832) {
        std::cout << "[PROTOCOL] Invalid WELCOME payload size: " << payload.size() << " (expected >= 832)" << std::endl;
        return;
    }
    
    // Find existing session - try with real peer ID first
    auto session = session_mgr_->get_session(peer_id_str);
    
    // If not found, try to find placeholder session (created by initiate_handshake)
    if (!session) {
        // std::cout << "[HANDSHAKE-3] Session with real peer ID not found, looking for placeholder..." << std::endl;
        auto [placeholder_key, placeholder_session] = session_mgr_->find_placeholder_session();
        if (placeholder_session) {
            // std::cout << "[HANDSHAKE-3] Found placeholder session, migrating to real peer ID" << std::endl;
            session_mgr_->migrate_session(placeholder_key, peer_id_str);
            session = session_mgr_->get_session(peer_id_str);
        }
    }
    
    if (!session) {
        std::cout << "[PROTOCOL] No session found for WELCOME" << std::endl;
        return;
    }
    
    // Extract peer's keys from WELCOME: [Kyber CT (768B)] [Peer Kyber SS (32B)] [Peer X25519 Pub (32B)]
    // NOTE: Peer's Kyber_Pub is NOT included - we already have it from HELLO!
    if (payload.size() < 832) {
        std::cout << "[PROTOCOL] Invalid WELCOME payload size: " << payload.size() << " (expected >= 832)" << std::endl;
        return;
    }
    
    std::string kyber_ct((const char*)payload.data(), 768);
    std::string peer_kyber_ss((const char*)payload.data() + 768, 32);  // CRITICAL: Extract responder's Kyber SS
    std::string peer_x25519_pub((const char*)payload.data() + 800, 32);
    
    // std::cout << "[HANDSHAKE-3] Peer X25519 Pub: " << bytes_to_hex_short(peer_x25519_pub) << "..." << std::endl;
    
    // CRITICAL: Store the responder's Kyber SS (received from WELCOME)
    session->temp_kyber_ss_responder = peer_kyber_ss;
    // std::cout << "[HANDSHAKE-3] Stored peer's Kyber SS from WELCOME: " << bytes_to_hex_short(peer_kyber_ss) << "..." << std::endl;
    
    // STEP 3A: Retrieve OUR X25519 priv from session
    // CRITICAL: If we are the initiator (temp_ecdh_priv_initiator is set), use initiator priv
    // Otherwise, use responder priv (from handle_hello)
    std::string our_ecdh_priv;
    
    if (!session->temp_ecdh_priv_initiator.empty()) {
        // We initiated this connection, use initiator priv
        our_ecdh_priv = session->temp_ecdh_priv_initiator;
        // std::cout << "[HANDSHAKE-3] Using X25519 Initiator Priv" << std::endl;
    } else if (!session->temp_ecdh_priv.empty()) {
        // We are responder (haven't initiated yet), use responder priv
        our_ecdh_priv = session->temp_ecdh_priv;
        // std::cout << "[HANDSHAKE-3] Using X25519 Responder Priv" << std::endl;
    } else {
        std::cout << "[PROTOCOL] ERROR: Neither initiator nor responder priv found!" << std::endl;
        return;
    }
    
    // STEP 3B: Calculate ECDH with peer's pub
    std::string ecdh_ss;
    if (!CryptoCore::compute_x25519_secret(our_ecdh_priv, peer_x25519_pub, ecdh_ss)) {
        std::cout << "[PROTOCOL] Failed to compute ECDH in handle_welcome" << std::endl;
        return;
    }
    // std::cout << "[HANDSHAKE-3] ECDH_SS: " << bytes_to_hex_short(ecdh_ss) << "..." << std::endl;
    
    // STEP 3C: Kyber decapsulate
    std::string kyber_ss;
    if (!CryptoCore::kyber_decaps(my_node_->kyber_priv, kyber_ct, kyber_ss)) {
        std::cout << "[PROTOCOL] Kyber decaps failed" << std::endl;
        return;
    }
    // std::cout << "[HANDSHAKE-3] Kyber_SS (from decaps): " << bytes_to_hex_short(kyber_ss) << "..." << std::endl;
    
     // Store Kyber SS (this is initiator's contribution)
    session->temp_kyber_ss_initiator = kyber_ss;
    session->temp_ecdh_peer_pub = peer_x25519_pub;
    session->temp_ecdh_ss = ecdh_ss;  // CRITICAL: Store ECDH_SS from initiator perspective
    
    // STEP 3E: Check if we have both Kyber SSs
    if (session->temp_kyber_ss_responder.empty()) {
        // std::cout << "[HANDSHAKE-3] Waiting for responder Kyber SS (from HELLO)..." << std::endl;
        session->state = SessionManager::SessionState::WELCOME_RECEIVED;
        return;
    }
    
    // STEP 3E: Derive final AES key from combined Kyber SS + ECDH SS
    // Use establish_session to properly derive keys
    if (!session_mgr_->establish_session(peer_id_str)) {
        std::cout << "[PROTOCOL] Failed to establish session in handle_welcome" << std::endl;
        return;
    }
    // std::cout << "[HANDSHAKE-3] Keys established successfully" << std::endl;
    
    // Send AUTH with initiator's Kyber SS so responder can complete key derivation
    std::vector<uint8_t> auth_payload;
    // AUTH payload: [Initiator Kyber SS (32B)]
    auth_payload.insert(auth_payload.end(), (uint8_t*)session->temp_kyber_ss_initiator.data(), (uint8_t*)session->temp_kyber_ss_initiator.data() + 32);
    
    PacketHeader hdr_auth;
    hdr_auth.magic[0] = 'S'; hdr_auth.magic[1] = 'M';
    hdr_auth.op_code = OpCode::AUTH;
    hdr_auth.flags = 0;
    hdr_auth.seq = 2;
    hdr_auth.payload_len = 0;
    hdr_auth.packet_nonce = session->packet_nonce_counter++;  // Monotonic counter
    hex_string_to_node_id(my_node_->node_id, hdr_auth.sender_id);
    memcpy(hdr_auth.target_id, hdr.sender_id, 32);
    
    char sender_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &sender.sin_addr, sender_ip, INET_ADDRSTRLEN);
    int sender_port = ntohs(sender.sin_port);
    
    net_engine_.send_packet(hdr_auth, auth_payload, sender_ip, sender_port);
    // std::cout << "[HANDSHAKE-3] AUTH sent!" << std::endl;
    
    session->state = SessionManager::SessionState::ESTABLISHED;
    // HOTFIX: Register peer in routing table when session becomes ESTABLISHED
    route_table_.update_route(peer_id_str, session->peer_ip, session->peer_port);
    // std::cout << "[HANDSHAKE-3] === SESSION ESTABLISHED ===" << std::endl;
}

// Final step: Node B receives AUTH from Node A
// Both sides now have the same AES key
void ProtocolManager::handle_auth(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender) {
    std::string peer_id_str = sender_id_to_string(hdr.sender_id);
    // std::cout << "\n[HANDSHAKE-FINAL] Received AUTH from " << peer_id_str.substr(0, 8) << "..." << std::endl;
    
    auto session = session_mgr_->get_session(peer_id_str);
    if (!session) {
        std::cout << "[PROTOCOL] No session found for AUTH" << std::endl;
        return;
    }
    
    // Extract initiator's Kyber SS from AUTH payload (if we're the responder)
    // We're the responder if we set temp_ecdh_priv (in handle_hello) and did NOT set temp_ecdh_priv_initiator
    if (!session->temp_ecdh_priv.empty() && session->temp_ecdh_priv_initiator.empty()) {
        // We are the responder - extract initiator's Kyber SS from AUTH
        if (payload.size() >= 32) {
            std::string initiator_kyber_ss((const char*)payload.data(), 32);
            session->temp_kyber_ss_initiator = initiator_kyber_ss;
            // std::cout << "[HANDSHAKE-FINAL] Extracted initiator Kyber SS from AUTH: " << bytes_to_hex_short(initiator_kyber_ss) << "..." << std::endl;
        } else {
            std::cout << "[PROTOCOL] AUTH payload too small to contain Kyber SS (got " << payload.size() << ", need 32)" << std::endl;
            return;
        }
    }
    
    // Verify we have all components
    if (session->temp_kyber_ss_responder.empty() || session->temp_kyber_ss_initiator.empty() || session->temp_ecdh_ss.empty()) {
        std::cout << "[PROTOCOL] Missing handshake state for AUTH" << std::endl;
        return;
    }
    
    // If we haven't derived keys yet, derive them now
    if (session->aes_key.empty()) {
        if (!session_mgr_->establish_session(peer_id_str)) {
            std::cout << "[PROTOCOL] Failed to establish session in handle_auth" << std::endl;
            return;
        }
        // std::cout << "[HANDSHAKE-FINAL] Keys established successfully" << std::endl;
    }
    
    session->state = SessionManager::SessionState::ESTABLISHED;
    // HOTFIX: Register peer in routing table when session becomes ESTABLISHED
    route_table_.update_route(peer_id_str, session->peer_ip, session->peer_port);
    // std::cout << "[HANDSHAKE-FINAL] === SESSION ESTABLISHED ===" << std::endl;
}

void ProtocolManager::handle_who_are_you(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender) {
//     std::cout << "[PROTOCOL] WHO_ARE_YOU" << std::endl;
}

void ProtocolManager::handle_iam(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender) {
//     std::cout << "[PROTOCOL] IAM from " << sender_id_to_string(hdr.sender_id) << std::endl;
}

void ProtocolManager::handle_ping(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender) {
    std::string sender_id_str = sender_id_to_string(hdr.sender_id);
//     std::cout << "[PROTOCOL] PING from " << sender_id_str << std::endl;
    
    // Payload: [8 bytes timestamp]
    if (payload.size() < 8) {
        std::cout << "[PROTOCOL] Invalid PING payload size" << std::endl;
        return;
    }
    
    // Extract ping timestamp
    uint64_t ping_ts = *(uint64_t*)payload.data();
    
    // Update session last_activity
    auto session = session_mgr_->get_session(sender_id_str);
    if (session) {
        session->last_activity = std::chrono::system_clock::now().time_since_epoch().count();
        
        // Check if this is a PING response (we sent a PING and got it back)
        if (session->ping_sent_ts > 0 && ping_ts == session->ping_sent_ts) {
            // This is a PONG response - calculate round-trip time
            uint64_t now = std::chrono::system_clock::now().time_since_epoch().count();
            uint64_t rtt_ns = now - ping_ts;
            // Convert nanoseconds to milliseconds
            uint64_t rtt_ms = rtt_ns / 1000000;
//             std::cout << "[PROTOCOL] Pong! (" << rtt_ms << " ms)" << std::endl;
            session->ping_sent_ts = 0;  // Clear the timestamp
            return;  // Don't send back another PING
        }
        
        // Otherwise, this is a PING request from peer - send PING back as response
        std::vector<uint8_t> pong_payload((uint8_t*)&ping_ts, (uint8_t*)&ping_ts + 8);
        
        PacketHeader hdr_pong;
        hdr_pong.magic[0] = 'S'; hdr_pong.magic[1] = 'M';
        hdr_pong.op_code = OpCode::PING;  // PING as response is the pong
        hdr_pong.flags = 0;
        hdr_pong.seq = hdr.seq + 1;
        hdr_pong.payload_len = pong_payload.size();
        hdr_pong.packet_nonce = session->packet_nonce_counter++;  // Monotonic counter
        memcpy(hdr_pong.sender_id, hdr.target_id, 32);
        memcpy(hdr_pong.target_id, hdr.sender_id, 32);
        
        char sender_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sender.sin_addr, sender_ip, INET_ADDRSTRLEN);
        int sender_port = ntohs(sender.sin_port);
        
        net_engine_.send_packet(hdr_pong, pong_payload, sender_ip, sender_port);
//         std::cout << "[PROTOCOL] PING (pong) sent to " << sender_id_str << std::endl;
    } else {
        // No session found - safely drop packet without dereferencing null session
        // Do not send SESSION_RST since we don't have session state to derive packet_nonce
        // Silent handling - no log output to avoid UI spam
    }
}

void ProtocolManager::handle_get_pubkey(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender) {
//     std::cout << "[PROTOCOL] GET_PUBKEY" << std::endl;
}

void ProtocolManager::handle_pubkey(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender) {
//     std::cout << "[PROTOCOL] PUBKEY" << std::endl;
}

void ProtocolManager::handle_data(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender) {
    std::string sender_id_str = sender_id_to_string(hdr.sender_id);
//     std::cout << "[PROTOCOL] DATA from " << sender_id_str << " (encrypted payload, size=" << payload.size() << ")" << std::endl;
    
    // Payload format:
    // [1 byte: flags (ACK_REQUIRED)]
    // [4 bytes: message_id]
    // [4 bytes: fragment_seq]
    // [2 bytes: fragment_total]
    // [variable: ciphertext + GCM tag]
    
    if (payload.size() < 11) {
        std::cout << "[PROTOCOL] Invalid DATA payload size: " << payload.size() << std::endl;
        return;
    }
    
    uint8_t msg_flags = payload[0];
    uint32_t msg_id = *(uint32_t*)(payload.data() + 1);
    uint32_t frag_seq = *(uint32_t*)(payload.data() + 5);
    uint16_t frag_total = *(uint16_t*)(payload.data() + 9);
    
//     std::cout << "[PROTOCOL] DATA: msg_id=" << msg_id << ", frag=" << frag_seq << "/" << frag_total 
//               << ", ciphertext_size=" << (payload.size() - 11) << std::endl;
    
    std::vector<uint8_t> ciphertext_with_tag(payload.begin() + 11, payload.end());
    
    auto session = session_mgr_->get_session(sender_id_str);
    if (!session) {
        std::cout << "[PROTOCOL] No session found for DATA from " << sender_id_str << std::endl;
        return;
    }
     if (session->state != SessionManager::SessionState::ESTABLISHED) {
         std::cout << "[PROTOCOL] Session not ESTABLISHED for DATA from " << sender_id_str 
                   << " (state=" << (int)session->state << ")" << std::endl;
         return;
     }
    
//     std::cout << "[PROTOCOL] Session established, proceeding with decryption..." << std::endl;
    
    // Send ACK if requested
    if (msg_flags & PacketFlag::ACK_REQUIRED) {
//         std::cout << "[PROTOCOL] ACK required, attempting to send..." << std::endl;
        send_ack(sender_id_str, msg_id);
    }
    
    // Decrypt the message
//     std::cout << "[PROTOCOL] Decrypting message..." << std::endl;
    std::vector<uint8_t> plaintext = session_mgr_->decrypt_message(sender_id_str, ciphertext_with_tag, hdr.packet_nonce);
    if (plaintext.empty()) {
        std::cout << "[PROTOCOL] Failed to decrypt message" << std::endl;
        return;
    }
//     std::cout << "[PROTOCOL] Decryption successful! Plaintext size: " << plaintext.size() << std::endl;
    
    // Handle fragmentation: reassemble if needed
    if (frag_total > 1) {
        // Multi-fragment message - store fragment
        auto& reassembly = session->reassembly_buffer[msg_id];
        if (reassembly.fragments.empty()) {
            reassembly.fragments.resize(frag_total);
            reassembly.total_fragments = frag_total;
            reassembly.first_fragment_time = std::chrono::system_clock::now().time_since_epoch().count();
        }
        
        if (frag_seq < frag_total) {
            reassembly.fragments[frag_seq] = plaintext;
        }
        
        // Check if all fragments received
        bool complete = true;
        for (size_t i = 0; i < frag_total; i++) {
            if (reassembly.fragments[i].empty()) {
                complete = false;
                break;
            }
        }
        
        if (!complete) {
//             std::cout << "[PROTOCOL] Received fragment " << frag_seq << "/" << (frag_total - 1) 
//                      << " for message " << msg_id << std::endl;
            return;  // Wait for more fragments
        }
        
        // All fragments received - reassemble
        std::vector<uint8_t> full_message;
        for (const auto& frag : reassembly.fragments) {
            full_message.insert(full_message.end(), frag.begin(), frag.end());
        }
        plaintext = full_message;
        session->reassembly_buffer.erase(msg_id);
    }
    
    // Display decrypted message to user
    std::string message_str((char*)plaintext.data(), plaintext.size());
    std::cout << "[MESSAGE] " << sender_id_str.substr(0, 8) << ": " << message_str << std::endl;
    
    session->last_activity = std::chrono::system_clock::now().time_since_epoch().count();
}

void ProtocolManager::handle_ack(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender) {
    std::string sender_id_str = sender_id_to_string(hdr.sender_id);
    
    // Payload: [4 bytes: message_id]
    if (payload.size() < 4) {
        std::cout << "[PROTOCOL] Invalid ACK payload size" << std::endl;
        return;
    }
    
    uint32_t ack_msg_id = *(uint32_t*)payload.data();
    
    auto session = session_mgr_->get_session(sender_id_str);
    if (!session) {
        std::cout << "[PROTOCOL] No session for ACK from " << sender_id_str << std::endl;
        return;
    }
    
    // Remove from pending messages
    auto it = session->pending_messages.find(ack_msg_id);
    if (it != session->pending_messages.end()) {
//         std::cout << "[PROTOCOL] ACK received for message " << ack_msg_id 
//                  << " from " << sender_id_str.substr(0, 8) << std::endl;
        session->pending_messages.erase(it);
    } else {
//         std::cout << "[PROTOCOL] ACK for unknown message " << ack_msg_id << std::endl;
    }
    
    session->last_activity = std::chrono::system_clock::now().time_since_epoch().count();
}

void ProtocolManager::handle_session_rst(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender) {
    std::string sender_id_str = sender_id_to_string(hdr.sender_id);
    
    // Remove session immediately
    session_mgr_->destroy_session(sender_id_str);
    
    // Print clean notification
    std::cout << COLOR_YELLOW << "[INFO] Peer " << sender_id_str.substr(0, 16) 
              << " has reset the connection. Session closed." << COLOR_RESET << std::endl;
     
    // If this peer was the current target, reset target
    if (cmd_handler_ && cmd_handler_->get_current_target_id() == sender_id_str) {
        cmd_handler_->reset_target();
    }
}

void ProtocolManager::handle_fs_list_req(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender) {
    // Decode sender ID
    std::string sender_id_str = sender_id_to_string(hdr.sender_id);
    
    // Get session to decrypt payload
    auto session = session_mgr_->get_session(sender_id_str);
    if (!session) {
        std::cout << COLOR_RED << "[SECURITY] FS_LIST_REQ from unknown session: " << sender_id_str << COLOR_RESET << std::endl;
        return;
    }
    
    if (session->state != SessionManager::SessionState::ESTABLISHED) {
        std::cout << COLOR_RED << "[SECURITY] FS_LIST_REQ from non-established session: " << sender_id_str << COLOR_RESET << std::endl;
        return;
    }
    
    // Decrypt payload
    auto plaintext = session_mgr_->decrypt_message(sender_id_str, payload, hdr.packet_nonce);
    if (plaintext.empty()) {
        std::cout << COLOR_RED << "[SECURITY] Failed to decrypt FS_LIST_REQ" << COLOR_RESET << std::endl;
        return;
    }
    
    // Parse path from plaintext: [path_len (2 bytes)][path]
    if (plaintext.size() < 2) {
        std::cout << COLOR_RED << "[SECURITY] FS_LIST_REQ payload too small" << COLOR_RESET << std::endl;
        return;
    }
    
    uint16_t path_len = (plaintext[0] << 8) | plaintext[1];
    if (plaintext.size() < 2 + path_len) {
        std::cout << COLOR_RED << "[SECURITY] FS_LIST_REQ path truncated" << COLOR_RESET << std::endl;
        return;
    }
    
     std::string path(plaintext.begin() + 2, plaintext.begin() + 2 + path_len);
     
     // Security check: validate path BEFORE any operations
     if (!SecurityUtils::is_safe_path(path)) {
         std::cout << COLOR_RED << "[SECURITY] Path Traversal attack blocked: " << path << COLOR_RESET << std::endl;
         SecurityUtils::log_security_attack(sender_id_str, "Path Traversal in FS_LIST_REQ");
         return;
     }
     
     // Normalize and canonicalize the path
     std::string normalized_path = SecurityUtils::normalize_path(path);
     
     // Build actual file path
     std::string full_path = "shellmap/shared/" + (normalized_path.empty() ? "" : normalized_path);
     
     // SECURITY: Verify the resolved path stays within the sandbox
     // Convert to canonical path if possible and verify it doesn't escape
     try {
         fs::path canonical = fs::canonical(full_path);
         fs::path sandbox_base = fs::canonical("shellmap/shared/");
         
         // Check if canonical path is within sandbox
         std::string canonical_str = canonical.string();
         std::string sandbox_str = sandbox_base.string();
         
         if (canonical_str.length() < sandbox_str.length() || 
             canonical_str.substr(0, sandbox_str.length()) != sandbox_str) {
             std::cout << COLOR_RED << "[SECURITY] Path escape attempt blocked: " << path << COLOR_RESET << std::endl;
             SecurityUtils::log_security_attack(sender_id_str, "Sandbox Escape in FS_LIST_REQ");
             return;
         }
     } catch (...) {
         // If path doesn't exist yet, just use the normalized version
         // (for operations like mkdir)
     }
    
    // List directory contents
    std::vector<uint8_t> response;
    try {
        fs::path dir_path(full_path);
        if (!fs::exists(dir_path) || !fs::is_directory(dir_path)) {
            // Directory doesn't exist, return empty list
            response.push_back(0);
            response.push_back(0);  // count = 0
        } else {
             // Build file list as: "name1|size1|type1;name2|size2|type2;...nameN|sizeN|typeN;"
             std::string file_list;
             int file_count = 0;
             
             for (const auto& entry : fs::directory_iterator(dir_path)) {
                 std::string filename = entry.path().filename().string();
                 
                 // Skip . and .. entries
                 if (filename == "." || filename == "..") {
                     continue;
                 }
                 
                 // Add entry with semicolon separator (including last entry!)
                 file_list += filename + "|";
                 file_list += std::to_string(fs::is_directory(entry) ? 0 : fs::file_size(entry)) + "|";
                 file_list += fs::is_directory(entry) ? "dir" : "file";
                 file_list += ";";  // CRITICAL: Add semicolon to EVERY entry, including the last!
                 
                 file_count++;
             }
             
             // Encode response: [count (2 bytes)][file_list]
             uint16_t list_len = file_list.length();
             response.push_back((file_count >> 8) & 0xFF);
             response.push_back(file_count & 0xFF);
             response.insert(response.end(), file_list.begin(), file_list.end());
        }
     } catch (const std::exception& e) {
         std::cout << COLOR_RED << "[SECURITY] Error listing directory: " << e.what() << COLOR_RESET << std::endl;
         response.clear();
         response.push_back(0);
         response.push_back(0);
     }
    
    // Create FS_LIST_RES packet
    PacketHeader res_hdr;
    res_hdr.magic[0] = 'S';
    res_hdr.magic[1] = 'M';
    res_hdr.op_code = static_cast<uint8_t>(OpCode::FS_LIST_RES);
    res_hdr.flags = 0;
     res_hdr.seq = hdr.seq;  // Echo request sequence
     res_hdr.packet_nonce = session->packet_nonce_counter++;  // Monotonic counter for nonce
    
    // Copy IDs
    std::memcpy(res_hdr.sender_id, hdr.target_id, 32);   // Our ID
    std::memcpy(res_hdr.target_id, hdr.sender_id, 32);   // Peer's ID
    
    // Encrypt response
    auto encrypted_response = session_mgr_->encrypt_message(sender_id_str, response, res_hdr.packet_nonce);
    res_hdr.payload_len = encrypted_response.size();  // Set AFTER encryption, not before!
    net_engine_.send_packet(res_hdr, encrypted_response, session->peer_ip, session->peer_port);
}

void ProtocolManager::handle_fs_list_res(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender) {
    // Decode sender ID
    std::string sender_id_str = sender_id_to_string(hdr.sender_id);
    
    // Get session
    auto session = session_mgr_->get_session(sender_id_str);
    if (!session) {
        std::cout << COLOR_RED << "✗ [ERROR] FS_LIST_RES from unknown session: " << sender_id_str << COLOR_RESET << std::endl;
        return;
    }
    
    // Decrypt payload - MUST NOT BE SILENT!
    auto plaintext = session_mgr_->decrypt_message(sender_id_str, payload, hdr.packet_nonce);
    if (plaintext.empty()) {
        std::cout << COLOR_RED << "✗ [ERROR] AES Decryption failed for FS_LIST_RES!" << COLOR_RESET << std::endl;
        return;
    }
    
    // Parse payload format: [file_count: 2 bytes][file_list_string]
    // File list format: "name1|size1|type1;name2|size2|type2;...nameN|sizeN|typeN;"
    if (plaintext.size() < 2) {
        std::cout << COLOR_RED << "✗ [ERROR] FS_LIST_RES payload too small" << COLOR_RESET << std::endl;
        return;
    }
    
    uint16_t file_count = (plaintext[0] << 8) | plaintext[1];
    
    // Convert remaining bytes to string
    std::string file_list(plaintext.begin() + 2, plaintext.end());
    
    // Print table header
    std::string dir_name = session->current_remote_dir.empty() ? "/" : session->current_remote_dir;
    int padding = 25 - dir_name.length();
    
    std::cout << COLOR_BRIGHT_CYAN << "\n╔════════════════════════════════════╗" << COLOR_RESET << std::endl;
    std::cout << COLOR_BRIGHT_CYAN << "║  Files in " << dir_name 
              << std::string(padding > 0 ? padding : 0, ' ')
              << "║" << COLOR_RESET << std::endl;
    std::cout << COLOR_BRIGHT_CYAN << "╠════════════════════════════════════╣" << COLOR_RESET << std::endl;
    
    // Check if directory is empty
    if (file_count == 0) {
        std::cout << COLOR_YELLOW << "  [INFO] Directory is empty" << COLOR_RESET << std::endl;
    } else if (file_list.empty()) {
        std::cout << COLOR_RED << "✗ [ERROR] Malformed directory list format!" << COLOR_RESET << std::endl;
    } else {
        // Parse and print files from string format using stringstream
        std::stringstream ss(file_list);
        std::string entry;
        int parsed_count = 0;
        
        // Split by semicolon using getline
        while (std::getline(ss, entry, ';') && parsed_count < file_count) {
            if (entry.empty()) {
                continue;
            }
            
            // Parse entry: "name|size|type"
            size_t pipe1 = entry.find('|');
            size_t pipe2 = entry.find('|', pipe1 + 1);
            
            if (pipe1 == std::string::npos || pipe2 == std::string::npos) {
                std::cout << COLOR_RED << "✗ [ERROR] Malformed directory list format: " << entry << COLOR_RESET << std::endl;
                continue;
            }
            
            std::string filename = entry.substr(0, pipe1);
            std::string size_str = entry.substr(pipe1 + 1, pipe2 - pipe1 - 1);
            std::string type_str = entry.substr(pipe2 + 1);
            
            if (filename.empty()) {
                std::cout << COLOR_RED << "✗ [ERROR] Empty filename in entry" << COLOR_RESET << std::endl;
                continue;
            }
            
            // Determine color based on type
            std::string color = (type_str == "dir") ? COLOR_YELLOW : COLOR_CYAN;
            std::string display_type = (type_str == "dir") ? "DIR" : "FILE";
            std::string size_display = (type_str == "dir") ? "-" : size_str;
            
            // Print formatted row
            std::cout << color << "  " << std::left << std::setw(25) << filename 
                      << "  " << std::right << std::setw(10) << size_display
                      << "  [" << display_type << "]" << COLOR_RESET << std::endl;
            parsed_count++;
        }
        
        // Warn if parsed count differs from announced count
        if (parsed_count < file_count) {
            std::cout << COLOR_YELLOW << "[WARNING] Parsed " << parsed_count << " files but expected " 
                      << file_count << COLOR_RESET << std::endl;
        }
    }
    
    std::cout << COLOR_BRIGHT_CYAN << "╚════════════════════════════════════╝" << COLOR_RESET << std::endl << std::endl;
}

void ProtocolManager::handle_fs_meta_req(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender) {
    // Decode sender ID
    std::string sender_id_str = sender_id_to_string(hdr.sender_id);
    
    // Get session to decrypt payload
    auto session = session_mgr_->get_session(sender_id_str);
    if (!session) {
         std::cout << COLOR_RED << "[SECURITY] FS_META_REQ from unknown session: " << sender_id_str << COLOR_RESET << std::endl;
         return;
     }
     
     if (session->state != SessionManager::SessionState::ESTABLISHED) {
         std::cout << COLOR_RED << "[SECURITY] FS_META_REQ from non-established session: " << sender_id_str << COLOR_RESET << std::endl;
         return;
     }
     
     // Decrypt payload
     auto plaintext = session_mgr_->decrypt_message(sender_id_str, payload, hdr.packet_nonce);
     if (plaintext.empty()) {
         std::cout << COLOR_RED << "[SECURITY] Failed to decrypt FS_META_REQ" << COLOR_RESET << std::endl;
         return;
     }
     
     // Parse path from plaintext: [path_len (2 bytes)][path]
     if (plaintext.size() < 2) {
         std::cout << COLOR_RED << "[SECURITY] FS_META_REQ payload too small" << COLOR_RESET << std::endl;
         return;
     }
     
     uint16_t path_len = (plaintext[0] << 8) | plaintext[1];
     if (plaintext.size() < 2 + path_len) {
         std::cout << COLOR_RED << "[SECURITY] FS_META_REQ path truncated" << COLOR_RESET << std::endl;
         return;
     }
     
      std::string path(plaintext.begin() + 2, plaintext.begin() + 2 + path_len);
      
      // Security check: validate path BEFORE any operations
      if (!SecurityUtils::is_safe_path(path)) {
          std::cout << COLOR_RED << "[SECURITY] Path Traversal attack blocked: " << path << COLOR_RESET << std::endl;
          SecurityUtils::log_security_attack(sender_id_str, "Path Traversal in FS_META_REQ");
          return;
      }
      
      // Normalize and canonicalize the path
      std::string normalized_path = SecurityUtils::normalize_path(path);
      
      // Build actual file path
      std::string full_path = "shellmap/shared/" + (normalized_path.empty() ? "" : normalized_path);
      
      // SECURITY: Verify the resolved path stays within the sandbox
      try {
          fs::path canonical = fs::canonical(full_path);
          fs::path sandbox_base = fs::canonical("shellmap/shared/");
          
          std::string canonical_str = canonical.string();
          std::string sandbox_str = sandbox_base.string();
          
          if (canonical_str.length() < sandbox_str.length() || 
              canonical_str.substr(0, sandbox_str.length()) != sandbox_str) {
              std::cout << COLOR_RED << "[SECURITY] Path escape attempt blocked: " << path << COLOR_RESET << std::endl;
              SecurityUtils::log_security_attack(sender_id_str, "Sandbox Escape in FS_META_REQ");
              return;
          }
      } catch (...) {
          // If path doesn't exist, just use normalized version
      }
    
    // Check if path exists and is a directory
    fs::path p(full_path);
    bool is_dir = fs::exists(p) && fs::is_directory(p);
    
    // Build response: [is_dir (1 byte)]
    std::vector<uint8_t> response;
    response.push_back(is_dir ? 1 : 0);
    
    // Create FS_META_RES packet
    PacketHeader res_hdr;
    res_hdr.magic[0] = 'S';
    res_hdr.magic[1] = 'M';
    res_hdr.op_code = static_cast<uint8_t>(OpCode::FS_META_RES);
    res_hdr.flags = 0;
     res_hdr.seq = hdr.seq;  // Echo request sequence
     res_hdr.packet_nonce = session->packet_nonce_counter++;  // Monotonic counter for nonce
    
    // Copy IDs
    std::memcpy(res_hdr.sender_id, hdr.target_id, 32);   // Our ID
    std::memcpy(res_hdr.target_id, hdr.sender_id, 32);   // Peer's ID
    
    // Encrypt response
    auto encrypted_response = session_mgr_->encrypt_message(sender_id_str, response, res_hdr.packet_nonce);
    res_hdr.payload_len = encrypted_response.size();  // Set AFTER encryption, not before!
    net_engine_.send_packet(res_hdr, encrypted_response, session->peer_ip, session->peer_port);
}

void ProtocolManager::handle_fs_meta_res(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender) {
     // Decode sender ID
     std::string sender_id_str = sender_id_to_string(hdr.sender_id);
     
     // Get session
     auto session = session_mgr_->get_session(sender_id_str);
     if (!session) {
         std::cout << COLOR_RED << "[FS] Response from unknown session: " << sender_id_str << COLOR_RESET << std::endl;
         return;
     }
     
     // Decrypt payload
     auto plaintext = session_mgr_->decrypt_message(sender_id_str, payload, hdr.packet_nonce);
     if (plaintext.empty() || plaintext.size() < 1) {
         std::cout << COLOR_RED << "[FS] Failed to decrypt FS_META_RES" << COLOR_RESET << std::endl;
         return;
     }
     
       // Parse status: 1 = directory exists (success), 0 = not found/error
       uint8_t status = plaintext[0];
       
        // Check if there's a pending CD request using the flag (handles empty string case for root)
        if (session->pending_cd_request) {
            if (status == 1) {
                // Directory exists! Update current remote directory
                session->current_remote_dir = session->pending_cd_path;
                std::cout << COLOR_GREEN << "✓ Changed to " << (session->current_remote_dir.empty() ? "/" : session->current_remote_dir) << COLOR_RESET << std::endl;
            } else {
                // Directory not found
                std::cout << COLOR_RED << "✗ Directory not found: " << (session->pending_cd_path.empty() ? "/" : session->pending_cd_path) << COLOR_RESET << std::endl;
            }
            // Clear pending CD request flag
            session->pending_cd_request = false;
            session->pending_cd_path = "";
        }
}

void ProtocolManager::handle_fs_data_req(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender) {
    // Decode sender ID
    std::string sender_id_str = sender_id_to_string(hdr.sender_id);
    
    // Get session to decrypt payload
    auto session = session_mgr_->get_session(sender_id_str);
    if (!session) {
         std::cout << COLOR_RED << "[SECURITY] FS_DATA_REQ from unknown session: " << sender_id_str << COLOR_RESET << std::endl;
         return;
     }
     
     if (session->state != SessionManager::SessionState::ESTABLISHED) {
         std::cout << COLOR_RED << "[SECURITY] FS_DATA_REQ from non-established session: " << sender_id_str << COLOR_RESET << std::endl;
         return;
     }
     
     // Decrypt payload
     auto plaintext = session_mgr_->decrypt_message(sender_id_str, payload, hdr.packet_nonce);
     if (plaintext.empty()) {
         std::cout << COLOR_RED << "[SECURITY] Failed to decrypt FS_DATA_REQ" << COLOR_RESET << std::endl;
         return;
     }
     
     // Parse filename from plaintext: [filename_len (2 bytes)][filename]
     if (plaintext.size() < 2) {
         std::cout << COLOR_RED << "[SECURITY] FS_DATA_REQ payload too small" << COLOR_RESET << std::endl;
         return;
     }
     
     uint16_t filename_len = (plaintext[0] << 8) | plaintext[1];
     if (plaintext.size() < 2 + filename_len) {
         std::cout << COLOR_RED << "[SECURITY] FS_DATA_REQ filename truncated" << COLOR_RESET << std::endl;
         return;
     }
     
      std::string filename(plaintext.begin() + 2, plaintext.begin() + 2 + filename_len);
      
      // Security check: validate path BEFORE any operations
      if (!SecurityUtils::is_safe_path(filename)) {
          std::cout << COLOR_RED << "[SECURITY] Path Traversal attack blocked: " << filename << COLOR_RESET << std::endl;
          SecurityUtils::log_security_attack(sender_id_str, "Path Traversal in FS_DATA_REQ");
          return;
      }
      
      // Normalize and canonicalize the path
      std::string normalized_filename = SecurityUtils::normalize_path(filename);
      
      // Build actual file path
      std::string full_path = "shellmap/shared/" + (normalized_filename.empty() ? "" : normalized_filename);
      
      // SECURITY: Verify the resolved path stays within the sandbox
      try {
          fs::path canonical = fs::canonical(full_path);
          fs::path sandbox_base = fs::canonical("shellmap/shared/");
          
          std::string canonical_str = canonical.string();
          std::string sandbox_str = sandbox_base.string();
          
          if (canonical_str.length() < sandbox_str.length() || 
              canonical_str.substr(0, sandbox_str.length()) != sandbox_str) {
              std::cout << COLOR_RED << "[SECURITY] Path escape attempt blocked: " << filename << COLOR_RESET << std::endl;
              SecurityUtils::log_security_attack(sender_id_str, "Sandbox Escape in FS_DATA_REQ");
              return;
          }
      } catch (...) {
          // If path doesn't exist, return error
          std::vector<uint8_t> response;
          response.push_back(0xFF);  // Error: file not found
          
          PacketHeader res_hdr;
          res_hdr.magic[0] = 'S';
          res_hdr.magic[1] = 'M';
          res_hdr.op_code = static_cast<uint8_t>(OpCode::FS_DATA_RES);
          res_hdr.flags = 0;
          res_hdr.seq = hdr.seq;
          res_hdr.packet_nonce = session->packet_nonce_counter++;
          
          std::memcpy(res_hdr.sender_id, hdr.target_id, 32);
          std::memcpy(res_hdr.target_id, hdr.sender_id, 32);
          
          auto encrypted_response = session_mgr_->encrypt_message(sender_id_str, response, res_hdr.packet_nonce);
          res_hdr.payload_len = encrypted_response.size();
          net_engine_.send_packet(res_hdr, encrypted_response, session->peer_ip, session->peer_port);
          return;
      }
    
    // Read file content with chunking support
    std::vector<uint8_t> response;
    try {
        std::ifstream file(full_path, std::ios::binary);
        if (!file.is_open()) {
            // File not found, return error (single byte 0xFF)
            response.push_back(0xFF);
        } else {
            // Get file size first
            file.seekg(0, std::ios::end);
            uint64_t file_size = file.tellg();
            file.seekg(0, std::ios::beg);
            
            // For simplicity, read entire file (assuming reasonable file sizes)
            // If file is larger than ~1200 bytes, the caller may need multiple requests
            // But we still handle it by fitting what we can in one packet
            const size_t MAX_FILE_CHUNK = 1200;  // Leave room for encryption overhead
            
            std::vector<uint8_t> file_data;
            if (file_size > MAX_FILE_CHUNK) {
                // Read only first chunk
                file_data.resize(MAX_FILE_CHUNK);
                file.read(reinterpret_cast<char*>(file_data.data()), MAX_FILE_CHUNK);
                file_data.resize(file.gcount());
            } else {
                // Read entire file
                file_data.assign((std::istreambuf_iterator<char>(file)), 
                                std::istreambuf_iterator<char>());
            }
            file.close();
            
            // Build response: [filename_len (2 bytes)][filename][chunk_offset (8 bytes)][file_data]
            // This way client knows what filename to save as!
            uint16_t fname_len = filename.length();
            response.push_back((fname_len >> 8) & 0xFF);
            response.push_back(fname_len & 0xFF);
            response.insert(response.end(), filename.begin(), filename.end());
            
            uint64_t chunk_offset = 0;  // First chunk starts at offset 0
            for (int i = 7; i >= 0; --i) {
                response.push_back((chunk_offset >> (i * 8)) & 0xFF);
            }
            response.insert(response.end(), file_data.begin(), file_data.end());
            
             if (file_data.size() < file_size) {
                 std::cout << COLOR_YELLOW << "[WARNING] FS_DATA_REQ: File " << filename 
                           << " is large (" << file_size << " bytes), sent " 
                           << file_data.size() << " bytes in first chunk" << COLOR_RESET << std::endl;
             }
         }
     } catch (const std::exception& e) {
         std::cout << COLOR_RED << "[SECURITY] Error reading file: " << e.what() << COLOR_RESET << std::endl;
        response.clear();
        response.push_back(0xFF);
    }
    
    // Create FS_DATA_RES packet
    PacketHeader res_hdr;
    res_hdr.magic[0] = 'S';
    res_hdr.magic[1] = 'M';
    res_hdr.op_code = static_cast<uint8_t>(OpCode::FS_DATA_RES);
    res_hdr.flags = 0;
     res_hdr.seq = hdr.seq;  // Echo request sequence
     res_hdr.packet_nonce = session->packet_nonce_counter++;  // Monotonic counter for nonce
    
    // Copy IDs
    std::memcpy(res_hdr.sender_id, hdr.target_id, 32);   // Our ID
    std::memcpy(res_hdr.target_id, hdr.sender_id, 32);   // Peer's ID
    
    // Encrypt response
    auto encrypted_response = session_mgr_->encrypt_message(sender_id_str, response, res_hdr.packet_nonce);
    res_hdr.payload_len = encrypted_response.size();  // Set AFTER encryption, not before!
    net_engine_.send_packet(res_hdr, encrypted_response, session->peer_ip, session->peer_port);
}

void ProtocolManager::handle_fs_data_res(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender) {
    // Decode sender ID
    std::string sender_id_str = sender_id_to_string(hdr.sender_id);
    
    // Get session to decrypt payload
    auto session = session_mgr_->get_session(sender_id_str);
    if (!session) {
        std::cout << COLOR_RED << "✗ [ERROR] FS_DATA_RES from unknown session: " << sender_id_str << COLOR_RESET << std::endl;
        return;
    }
    
    if (session->state != SessionManager::SessionState::ESTABLISHED) {
        std::cout << COLOR_RED << "✗ [ERROR] FS_DATA_RES from non-established session: " << sender_id_str << COLOR_RESET << std::endl;
        return;
    }
    
    // Decrypt payload - MUST NOT BE SILENT!
    auto plaintext = session_mgr_->decrypt_message(sender_id_str, payload, hdr.packet_nonce);
    if (plaintext.empty()) {
        std::cout << COLOR_RED << "✗ [ERROR] AES Decryption failed for FS_DATA_RES!" << COLOR_RESET << std::endl;
        return;
    }
    
    // Check if it's an error response (single 0xFF byte)
    if (plaintext.size() == 1 && plaintext[0] == 0xFF) {
        std::cout << COLOR_RED << "✗ [ERROR] File not found on remote server!" << COLOR_RESET << std::endl;
        return;
    }
    
    // Parse response: [filename_len (2 bytes)][filename][chunk_offset (8 bytes)][file_data]
    if (plaintext.size() < 2) {
        std::cout << COLOR_RED << "✗ [ERROR] FS_DATA_RES payload too small (need at least 2 bytes for filename_len)" << COLOR_RESET << std::endl;
        return;
    }
    
    // Extract filename length
    uint16_t filename_len = (plaintext[0] << 8) | plaintext[1];
    
    // Validate we have enough bytes for filename
    if (plaintext.size() < 2 + filename_len + 8) {
        std::cout << COLOR_RED << "✗ [ERROR] FS_DATA_RES payload truncated (need " 
                  << (2 + filename_len + 8) << " bytes, got " << plaintext.size() << ")" << COLOR_RESET << std::endl;
        return;
    }
    
    // Extract filename
    std::string filename(plaintext.begin() + 2, plaintext.begin() + 2 + filename_len);
    
    // Extract chunk offset (8 bytes, big-endian)
    uint64_t chunk_offset = 0;
    size_t offset_pos = 2 + filename_len;
    for (int i = 0; i < 8; ++i) {
        chunk_offset = (chunk_offset << 8) | plaintext[offset_pos + i];
    }
    
    // Extract chunk data
    std::vector<uint8_t> chunk_data(plaintext.begin() + offset_pos + 8, plaintext.end());
    
    if (chunk_data.empty()) {
        std::cout << COLOR_RED << "✗ [ERROR] FS_DATA_RES contains no file data" << COLOR_RESET << std::endl;
        return;
    }
    
    // Security check: validate filename (no path traversal)
    if (!SecurityUtils::is_safe_path(filename)) {
        std::cout << COLOR_RED << "✗ [ERROR] Invalid filename with path traversal attempt: " << filename << COLOR_RESET << std::endl;
        return;
    }
    
    // Extract only the basename from filename (remove any path components)
    // This ensures downloads always go to shellmap/downloads/ root, not subdirectories
    size_t last_slash = filename.find_last_of("/\\");
    std::string basename = (last_slash != std::string::npos) ? filename.substr(last_slash + 1) : filename;
    
    // Write chunk to file in shellmap/downloads/ root with just the basename
    std::string download_dir = "shellmap/downloads";
    try {
        // Create download directory if needed
        fs::create_directories(download_dir);
        
        // Use basename only (no subdirectories)
        std::string full_path = download_dir + "/" + basename;
        
        // Write chunk (append mode to handle multiple chunks)
        std::ofstream file(full_path, std::ios::binary | std::ios::app);
        if (!file.is_open()) {
            std::cout << COLOR_RED << "✗ [ERROR] Failed to open file for writing: " << full_path << COLOR_RESET << std::endl;
            return;
        }
        
        file.write(reinterpret_cast<const char*>(chunk_data.data()), chunk_data.size());
        file.close();
        
        std::cout << COLOR_GREEN << "[SUCCESS] Received chunk at offset " << chunk_offset 
                  << " (" << chunk_data.size() << " bytes). Saved to: " << full_path << COLOR_RESET << std::endl;
    } catch (const std::exception& e) {
        std::cout << COLOR_RED << "✗ [ERROR] Exception while saving file chunk: " << e.what() << COLOR_RESET << std::endl;
        return;
    }
}

void ProtocolManager::handle_fs_put_meta_req(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender) {
    // Decode sender ID
    std::string sender_id_str = sender_id_to_string(hdr.sender_id);
    
    // Get session to decrypt payload
    auto session = session_mgr_->get_session(sender_id_str);
    if (!session) {
         std::cout << COLOR_RED << "[SECURITY] FS_PUT_META_REQ from unknown session: " << sender_id_str << COLOR_RESET << std::endl;
         return;
     }
     
     if (session->state != SessionManager::SessionState::ESTABLISHED) {
         std::cout << COLOR_RED << "[SECURITY] FS_PUT_META_REQ from non-established session: " << sender_id_str << COLOR_RESET << std::endl;
         return;
     }
     
     // Decrypt payload
     auto plaintext = session_mgr_->decrypt_message(sender_id_str, payload, hdr.packet_nonce);
     if (plaintext.empty()) {
         std::cout << COLOR_RED << "[SECURITY] Failed to decrypt FS_PUT_META_REQ" << COLOR_RESET << std::endl;
         return;
     }
     
     // Parse metadata: [filename_len (2 bytes)][filename][file_size (8 bytes)]
     if (plaintext.size() < 2 + 8) {
         std::cout << COLOR_RED << "[SECURITY] FS_PUT_META_REQ payload too small" << COLOR_RESET << std::endl;
         return;
     }
     
     uint16_t filename_len = (plaintext[0] << 8) | plaintext[1];
     if (plaintext.size() < 2 + filename_len + 8) {
         std::cout << COLOR_RED << "[SECURITY] FS_PUT_META_REQ truncated" << COLOR_RESET << std::endl;
         return;
     }
     
     std::string filename(plaintext.begin() + 2, plaintext.begin() + 2 + filename_len);
     
     // Security check: validate path
     if (!SecurityUtils::is_safe_path(filename)) {
         std::cout << COLOR_RED << "[SECURITY] Path Traversal attack blocked: " << filename << COLOR_RESET << std::endl;
         return;
     }
    
    // Parse file size (big-endian)
    uint64_t file_size = 0;
    for (int i = 0; i < 8; ++i) {
        file_size = (file_size << 8) | plaintext[2 + filename_len + i];
    }
    
    // Build response: [status (1 byte)] - 0 = OK, 1 = ERROR
    std::vector<uint8_t> response;
    response.push_back(0);  // Accept the upload
    
    // Create FS_PUT_META_RES packet
    PacketHeader res_hdr;
    res_hdr.magic[0] = 'S';
    res_hdr.magic[1] = 'M';
    res_hdr.op_code = static_cast<uint8_t>(OpCode::FS_PUT_META_RES);
    res_hdr.flags = 0;
     res_hdr.seq = hdr.seq;  // Echo request sequence
     res_hdr.packet_nonce = session->packet_nonce_counter++;  // Monotonic counter for nonce
    
    // Copy IDs
    std::memcpy(res_hdr.sender_id, hdr.target_id, 32);   // Our ID
    std::memcpy(res_hdr.target_id, hdr.sender_id, 32);   // Peer's ID
    
    // Encrypt response
    auto encrypted_response = session_mgr_->encrypt_message(sender_id_str, response, res_hdr.packet_nonce);
    res_hdr.payload_len = encrypted_response.size();  // Set AFTER encryption, not before!
    net_engine_.send_packet(res_hdr, encrypted_response, session->peer_ip, session->peer_port);
}

void ProtocolManager::handle_fs_put_meta_res(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender) {
    // Decode sender ID
    std::string sender_id_str = sender_id_to_string(hdr.sender_id);
    
    // Get session
    auto session = session_mgr_->get_session(sender_id_str);
    if (!session) {
        std::cout << COLOR_RED << "[FS] PUT_META_RES from unknown session: " << sender_id_str << COLOR_RESET << std::endl;
        return;
    }
    
    // Decrypt payload
    auto plaintext = session_mgr_->decrypt_message(sender_id_str, payload, hdr.packet_nonce);
    if (plaintext.empty() || plaintext.size() < 1) {
        std::cout << COLOR_RED << "[FS] Failed to decrypt FS_PUT_META_RES" << COLOR_RESET << std::endl;
        return;
    }
    
     // Parse status: 0 = ready to receive data (server accepted), 1 = error/rejected
     uint8_t status = plaintext[0];
     
     if (status == 0) {
         std::cout << COLOR_GREEN << "✓ Server accepted upload request" << COLOR_RESET << std::endl;
     } else {
         std::cout << COLOR_RED << "✗ Server rejected file upload request" << COLOR_RESET << std::endl;
     }
}

void ProtocolManager::handle_fs_put_data(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender) {
    // Decode sender ID
    std::string sender_id_str = sender_id_to_string(hdr.sender_id);
    
    // Get session to decrypt payload
    auto session = session_mgr_->get_session(sender_id_str);
    if (!session) {
         std::cout << COLOR_RED << "[SECURITY] FS_PUT_DATA from unknown session: " << sender_id_str << COLOR_RESET << std::endl;
         return;
     }
     
     if (session->state != SessionManager::SessionState::ESTABLISHED) {
         std::cout << COLOR_RED << "[SECURITY] FS_PUT_DATA from non-established session: " << sender_id_str << COLOR_RESET << std::endl;
         return;
     }
     
     // Decrypt payload
     auto plaintext = session_mgr_->decrypt_message(sender_id_str, payload, hdr.packet_nonce);
     if (plaintext.empty()) {
         std::cout << COLOR_RED << "[SECURITY] Failed to decrypt FS_PUT_DATA" << COLOR_RESET << std::endl;
         return;
     }
     
     // Parse chunk data: [filename_len (2 bytes)][filename][chunk_offset (8 bytes)][chunk_data]
     if (plaintext.size() < 2 + 8) {
         std::cout << COLOR_RED << "[SECURITY] FS_PUT_DATA payload too small" << COLOR_RESET << std::endl;
         return;
     }
     
     uint16_t filename_len = (plaintext[0] << 8) | plaintext[1];
     if (plaintext.size() < 2 + filename_len + 8) {
         std::cout << COLOR_RED << "[SECURITY] FS_PUT_DATA truncated" << COLOR_RESET << std::endl;
         return;
     }
     
     std::string filename(plaintext.begin() + 2, plaintext.begin() + 2 + filename_len);
     
     // Security check: validate path
     if (!SecurityUtils::is_safe_path(filename)) {
         std::cout << COLOR_RED << "[SECURITY] Path Traversal attack blocked: " << filename << COLOR_RESET << std::endl;
         return;
     }
    
    // Parse chunk offset (big-endian)
    uint64_t chunk_offset = 0;
    for (int i = 0; i < 8; ++i) {
        chunk_offset = (chunk_offset << 8) | plaintext[2 + filename_len + i];
    }
    
    // Extract chunk data
    std::vector<uint8_t> chunk_data(plaintext.begin() + 2 + filename_len + 8, plaintext.end());
    
    // Write chunk to file
    std::string full_path = "shellmap/shared/" + (filename.empty() ? "" : filename);
    
    try {
        // Ensure parent directories exist
        fs::create_directories(fs::path(full_path).parent_path());
        
         // Open file in append mode and write chunk
         std::ofstream file(full_path, std::ios::binary | std::ios::app);
         if (!file.is_open()) {
             std::cout << COLOR_RED << "[SECURITY] Failed to open file for writing: " << full_path << COLOR_RESET << std::endl;
             return;
         }
         
         file.write(reinterpret_cast<const char*>(chunk_data.data()), chunk_data.size());
         file.close();
     } catch (const std::exception& e) {
         std::cout << COLOR_RED << "[SECURITY] Error writing file chunk: " << e.what() << COLOR_RESET << std::endl;
         return;
     }
}

void ProtocolManager::handle_p2p_find_node_req(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender) {
//     std::cout << "[PROTOCOL] P2P_FIND_NODE_REQ" << std::endl;
}

void ProtocolManager::handle_p2p_find_node_res(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender) {
//     std::cout << "[PROTOCOL] P2P_FIND_NODE_RES" << std::endl;
}

void ProtocolManager::handle_p2p_assist_req(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender) {
//     std::cout << "[PROTOCOL] P2P_ASSIST_REQ" << std::endl;
}

void ProtocolManager::handle_p2p_hole_punch(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender) {
//     std::cout << "[PROTOCOL] P2P_HOLE_PUNCH" << std::endl;
}

void ProtocolManager::handle_relay_req(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender) {
//     std::cout << "[PROTOCOL] RELAY_REQ" << std::endl;
}

void ProtocolManager::handle_relay_fwd(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender) {
//     std::cout << "[PROTOCOL] RELAY_FWD" << std::endl;
}

void ProtocolManager::handle_verify_req(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender) {
//     std::cout << "[PROTOCOL] VERIFY_REQ" << std::endl;
}

void ProtocolManager::handle_probe(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender) {
//     std::cout << "[PROTOCOL] PROBE" << std::endl;
}

void ProtocolManager::handle_probe_ack(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender) {
//     std::cout << "[PROTOCOL] PROBE_ACK" << std::endl;
}

void ProtocolManager::handle_mml_index_req(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender) {
//     std::cout << "[PROTOCOL] MML_INDEX_REQ" << std::endl;
}

void ProtocolManager::handle_mml_index_res(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender) {
//     std::cout << "[PROTOCOL] MML_INDEX_RES" << std::endl;
}

void ProtocolManager::handle_cmd_shell_req(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender) {
//     std::cout << "[PROTOCOL] CMD_SHELL_REQ" << std::endl;
}

void ProtocolManager::handle_cmd_shell_res(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender) {
//     std::cout << "[PROTOCOL] CMD_SHELL_RES" << std::endl;
}

void ProtocolManager::handle_error(PacketHeader& hdr, std::vector<uint8_t>& payload, const sockaddr_in& sender) {
    std::cout << "[PROTOCOL] ERROR from " << sender_id_to_string(hdr.sender_id) << std::endl;
}

void ProtocolManager::send_packet(
     const uint8_t* target_id,
     uint8_t opcode,
     uint8_t flags,
     const std::vector<uint8_t>& payload,
     const std::string& target_ip,
     int target_port
 ) {
     // Create packet header
     PacketHeader hdr;
     hdr.magic[0] = 'S';
     hdr.magic[1] = 'M';
     hdr.op_code = opcode;
     hdr.flags = flags;
     hdr.seq = 0;  // TODO: Use proper sequence number
     hdr.payload_len = payload.size();
     hdr.packet_nonce = 0;  // TODO: Generate proper nonce
     
     memset(hdr.sender_id, 0, 32);  // TODO: Use our node ID
     memcpy(hdr.target_id, target_id, 32);
     
     // Serialize header + payload
     std::vector<uint8_t> packet;
      packet.insert(packet.end(), (uint8_t*)&hdr, (uint8_t*)&hdr + sizeof(PacketHeader));
      packet.insert(packet.end(), payload.begin(), payload.end());
      
      // Send via NetworkEngine
      // TODO: Implement actual UDP send through net_engine_
      // std::cout << "[PROTOCOL] Sending packet opcode=0x" << std::hex << (int)opcode 
      //        << std::dec << " to " << target_ip << ":" << target_port << std::endl;
 }

// ============= CLI COMMAND INTEGRATION =============

bool ProtocolManager::initiate_handshake(const std::string& target_ip, int target_port) {
//     std::cout << "[PROTOCOL] Initiating handshake with " << target_ip << ":" << target_port << std::endl;
    
    if (!my_node_) {
        std::cout << "[PROTOCOL] Node context not initialized" << std::endl;
        return false;
    }
    
     // Generate X25519 key pair
    std::string x25519_pub, x25519_priv;
    if (!CryptoCore::generate_x25519_keypair(x25519_pub, x25519_priv)) {
        std::cout << "[PROTOCOL] Failed to generate X25519 keypair" << std::endl;
        return false;
    }
    // std::cout << "[DEBUG-INITIATE] Generated X25519 Pub: " << bytes_to_hex_short(x25519_pub) << "..." << std::endl;
    
    // Create a placeholder target node ID (in real code, resolve from IP or use provided ID)
    uint8_t target_id[32];
    memset(target_id, 0, 32);
    
    // Build HELLO payload: [OUR Kyber Pub (800B)] [OUR X25519_Pub (32B)]
    // DO NOT include listen port - let responder use kernel source address!
    std::vector<uint8_t> hello_payload;
    hello_payload.insert(hello_payload.end(), (uint8_t*)my_node_->kyber_pub.data(), (uint8_t*)my_node_->kyber_pub.data() + my_node_->kyber_pub.size());
    hello_payload.insert(hello_payload.end(), (uint8_t*)x25519_pub.data(), (uint8_t*)x25519_pub.data() + 32);
    
//     std::cout << "[PROTOCOL] HELLO payload: Kyber(800B) + X25519(32B) = 832B" << std::endl;
    
     // Create HELLO packet with OUR real node ID
     PacketHeader hdr_hello;
     hdr_hello.magic[0] = 'S';
     hdr_hello.magic[1] = 'M';
     hdr_hello.op_code = OpCode::HELLO;
     hdr_hello.flags = 0;
     hdr_hello.seq = 0;
     hdr_hello.payload_len = hello_payload.size();
     // Will set nonce after session creation
     hex_string_to_node_id(my_node_->node_id, hdr_hello.sender_id);  // OUR real node ID
     memcpy(hdr_hello.target_id, target_id, 32);  // Placeholder for target
     
     // Create session FIRST so we can use its packet_nonce_counter
     std::string target_id_str = sender_id_to_string(target_id);
     auto session = session_mgr_->get_or_create_session(target_id_str);
     if (session) {
         session->state = SessionManager::SessionState::INITIATED;
         session->peer_ip = target_ip;
         session->peer_port = target_port;
         // CRITICAL: Store both X25519 priv and pub (never regenerate!)
         // Store as initiator keys (we are the initiator in this handshake)
         session->temp_ecdh_priv = x25519_priv;
         session->temp_ecdh_pub = x25519_pub;
         session->temp_ecdh_priv_initiator = x25519_priv;  // Save for future use when we act as responder too
         session->temp_ecdh_pub_initiator = x25519_pub;
         
         // NOW set nonce using session counter
         hdr_hello.packet_nonce = session->packet_nonce_counter++;
     } else {
         hdr_hello.packet_nonce = 1;  // Fallback if session creation fails
     }
     
     // Send HELLO
     if (!net_engine_.send_packet(hdr_hello, hello_payload, target_ip, target_port)) {
         std::cout << "[PROTOCOL] Failed to send HELLO packet" << std::endl;
         return false;
     }
    
    return true;
}

bool ProtocolManager::send_ping(const std::string& target_ip, int target_port) {
//     std::cout << "[PROTOCOL] Sending PING to " << target_ip << ":" << target_port << std::endl;
    
    // Get session for this target (must have active session)
    // For now, use a placeholder target ID
    uint8_t target_id[32];
    memset(target_id, 0, 32);
    std::string target_id_str = sender_id_to_string(target_id);
    
    auto session = session_mgr_->get_session(target_id_str);
    if (!session || session->state != SessionManager::SessionState::ESTABLISHED) {
        std::cout << "[PROTOCOL] No established session with " << target_id_str << std::endl;
        return false;
    }
    
    // Create PING payload with current timestamp
    uint64_t ping_ts = std::chrono::system_clock::now().time_since_epoch().count();
    std::vector<uint8_t> ping_payload((uint8_t*)&ping_ts, (uint8_t*)&ping_ts + 8);
    
    // Store the timestamp for latency calculation when response arrives
    session->ping_sent_ts = ping_ts;
    
    // Create PING packet
    PacketHeader hdr_ping;
    hdr_ping.magic[0] = 'S';
    hdr_ping.magic[1] = 'M';
    hdr_ping.op_code = OpCode::PING;
    hdr_ping.flags = 0;
    hdr_ping.seq = session->crypto_nonce_counter++;
    hdr_ping.payload_len = ping_payload.size();
    hdr_ping.packet_nonce = session->packet_nonce_counter++;  // Monotonic counter
    memset(hdr_ping.sender_id, 0, 32);  // Will be filled by NetworkEngine
    memcpy(hdr_ping.target_id, target_id, 32);
    
    // Send PING
    if (!net_engine_.send_packet(hdr_ping, ping_payload, target_ip, target_port)) {
        std::cout << "[PROTOCOL] Failed to send PING packet" << std::endl;
         return false;
     }
     
//      std::cout << "[PROTOCOL] PING sent to " << target_ip << ":" << target_port << " (ts=" << ping_ts << ")" << std::endl;
     return true;
}

bool ProtocolManager::send_message(const std::string& node_id, const std::string& message) {
//     std::cout << "[PROTOCOL] Sending message to " << node_id << ": " << message << std::endl;
    
    auto session = session_mgr_->get_session(node_id);
    if (!session || session->state != SessionManager::SessionState::ESTABLISHED) {
        std::cout << "[PROTOCOL] No established session with " << node_id << std::endl;
        return false;
    }
    
    // Assign message ID
    uint32_t msg_id = session->next_msg_id++;
    
    // Pre-allocate packet nonce for encryption
    uint64_t packet_nonce = session->packet_nonce_counter++;
    
    // Convert message to plaintext bytes
    std::vector<uint8_t> plaintext(message.begin(), message.end());
    
    // Encrypt the message with packet_nonce
    std::vector<uint8_t> ciphertext_with_tag = session_mgr_->encrypt_message(node_id, plaintext, packet_nonce);
    if (ciphertext_with_tag.empty()) {
        std::cout << "[PROTOCOL] Failed to encrypt message" << std::endl;
        return false;
    }
    
    // Check if message needs fragmentation (max fragment size: 1400 bytes)
    const size_t MAX_FRAGMENT_SIZE = 1400;
    uint16_t total_fragments = (ciphertext_with_tag.size() + MAX_FRAGMENT_SIZE - 1) / MAX_FRAGMENT_SIZE;
    
    // Build and send DATA packet(s)
    for (uint16_t frag_seq = 0; frag_seq < total_fragments; frag_seq++) {
        size_t frag_start = frag_seq * MAX_FRAGMENT_SIZE;
        size_t frag_end = std::min(frag_start + MAX_FRAGMENT_SIZE, ciphertext_with_tag.size());
        std::vector<uint8_t> fragment(ciphertext_with_tag.begin() + frag_start, ciphertext_with_tag.begin() + frag_end);
        
        // Build DATA packet payload
        std::vector<uint8_t> data_payload;
        uint8_t flags = PacketFlag::ACK_REQUIRED;  // Request ACK
        data_payload.push_back(flags);
        data_payload.insert(data_payload.end(), (uint8_t*)&msg_id, (uint8_t*)&msg_id + 4);
        data_payload.insert(data_payload.end(), (uint8_t*)&frag_seq, (uint8_t*)&frag_seq + 4);
        data_payload.insert(data_payload.end(), (uint8_t*)&total_fragments, (uint8_t*)&total_fragments + 2);
        data_payload.insert(data_payload.end(), fragment.begin(), fragment.end());
        
        // Create DATA packet
        PacketHeader hdr_data;
        hdr_data.magic[0] = 'S'; hdr_data.magic[1] = 'M';
        hdr_data.op_code = OpCode::DATA;
        hdr_data.flags = PacketFlag::ENCRYPTED;  // Mark as encrypted
        hdr_data.seq = session->crypto_nonce_counter++;
        hdr_data.payload_len = data_payload.size();
        hdr_data.packet_nonce = packet_nonce;  // Use the pre-allocated nonce
        hex_string_to_node_id(my_node_->node_id, hdr_data.sender_id);
        hex_string_to_node_id(node_id, hdr_data.target_id);
        
        // Send DATA packet
        if (!net_engine_.send_packet(hdr_data, data_payload, session->peer_ip, session->peer_port)) {
            std::cout << "[PROTOCOL] Failed to send DATA packet" << std::endl;
            return false;
        }
    }
    
    // Store in pending (awaiting ACK)
    SessionManager::Session::PendingMessage pending;
    pending.msg_id = msg_id;
    pending.payload = plaintext;
    pending.sent_time = std::chrono::system_clock::now().time_since_epoch().count();
    session->pending_messages[msg_id] = pending;
    
//     std::cout << "[PROTOCOL] Message " << msg_id << " sent (" << total_fragments << " fragment(s))" << std::endl;
    return true;
}

void ProtocolManager::send_ack(const std::string& node_id, uint32_t msg_id) {
    auto session = session_mgr_->get_session(node_id);
    if (!session) {
        std::cout << "[PROTOCOL] Cannot send ACK: no session for " << node_id << std::endl;
        return;
    }
    
    // Build ACK packet
    std::vector<uint8_t> ack_payload;
    ack_payload.insert(ack_payload.end(), (uint8_t*)&msg_id, (uint8_t*)&msg_id + 4);
    
    PacketHeader hdr_ack;
    hdr_ack.magic[0] = 'S'; hdr_ack.magic[1] = 'M';
    hdr_ack.op_code = OpCode::ACK;
    hdr_ack.flags = 0;
    hdr_ack.seq = session->crypto_nonce_counter++;
    hdr_ack.payload_len = ack_payload.size();
    hdr_ack.packet_nonce = session->packet_nonce_counter++;  // Monotonic counter
    hex_string_to_node_id(my_node_->node_id, hdr_ack.sender_id);
    hex_string_to_node_id(node_id, hdr_ack.target_id);
    
    if (!net_engine_.send_packet(hdr_ack, ack_payload, session->peer_ip, session->peer_port)) {
        std::cout << "[PROTOCOL] Failed to send ACK" << std::endl;
        return;
    }
     
//      std::cout << "[PROTOCOL] ACK sent for message " << msg_id << " to " << node_id.substr(0, 8) << std::endl;
}

// ===== NAT KEEP-ALIVE & DYNAMIC UPDATE FUNCTIONS =====

bool ProtocolManager::update_peer_address(const std::string& node_id, const std::string& new_ip, uint16_t new_port) {
    auto session = session_mgr_->get_session(node_id);
    if (!session) {
        return false;  // No session to update
    }
    
    bool changed = false;
    
     // Check if IP changed
    if (session->peer_ip != new_ip) {
        // Suppress verbose NAT update logs to reduce console spam
        // std::cout << "[NAT-UPDATE] Peer IP changed: " << session->peer_ip << " -> " << new_ip << std::endl;
        session->peer_ip = new_ip;
        changed = true;
    }
    
    // CRITICAL: Check if port changed (Symmetric NAT behavior)
    if (session->peer_port != new_port) {
        // Suppress verbose NAT update logs to reduce console spam
        // std::cout << "[NAT-UPDATE] Peer port changed: " << session->peer_port << " -> " << new_port;
        // std::cout << " (Symmetric NAT detected!)" << std::endl;
        session->peer_port = new_port;
        session->dynamic_peer_port = new_port;  // Track dynamic port
        changed = true;
    }
    
    return changed;
}

int ProtocolManager::send_heartbeat_pings() {
    int pings_sent = 0;
    uint64_t now = std::chrono::system_clock::now().time_since_epoch().count();
    const uint64_t HEARTBEAT_INTERVAL = 15000000000ULL;  // 15 seconds in nanoseconds
    const uint64_t PING_TIMEOUT = 45000000000ULL;  // 45 seconds (3 PINGs x 15s) for session timeout
    
    auto all_sessions = session_mgr_->get_all_sessions();
    
    for (auto& [node_id, session] : all_sessions) {
        // Only send heartbeat for ESTABLISHED or INITIATED sessions
        if (session->state != SessionManager::SessionState::ESTABLISHED &&
            session->state != SessionManager::SessionState::INITIATED &&
            session->state != SessionManager::SessionState::HELLO_SENT &&
            session->state != SessionManager::SessionState::WELCOME_SENT) {
            continue;
        }
        
        // Check if last activity was more than HEARTBEAT_INTERVAL ago
        uint64_t time_since_activity = now - session->last_activity;
        
        if (time_since_activity > HEARTBEAT_INTERVAL) {
            // Need to send PING
            
            // Check if we already sent PING but haven't received ACK
            if (session->ping_sent_ts > 0) {
                uint64_t time_since_ping = now - session->ping_sent_ts;
                
                // If PING has been pending for too long (45s = 3 retries), timeout the session
                if (time_since_ping > PING_TIMEOUT) {
//                     std::cout << "[HEARTBEAT] WARNING: No PING_ACK for " << node_id.substr(0, 8);
                    std::cout << " (" << (time_since_ping / 1000000000ULL) << "s). Ping count: ";
                    std::cout << (int)session->ping_sent_count << "/3" << std::endl;
                    
                    session->ping_sent_count++;
                    
                    if (session->ping_sent_count >= 3) {
//                         std::cout << "[HEARTBEAT] TIMEOUT: " << node_id.substr(0, 8);
                        std::cout << " - No response after 3 PINGs (45s)" << std::endl;
                        session_mgr_->destroy_session(node_id);
                        continue;
                    }
                }
            }
            
            // Send PING packet
            std::vector<uint8_t> ping_payload;
            uint64_t ping_ts = now;
            ping_payload.insert(ping_payload.end(), (uint8_t*)&ping_ts, (uint8_t*)&ping_ts + 8);
            
            PacketHeader hdr_ping;
            hdr_ping.magic[0] = 'S'; hdr_ping.magic[1] = 'M';
            hdr_ping.op_code = OpCode::PING;
            hdr_ping.flags = 0;
            hdr_ping.seq = session->crypto_nonce_counter++;
            hdr_ping.payload_len = ping_payload.size();
            hdr_ping.packet_nonce = session->packet_nonce_counter++;  // Monotonic counter
            hex_string_to_node_id(my_node_->node_id, hdr_ping.sender_id);
            hex_string_to_node_id(node_id, hdr_ping.target_id);
            
            // Encrypt PING if session is ESTABLISHED, otherwise send plaintext
            if (session->state == SessionManager::SessionState::ESTABLISHED) {
                // TODO: Encrypt PING with session AES key
                // For now, send plaintext
            }
            
             if (net_engine_.send_packet(hdr_ping, ping_payload, session->peer_ip, session->peer_port)) {
                  session->ping_sent_ts = ping_ts;
                  session->ping_sent_count = 0;  // Reset count on successful send
                  pings_sent++;
                  
                  // Orphaned log suppressed - causes prompt rendering issues
                  // std::cout << "[HEARTBEAT] PING sent to " << node_id.substr(0, 8) << " (" 
                  //          << session->peer_ip << ":" << session->peer_port << ")" << std::endl;
              } else {
                  // Suppress failed PING logs - too noisy during network issues
                  // std::cout << "[HEARTBEAT] Failed to send PING to " << node_id.substr(0, 8) << std::endl;
              }
        }
    }
    
    return pings_sent;
}

int ProtocolManager::detect_relay_fallback_timeout() {
    int relayed = 0;
    uint64_t now = std::chrono::system_clock::now().time_since_epoch().count();
    const uint64_t DIRECT_TIMEOUT = 5000000000ULL;  // 5 seconds for direct connection attempt
    
    auto all_sessions = session_mgr_->get_all_sessions();
    
    for (auto& [node_id, session] : all_sessions) {
        // Only check INITIATED sessions (waiting for WELCOME)
        if (session->state != SessionManager::SessionState::INITIATED &&
            session->state != SessionManager::SessionState::HELLO_SENT) {
            continue;
        }
        
        // Check if HELLO was sent but WELCOME not received yet
        uint64_t time_since_created = now - session->created_time;
        
        if (time_since_created > DIRECT_TIMEOUT && !session->is_relayed) {
            // Direct connection attempt timeout
            std::cout << "[RELAY-FALLBACK] WARNING: Direct connection to " << node_id.substr(0, 8);
            std::cout << " timeout (Symmetric NAT detected). Switching to Relay Mode..." << std::endl;
            
            // Mark session for relay
            session->is_relayed = true;
            relayed++;
            
            // TODO: Initiate relay request to known SuperNode
            // For now, just log it
        }
    }
    
    return relayed;
}

void ProtocolManager::send_ping_ack(const std::string& node_id) {
    auto session = session_mgr_->get_session(node_id);
    if (!session) {
        std::cout << "[PROTOCOL] Cannot send PING_ACK: no session for " << node_id << std::endl;
        return;
    }
    
    // Build PING_ACK packet with current timestamp
    std::vector<uint8_t> ping_ack_payload;
    uint64_t now = std::chrono::system_clock::now().time_since_epoch().count();
    ping_ack_payload.insert(ping_ack_payload.end(), (uint8_t*)&now, (uint8_t*)&now + 8);
    
    PacketHeader hdr_ping_ack;
    hdr_ping_ack.magic[0] = 'S'; hdr_ping_ack.magic[1] = 'M';
    hdr_ping_ack.op_code = OpCode::PING;  // Same as PING (responder sends back)
    hdr_ping_ack.flags = 0;
    hdr_ping_ack.seq = session->crypto_nonce_counter++;
    hdr_ping_ack.payload_len = ping_ack_payload.size();
    hdr_ping_ack.packet_nonce = session->packet_nonce_counter++;  // Monotonic counter
    hex_string_to_node_id(my_node_->node_id, hdr_ping_ack.sender_id);
    hex_string_to_node_id(node_id, hdr_ping_ack.target_id);
    
    if (!net_engine_.send_packet(hdr_ping_ack, ping_ack_payload, session->peer_ip, session->peer_port)) {
        std::cout << "[PROTOCOL] Failed to send PING_ACK" << std::endl;
        return;
    }
    
//     std::cout << "[PROTOCOL] PING_ACK sent to " << node_id.substr(0, 8) << std::endl;
}
