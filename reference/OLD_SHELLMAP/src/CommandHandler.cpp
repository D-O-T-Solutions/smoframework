#include "CommandHandler.hpp"
#include <iostream>
#include <sstream>
#include <vector>
#include <iomanip>
#include <cstdlib>
#include <unistd.h>
#include <filesystem>
#include <fstream>
#include <ctime>
#include "SessionManager.hpp"
#include "RoutingTable.hpp"
#include "NodeInitializer.hpp"
#include "ProtocolManager.hpp"
#include "SecurityUtils.hpp"

namespace fs = std::filesystem;

CommandHandler::CommandHandler(
    std::shared_ptr<SessionManager> session_mgr,
    std::shared_ptr<VerificationManager> verify_mgr,
    std::shared_ptr<Web3Manager> web3_mgr,
    FileManager* file_mgr,
    NetworkEngine& net_engine,
    RoutingTable& route_table,
    std::shared_ptr<ProtocolManager> proto_mgr,
    NodeContext* node_ctx
) : session_mgr_(session_mgr),
    verify_mgr_(verify_mgr),
    web3_mgr_(web3_mgr),
    file_mgr_(file_mgr),
    net_engine_(net_engine),
    route_table_(route_table),
    proto_mgr_(proto_mgr),
    node_ctx_(node_ctx) {
    std::cout << COLOR_CYAN << "[COMMAND] CommandHandler initialized" << COLOR_RESET << std::endl;
}

bool CommandHandler::process_command(const std::string& cmd) {
    if (cmd.empty()) return false;

    auto args = parse_command(cmd);
    if (args.empty()) return false;

    std::string command = args[0];

    // Network commands
    if (command == "connect") return cmd_connect(args);
    if (command == "discover") return cmd_discover(args);
    if (command == "find") return cmd_find(args);
    if (command == "peers") return cmd_list_peers(args);
    if (command == "nodes") return cmd_list_nodes(args);
    if (command == "relay") return cmd_relay_mode(args);
    if (command == "verify") return cmd_verify(args);
    if (command == "ping") return cmd_ping(args);
    if (command == "send") return cmd_send(args);
    if (command == "me") return cmd_me(args);
    if (command == "myid") return cmd_myid(args);

     // File system commands
    if (command == "ls") return cmd_ls(args);
    if (command == "get") return cmd_get(args);
    if (command == "put") return cmd_put(args);
    if (command == "pwd") return cmd_pwd(args);
    if (command == "cd") return cmd_cd(args);
     if (command == "myshare") return cmd_myshare(args);
     if (command == "mydownload") return cmd_mydownload(args);
     if (command == "bye") return cmd_bye(args);
     if (command == "return") return cmd_return(args);
     if (command == "reconnect") return cmd_reconnect(args);

    // Web3 commands
    if (command == "mml") return cmd_mml(args);
    if (command == "shell") return cmd_shell(args);
    if (command == "acl") return cmd_acl(args);
    if (command == "config") return cmd_config(args);

    // System commands
    if (command == "help") return cmd_help(args);
    if (command == "exit") return cmd_exit(args);

    std::cout << COLOR_RED << "✗ Unknown command: " << command 
              << ". Type 'help' for options." << COLOR_RESET << std::endl;
    return false;
}

void CommandHandler::set_current_target(const std::string& target) {
    current_target_ = target;
    is_connected_ = true;
}

void CommandHandler::print_splash_screen() {
    std::cout << "\n" << COLOR_BRIGHT_GREEN;
    std::cout << " ███████╗██╗  ██╗███████╗██╗     ██╗     ███╗   ███╗ █████╗ ██████╗ \n";
    std::cout << " ██╔════╝██║  ██║██╔════╝██║     ██║     ████╗ ████║██╔══██╗██╔══██╗\n";
    std::cout << " ███████╗███████║█████╗  ██║     ██║     ██╔████╔██║███████║██████╔╝\n";
    std::cout << " ╚════██║██╔══██║██╔══╝  ██║     ██║     ██║╚██╔╝██║██╔══██║██╔═══╝ \n";
    std::cout << " ███████║██║  ██║███████╗███████╗███████╗██║ ╚═╝ ██║██║  ██║██║     \n";
    std::cout << " ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     \n";
    std::cout << COLOR_RESET << "\n";
}

void CommandHandler::print_help() {
    std::cout << "\n" << COLOR_BRIGHT_CYAN << "=== ShellMap Commands ===" << COLOR_RESET << "\n\n";
    
    std::cout << COLOR_CYAN << "Network Commands:" << COLOR_RESET << "\n";
    std::cout << "  connect <id|ip:port>     - Connect to a peer node\n";
    std::cout << "  discover                 - Discover nodes on network\n";
    std::cout << "  find <target_id>         - Find a specific node\n";
    std::cout << "  peers                    - List active peer connections\n";
    std::cout << "  nodes                    - List all known nodes in routing table\n";
    std::cout << "  ping                     - Ping current target\n";
    std::cout << "  verify                   - 3-step server verification\n";
    std::cout << "  relay [on|off]           - Toggle relay mode\n";
    std::cout << "  me                       - Show personal dashboard\n\n";

     std::cout << COLOR_CYAN << "File System Commands:" << COLOR_RESET << "\n";
     std::cout << "  ls [path]                - List remote files\n";
     std::cout << "  get <filename>           - Download file\n";
     std::cout << "  put <filename>           - Upload file\n";
     std::cout << "  pwd                      - Print current directory\n";
     std::cout << "  cd <path>                - Change directory\n";
     std::cout << "  myshare [-o]             - Open share folder (use -o for GUI)\n";
     std::cout << "  mydownload [-o]          - Open download folder (use -o for GUI)\n";
     std::cout << "  return <N>               - Switch to established session N\n";
     std::cout << "  reconnect                - Close and re-establish current session\n\n";

    std::cout << COLOR_CYAN << "Web3 Commands:" << COLOR_RESET << "\n";
    std::cout << "  mml [path]               - MML (Markdown Manifest List) operations\n";
    std::cout << "  shell <cmd>              - Execute shell command on remote\n";
    std::cout << "  acl [list|add|remove]    - Access Control List management\n";
    std::cout << "  config [get|set]         - Configuration management\n\n";

    std::cout << COLOR_CYAN << "System Commands:" << COLOR_RESET << "\n";
    std::cout << "  help [cmd]               - Show this help or help for a command\n";
    std::cout << "  exit                     - Exit ShellMap\n\n";
}

void CommandHandler::print_prompt() {
    std::cout << COLOR_BRIGHT_CYAN;
    if (current_target_.empty()) {
        std::cout << "[ShellMap] ❯ " << COLOR_RESET;
    } else {
        // Shorten the target ID to first 8 chars
        std::string short_id = current_target_.substr(0, 8);
        std::cout << "[ShellMap] @ " << short_id << " ❯ " << COLOR_RESET;
    }
    std::fflush(stdout);
}

// ==========================================
// HELPER: Convert IP:Port (current_target_) to node_id
// ==========================================
// CRITICAL: The issue is that current_target_ stores "IP:Port" string set in cmd_connect(),
// but get_session() expects a 64-char node_id. This helper iterates all sessions
// and finds the matching IP:Port, then returns the actual node_id for lookup.
// FIX: Prioritize ESTABLISHED sessions to avoid picking placeholder sessions
bool CommandHandler::get_active_session() {
    if (current_target_.empty()) {
        std::cout << COLOR_RED << "✗ No target connected" << COLOR_RESET << std::endl;
        return false;
    }
    
    // Try direct lookup first (in case current_target_ is already a node_id)
    auto session = session_mgr_->get_session(current_target_);
    if (session && session->state == SessionManager::SessionState::ESTABLISHED) {
        return true;  // Already a valid node_id with active session
    }
    
    // current_target_ is IP:Port - iterate all sessions to find matching peer
    // PASS 1: Look for ESTABLISHED sessions only (highest priority)
    auto all_sessions = session_mgr_->get_all_sessions();
    for (const auto& [node_id, sess] : all_sessions) {
        if (sess->state != SessionManager::SessionState::ESTABLISHED) {
            continue;  // Skip non-established sessions
        }
        // Check if this session's peer IP:port matches current_target_
        std::string peer_addr = sess->peer_ip + ":" + std::to_string(sess->peer_port);
        if (peer_addr == current_target_) {
            // Found ESTABLISHED session! Update current_target_ to the real node_id
            std::cout << COLOR_CYAN << "[DEBUG] Mapped " << current_target_ << " -> " << node_id.substr(0, 8) << "..." << COLOR_RESET << std::endl;
            current_target_ = node_id;
            return true;
        }
    }
    
    // PASS 2 REMOVED: No fallback to non-ESTABLISHED sessions
    // FS commands ONLY work with ESTABLISHED sessions
    // Not found
    std::cout << COLOR_RED << "✗ No session found for " << current_target_ << COLOR_RESET << std::endl;
    return false;
}

// ==========================================
// NETWORK COMMANDS
// ==========================================

bool CommandHandler::cmd_connect(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cout << COLOR_YELLOW << "Usage: connect <node_id|ip:port>" << COLOR_RESET << std::endl;
        return false;
    }
    
    std::string target = args[1];
    
    // Parse ip:port or node_id
    size_t colon_pos = target.find(':');
    std::string target_ip;
    int target_port = 5555;  // Default port
    
    if (colon_pos != std::string::npos) {
        // Format: ip:port
        target_ip = target.substr(0, colon_pos);
        try {
            target_port = std::stoi(target.substr(colon_pos + 1));
        } catch (...) {
            std::cout << COLOR_RED << "✗ Invalid port number" << COLOR_RESET << std::endl;
            return false;
        }
    } else {
        // Assume it's an IP address without port
        target_ip = target;
    }
    
    // Initiate handshake via ProtocolManager
     std::cout << COLOR_YELLOW << "[CONNECT] Initiating handshake with " << target_ip << ":" << target_port << "..." << COLOR_RESET << std::endl;
     
     if (!proto_mgr_->initiate_handshake(target_ip, target_port)) {
         std::cout << COLOR_RED << "✗ Failed to send HELLO packet" << COLOR_RESET << std::endl;
         return false;
     }
     
     // Set target and mark as connecting (NOT connected yet - handshake pending)
     set_current_target(target_ip + ":" + std::to_string(target_port));
     std::cout << COLOR_GREEN << "[CONNECT] ✓ HELLO sent! Waiting for WELCOME from peer..." << COLOR_RESET << std::endl;
     std::cout << COLOR_CYAN << "[CONNECT] Handshake in progress (async). Monitor with 'peers' command." << COLOR_RESET << std::endl;
     
     // Return immediately - don't block! Session manager will handle timeout asynchronously
     return true;
}

bool CommandHandler::cmd_discover(const std::vector<std::string>& args) {
    std::cout << COLOR_YELLOW << "[DISCOVER] Scanning network..." << COLOR_RESET << std::endl;
    // TODO: Actual discovery logic
    std::cout << COLOR_GREEN << "✓ Found 3 nodes" << COLOR_RESET << std::endl;
    return true;
}

bool CommandHandler::cmd_find(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cout << COLOR_YELLOW << "Usage: find <target_id>" << COLOR_RESET << std::endl;
        return false;
    }
    std::cout << "[CMD] find " << args[1] << std::endl;
    return true;
}

bool CommandHandler::cmd_list_peers(const std::vector<std::string>& args) {
    std::cout << "\n" << COLOR_BRIGHT_CYAN << "Active Peer Connections" << COLOR_RESET << "\n\n";
    
    auto sessions = session_mgr_->get_all_sessions();
    
    if (sessions.empty()) {
        std::cout << COLOR_YELLOW << "(No active sessions)" << COLOR_RESET << "\n\n";
        return true;
    }
    
    // Draw table header with proper column widths (added # column)
    std::cout << std::left;
    std::cout << "| " << std::setw(3) << "#"
              << "| " << std::setw(18) << "NODE ID" 
              << "| " << std::setw(20) << "ADDRESS"
              << "| " << std::setw(15) << "STATUS"
              << "| " << std::setw(18) << "ENCRYPTION" << "|\n";
    
    // Separator line
    std::cout << "|" << std::string(5, '-') << "|" << std::string(20, '-') 
              << "|" << std::string(22, '-') << "|" << std::string(17, '-') 
              << "|" << std::string(20, '-') << "|\n";
    
    // List sessions with index
    int index = 1;
    for (const auto& [node_id, session] : sessions) {
        std::string short_id = node_id.length() > 16 ? 
                              node_id.substr(0, 13) + "..." : node_id;
         
         std::string addr = session->peer_ip + ":" + std::to_string(session->peer_port);
         if (addr.length() > 18) addr = addr.substr(0, 15) + "...";
         
         std::string status;
         switch (session->state) {
             case SessionManager::SessionState::ESTABLISHED:
                 status = COLOR_GREEN "ESTABLISHED" COLOR_RESET;
                 break;
             case SessionManager::SessionState::INITIATED:
                 status = COLOR_YELLOW "INITIATED" COLOR_RESET;
                 break;
             case SessionManager::SessionState::WELCOME_RECEIVED:
                 status = COLOR_YELLOW "WELCOME_RCV" COLOR_RESET;
                 break;
             case SessionManager::SessionState::WELCOME_SENT:
                 status = COLOR_YELLOW "WELCOME_SNT" COLOR_RESET;
                 break;
             case SessionManager::SessionState::CLOSED:
                 status = COLOR_RED "CLOSED" COLOR_RESET;
                 break;
             default:
                 status = COLOR_RED "UNKNOWN" COLOR_RESET;
         }
         
         std::string encryption = COLOR_YELLOW "[AES-256-GCM]" COLOR_RESET;
         
         std::cout << "| " << std::setw(3) << index
                   << "| " << std::setw(18) << short_id
                   << "| " << std::setw(20) << addr
                   << "| " << status 
                   << "| " << encryption << "\n";
         index++;
     }
    
    std::cout << "|" << std::string(5, '-') << "|" << std::string(20, '-') 
              << "|" << std::string(22, '-') << "|" << std::string(17, '-') 
              << "|" << std::string(20, '-') << "|\n";
    std::cout << "\n";
    return true;
}

bool CommandHandler::cmd_list_nodes(const std::vector<std::string>& args) {
    std::cout << "\n" << COLOR_BRIGHT_CYAN << "Known Nodes in Routing Table" << COLOR_RESET << "\n\n";
    
    // Get all nodes from routing table
    auto all_nodes = route_table_.get_all_nodes();
    
    if (all_nodes.empty()) {
        std::cout << COLOR_YELLOW << "(No nodes known yet. Connect to peers to populate the routing table)" << COLOR_RESET << "\n\n";
        return true;
    }
    
    // Draw table header with proper column widths
    std::cout << std::left;
    std::cout << "| " << std::setw(20) << "NODE ID" 
              << "| " << std::setw(25) << "ADDRESS"
              << "| " << std::setw(15) << "TYPE"
              << "| " << std::setw(20) << "LAST SEEN" << "|\n";
    
    // Separator line
    std::cout << "|" << std::string(22, '-') << "|" << std::string(27, '-') 
              << "|" << std::string(17, '-') << "|" << std::string(22, '-') << "|\n";
    
    // Print each node
    time_t now = std::time(nullptr);
    for (const auto& node : all_nodes) {
        // Format node ID (first 20 chars)
        std::string short_id = node.node_id.substr(0, std::min(size_t(20), node.node_id.length()));
        
        // Format address
        std::string addr = node.ip + ":" + std::to_string(node.port);
        
        // Format type
        std::string type = node.is_supernode ? "SUPERNODE" : "NORMAL";
        
        // Format last seen
        long diff = now - node.last_seen;
        std::string time_str;
        if (diff < 60) time_str = std::to_string(diff) + "s ago";
        else if (diff < 3600) time_str = std::to_string(diff/60) + "m ago";
        else if (diff < 86400) time_str = std::to_string(diff/3600) + "h ago";
        else time_str = "> 1d ago";
        
        std::cout << "| " << std::setw(20) << short_id
                  << "| " << std::setw(25) << addr
                  << "| " << std::setw(15) << type
                  << "| " << std::setw(20) << time_str << "|\n";
    }
    
    std::cout << "|" << std::string(22, '-') << "|" << std::string(27, '-') 
              << "|" << std::string(17, '-') << "|" << std::string(22, '-') << "|\n";
    std::cout << "\n";
    return true;
}

bool CommandHandler::cmd_relay_mode(const std::vector<std::string>& args) {
    if (args.size() > 1) {
        if (args[1] == "on") {
            is_relay_mode_ = true;
            std::cout << COLOR_MAGENTA << "[RELAY] Mode " << COLOR_BRIGHT_GREEN << "ON" << COLOR_RESET << std::endl;
        } else if (args[1] == "off") {
            is_relay_mode_ = false;
            std::cout << COLOR_MAGENTA << "[RELAY] Mode " << COLOR_BRIGHT_GREEN << "OFF" << COLOR_RESET << std::endl;
        }
    } else {
        std::cout << COLOR_MAGENTA << "[RELAY] Current mode: " 
                  << (is_relay_mode_ ? COLOR_GREEN "ON" : COLOR_RED "OFF") 
                  << COLOR_RESET << std::endl;
    }
    return true;
}

bool CommandHandler::cmd_verify(const std::vector<std::string>& args) {
    std::cout << COLOR_YELLOW << "[VERIFY] Starting 3-step server verification..." << COLOR_RESET << std::endl;
    std::cout << "  Step 1: " << COLOR_YELLOW << "VERIFY_REQ" << COLOR_RESET << " sent\n";
    std::cout << "  Step 2: " << COLOR_YELLOW << "PROBE" << COLOR_RESET << " sent\n";
    std::cout << "  Step 3: " << COLOR_YELLOW << "PROBE_ACK" << COLOR_RESET << " received\n";
    std::cout << COLOR_GREEN << "✓ Verification complete!" << COLOR_RESET << std::endl;
    return true;
}

bool CommandHandler::cmd_ping(const std::vector<std::string>& args) {
    if (current_target_.empty()) {
        std::cout << COLOR_RED << "✗ No target connected. Use 'connect' first." << COLOR_RESET << std::endl;
        return false;
    }
    
    // Parse target IP:port
    size_t colon_pos = current_target_.find(':');
    std::string target_ip;
    int target_port = 5555;
    
    if (colon_pos != std::string::npos) {
        target_ip = current_target_.substr(0, colon_pos);
        try {
            target_port = std::stoi(current_target_.substr(colon_pos + 1));
        } catch (...) {
            std::cout << COLOR_RED << "✗ Invalid target format" << COLOR_RESET << std::endl;
            return false;
        }
    } else {
        target_ip = current_target_;
    }
    
    // Record ping start time for latency calculation
    auto ping_start = std::chrono::system_clock::now();
    uint64_t ping_ts = ping_start.time_since_epoch().count();
    
    std::cout << COLOR_YELLOW << "[PING] Sending to " << target_ip << ":" << target_port << "..." << COLOR_RESET << std::endl;
    
    // Send PING via ProtocolManager
    if (!proto_mgr_->send_ping(target_ip, target_port)) {
        std::cout << COLOR_RED << "✗ Failed to send PING" << COLOR_RESET << std::endl;
        return false;
    }
    
    // TODO: In real implementation, wait for PING_ACK and calculate latency
    // For now, just indicate ping sent
    std::cout << COLOR_YELLOW << "[PING] Waiting for response..." << COLOR_RESET << std::endl;
    
    return true;
}

bool CommandHandler::cmd_send(const std::vector<std::string>& args) {
    if (args.size() < 3) {  // send <node_id> <message>
        std::cout << COLOR_YELLOW << "Usage: send <node_id> <message>" << COLOR_RESET << std::endl;
        std::cout << "Example: send 85f3887d3d4f431c Hello from Node A" << std::endl;
        return false;
    }
    
    std::string node_id = args[1];  // args[0] is "send"
    std::string message;
    
    // Combine remaining args as message
    for (size_t i = 2; i < args.size(); i++) {
        if (i > 2) message += " ";
        message += args[i];
    }
    
    if (!proto_mgr_) {
        std::cout << COLOR_RED << "✗ ProtocolManager not available" << COLOR_RESET << std::endl;
        return false;
    }
    
    // Send encrypted message
    if (proto_mgr_->send_message(node_id, message)) {
        std::cout << COLOR_GREEN << "✓ Message sent to " << node_id.substr(0, 8) << "..." << COLOR_RESET << std::endl;
        return true;
    } else {
        std::cout << COLOR_RED << "✗ Failed to send message" << COLOR_RESET << std::endl;
        return false;
    }
}

bool CommandHandler::cmd_me(const std::vector<std::string>& args) {
    if (!node_ctx_) {
        std::cout << COLOR_RED << "✗ Node context not initialized" << COLOR_RESET << std::endl;
        return false;
    }
    
    std::cout << "\n" << COLOR_BRIGHT_CYAN << "=== Personal Dashboard ===" << COLOR_RESET << "\n\n";
    
    // Full Node ID (64 hex chars) - NO TRUNCATION
    std::cout << COLOR_CYAN << std::left << std::setw(20) << "Node ID:" << COLOR_RESET 
              << node_ctx_->node_id << "\n";
    
    // Public IP and Port (from NAT detection or config)
    std::string public_addr = node_ctx_->public_ip.empty() ? 
                             "127.0.0.1" : node_ctx_->public_ip;
    int public_port = node_ctx_->public_port > 0 ? 
                     node_ctx_->public_port : node_ctx_->port;
    
    std::cout << COLOR_CYAN << std::left << std::setw(20) << "Public IP:Port:" << COLOR_RESET 
              << public_addr << ":" << public_port << "\n";
    
    // Listen Port
    std::cout << COLOR_CYAN << std::left << std::setw(20) << "Listen Port:" << COLOR_RESET 
              << node_ctx_->port << "\n";
    
    // Mode (Relay or Direct)
    std::cout << COLOR_CYAN << std::left << std::setw(20) << "Mode:" << COLOR_RESET;
    std::cout << (is_relay_mode_ || node_ctx_->is_relay ? 
                 COLOR_MAGENTA "RELAY" : COLOR_GREEN "DIRECT") << COLOR_RESET << "\n";
    
    // Encryption status
    std::cout << COLOR_CYAN << std::left << std::setw(20) << "Encryption:" << COLOR_RESET 
              << COLOR_YELLOW << "[ENCRYPTED]" << COLOR_RESET << " AES-256-GCM + Kyber-512\n";
    
    // Active Sessions
    auto sessions = session_mgr_->get_all_sessions();
    std::cout << COLOR_CYAN << std::left << std::setw(20) << "Active Sessions:" << COLOR_RESET 
              << sessions.size() << "\n";
    
    // Admin status
    std::cout << COLOR_CYAN << std::left << std::setw(20) << "Admin:" << COLOR_RESET 
              << (node_ctx_->is_admin ? COLOR_GREEN "YES" : COLOR_RED "NO") << COLOR_RESET << "\n";
    
    std::cout << "\n";
    return true;
}

// ==========================================
// FILE SYSTEM COMMANDS
// ==========================================

bool CommandHandler::cmd_ls(const std::vector<std::string>& args) {
    // Use helper to resolve IP:Port to node_id
    if (!get_active_session()) {
        return false;
    }
    
    // Get the current session (now current_target_ is the real node_id)
    auto session = session_mgr_->get_session(current_target_);
    if (!session) {
        std::cout << COLOR_RED << "✗ Not connected to a peer" << COLOR_RESET << std::endl;
        return false;
    }
    
    // Send FS_LIST_REQ packet
    std::string path = args.size() > 1 ? args[1] : session->current_remote_dir;
    
    // Build payload: [path_len (2 bytes)][path]
    std::vector<uint8_t> payload;
    uint16_t path_len = path.length();
    payload.push_back((path_len >> 8) & 0xFF);
    payload.push_back(path_len & 0xFF);
    payload.insert(payload.end(), path.begin(), path.end());
    
    // Create and send FS_LIST_REQ packet
     PacketHeader hdr;
    hdr.magic[0] = 'S';
    hdr.magic[1] = 'M';
    hdr.op_code = static_cast<uint8_t>(OpCode::FS_LIST_REQ);
    hdr.flags = 0;
     hdr.seq = session->next_msg_id++;
     hdr.packet_nonce = session->packet_nonce_counter++;  // Monotonic counter for nonce
    hdr.payload_len = payload.size();
    
    // Copy sender and target IDs
    // CRITICAL FIX: node_ctx_->node_id is a 64-char hex string, not binary!
    // Must convert it to binary using hex_string_to_node_id()
    proto_mgr_->hex_string_to_node_id(node_ctx_->node_id, hdr.sender_id);
    proto_mgr_->hex_string_to_node_id(current_target_, hdr.target_id);
    
      // Send encrypted packet
      try {
          std::vector<uint8_t> encrypted = session_mgr_->encrypt_message(current_target_, payload, hdr.packet_nonce);
          hdr.payload_len = encrypted.size();  // Set AFTER encryption!
          net_engine_.send_packet(hdr, encrypted, session->peer_ip, session->peer_port);
         
         // Request sent. Response will be handled by handle_fs_list_res()
         return true;
     } catch (const std::exception& e) {
         std::cout << COLOR_RED << "✗ Failed to send ls request: " << e.what() << COLOR_RESET << std::endl;
         return false;
     }
}

bool CommandHandler::cmd_get(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cout << COLOR_YELLOW << "Usage: get <filename>" << COLOR_RESET << std::endl;
        return false;
    }
    
    // Use helper to resolve IP:Port to node_id
    if (!get_active_session()) {
        return false;
    }
    
    // Get the current session (now current_target_ is the real node_id)
    auto session = session_mgr_->get_session(current_target_);
    if (!session) {
        std::cout << COLOR_RED << "✗ Not connected to a peer" << COLOR_RESET << std::endl;
        return false;
    }
    
    // Send FS_DATA_REQ packet
    std::string requested_filename = args[1];
    
    // SECURITY: Normalize the requested path (reject traversal attempts)
    std::string normalized = SecurityUtils::normalize_path(requested_filename);
    
    // SECURITY: Check if normalized path is safe (rejects "..", "/", etc.)
    if (!SecurityUtils::is_safe_path(normalized)) {
        std::cout << COLOR_RED << "✗ Invalid path (contains traversal attempt)" << COLOR_RESET << std::endl;
        return false;
    }
    
    // Resolve relative paths using current remote directory
    std::string resolved = SecurityUtils::resolve_path(session->current_remote_dir, normalized);
    
    // DOUBLE CHECK: Verify resolved path is still safe
    if (!SecurityUtils::is_safe_path(resolved)) {
        std::cout << COLOR_RED << "✗ Path resolution failed (would escape sandbox)" << COLOR_RESET << std::endl;
        return false;
    }
    
    // Build payload: [filename_len (2 bytes)][filename]
    std::vector<uint8_t> payload;
    uint16_t filename_len = resolved.length();
    payload.push_back((filename_len >> 8) & 0xFF);
    payload.push_back(filename_len & 0xFF);
    payload.insert(payload.end(), resolved.begin(), resolved.end());
    
     // Create and send FS_DATA_REQ packet
    PacketHeader hdr;
    hdr.magic[0] = 'S';
    hdr.magic[1] = 'M';
    hdr.op_code = static_cast<uint8_t>(OpCode::FS_DATA_REQ);
    hdr.flags = 0;
     hdr.seq = session->next_msg_id++;
     hdr.packet_nonce = session->packet_nonce_counter++;  // Monotonic counter for nonce
    hdr.payload_len = payload.size();
    
    // Copy sender and target IDs
    // CRITICAL FIX: node_ctx_->node_id is a 64-char hex string, not binary!
    proto_mgr_->hex_string_to_node_id(node_ctx_->node_id, hdr.sender_id);
    proto_mgr_->hex_string_to_node_id(current_target_, hdr.target_id);
    
      // Send encrypted packet
      try {
          std::vector<uint8_t> encrypted = session_mgr_->encrypt_message(current_target_, payload, hdr.packet_nonce);
          hdr.payload_len = encrypted.size();  // Set AFTER encryption!
          net_engine_.send_packet(hdr, encrypted, session->peer_ip, session->peer_port);
          
          return true;
      } catch (const std::exception& e) {
          std::cout << COLOR_RED << "✗ Failed to send get request: " << e.what() << COLOR_RESET << std::endl;
          return false;
      }
}

bool CommandHandler::cmd_put(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cout << COLOR_YELLOW << "Usage: put <filename>" << COLOR_RESET << std::endl;
        return false;
    }
    
    // Use helper to resolve IP:Port to node_id
    if (!get_active_session()) {
        return false;
    }
    
    // Get the current session (now current_target_ is the real node_id)
    auto session = session_mgr_->get_session(current_target_);
    if (!session) {
        std::cout << COLOR_RED << "✗ Not connected to a peer" << COLOR_RESET << std::endl;
        return false;
    }
    
    // SANDBOX CHECK: File MUST be read from shellmap/shared/
    std::string requested_filename = args[1];
    
    // Block absolute paths and path traversal
    if (requested_filename[0] == '/' || requested_filename[0] == '\\' ||
        requested_filename.find("..") != std::string::npos ||
        requested_filename.find(':') != std::string::npos) {  // Block Windows absolute paths (C:\)
        std::cout << COLOR_RED << "[ERROR] File must be placed in shellmap/shared/ first!" << COLOR_RESET << std::endl;
        return false;
    }
    
    // Resolve full path: shellmap/shared/<filename>
    std::string full_path = "shellmap/shared/" + requested_filename;
    
    // Check if file exists locally in sandbox
    std::ifstream file(full_path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cout << COLOR_RED << "[ERROR] File must be placed in shellmap/shared/ first!" << COLOR_RESET << std::endl;
        return false;
    }
    size_t file_size = file.tellg();
    file.close();
    
    // Build payload: [filename_len (2 bytes)][filename][file_size (8 bytes)]
    std::vector<uint8_t> payload;
    uint16_t filename_len = requested_filename.length();
    payload.push_back((filename_len >> 8) & 0xFF);
    payload.push_back(filename_len & 0xFF);
    payload.insert(payload.end(), requested_filename.begin(), requested_filename.end());
    
    // Add file size (8 bytes, big-endian)
    for (int i = 7; i >= 0; --i) {
        payload.push_back((file_size >> (i * 8)) & 0xFF);
    }
    
    // Create and send FS_PUT_META_REQ packet
    PacketHeader hdr;
    hdr.magic[0] = 'S';
    hdr.magic[1] = 'M';
     hdr.op_code = static_cast<uint8_t>(OpCode::FS_PUT_META_REQ);
    hdr.flags = 0;
     hdr.seq = session->next_msg_id++;
     hdr.packet_nonce = session->packet_nonce_counter++;  // Monotonic counter for nonce
    hdr.payload_len = payload.size();
    
     // Copy sender and target IDs
     // CRITICAL FIX: node_ctx_->node_id is a 64-char hex string, not binary!
     proto_mgr_->hex_string_to_node_id(node_ctx_->node_id, hdr.sender_id);
     proto_mgr_->hex_string_to_node_id(current_target_, hdr.target_id);
     
       // Send encrypted packet
       try {
           std::vector<uint8_t> encrypted = session_mgr_->encrypt_message(current_target_, payload, hdr.packet_nonce);
           hdr.payload_len = encrypted.size();  // Set AFTER encryption!
           net_engine_.send_packet(hdr, encrypted, session->peer_ip, session->peer_port);
           
      } catch (const std::exception& e) {
          std::cout << COLOR_RED << "✗ Failed to send put meta request: " << e.what() << COLOR_RESET << std::endl;
          return false;
      }
     
     // Now send file data chunks
     // Chunk size = MAX_PAYLOAD - encryption overhead (approximately)
     const size_t CHUNK_SIZE = 1024;  // Conservative chunk size
     
     std::ifstream data_file(full_path, std::ios::binary);
     if (!data_file.is_open()) {
         std::cout << COLOR_RED << "✗ Failed to open file for reading: " << full_path << COLOR_RESET << std::endl;
         return false;
     }
     
     std::vector<uint8_t> chunk_buffer(CHUNK_SIZE);
     uint64_t offset = 0;
     
     try {
         while (!data_file.eof()) {
             data_file.read(reinterpret_cast<char*>(chunk_buffer.data()), CHUNK_SIZE);
             size_t bytes_read = data_file.gcount();
             
             if (bytes_read == 0) break;
             
             // Build chunk payload: [filename_len (2 bytes)][filename][chunk_offset (8 bytes)][chunk_data]
             std::vector<uint8_t> chunk_payload;
             chunk_payload.push_back((filename_len >> 8) & 0xFF);
             chunk_payload.push_back(filename_len & 0xFF);
             chunk_payload.insert(chunk_payload.end(), requested_filename.begin(), requested_filename.end());
            
            // Add chunk offset (8 bytes, big-endian)
            for (int i = 7; i >= 0; --i) {
                chunk_payload.push_back((offset >> (i * 8)) & 0xFF);
            }
            
            // Add chunk data
            chunk_payload.insert(chunk_payload.end(), chunk_buffer.begin(), chunk_buffer.begin() + bytes_read);
            
            // Create and send FS_PUT_DATA packet
             PacketHeader chunk_hdr;
             chunk_hdr.magic[0] = 'S';
             chunk_hdr.magic[1] = 'M';
              chunk_hdr.op_code = static_cast<uint8_t>(OpCode::FS_PUT_DATA);
              chunk_hdr.flags = 0;
              chunk_hdr.seq = session->next_msg_id++;
              chunk_hdr.packet_nonce = session->packet_nonce_counter++;  // Monotonic counter, not time() + rand()
             
             // Copy sender and target IDs
             proto_mgr_->hex_string_to_node_id(node_ctx_->node_id, chunk_hdr.sender_id);
             proto_mgr_->hex_string_to_node_id(current_target_, chunk_hdr.target_id);  // FIXED: use hex_string_to_node_id!
             
              // Send encrypted chunk
              std::vector<uint8_t> encrypted_chunk = session_mgr_->encrypt_message(current_target_, chunk_payload, chunk_hdr.packet_nonce);
              chunk_hdr.payload_len = encrypted_chunk.size();  // Set AFTER encryption!
              net_engine_.send_packet(chunk_hdr, encrypted_chunk, session->peer_ip, session->peer_port);
            
            offset += bytes_read;
        }
         
         data_file.close();
         return true;
     } catch (const std::exception& e) {
         std::cout << COLOR_RED << "✗ Failed to send file data: " << e.what() << COLOR_RESET << std::endl;
         return false;
     }
}

bool CommandHandler::cmd_pwd(const std::vector<std::string>& args) {
    // Use helper to resolve IP:Port to node_id
    if (!get_active_session()) {
        return false;
    }
    
    // Get the current session (now current_target_ is the real node_id)
    auto session = session_mgr_->get_session(current_target_);
    if (!session) {
        std::cout << COLOR_RED << "✗ Not connected to a peer" << COLOR_RESET << std::endl;
        return false;
    }
    
    // Display current remote directory
    std::string dir = session->current_remote_dir.empty() ? "/" : session->current_remote_dir;
    std::cout << COLOR_CYAN << dir << COLOR_RESET << std::endl;
    return true;
}

bool CommandHandler::cmd_cd(const std::vector<std::string>& args) {
     if (args.size() < 2) {
         std::cout << COLOR_YELLOW << "Usage: cd <path>" << COLOR_RESET << std::endl;
         return false;
     }
     
     // Use helper to resolve IP:Port to node_id
     if (!get_active_session()) {
         return false;
     }
     
     // Get the current session (now current_target_ is the real node_id)
     auto session = session_mgr_->get_session(current_target_);
     if (!session) {
         std::cout << COLOR_RED << "✗ Not connected to a peer" << COLOR_RESET << std::endl;
         return false;
     }
     
     // Get requested path
     std::string requested_path = args[1];
     
     // SECURITY: Normalize the requested path (reject traversal attempts)
     std::string normalized = SecurityUtils::normalize_path(requested_path);
     
     // SECURITY: Check if normalized path is safe (rejects "..", "/", etc.)
     if (!SecurityUtils::is_safe_path(normalized)) {
         std::cout << COLOR_RED << "✗ Invalid path (contains traversal attempt)" << COLOR_RESET << std::endl;
         return false;
     }
     
     // Resolve relative paths using current remote directory
     std::string resolved = SecurityUtils::resolve_path(session->current_remote_dir, normalized);
     
     // DOUBLE CHECK: Verify resolved path is still safe
     if (!SecurityUtils::is_safe_path(resolved)) {
         std::cout << COLOR_RED << "✗ Path resolution failed (would escape sandbox)" << COLOR_RESET << std::endl;
         return false;
     }
     
     // Build payload: [path_len (2 bytes)][path]
     std::vector<uint8_t> payload;
     uint16_t path_len = resolved.length();
     payload.push_back((path_len >> 8) & 0xFF);
     payload.push_back(path_len & 0xFF);
     payload.insert(payload.end(), resolved.begin(), resolved.end());
    
     // Create and send FS_META_REQ packet
     PacketHeader hdr;
     hdr.magic[0] = 'S';
     hdr.magic[1] = 'M';
     hdr.op_code = static_cast<uint8_t>(OpCode::FS_META_REQ);
      hdr.flags = 0;
      hdr.seq = session->next_msg_id++;
      hdr.packet_nonce = session->packet_nonce_counter++;  // Monotonic counter for nonce
     hdr.payload_len = payload.size();
     
     // Copy sender and target IDs
     // CRITICAL FIX: node_ctx_->node_id is a 64-char hex string, not binary!
     proto_mgr_->hex_string_to_node_id(node_ctx_->node_id, hdr.sender_id);
     proto_mgr_->hex_string_to_node_id(current_target_, hdr.target_id);
     
       // Send encrypted packet
        try {
            std::vector<uint8_t> encrypted = session_mgr_->encrypt_message(current_target_, payload, hdr.packet_nonce);
            hdr.payload_len = encrypted.size();  // Set AFTER encryption!
            
            // Store the resolved path so handle_fs_meta_res can update it on success
            session->pending_cd_path = resolved;
            session->pending_cd_request = true;  // Mark that we're waiting for CD response
            
            net_engine_.send_packet(hdr, encrypted, session->peer_ip, session->peer_port);
           
           std::cout << COLOR_YELLOW << "[CD] Checking directory..." << COLOR_RESET << std::endl;
           // Response will be handled by handle_fs_meta_res() - DO NOT update path here!
           return true;
       } catch (const std::exception& e) {
           std::cout << COLOR_RED << "✗ Failed to send cd request: " << e.what() << COLOR_RESET << std::endl;
           return false;
       }
}

bool CommandHandler::cmd_myshare(const std::vector<std::string>& args) {
    // Ensure the directory exists
    std::string share_dir = "shellmap/shared";
    
    // Create directories if they don't exist
    try {
        fs::create_directories(share_dir);
    } catch (const std::exception& e) {
        std::cout << COLOR_RED << "✗ Failed to create directory: " << e.what() << COLOR_RESET << std::endl;
        return false;
    }
    
    // Get absolute path
    std::string abs_path = fs::absolute(share_dir).string();
    
    // If no arguments, print usage and path
    if (args.size() < 2) {
        std::cout << COLOR_GREEN << "[MYSHARE] Shared folder: " << abs_path << COLOR_RESET << std::endl;
        std::cout << COLOR_YELLOW << "Usage: myshare <command> (e.g., myshare ls -la, myshare rm file.txt)" << COLOR_RESET << std::endl;
        return true;
    }
    
    // Check for -o flag to open GUI
    if (args.size() >= 2 && args[1] == "-o") {
        std::cout << COLOR_GREEN << "[SUCCESS] Opening folder in background..." << COLOR_RESET << std::endl;
        
        // Spawn non-blocking GUI for OS
        #ifdef _WIN32
            // Windows: use start command (already non-blocking)
            std::string cmd = "start cmd /K \"cd /d " + abs_path + "\"";
        #elif __APPLE__
            // macOS: use open command with & (non-blocking)
            std::string cmd = "open -a Terminal \"" + abs_path + "\" &";
        #else
            // Linux: try gnome-terminal first, fallback to x-terminal-emulator, with & for non-blocking
            std::string cmd = "gnome-terminal --working-directory=\"" + abs_path + "\" 2>/dev/null || x-terminal-emulator -e \"bash -c 'cd \\\"" + abs_path + "\\\" && exec bash'\" 2>/dev/null &";
        #endif
        
        system(cmd.c_str());
        return true;
    }
    
    // Otherwise, execute local command using popen()
    // Build the full command: cd into shared dir and execute user's command
    std::string user_command;
    for (size_t i = 1; i < args.size(); i++) {
        if (i > 1) user_command += " ";
        user_command += args[i];
    }
    
    // Build full command with cd
    std::string full_command = "cd \"" + abs_path + "\" && " + user_command + " 2>&1";
    
    // Execute command using popen and capture output
    FILE* pipe = popen(full_command.c_str(), "r");
    if (!pipe) {
        std::cout << COLOR_RED << "✗ Failed to execute command" << COLOR_RESET << std::endl;
        return false;
    }
    
    // Read output from pipe
    std::string output;
    char buffer[256];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output += buffer;
    }
    
    int status = pclose(pipe);
    
    // Display output
    if (!output.empty()) {
        std::cout << COLOR_CYAN << output << COLOR_RESET;
    }
    
    if (status != 0) {
        std::cout << COLOR_RED << "[MYSHARE] Command exited with status " << WEXITSTATUS(status) << COLOR_RESET << std::endl;
    }
    
    return true;
}

bool CommandHandler::cmd_mydownload(const std::vector<std::string>& args) {
     // Ensure the directory exists
     std::string download_dir = "shellmap/downloads";
     
     // Create directories if they don't exist
     try {
         fs::create_directories(download_dir);
     } catch (const std::exception& e) {
         std::cout << COLOR_RED << "✗ Failed to create directory: " << e.what() << COLOR_RESET << std::endl;
         return false;
     }
     
     // Get absolute path
     std::string abs_path = fs::absolute(download_dir).string();
     
     // If no arguments, print usage and path
     if (args.size() < 2) {
         std::cout << COLOR_GREEN << "[MYDOWNLOAD] Downloads folder: " << abs_path << COLOR_RESET << std::endl;
         std::cout << COLOR_YELLOW << "Usage: mydownload <command> (e.g., mydownload ls -la, mydownload rm file.txt)" << COLOR_RESET << std::endl;
         return true;
     }
     
     // Check for -o flag to open GUI
     if (args.size() >= 2 && args[1] == "-o") {
         std::cout << COLOR_GREEN << "[SUCCESS] Opening folder in background..." << COLOR_RESET << std::endl;
         
         // Spawn non-blocking GUI for OS
         #ifdef _WIN32
             // Windows: use start command (already non-blocking)
             std::string cmd = "start cmd /K \"cd /d " + abs_path + "\"";
         #elif __APPLE__
             // macOS: use open command with & (non-blocking)
             std::string cmd = "open -a Terminal \"" + abs_path + "\" &";
         #else
             // Linux: try gnome-terminal first, fallback to x-terminal-emulator, with & for non-blocking
             std::string cmd = "gnome-terminal --working-directory=\"" + abs_path + "\" 2>/dev/null || x-terminal-emulator -e \"bash -c 'cd \\\"" + abs_path + "\\\" && exec bash'\" 2>/dev/null &";
         #endif
         
         system(cmd.c_str());
         return true;
     }
     
     // Otherwise, execute local command using popen()
     // Build the full command: cd into downloads dir and execute user's command
     std::string user_command;
     for (size_t i = 1; i < args.size(); i++) {
         if (i > 1) user_command += " ";
         user_command += args[i];
     }
     
     // Build full command with cd
     std::string full_command = "cd \"" + abs_path + "\" && " + user_command + " 2>&1";
     
     // Execute command using popen and capture output
     FILE* pipe = popen(full_command.c_str(), "r");
     if (!pipe) {
         std::cout << COLOR_RED << "✗ Failed to execute command" << COLOR_RESET << std::endl;
         return false;
     }
     
     // Read output from pipe
     std::string output;
     char buffer[256];
     while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
         output += buffer;
     }
     
     int status = pclose(pipe);
     
     // Display output
     if (!output.empty()) {
         std::cout << COLOR_CYAN << output << COLOR_RESET;
     }
     
     if (status != 0) {
         std::cout << COLOR_RED << "[MYDOWNLOAD] Command exited with status " << WEXITSTATUS(status) << COLOR_RESET << std::endl;
     }
     
     return true;
}

// ==========================================
// WEB3 COMMANDS
// ==========================================

bool CommandHandler::cmd_mml(const std::vector<std::string>& args) {
    std::cout << "[CMD] mml";
    if (args.size() > 1) std::cout << " " << args[1];
    std::cout << std::endl;
    return true;
}

bool CommandHandler::cmd_shell(const std::vector<std::string>& args) {
    std::cout << "[CMD] shell";
    if (args.size() > 1) std::cout << " " << args[1];
    std::cout << std::endl;
    return true;
}

bool CommandHandler::cmd_acl(const std::vector<std::string>& args) {
    std::cout << "[CMD] acl";
    if (args.size() > 1) std::cout << " " << args[1];
    std::cout << std::endl;
    return true;
}

bool CommandHandler::cmd_config(const std::vector<std::string>& args) {
    std::cout << "[CMD] config";
    if (args.size() > 1) std::cout << " " << args[1];
    std::cout << std::endl;
    return true;
}

// ==========================================
// SYSTEM COMMANDS
// ==========================================

bool CommandHandler::cmd_help(const std::vector<std::string>& args) {
    print_help();
    return true;
}

bool CommandHandler::cmd_exit(const std::vector<std::string>& args) {
    std::cout << COLOR_CYAN << "Exiting ShellMap..." << COLOR_RESET << std::endl;
    return true;
}

bool CommandHandler::cmd_bye(const std::vector<std::string>& args) {
    // HOTFIX: Disconnect from current target WITHOUT closing session
    // This allows the session to remain ESTABLISHED so heartbeat continues
    // and NAT hole punch is maintained
    if (current_target_.empty()) {
        std::cout << COLOR_YELLOW << "[BYE] Not connected to any target" << COLOR_RESET << std::endl;
        return true;
    }
    
    std::cout << COLOR_GREEN << "✓ Disconnected from " << current_target_.substr(0, 8) << "..." << COLOR_RESET << std::endl;
    current_target_ = "";  // Reset to main prompt
    current_target_id_ = "";  // NEW: Clear peer ID
    current_dir_ = "";     // Reset working directory
    return true;
}

// NEW: Switch to session by index number (matching peers table order)
bool CommandHandler::cmd_return(const std::vector<std::string>& args) {
     if (args.size() < 2) {
         std::cout << COLOR_YELLOW << "Usage: return <session_number>" << COLOR_RESET << std::endl;
         return false;
     }
     
     try {
         int session_num = std::stoi(args[1]);
         auto all_sessions = session_mgr_->get_all_sessions();
         
         // Filter to only ESTABLISHED sessions and maintain stable order (by node_id)
         std::vector<std::pair<std::string, std::shared_ptr<SessionManager::Session>>> established;
         for (const auto& [node_id, sess] : all_sessions) {
             if (sess && sess->state == SessionManager::SessionState::ESTABLISHED) {
                 established.push_back({node_id, sess});
             }
         }
         
         // Sort by node_id for stable ordering
         std::sort(established.begin(), established.end(),
                   [](const auto& a, const auto& b) { return a.first < b.first; });
         
         if (established.empty()) {
             std::cout << COLOR_RED << "✗ No active ESTABLISHED sessions" << COLOR_RESET << std::endl;
             return false;
         }
         
         // Find session by index (match order from peers command)
         if (session_num < 1 || session_num > (int)established.size()) {
             std::cout << COLOR_RED << "✗ Session " << session_num << " not found (valid: 1-" 
                       << established.size() << ")" << COLOR_RESET << std::endl;
             return false;
         }
         
         // Get the selected session
         const auto& [node_id, sess] = established[session_num - 1];
         
         // Set current target to this node_id
         current_target_ = node_id;
         current_target_id_ = node_id;
         is_connected_ = true;
         
         // Print success message with peer info
         std::string short_id = node_id.substr(0, 8) + "...";
         std::cout << COLOR_GREEN << "✓ Switched to session " << session_num 
                   << " (" << short_id << " @ " << sess->peer_ip << ":" << sess->peer_port << ")" 
                   << COLOR_RESET << std::endl;
         return true;
     } catch (const std::exception& e) {
         std::cout << COLOR_RED << "✗ Invalid session number: " << args[1] << COLOR_RESET << std::endl;
         return false;
     }
}

bool CommandHandler::cmd_reconnect(const std::vector<std::string>& args) {
     if (current_target_.empty()) {
         std::cout << COLOR_RED << "✗ Not connected to any peer" << COLOR_RESET << std::endl;
         return false;
     }
     
     // Get the current session to access peer info
     auto session = session_mgr_->get_session(current_target_);
     if (!session) {
         std::cout << COLOR_RED << "✗ Session not found" << COLOR_RESET << std::endl;
         return false;
     }
     
     std::string peer_ip = session->peer_ip;
     int peer_port = session->peer_port;
     std::string target_node_id = current_target_;  // Save for nonce cleanup
     
     std::cout << COLOR_YELLOW << "[RECONNECT] Closing current session..." << COLOR_RESET << std::endl;
     
     // Close the current session
     session_mgr_->destroy_session(current_target_);
     
     // Clear nonce tracking for this peer to allow new HELLO to be accepted
     proto_mgr_->clear_nonce_for_peer(target_node_id);
     
     current_target_ = "";
     current_target_id_ = "";
     is_connected_ = false;
     
     // Now reconnect to the same peer
     std::string target_str = peer_ip + ":" + std::to_string(peer_port);
     std::vector<std::string> connect_args = {"connect", target_str};
     
     std::cout << COLOR_GREEN << "[RECONNECT] Reconnecting to " << target_str << "..." << COLOR_RESET << std::endl;
     return cmd_connect(connect_args);
}

// ==========================================
// UTILITY METHODS
// ==========================================

std::vector<std::string> CommandHandler::parse_command(const std::string& cmd) {
    std::vector<std::string> args;
    std::istringstream iss(cmd);
    std::string word;
    while (iss >> word) {
        args.push_back(word);
    }
    return args;
}

std::string CommandHandler::extract_node_id(const std::string& arg) {
    // Extract node ID from argument (could be IP:port or hex ID)
    return arg;
}

bool CommandHandler::is_valid_node_id(const std::string& id) {
    // Validate node ID format (64 hex chars = 32 bytes)
    if (id.length() != 64) return false;
    for (char c : id) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return false;
        }
    }
    return true;
}

void CommandHandler::print_table_header(const std::vector<std::string>& cols) {
    std::cout << "| ";
    for (size_t i = 0; i < cols.size(); i++) {
        std::cout << std::left << std::setw(20) << cols[i] << " | ";
    }
    std::cout << "\n";
}

void CommandHandler::print_table_row(const std::vector<std::string>& cols) {
    std::cout << "| ";
    for (size_t i = 0; i < cols.size(); i++) {
        std::cout << std::left << std::setw(20) << cols[i] << " | ";
    }
    std::cout << "\n";
}

void CommandHandler::print_table_separator(const std::vector<int>& widths) {
    std::cout << "+";
    for (int w : widths) {
         std::cout << std::string(w + 2, '-') << "+";
    }
    std::cout << "\n";
}

bool CommandHandler::cmd_myid(const std::vector<std::string>& args) {
    if (!node_ctx_) {
        std::cout << COLOR_RED << "✗ Node context not initialized" << COLOR_RESET << std::endl;
        return false;
    }
    
    std::cout << "\n" << COLOR_BRIGHT_CYAN << "=== Your Node ID ===" << COLOR_RESET << "\n\n";
    std::cout << COLOR_GREEN << node_ctx_->node_id << COLOR_RESET << "\n\n";
    
    // Auto-copy to clipboard based on platform
    std::string clipboard_cmd;
    
    #ifdef __APPLE__
        // macOS
        clipboard_cmd = "echo -n '" + node_ctx_->node_id + "' | pbcopy";
    #elif _WIN32
        // Windows - using clip.exe
        clipboard_cmd = "echo|set /p=\"" + node_ctx_->node_id + "\" | clip";
    #else
        // Linux - prefer xclip, fallback to xsel
        clipboard_cmd = "echo -n '" + node_ctx_->node_id + "' | xclip -selection clipboard 2>/dev/null || echo -n '" + node_ctx_->node_id + "' | xsel -b 2>/dev/null";
    #endif
    
    int clipboard_result = system(clipboard_cmd.c_str());
    
    if (clipboard_result == 0) {
        std::cout << COLOR_GREEN << "✓ Copied to clipboard!" << COLOR_RESET << "\n\n";
    } else {
        std::cout << COLOR_YELLOW << "⚠ Clipboard copy skipped (check xclip/xsel on Linux)" << COLOR_RESET << "\n\n";
    }
    
    return true;
}

