#include <iostream>
#include <vector>
#include <memory>
#include <sys/select.h>
#include <unistd.h>
#include <cstring>
#include <algorithm>

#include "Protocol.hpp"
#include "NetworkEngine.hpp"
#include "RoutingTable.hpp"
#include "FileManager.hpp"
#include "ProtocolManager.hpp"
#include "SessionManager.hpp"
#include "VerificationManager.hpp"
#include "RelayManager.hpp"
#include "Web3Manager.hpp"
#include "CommandHandler.hpp"
#include "NodeInitializer.hpp"

using namespace std;

// Global instances
NetworkEngine net_engine;
RoutingTable route_table;
FileManager file_mgr;
NodeContext my_identity;

// Manager instances
shared_ptr<SessionManager> session_mgr;
shared_ptr<VerificationManager> verify_mgr;
shared_ptr<RelayManager> relay_mgr;
shared_ptr<Web3Manager> web3_mgr;
shared_ptr<CommandHandler> cmd_handler;
shared_ptr<ProtocolManager> proto_mgr;

/**
 * @brief Initialize all manager instances
 */
void init_managers() {
    session_mgr = make_shared<SessionManager>();
    verify_mgr = make_shared<VerificationManager>();
    relay_mgr = make_shared<RelayManager>();
    web3_mgr = make_shared<Web3Manager>();
    proto_mgr = make_shared<ProtocolManager>(session_mgr, verify_mgr, relay_mgr, web3_mgr, &file_mgr, nullptr, net_engine, route_table, &my_identity);
    cmd_handler = make_shared<CommandHandler>(session_mgr, verify_mgr, web3_mgr, &file_mgr, net_engine, route_table, proto_mgr, &my_identity);
    
    cout << "[INIT] All managers initialized" << endl;
}

/**
 * @brief Read user input from stdin and execute command
 */
void handle_user_input() {
    string input;
    if (!getline(cin, input)) return;
    
    if (input.empty()) {
        cmd_handler->print_prompt();
        return;
    }

    // Process command
    if (cmd_handler->process_command(input)) {
        // Command executed successfully
    }
    
    cmd_handler->print_prompt();
}

int main(int argc, char* argv[]) {
    cout << "=== ShellMap - P2P Anonymous File-Sharing Network ===" << endl;

    // Parse command-line arguments
    int cli_port = -1;  // Default: not specified
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            try {
                cli_port = std::stoi(argv[i + 1]);
                cout << "[INIT] Using command-line port: " << cli_port << endl;
            } catch (...) {
                cout << "[INIT] Invalid port argument: " << argv[i + 1] << endl;
            }
        }
    }

    // 1. Initialize node identity (keys, config, directories)
    cout << "\n[INIT] Initializing node identity..." << endl;
    NodeInitializer::init();
    my_identity = NodeInitializer::init();
    
    // Override port if provided via command-line
    if (cli_port > 0) {
        my_identity.port = cli_port;
    }

    // 2. Initialize Network with configured port
    cout << "[INIT] Initializing network engine..." << endl;
    if (!net_engine.init(my_identity.port)) {
        cerr << COLOR_RED << "[ERROR] Failed to initialize network engine" << COLOR_RESET << endl;
        return -1;
    }
    
    // Get actual port (may differ from requested if bind fails or port=0)
    int actual_port = net_engine.get_actual_port();
    my_identity.port = actual_port;
    cout << "[INIT] Node listening on port: " << actual_port << endl;

    // 3. Initialize managers
    init_managers();

    // 4. Load routing table (bootstrap nodes)
    cout << "[INIT] Loading routing table..." << endl;
    route_table.load_db();

    // 5. Display node info
    cout << "\n" << COLOR_BRIGHT_CYAN << "=== ShellMap Node Started ===" << COLOR_RESET << "\n";
    cout << COLOR_CYAN << "Node ID: " << COLOR_RESET << my_identity.node_id << "\n";
    cout << COLOR_CYAN << "Port: " << COLOR_RESET << my_identity.port << "\n";
    cout << COLOR_CYAN << "Relay: " << COLOR_RESET << (my_identity.is_relay ? "YES" : "NO") << "\n";
    cout << COLOR_CYAN << "Type 'help' for available commands" << COLOR_RESET << "\n\n";
    
    cmd_handler->print_splash_screen();
    cmd_handler->print_prompt();
    int sockfd = net_engine.get_socket_fd();
    bool running = true;

    while (running) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);           // Network socket
        FD_SET(STDIN_FILENO, &readfds);     // User input

        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 100000;  // 100ms timeout

        int activity = select(max(sockfd, STDIN_FILENO) + 1, &readfds, NULL, NULL, &tv);

        if (activity > 0) {
            // A. Network packet received
            if (FD_ISSET(sockfd, &readfds)) {
                PacketHeader hdr;
                vector<uint8_t> payload;
                sockaddr_in sender;
                
                if (net_engine.recv_packet(hdr, payload, sender) > 0) {
                    // Dispatch packet via ProtocolManager
                    proto_mgr->dispatch_packet(hdr, payload, sender);
                    
                    // Print prompt after response packets to show command completion
                    // This provides visual feedback that async response has been processed
                    if (hdr.op_code == OpCode::FS_LIST_RES || 
                        hdr.op_code == OpCode::FS_DATA_RES ||
                        hdr.op_code == OpCode::FS_META_RES ||
                        hdr.op_code == OpCode::FS_PUT_META_RES) {
                        cmd_handler->print_prompt();
                    }
                }
            }

            // B. User input received
            if (FD_ISSET(STDIN_FILENO, &readfds)) {
                string input;
                if (getline(cin, input)) {
                    if (input == "exit" || input == "quit") {
                        running = false;
                    } else if (!input.empty()) {
                        cmd_handler->process_command(input);
                    }
                }
                cmd_handler->print_prompt();
            }
        }

        // Periodic cleanup tasks
        static int cleanup_counter = 0;
        if (++cleanup_counter % 100 == 0) {  // Every ~10 seconds
            session_mgr->cleanup_expired_sessions();
            verify_mgr->cleanup_expired_verifications();
            relay_mgr->cleanup_expired_sessions();
            web3_mgr->cleanup_expired_sessions();
            cleanup_counter = 0;
        }

        // CRITICAL: NAT Keep-Alive heartbeat
        // Send PING to keep NAT hole open every 15 seconds
        static int heartbeat_counter = 0;
        if (++heartbeat_counter % 150 == 0) {  // Every ~15 seconds (150 * 100ms)
            int pings_sent = proto_mgr->send_heartbeat_pings();
            if (pings_sent > 0) {
                // Only log if we sent PINGs
            }
            heartbeat_counter = 0;
        }

        // Detect relay fallback timeout (for Symmetric NAT)
        static int relay_check_counter = 0;
        if (++relay_check_counter % 50 == 0) {  // Every ~5 seconds
            int relayed = proto_mgr->detect_relay_fallback_timeout();
            if (relayed > 0) {
                // Relay fallback was triggered
            }
            relay_check_counter = 0;
        }
    }

    cout << "\n" << COLOR_YELLOW << "[SYSTEM] Shutting down..." << COLOR_RESET << endl;
    net_engine.close_socket();
    
    // Cleanup
    session_mgr.reset();
    verify_mgr.reset();
    relay_mgr.reset();
    web3_mgr.reset();
    cmd_handler.reset();
    proto_mgr.reset();

    cout << COLOR_GREEN << "[SYSTEM] Goodbye!" << COLOR_RESET << endl;
    return 0;
}
