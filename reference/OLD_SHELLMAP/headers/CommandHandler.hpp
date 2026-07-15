#ifndef COMMAND_HANDLER_HPP
#define COMMAND_HANDLER_HPP

#include <string>
#include <vector>
#include <map>
#include <memory>
#include "Protocol.hpp"
#include "NetworkEngine.hpp"
#include "RoutingTable.hpp"

// Forward declarations
class SessionManager;
class VerificationManager;
class Web3Manager;
class FileManager;
class ProtocolManager;
struct NodeContext;

// ==========================================
// ANSI COLOR CODES
// ==========================================
#define COLOR_RESET     "\033[0m"
#define COLOR_CYAN      "\033[36m"
#define COLOR_GREEN     "\033[32m"
#define COLOR_YELLOW    "\033[33m"
#define COLOR_RED       "\033[31m"
#define COLOR_MAGENTA   "\033[35m"
#define COLOR_BRIGHT_GREEN   "\033[1;32m"
#define COLOR_BRIGHT_CYAN    "\033[1;36m"

/**
 * @class CommandHandler
 * @brief Xử lý các lệnh từ keyboard (interactive CLI)
 * 
 * Trách nhiệm:
 * - Parse lệnh từ user (connect, ls, get, put, verify, ...)
 * - Gữi request packets qua network
 * - Hiển thị kết quả cho user
 * - Quản lý state hiện tại (current_target, current_dir)
 * - Cung cấp TUI với màu sắc ANSI
 */
class CommandHandler {
public:
    CommandHandler(
        std::shared_ptr<SessionManager> session_mgr,
        std::shared_ptr<VerificationManager> verify_mgr,
        std::shared_ptr<Web3Manager> web3_mgr,
        FileManager* file_mgr,
        NetworkEngine& net_engine,
        RoutingTable& route_table,
        std::shared_ptr<ProtocolManager> proto_mgr,
        NodeContext* node_ctx = nullptr
    );

    /**
     * @brief Process user command từ stdin
     * @param cmd Command string (ví dụ: "connect 192.168.1.100:5556")
     * @return true nếu command processed thành công
     */
    bool process_command(const std::string& cmd);

    /**
     * @brief Set current target node
     * @param target Target ID (hex string)
     */
    void set_current_target(const std::string& target);

    /**
     * @brief Get current target
     */
    std::string get_current_target() const { return current_target_; }

    /**
     * @brief Get current working directory (virtual)
     */
    std::string get_current_dir() const { return current_dir_; }

    /**
     * @brief Set current directory
     */
    void set_current_dir(const std::string& dir) { current_dir_ = dir; }

    /**
     * @brief Get current target node ID (NEW)
     */
    std::string get_current_target_id() const { return current_target_id_; }

    /**
     * @brief Reset current connection (NEW)
     */
    void reset_target() { current_target_ = ""; current_target_id_ = ""; }

    /**
     * @brief Print command help
     */
    void print_help();

    /**
     * @brief Print current prompt with TUI styling
     */
    void print_prompt();

    /**
     * @brief Print splash screen with ASCII art
     */
    void print_splash_screen();

private:
    // Dependencies
    std::shared_ptr<SessionManager> session_mgr_;
    std::shared_ptr<VerificationManager> verify_mgr_;
    std::shared_ptr<Web3Manager> web3_mgr_;
    FileManager* file_mgr_;
    NetworkEngine& net_engine_;
    RoutingTable& route_table_;
    std::shared_ptr<ProtocolManager> proto_mgr_;  // NEW: Protocol manager for handshake/ping
    NodeContext* node_ctx_;  // Pointer to our node identity

    // State
    std::string current_target_;  // Current node to interact with
    std::string current_target_id_;  // Current connected peer's node ID (NEW)
    std::string current_dir_;     // Virtual current directory
    bool is_relay_mode_ = false;  // Relay mode on/off
    std::string node_id_;         // Our own node ID (shortened for display)
    bool is_connected_ = false;   // Whether we're connected to a peer

    // --- Command handlers ---
    
    /// Network commands
    bool cmd_connect(const std::vector<std::string>& args);      // connect <id|ip:port>
    bool cmd_discover(const std::vector<std::string>& args);     // discover
    bool cmd_find(const std::vector<std::string>& args);         // find <target_id>
    bool cmd_list_peers(const std::vector<std::string>& args);   // peers
    bool cmd_list_nodes(const std::vector<std::string>& args);   // nodes (NEW)
    bool cmd_relay_mode(const std::vector<std::string>& args);   // relay on|off
    bool cmd_verify(const std::vector<std::string>& args);       // verify
    bool cmd_ping(const std::vector<std::string>& args);         // ping
    bool cmd_send(const std::vector<std::string>& args);         // send <node_id> <message> (NEW: send encrypted message)
    bool cmd_me(const std::vector<std::string>& args);           // me (NEW: show dashboard)
    bool cmd_myid(const std::vector<std::string>& args);         // myid (NEW: show full ID with clipboard)

    /// File system commands
    bool cmd_ls(const std::vector<std::string>& args);           // ls [path]
    bool cmd_get(const std::vector<std::string>& args);          // get <filename>
    bool cmd_put(const std::vector<std::string>& args);          // put <filename>
    bool cmd_pwd(const std::vector<std::string>& args);          // pwd
    bool cmd_cd(const std::vector<std::string>& args);           // cd <path>
    bool cmd_myshare(const std::vector<std::string>& args);      // myshare [-o] (NEW)
    bool cmd_mydownload(const std::vector<std::string>& args);   // mydownload [-o] (NEW)

    /// Web3 commands
    bool cmd_mml(const std::vector<std::string>& args);          // mml [path]
    bool cmd_shell(const std::vector<std::string>& args);        // shell <cmd>
    bool cmd_acl(const std::vector<std::string>& args);          // acl list|add|remove
    bool cmd_config(const std::vector<std::string>& args);       // config get|set

     /// System commands
      bool cmd_help(const std::vector<std::string>& args);         // help [cmd]
     bool cmd_exit(const std::vector<std::string>& args);         // exit
     bool cmd_bye(const std::vector<std::string>& args);          // bye (HOTFIX: disconnect without closing session)
     bool cmd_return(const std::vector<std::string>& args);       // return N (switch to session N)
     bool cmd_reconnect(const std::vector<std::string>& args);    // reconnect (close and re-establish current session)

    // Utility methods
    std::vector<std::string> parse_command(const std::string& cmd);
    std::string extract_node_id(const std::string& arg);
    bool is_valid_node_id(const std::string& id);
     bool get_active_session();  // HOTFIX: Convert IP:Port to node_id and update current_target_
    
     // TUI helpers (NEW)
     void print_table_header(const std::vector<std::string>& cols);
     void print_table_row(const std::vector<std::string>& cols);
     void print_table_separator(const std::vector<int>& widths);
};

#endif // COMMAND_HANDLER_HPP

