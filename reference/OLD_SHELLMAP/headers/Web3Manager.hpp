#ifndef WEB3_MANAGER_HPP
#define WEB3_MANAGER_HPP

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <set>

/**
 * @class Web3Manager
 * @brief Quản lý Web3 features: MML, Virtual Shell, Public-First ACL
 * 
 * Trách nhiệm:
 * - Xử lý MML (Modular Markup Language) index files
 * - Xử lý virtual shell commands (ls, cd, pwd, ...)
 * - Implement public-first ACL (default public, restrict nếu .acl file exists)
 * - Track virtual filesystem state per session
 */
class Web3Manager {
public:
    struct VirtualShellSession {
        std::string current_dir;            // Current working directory
        std::map<std::string, std::string> environment;  // Shell variables
        uint64_t created_time;
        uint64_t last_command_time;
    };

    enum class AclMode {
        PUBLIC,     // Default: folder is public, everyone can access
        PRIVATE     // Private: restricted access (nếu .acl file exists)
    };

    /**
     * @brief Get ACL mode cho directory
     * @param dir_path Path đến directory
     * @return AclMode (PUBLIC nếu không có .acl file, PRIVATE nếu có)
     */
    AclMode check_acl_mode(const std::string& dir_path);

    /**
     * @brief Check if user can access path
     * @param dir_path Path đến directory
     * @param user_id ID của user muốn access
     * @return true nếu user có quyền access
     */
    bool check_access(const std::string& dir_path, const std::string& user_id);

    /**
     * @brief Get or create virtual shell session
     */
    std::shared_ptr<VirtualShellSession> get_or_create_shell_session(const std::string& node_id);

    /**
     * @brief Execute shell command (ls, cd, pwd, ...)
     * @param node_id Node ID
     * @param cmd Command string (ví dụ: "ls /path" hoặc "cd /home")
     * @return Command output
     */
    std::string execute_shell_command(const std::string& node_id, const std::string& cmd);

    /**
     * @brief Get MML index file content
     * @param dir_path Path đến directory
     * @return MML content (JSON format)
     */
    std::vector<uint8_t> get_mml_index(const std::string& dir_path);

    /**
     * @brief Lấy virtual current directory của node
     */
    std::string get_current_dir(const std::string& node_id);

    /**
     * @brief Set virtual current directory của node
     */
    void set_current_dir(const std::string& node_id, const std::string& dir);

    /**
     * @brief Parse ACL file (.acl)
     * @param acl_path Path đến .acl file
     * @return Set of user IDs có quyền access
     */
    std::set<std::string> parse_acl_file(const std::string& acl_path);

    /**
     * @brief Cleanup expired shell sessions
     */
    void cleanup_expired_sessions(uint64_t timeout_ms = 3600000);  // 1 hour

    /**
     * @brief List all active shell sessions
     */
    std::map<std::string, std::shared_ptr<VirtualShellSession>> get_all_sessions();

private:
    std::map<std::string, std::shared_ptr<VirtualShellSession>> shell_sessions_;
    std::map<std::string, AclMode> acl_cache_;  // Cache ACL mode per directory
    std::map<std::string, std::set<std::string>> acl_file_cache_;  // Cache ACL permissions

    /**
     * @brief List files trong directory (local filesystem)
     */
    std::string list_directory(const std::string& dir_path);

    /**
     * @brief Change directory
     */
    bool change_directory(const std::string& node_id, const std::string& new_dir);

    /**
     * @brief Get absolute path, resolve symlinks/.. etc
     */
    std::string resolve_path(const std::string& base_dir, const std::string& relative_path);

    /**
     * @brief Generate MML JSON index
     */
    std::string generate_mml_index_json(const std::string& dir_path);
};

#endif // WEB3_MANAGER_HPP
