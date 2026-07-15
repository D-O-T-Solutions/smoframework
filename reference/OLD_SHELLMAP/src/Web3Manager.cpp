#include "Web3Manager.hpp"
#include <iostream>
#include <filesystem>
#include <fstream>

Web3Manager::AclMode Web3Manager::check_acl_mode(const std::string& dir_path) {
    std::string acl_file = dir_path + "/.acl";
    if (std::filesystem::exists(acl_file)) {
        return AclMode::PRIVATE;
    }
    return AclMode::PUBLIC;
}

bool Web3Manager::check_access(const std::string& dir_path, const std::string& user_id) {
    if (check_acl_mode(dir_path) == AclMode::PUBLIC) {
        return true;  // Public folder, everyone can access
    }
    
    // Private folder - check ACL file
    auto acl_list = parse_acl_file(dir_path + "/.acl");
    return acl_list.find(user_id) != acl_list.end();
}

std::shared_ptr<Web3Manager::VirtualShellSession> Web3Manager::get_or_create_shell_session(const std::string& node_id) {
    auto it = shell_sessions_.find(node_id);
    if (it != shell_sessions_.end()) {
        return it->second;
    }

    auto session = std::make_shared<VirtualShellSession>();
    session->current_dir = "/";
    shell_sessions_[node_id] = session;
    return session;
}

std::string Web3Manager::execute_shell_command(const std::string& node_id, const std::string& cmd) {
    auto session = get_or_create_shell_session(node_id);
    // TODO: Parse and execute shell command (ls, cd, pwd, etc.)
    return "";
}

std::vector<uint8_t> Web3Manager::get_mml_index(const std::string& dir_path) {
    std::string json_content = generate_mml_index_json(dir_path);
    return std::vector<uint8_t>(json_content.begin(), json_content.end());
}

std::string Web3Manager::get_current_dir(const std::string& node_id) {
    auto session = get_or_create_shell_session(node_id);
    return session->current_dir;
}

void Web3Manager::set_current_dir(const std::string& node_id, const std::string& dir) {
    auto session = get_or_create_shell_session(node_id);
    session->current_dir = dir;
}

std::set<std::string> Web3Manager::parse_acl_file(const std::string& acl_path) {
    // TODO: Parse .acl file (JSON or text format)
    return {};
}

void Web3Manager::cleanup_expired_sessions(uint64_t timeout_ms) {
    // TODO: Implement timeout logic
}

std::map<std::string, std::shared_ptr<Web3Manager::VirtualShellSession>> Web3Manager::get_all_sessions() {
    return shell_sessions_;
}

std::string Web3Manager::list_directory(const std::string& dir_path) {
    // TODO: List files in directory
    return "";
}

bool Web3Manager::change_directory(const std::string& node_id, const std::string& new_dir) {
    // TODO: Change virtual directory
    return true;
}

std::string Web3Manager::resolve_path(const std::string& base_dir, const std::string& relative_path) {
    // TODO: Resolve path properly
    return base_dir;
}

std::string Web3Manager::generate_mml_index_json(const std::string& dir_path) {
    // TODO: Generate MML JSON index
    return "{}";
}
