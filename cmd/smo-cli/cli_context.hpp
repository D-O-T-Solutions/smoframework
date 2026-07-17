#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <unordered_map>
#include <functional>
#include <chrono>
#include <memory>
#include "core/types.hpp"
#include "core/errors/error.hpp"
#include "core/contract/contract.hpp"
#include "core/acl/policy_engine.hpp"

namespace smo {

// ===========================================================================
// CLI Context Management
// ===========================================================================

struct SelectionContext {
    std::vector<std::string> node_names;
    std::vector<std::string> node_ids;
    std::vector<std::string> roles;
    std::vector<std::string> tags;
    std::string where_expression;
    std::string mesh_name;
    std::string os_filter;
    std::string arch_filter;
    std::string version_filter;
    std::optional<float> trust_min;
    std::optional<float> trust_max;
    std::string saved_name;
    bool is_active = false;
};

struct ExecutionContext {
    ControlLevel control = ControlLevel::Safe;
    ExecutionScope scope = ExecutionScope::Single;
    int timeout_ms = 30000;
    int retry_count = 3;
    bool dry_run = false;
    std::string policy_name;
};

struct SessionContext {
    std::string node_address;
    std::string node_name;
    std::string mesh_name;
    std::chrono::steady_clock::time_point connected_at;
    bool is_active = false;
};

struct CLIContext {
    std::string current_mesh;
    SelectionContext selection;
    ExecutionContext execution;
    std::optional<SessionContext> session;
    std::string prompt;
    std::vector<std::string> history;
    std::unordered_map<std::string, SelectionContext> saved_selections;
    std::unordered_map<std::string, ExecutionContext> saved_execution_contexts;
    std::vector<std::string> context_stack;  // For push/pop
    std::string data_dir;    // Data directory
    std::string node_name;   // Node name
    int port = 5454;         // Listen port
};

class CLIContextManager {
public:
    explicit CLIContextManager();
    ~CLIContextManager();

    CLIContextManager(const CLIContextManager&) = delete;
    CLIContextManager& operator=(const CLIContextManager&) = delete;

    // Mesh context
    Result<void> set_mesh(const std::string& mesh_name);
    Result<std::string> get_current_mesh() const;

    // Selection context
    Result<void> set_selection(const SelectionContext& ctx);
    Result<void> clear_selection();
    Result<SelectionContext> get_selection() const;
    Result<void> save_selection(const std::string& name);
    Result<void> load_selection(const std::string& name);
    void clear_saved_selections();

    // Execution context
    Result<void> set_execution_context(const ExecutionContext& ctx);
    Result<ExecutionContext> get_execution_context() const;
    void set_control_level(ControlLevel level);
    ControlLevel get_control_level() const;
    void set_scope(ExecutionScope scope);
    ExecutionScope get_scope() const;
    void set_timeout(int ms);
    int get_timeout() const;
    void set_retry(int count);
    int get_retry() const;
    void set_dry_run(bool dry);
    bool get_dry_run() const;

    // Session management
    Result<void> connect(const std::string& node_address);
    Result<void> disconnect();
    bool is_connected() const;
    std::string get_connected_node() const;

    // Context stack (push/pop)
    void push_context();
    Result<void> pop_context();

    // Prompt generation
    std::string get_prompt() const;
    
    // History
    void add_history(const std::string& command);
    const std::vector<std::string>& get_history() const;

    // Port
    void set_port(int port);
    std::optional<int> get_port() const;

    // Data dir
    void set_data_dir(const std::string& dir);
    std::string get_data_dir() const;
    
    // Node name
    void set_node_name(const std::string& name);
    std::string get_node_name() const;

    // Saved contexts
    Result<void> save_execution_context(const std::string& name);
    Result<void> load_execution_context(const std::string& name);

    // Initialize
    Result<void> initialize(const std::string& data_dir);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace smo