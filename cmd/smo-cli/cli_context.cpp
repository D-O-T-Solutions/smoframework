#include "cli_context.hpp"

#include <cstdlib>
#include <chrono>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <iostream>

namespace smo {

namespace {

std::string context_file_path() {
    const char* home = std::getenv("HOME");
    if (!home) return "/tmp/.smo_context.json";
    return std::string(home) + "/.smo/context.json";
}

void ensure_dir(const std::string& path) {
    auto dir = std::filesystem::path(path).parent_path();
    if (!dir.empty()) std::filesystem::create_directories(dir);
}

std::string read_file(const std::string& path) {
    std::ifstream f(path);
    if (!f) return "";
    return std::string((std::istreambuf_iterator<char>(f)),
                        std::istreambuf_iterator<char>());
}

void write_file(const std::string& path, const std::string& content) {
    ensure_dir(path);
    std::ofstream f(path);
    if (f) f << content;
}

std::string json_get(const std::string& json, const std::string& key) {
    auto pos = json.find("\"" + key + "\"");
    if (pos == std::string::npos) return "";
    auto colon = json.find(':', pos);
    if (colon == std::string::npos) return "";
    auto start = json.find('"', colon);
    if (start == std::string::npos) return "";
    auto end = json.find('"', start + 1);
    if (end == std::string::npos) return "";
    return json.substr(start + 1, end - start - 1);
}

void json_set(std::string& json, const std::string& key, const std::string& value) {
    // Simple append mode for building JSON from scratch
    (void)json;
    (void)key;
    (void)value;
}

} // anonymous namespace

struct CLIContextManager::Impl {
    // Mesh context
    std::string current_mesh_;
    
    // Selection context
    SelectionContext selection_;
    bool has_selection_ = false;
    std::unordered_map<std::string, SelectionContext> saved_selections_;
    
    // Execution context
    ExecutionContext execution_;
    
    // Session
    std::optional<SessionContext> session_;
    
    // State
    std::string prompt_template_ = "{mesh}({selection})> ";
    std::vector<std::string> history_;
    size_t history_index_ = 0;
    std::string last_command_;
    std::vector<std::string> context_stack_;
    std::unordered_map<std::string, ExecutionContext> saved_execution_contexts_;

    Impl() {
        // Default execution context
        execution_.control = ControlLevel::Safe;
        execution_.scope = ExecutionScope::Single;
        execution_.timeout_ms = 30000;
        execution_.retry_count = 3;
        execution_.dry_run = false;
        load_context();
    }

    // ── Context persistence ──────────────────────────────────

    void save_context() {
        std::string path = context_file_path();
        std::ostringstream json;
        json << "{\n";
        json << "  \"current_mesh\": \"" << current_mesh_ << "\",\n";
        json << "  \"control_level\": " << static_cast<int>(execution_.control) << ",\n";
        json << "  \"execution_scope\": " << static_cast<int>(execution_.scope) << ",\n";
        json << "  \"timeout_ms\": " << execution_.timeout_ms << ",\n";
        json << "  \"retry_count\": " << execution_.retry_count << ",\n";
        json << "  \"session_address\": \"" << (session_ ? session_->node_address : "") << "\",\n";
        json << "  \"session_active\": " << (session_ && session_->is_active ? "true" : "false") << ",\n";
        json << "  \"selection_active\": " << (selection_.is_active ? "true" : "false") << "\n";
        json << "}\n";
        write_file(path, json.str());
    }

    void load_context() {
        std::string path = context_file_path();
        std::string content = read_file(path);
        if (content.empty()) return;

        auto val = [&](const std::string& k) -> std::string {
            return json_get(content, k);
        };

        current_mesh_ = val("current_mesh");

        try {
            int cl = std::stoi(val("control_level"));
            execution_.control = static_cast<ControlLevel>(cl);
        } catch (...) {}

        try {
            int es = std::stoi(val("execution_scope"));
            execution_.scope = static_cast<ExecutionScope>(es);
        } catch (...) {}

        try {
            execution_.timeout_ms = std::stoi(val("timeout_ms"));
        } catch (...) {}
        try {
            execution_.retry_count = std::stoi(val("retry_count"));
        } catch (...) {}

        if (val("session_active") == "true") {
            SessionContext sctx;
            sctx.node_address = val("session_address");
            sctx.node_name = sctx.node_address;
            sctx.connected_at = std::chrono::steady_clock::now();
            sctx.is_active = true;
            session_ = std::move(sctx);
        }

        if (val("selection_active") == "true") {
            selection_.is_active = true;
        }
    }

    // Mesh operations
    Result<void> set_mesh(const std::string& mesh_name) {
        current_mesh_ = mesh_name;
        save_context();
        return {};
    }
    
    Result<std::string> get_current_mesh() const {
        if (current_mesh_.empty()) {
            return SMO_ERR_STORAGE(404, Info, NoRetry, None, "No mesh selected");
        }
        return current_mesh_;
    }
    
    // Selection
    Result<void> set_selection(const SelectionContext& ctx) {
        selection_ = ctx;
        save_context();
        return {};
    }
    
    Result<void> clear_selection() {
        selection_ = SelectionContext{};
        save_context();
        return {};
    }
    
    Result<SelectionContext> get_selection() const {
        if (!selection_.is_active) {
            return SMO_ERR_STORAGE(404, Info, RetrySafe, None, "No active selection");
        }
        return selection_;
    }
    
    Result<void> save_selection(const std::string& name) {
        if (!selection_.is_active) {
            return SMO_ERR_STORAGE(404, Error, NoRetry, None, "No active selection to save");
        }
        saved_selections_[name] = selection_;
        return {};
    }
    
    Result<void> load_selection(const std::string& name) {
        auto it = saved_selections_.find(name);
        if (it == saved_selections_.end()) {
            return SMO_ERR_STORAGE(404, Info, RetrySafe, None, "Selection not found: " + name);
        }
        selection_ = it->second;
        return {};
    }
    
    void clear_saved_selections() {
        saved_selections_.clear();
    }
    
    // Execution context
    Result<void> set_execution_context(const ExecutionContext& ctx) {
        execution_ = ctx;
        save_context();
        return {};
    }
    
    Result<ExecutionContext> get_execution_context() const {
        return execution_;
    }
    
    void set_control_level(ControlLevel level) {
        execution_.control = level;
        save_context();
    }
    
    ControlLevel get_control_level() const {
        return execution_.control;
    }
    
    void set_scope(ExecutionScope scope) {
        execution_.scope = scope;
        save_context();
    }
    
    ExecutionScope get_scope() const {
        return execution_.scope;
    }
    
    void set_timeout(int ms) {
        execution_.timeout_ms = ms;
        save_context();
    }
    
    int get_timeout() const {
        return execution_.timeout_ms;
    }
    
    void set_retry(int count) {
        execution_.retry_count = count;
        save_context();
    }
    
    int get_retry() const {
        return execution_.retry_count;
    }
    
    void set_dry_run(bool dry) {
        execution_.dry_run = dry;
    }
    
    bool get_dry_run() const {
        return execution_.dry_run;
    }
    
    // Session management
    Result<void> connect(const std::string& node_address) {
        SessionContext ctx;
        ctx.node_address = node_address;
        ctx.node_name = node_address;
        ctx.connected_at = std::chrono::steady_clock::now();
        ctx.is_active = true;
        session_ = std::move(ctx);
        save_context();
        return {};
    }
    
    Result<void> disconnect() {
        session_.reset();
        save_context();
        return {};
    }
    
    bool is_connected() const {
        return session_.has_value() && session_->is_active;
    }
    
    std::string get_connected_node() const {
        return session_ ? session_->node_address : "";
    }
    
    // Context stack
    void push_context() {
        // Push current context to stack
        context_stack_.push_back(
            current_mesh_ + "|" + 
            std::to_string(static_cast<int>(execution_.control)) + "|" +
            std::to_string(static_cast<int>(execution_.scope))
        );
    }
    
    Result<void> pop_context() {
        if (context_stack_.empty()) {
            return SMO_ERR_STORAGE(404, Error, NoRetry, None, "No context to pop");
        }
        // Would restore previous context
        context_stack_.pop_back();
        return {};
    }
    
    // Prompt generation
    std::string get_prompt() const {
        std::string mesh_part = current_mesh_.empty() ? "no-mesh" : current_mesh_;
        std::string sel_part = has_selection() ? "sel" : "none";
        
        std::string control_str;
        switch (get_control_level()) {
            case ControlLevel::Safe: control_str = "safe"; break;
            case ControlLevel::Normal: control_str = "normal"; break;
            case ControlLevel::Force: control_str = "force"; break;
            case ControlLevel::Emergency: control_str = "emergency"; break;
        }
        
        std::string scope_str;
        switch (get_scope()) {
            case ExecutionScope::Single: scope_str = "single"; break;
            case ExecutionScope::Mesh: scope_str = "mesh"; break;
            case ExecutionScope::Quorum: scope_str = "quorum"; break;
            case ExecutionScope::Witness: scope_str = "witness"; break;
        }
        
        std::ostringstream oss;
        oss << "[" << current_mesh_ << "][" << (has_selection() ? "sel" : "none") << "]"
            << "[" << control_str << "][" << scope_str << "]> ";
        return oss.str();
    }
    
    bool has_selection() const {
        return false; // placeholder
    }
    
    void add_history(const std::string& command) {
        if (!command.empty() && (history_.empty() || history_.back() != command)) {
            history_.push_back(command);
            if (history_.size() > 1000) history_.erase(history_.begin());
        }
    }
    
    const std::vector<std::string>& get_history() const {
        return history_;
    }
};

CLIContextManager::CLIContextManager() : impl_(std::make_unique<Impl>()) {}

CLIContextManager::~CLIContextManager() = default;

Result<void> CLIContextManager::set_mesh(const std::string& mesh_name) {
    return impl_->set_mesh(mesh_name);
}

Result<std::string> CLIContextManager::get_current_mesh() const {
    return impl_->get_current_mesh();
}

Result<void> CLIContextManager::set_selection(const SelectionContext& ctx) {
    return impl_->set_selection(ctx);
}

Result<void> CLIContextManager::clear_selection() {
    return impl_->clear_selection();
}

Result<SelectionContext> CLIContextManager::get_selection() const {
    return impl_->get_selection();
}

Result<void> CLIContextManager::save_selection(const std::string& name) {
    return impl_->save_selection(name);
}

Result<void> CLIContextManager::load_selection(const std::string& name) {
    return impl_->load_selection(name);
}

void CLIContextManager::clear_saved_selections() {
    impl_->clear_saved_selections();
}

Result<void> CLIContextManager::set_execution_context(const ExecutionContext& ctx) {
    return impl_->set_execution_context(ctx);
}

Result<ExecutionContext> CLIContextManager::get_execution_context() const {
    return impl_->get_execution_context();
}

void CLIContextManager::set_control_level(ControlLevel level) {
    impl_->set_control_level(level);
}

ControlLevel CLIContextManager::get_control_level() const {
    return impl_->get_control_level();
}

void CLIContextManager::set_scope(ExecutionScope scope) {
    impl_->set_scope(scope);
}

ExecutionScope CLIContextManager::get_scope() const {
    return impl_->get_scope();
}

void CLIContextManager::set_timeout(int ms) {
    impl_->set_timeout(ms);
}

int CLIContextManager::get_timeout() const {
    return impl_->get_timeout();
}

void CLIContextManager::set_retry(int count) {
    impl_->set_retry(count);
}

int CLIContextManager::get_retry() const {
    return impl_->get_retry();
}

void CLIContextManager::set_dry_run(bool dry) {
    impl_->set_dry_run(dry);
}

bool CLIContextManager::get_dry_run() const {
    return impl_->get_dry_run();
}

Result<void> CLIContextManager::connect(const std::string& node_address) {
    return impl_->connect(node_address);
}

Result<void> CLIContextManager::disconnect() {
    return impl_->disconnect();
}

bool CLIContextManager::is_connected() const {
    return impl_->is_connected();
}

std::string CLIContextManager::get_connected_node() const {
    return impl_->get_connected_node();
}

void CLIContextManager::push_context() {
    impl_->push_context();
}

Result<void> CLIContextManager::pop_context() {
    return impl_->pop_context();
}

std::string CLIContextManager::get_prompt() const {
    return impl_->get_prompt();
}

void CLIContextManager::add_history(const std::string& command) {
    impl_->add_history(command);
}

const std::vector<std::string>& CLIContextManager::get_history() const {
    return impl_->get_history();
}

Result<void> CLIContextManager::save_execution_context(const std::string& name) {
    // Not implemented yet
    return SMO_ERR_STORAGE(905, Error, NoRetry, None, "Not implemented");
}

Result<void> CLIContextManager::load_execution_context(const std::string& name) {
    return SMO_ERR_STORAGE(905, Error, NoRetry, None, "Not implemented");
}

Result<void> CLIContextManager::initialize(const std::string& data_dir) {
    (void)data_dir;
    return {};
}

} // namespace smo