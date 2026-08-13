#include "cli_context.hpp"

#include <cstdlib>
#include <chrono>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <iostream>
#include <vector>
#include <cstring>
#include <poll.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#include <fcntl.h>
#include "core/errors/error.hpp"
#include "core/enroll/join_token.hpp"
#include "core/enroll/auto_enroll.hpp"
#include "core/transport/framing.hpp"
#include "core/transport/secure_session.hpp"
#include "core/crypto/registry.hpp"
#include "core/crypto/suite.hpp"
#include "protocol/packet/packet.h"
#include "providers/suite1_classical/suite1_classical_provider.hpp"
#ifdef SMO_WITH_PQC
#include "providers/suite3_purepqc/suite3_purepqc_provider.hpp"
#endif

namespace smo {

    namespace {

        static void ensure_crypto_registered()
        {
            static bool initialized = false;
            if (initialized)
                return;
            initialized = true;

            smo::providers::register_suite1_classical();
#ifdef SMO_WITH_PQC
            smo::providers::register_suite3_purepqc();
#endif
        }

        static std::string json_escape(const std::string& s)
        {
            std::string out;
            out.reserve(s.size() + 8);
            for (char c : s)
            {
                switch (c)
                {
                case '"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default: out += c; break;
                }
            }
            return out;
        }

        static int tcp_connect(const std::string& host, uint16_t port, int timeout_ms = 10000)
        {
            struct addrinfo hints{}, *res = nullptr;
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            std::string port_str = std::to_string(port);
            int gai_err = ::getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res);
            if (gai_err != 0 || !res)
            {
                return -1;
            }

            int fd = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
            if (fd < 0)
            {
                ::freeaddrinfo(res);
                return -1;
            }

            // Non-blocking connect with timeout
            int flags = fcntl(fd, F_GETFL, 0);
            if (flags >= 0)
                fcntl(fd, F_SETFL, flags | O_NONBLOCK);

            int connect_res = ::connect(fd, res->ai_addr, res->ai_addrlen);
            ::freeaddrinfo(res);

            if (connect_res < 0 && errno != EINPROGRESS)
            {
                ::close(fd);
                return -1;
            }

            if (connect_res == 0)
            {
                // Connected immediately
                if (flags >= 0)
                    fcntl(fd, F_SETFL, flags);
                return fd;
            }

            // Wait for connect to complete
            struct pollfd pfd{fd, POLLOUT, 0};
            int poll_res = poll(&pfd, 1, timeout_ms);
            if (poll_res <= 0)
            {
                ::close(fd);
                return -1;
            }

            // Check connect status
            int so_error = 0;
            socklen_t len = sizeof(so_error);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0 || so_error != 0)
            {
                ::close(fd);
                return -1;
            }

            // Restore blocking mode
            if (flags >= 0)
                fcntl(fd, F_SETFL, flags);

            // Set receive timeout for all subsequent reads
            struct timeval tv;
            tv.tv_sec = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

            return fd;
        }

        std::string context_file_path()
        {
            const char* home = std::getenv("HOME");
            if (!home)
                return "/tmp/.smo_context.json";
            return std::string(home) + "/.smo/context.json";
        }

        void ensure_dir(const std::string& path)
        {
            auto dir = std::filesystem::path(path).parent_path();
            if (!dir.empty())
                std::filesystem::create_directories(dir);
        }

        std::string read_file(const std::string& path)
        {
            std::ifstream f(path);
            if (!f)
                return "";
            return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        }

        void write_file(const std::string& path, const std::string& content)
        {
            ensure_dir(path);
            std::ofstream f(path);
            if (f)
                f << content;
        }

        std::string json_get(const std::string& json, const std::string& key)
        {
            auto pos = json.find("\"" + key + "\"");
            if (pos == std::string::npos)
                return "";
            auto colon = json.find(':', pos);
            if (colon == std::string::npos)
                return "";
            auto start = json.find('"', colon);
            if (start == std::string::npos)
                return "";
            auto end = json.find('"', start + 1);
            if (end == std::string::npos)
                return "";
            return json.substr(start + 1, end - start - 1);
        }

        void json_set(std::string& json, const std::string& key, const std::string& value)
        {
            (void)json;
            (void)key;
            (void)value;
        }

    } // anonymous namespace

    struct CLIContextManager::Impl
    {
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
        std::string data_dir_;
        std::string node_name_;
        int port_ = 5454;

        Impl()
        {
            // Default execution context
            execution_.control = ControlLevel::Safe;
            execution_.scope = ExecutionScope::Single;
            execution_.timeout_ms = 30000;
            execution_.retry_count = 3;
            execution_.dry_run = false;
            load_context();
        }

        // ── Context persistence ──────────────────────────────────

        void save_context()
        {
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

        void load_context()
        {
            std::string path = context_file_path();
            std::string content = read_file(path);
            if (content.empty())
                return;

            auto val = [&](const std::string& k) -> std::string { return json_get(content, k); };

            current_mesh_ = val("current_mesh");

            try
            {
                int cl = std::stoi(val("control_level"));
                execution_.control = static_cast<ControlLevel>(cl);
            }
            catch (...)
            {
            }

            try
            {
                int es = std::stoi(val("execution_scope"));
                execution_.scope = static_cast<ExecutionScope>(es);
            }
            catch (...)
            {
            }

            try
            {
                execution_.timeout_ms = std::stoi(val("timeout_ms"));
            }
            catch (...)
            {
            }
            try
            {
                execution_.retry_count = std::stoi(val("retry_count"));
            }
            catch (...)
            {
            }

            if (val("session_active") == "true")
            {
                SessionContext sctx;
                sctx.node_address = val("session_address");
                sctx.node_name = sctx.node_address;
                sctx.connected_at = std::chrono::steady_clock::now();
                sctx.is_active = true;
                session_ = std::move(sctx);
            }

            if (val("selection_active") == "true")
            {
                selection_.is_active = true;
            }
        }

        // Mesh operations
        Result<void> set_mesh(const std::string& mesh_name)
        {
            current_mesh_ = mesh_name;
            save_context();
            return {};
        }

        Result<std::string> get_current_mesh() const
        {
            if (current_mesh_.empty())
            {
                return SMO_ERR_STORAGE(404, Info, NoRetry, None, "No mesh selected");
            }
            return current_mesh_;
        }

        // Selection
        Result<void> set_selection(const SelectionContext& ctx)
        {
            selection_ = ctx;
            save_context();
            return {};
        }

        Result<void> clear_selection()
        {
            selection_ = SelectionContext{};
            save_context();
            return {};
        }

        Result<SelectionContext> get_selection() const
        {
            if (!selection_.is_active)
            {
                return SMO_ERR_STORAGE(404, Info, RetrySafe, None, "No active selection");
            }
            return selection_;
        }

        Result<void> save_selection(const std::string& name)
        {
            if (!selection_.is_active)
            {
                return SMO_ERR_STORAGE(404, Error, NoRetry, None, "No active selection to save");
            }
            saved_selections_[name] = selection_;
            return {};
        }

        Result<void> load_selection(const std::string& name)
        {
            auto it = saved_selections_.find(name);
            if (it == saved_selections_.end())
            {
                return SMO_ERR_STORAGE(404, Info, RetrySafe, None, "Selection not found: " + name);
            }
            selection_ = it->second;
            return {};
        }

        void clear_saved_selections() { saved_selections_.clear(); }

        // Execution context
        Result<void> set_execution_context(const ExecutionContext& ctx)
        {
            execution_ = ctx;
            save_context();
            return {};
        }

        Result<ExecutionContext> get_execution_context() const { return execution_; }

        void set_control_level(ControlLevel level)
        {
            execution_.control = level;
            save_context();
        }

        ControlLevel get_control_level() const { return execution_.control; }

        void set_scope(ExecutionScope scope)
        {
            execution_.scope = scope;
            save_context();
        }

        ExecutionScope get_scope() const { return execution_.scope; }

        void set_timeout(int ms)
        {
            execution_.timeout_ms = ms;
            save_context();
        }

        int get_timeout() const { return execution_.timeout_ms; }

        void set_retry(int count)
        {
            execution_.retry_count = count;
            save_context();
        }

        int get_retry() const { return execution_.retry_count; }

        void set_dry_run(bool dry) { execution_.dry_run = dry; }

        bool get_dry_run() const { return execution_.dry_run; }

        // Session management
        Result<void> connect(const std::string& node_address)
        {
            SessionContext ctx;
            ctx.node_address = node_address;
            ctx.node_name = node_address;
            ctx.connected_at = std::chrono::steady_clock::now();
            ctx.is_active = true;
            session_ = std::move(ctx);
            save_context();
            return {};
        }

        Result<void> disconnect()
        {
            session_.reset();
            save_context();
            return {};
        }

        bool is_connected() const { return session_.has_value() && session_->is_active; }

        std::string get_connected_node() const { return session_ ? session_->node_address : ""; }

        // Context stack
        void push_context()
        {
            // Push current context to stack
            context_stack_.push_back(current_mesh_ + "|" + std::to_string(static_cast<int>(execution_.control)) + "|" +
                                     std::to_string(static_cast<int>(execution_.scope)));
        }

        Result<void> pop_context()
        {
            if (context_stack_.empty())
            {
                return SMO_ERR_STORAGE(404, Error, NoRetry, None, "No context to pop");
            }
            // Would restore previous context
            context_stack_.pop_back();
            return {};
        }

        // Prompt generation
        std::string get_prompt() const
        {
            std::string mesh_part = current_mesh_.empty() ? "no-mesh" : current_mesh_;
            std::string sel_part = has_selection() ? "sel" : "none";

            std::string control_str;
            switch (get_control_level())
            {
            case ControlLevel::Safe:
                control_str = "safe";
                break;
            case ControlLevel::Normal:
                control_str = "normal";
                break;
            case ControlLevel::Force:
                control_str = "force";
                break;
            case ControlLevel::Emergency:
                control_str = "emergency";
                break;
            }

            std::string scope_str;
            switch (get_scope())
            {
            case ExecutionScope::Single:
                scope_str = "single";
                break;
            case ExecutionScope::Mesh:
                scope_str = "mesh";
                break;
            case ExecutionScope::Quorum:
                scope_str = "quorum";
                break;
            case ExecutionScope::Witness:
                scope_str = "witness";
                break;
            }

            std::ostringstream oss;
            oss << "[" << current_mesh_ << "][" << (has_selection() ? "sel" : "none") << "]"
                << "[" << control_str << "][" << scope_str << "]> ";
            return oss.str();
        }

        bool has_selection() const
        {
            return false; // placeholder
        }

        void add_history(const std::string& command)
        {
            if (!command.empty() && (history_.empty() || history_.back() != command))
            {
                history_.push_back(command);
                if (history_.size() > 1000)
                    history_.erase(history_.begin());
            }
        }

        const std::vector<std::string>& get_history() const { return history_; }

        void set_port(int port) { port_ = port; }
        std::optional<int> get_port() const { return port_ > 0 ? std::optional<int>(port_) : std::nullopt; }
        void set_data_dir(const std::string& dir) { data_dir_ = dir; }
        std::string get_data_dir() const { return data_dir_; }
        void set_node_name(const std::string& name) { node_name_ = name; }
        std::string get_node_name() const { return node_name_; }
    };

    CLIContextManager::CLIContextManager() : impl_(std::make_unique<Impl>()) {}

    CLIContextManager::~CLIContextManager() = default;

    Result<void> CLIContextManager::set_mesh(const std::string& mesh_name)
    {
        return impl_->set_mesh(mesh_name);
    }

    Result<std::string> CLIContextManager::get_current_mesh() const
    {
        return impl_->get_current_mesh();
    }

    Result<void> CLIContextManager::set_selection(const SelectionContext& ctx)
    {
        return impl_->set_selection(ctx);
    }

    Result<void> CLIContextManager::clear_selection()
    {
        return impl_->clear_selection();
    }

    Result<SelectionContext> CLIContextManager::get_selection() const
    {
        return impl_->get_selection();
    }

    Result<void> CLIContextManager::save_selection(const std::string& name)
    {
        return impl_->save_selection(name);
    }

    Result<void> CLIContextManager::load_selection(const std::string& name)
    {
        return impl_->load_selection(name);
    }

    void CLIContextManager::clear_saved_selections()
    {
        impl_->clear_saved_selections();
    }

    Result<void> CLIContextManager::set_execution_context(const ExecutionContext& ctx)
    {
        return impl_->set_execution_context(ctx);
    }

    Result<ExecutionContext> CLIContextManager::get_execution_context() const
    {
        return impl_->get_execution_context();
    }

    void CLIContextManager::set_control_level(ControlLevel level)
    {
        impl_->set_control_level(level);
    }

    ControlLevel CLIContextManager::get_control_level() const
    {
        return impl_->get_control_level();
    }

    void CLIContextManager::set_scope(ExecutionScope scope)
    {
        impl_->set_scope(scope);
    }

    ExecutionScope CLIContextManager::get_scope() const
    {
        return impl_->get_scope();
    }

    void CLIContextManager::set_timeout(int ms)
    {
        impl_->set_timeout(ms);
    }

    int CLIContextManager::get_timeout() const
    {
        return impl_->get_timeout();
    }

    void CLIContextManager::set_retry(int count)
    {
        impl_->set_retry(count);
    }

    int CLIContextManager::get_retry() const
    {
        return impl_->get_retry();
    }

    void CLIContextManager::set_dry_run(bool dry)
    {
        impl_->set_dry_run(dry);
    }

    bool CLIContextManager::get_dry_run() const
    {
        return impl_->get_dry_run();
    }

    Result<void> CLIContextManager::connect(const std::string& node_address)
    {
        return impl_->connect(node_address);
    }

    Result<void> CLIContextManager::disconnect()
    {
        return impl_->disconnect();
    }

    bool CLIContextManager::is_connected() const
    {
        return impl_->is_connected();
    }

    std::string CLIContextManager::get_connected_node() const
    {
        return impl_->get_connected_node();
    }

    void CLIContextManager::push_context()
    {
        impl_->push_context();
    }

    Result<void> CLIContextManager::pop_context()
    {
        return impl_->pop_context();
    }

    std::string CLIContextManager::get_prompt() const
    {
        return impl_->get_prompt();
    }

    void CLIContextManager::add_history(const std::string& command)
    {
        impl_->add_history(command);
    }

    const std::vector<std::string>& CLIContextManager::get_history() const
    {
        return impl_->get_history();
    }

    void CLIContextManager::set_port(int port)
    {
        impl_->set_port(port);
    }
    std::optional<int> CLIContextManager::get_port() const
    {
        return impl_->get_port();
    }
    void CLIContextManager::set_data_dir(const std::string& dir)
    {
        impl_->set_data_dir(dir);
    }
    std::string CLIContextManager::get_data_dir() const
    {
        return impl_->get_data_dir();
    }
    void CLIContextManager::set_node_name(const std::string& name)
    {
        impl_->set_node_name(name);
    }
    std::string CLIContextManager::get_node_name() const
    {
        return impl_->get_node_name();
    }

    Result<void> CLIContextManager::save_execution_context(const std::string& name)
    {
        // Not implemented yet
        return SMO_ERR_STORAGE(905, Error, NoRetry, None, "Not implemented");
    }

    Result<void> CLIContextManager::load_execution_context(const std::string& name)
    {
        return SMO_ERR_STORAGE(905, Error, NoRetry, None, "Not implemented");
    }

    Result<void> CLIContextManager::initialize(const std::string& data_dir)
    {
        if (!data_dir.empty())
        {
            set_data_dir(data_dir);
        }
        return {};
    }

Result<std::string> CLIContextManager::network_execute(const std::string& node_address,
                                                             uint32_t opcode,
                                                             const std::string& method,
                                                             const std::unordered_map<std::string, std::string>& args)
    {
        // Ensure crypto providers are registered (lazy init for REPL)
        ensure_crypto_registered();

        // 1. Parse host:port
        auto colon = node_address.rfind(':');
        if (colon == std::string::npos)
        {
            return SMO_ERR_TRANSPORT(306, Error, NoRetry, None, "node address must be host:port");
        }
        std::string host = node_address.substr(0, colon);
        uint16_t port = static_cast<uint16_t>(std::stoul(node_address.substr(colon + 1)));

        // 2. Get PQC crypto provider (matches smo-node daemon)
        auto& reg = smo::CryptoRegistry::instance();
        auto crypto_res = reg.get_suite(smo::kSuitePurePQC);
        if (!crypto_res)
        {
            return crypto_res.error();
        }
        const auto* crypto = crypto_res.value();

        // 3. TCP connect + version handshake
        int fd = tcp_connect(host, port, 15000);
        if (fd < 0)
        {
            return SMO_ERR_TRANSPORT(304, Error, RetrySafe, Reconnect, "connection refused: " + node_address);
        }

        auto ver_res = smo::version_handshake_client(fd);
        if (!ver_res)
        {
            ::close(fd);
            return SMO_ERR_TRANSPORT(313, Error, NoRetry, Reconnect, "version handshake failed: " + ver_res.error().message);
        }

        // 4. PQ handshake (client role)
        smo::SecureSession::Config sec_cfg;
        sec_cfg.role = smo::SecureSession::Role::Client;
        smo::SecureSession sec(fd, sec_cfg, *crypto);
        auto hs = sec.handshake();
        if (!hs)
        {
            ::close(fd);
            return hs.error();
        }

        // 5. Build JSON payload: {"method":"...", "key":"value", ...}
        std::string payload = "{\"method\":\"" + json_escape(method) + "\"";
        for (const auto& [k, v] : args)
        {
            payload += ",\"" + json_escape(k) + "\":\"" + json_escape(v) + "\"";
        }
        payload += "}";

        // 6. Build packet + frame
        smo::Packet pkt;
        pkt.header.version = 1;
        pkt.opcode_id = opcode;
        pkt.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count();
        pkt.payload.assign(payload.begin(), payload.end());

        std::vector<uint8_t> buf;
        auto pack_res = smo::packet_to_buffer(pkt, buf);
        if (!pack_res)
        {
            return pack_res.error();
        }

        smo::Bytes framed;
        smo::frame_write(smo::BytesView(buf.data(), buf.size()), smo::kFrameFlagNone, framed);

        // 7. Send over secure session
        auto send_res = sec.send(smo::BytesView(framed));
        if (!send_res)
        {
            return send_res.error();
        }

        // 8. Receive response
        auto enc_resp = sec.recv();
        if (!enc_resp)
        {
            return enc_resp.error();
        }

        // 9. Unframe + parse response packet
        smo::FrameHeader fh;
        smo::BytesView resp_payload;
        size_t frame_sz = smo::frame_read(smo::BytesView(enc_resp.value().data(), enc_resp.value().size()), fh, resp_payload);
        if (frame_sz == 0)
        {
            return SMO_ERR_TRANSPORT(309, Error, RetrySafe, None, "failed to unframe response");
        }

        auto resp_pkt = smo::packet_from_buffer(resp_payload);
        if (!resp_pkt)
        {
            return resp_pkt.error();
        }

        // 10. Return payload as string
        const auto& rp = resp_pkt.value().payload;
        return std::string(rp.begin(), rp.end());
    }

} // namespace smo