#include "structured_logger.hpp"
#include <cstdio>
#include <chrono>
#include <memory>
#include <sstream>
#include <iomanip>
#include <ctime>

namespace smo::runtime {

// ── LogEntry ────────────────────────────────────────────────────

std::string LogEntry::level_str() const noexcept {
    switch (level) {
        case LogLevel::Debug: return "debug";
        case LogLevel::Info:  return "info";
        case LogLevel::Warn:  return "warn";
        case LogLevel::Error: return "error";
        case LogLevel::Fatal: return "fatal";
    }
    return "unknown";
}

static std::string now_iso8601() {
    auto now = std::chrono::system_clock::now();
    auto tt = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    std::tm tm{};
    gmtime_r(&tt, &tm);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm);
    std::ostringstream os;
    os << buf << '.' << std::setfill('0') << std::setw(3) << ms.count() << 'Z';
    return os.str();
}

std::string LogEntry::to_json() const {
    auto escape_json = [](const std::string& s) -> std::string {
        std::string out;
        out.reserve(s.size() + 4);
        for (char c : s) {
            if (c == '"' || c == '\\') { out += '\\'; out += c; }
            else if (c == '\n') { out += "\\n"; }
            else if (c == '\t') { out += "\\t"; }
            else { out += c; }
        }
        return out;
    };

    std::string j = R"({"timestamp":")" + escape_json(timestamp) + '"';
    if (!node_id.empty())   j += R"(,"node_id":")"   + escape_json(node_id) + '"';
    if (!mesh_id.empty())   j += R"(,"mesh_id":")"   + escape_json(mesh_id) + '"';
    if (!trace_id.empty())  j += R"(,"trace_id":")"  + escape_json(trace_id) + '"';
    if (!span_id.empty())   j += R"(,"span_id":")"   + escape_json(span_id) + '"';
    if (!session_id.empty()) j += R"(,"session_id":")" + escape_json(session_id) + '"';
    if (!component.empty()) j += R"(,"component":")" + escape_json(component) + '"';
    j += R"(,"level":")" + escape_json(level_str()) + '"';
    j += R"(,"message":")" + escape_json(message) + '"';
    for (const auto& [k, v] : fields) {
        j += R"(,")" + escape_json(k) + R"(":")" + escape_json(v) + '"';
    }
    j += '}';
    return j;
}

std::string LogEntry::to_plaintext() const {
    std::string pt = '[' + timestamp + "] [" + level_str() + "]";
    if (!component.empty()) pt += " [" + component + ']';
    if (!trace_id.empty())  pt += " [trace=" + trace_id + ']';
    if (!span_id.empty())   pt += " [span=" + span_id + ']';
    pt += " " + message;
    for (const auto& [k, v] : fields) {
        pt += " " + k + '=' + v;
    }
    return pt;
}

LogEntry LogEntry::make(std::string component,
                         LogLevel level,
                         std::string message,
                         std::string trace_id,
                         std::string span_id) {
    LogEntry e;
    e.timestamp = now_iso8601();
    e.component = std::move(component);
    e.level = level;
    e.message = std::move(message);
    e.trace_id = std::move(trace_id);
    e.span_id = std::move(span_id);
    return e;
}

// ── StructuredLogger ────────────────────────────────────────────

struct StructuredLogger::Impl {
    Format format = Format::Plaintext;
    std::string node_id;
    std::string mesh_id;
    std::string component;
    bool trace_id_enabled = true;
};

StructuredLogger::StructuredLogger(Format fmt)
    : impl_(std::make_unique<Impl>()) {
    impl_->format = fmt;
}

StructuredLogger::~StructuredLogger() = default;

void StructuredLogger::set_format(Format fmt) { impl_->format = fmt; }
void StructuredLogger::set_node_id(std::string n) { impl_->node_id = std::move(n); }
void StructuredLogger::set_mesh_id(std::string m) { impl_->mesh_id = std::move(m); }
void StructuredLogger::set_component(std::string c) { impl_->component = std::move(c); }
void StructuredLogger::enable_trace_id(bool e) { impl_->trace_id_enabled = e; }
std::string StructuredLogger::node_id() const noexcept { return impl_->node_id; }

void StructuredLogger::log(LogLevel level, std::string_view message) {
    log_with_fields(level, message, {});
}

void StructuredLogger::log_with_fields(LogLevel level, std::string_view message,
                                       std::unordered_map<std::string, std::string> fields) {
    auto entry = LogEntry::make(impl_->component, level, std::string(message));
    entry.node_id = impl_->node_id;
    entry.mesh_id = impl_->mesh_id;
    if (!impl_->trace_id_enabled) {
        entry.trace_id.clear();
        entry.span_id.clear();
    }
    entry.fields = std::move(fields);

    switch (impl_->format) {
        case Format::Json:
            std::fprintf(stdout, "%s\n", entry.to_json().c_str());
            break;
        case Format::Plaintext:
            std::fprintf(stdout, "%s\n", entry.to_plaintext().c_str());
            break;
    }

    if (level == LogLevel::Fatal) {
        std::fflush(stdout);
        std::abort();
    }
}

void StructuredLogger::debug(std::string_view msg) { log(LogLevel::Debug, msg); }
void StructuredLogger::info(std::string_view msg)  { log(LogLevel::Info, msg); }
void StructuredLogger::warn(std::string_view msg)  { log(LogLevel::Warn, msg); }
void StructuredLogger::error(std::string_view msg) { log(LogLevel::Error, msg); }

// ── Global ──────────────────────────────────────────────────────

static std::unique_ptr<StructuredLogger> g_logger_ptr;

StructuredLogger& global_logger() {
    if (!g_logger_ptr) {
        g_logger_ptr = std::make_unique<StructuredLogger>();
    }
    return *g_logger_ptr;
}

void set_global_logger(std::unique_ptr<StructuredLogger> logger) {
    g_logger_ptr = std::move(logger);
}

} // namespace smo::runtime