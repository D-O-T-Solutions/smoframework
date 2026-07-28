#pragma once

#include <string>
#include <string_view>
#include <unordered_map>
#include <memory>
#include <cstdint>

namespace smo::runtime {

enum class LogLevel {
    Debug,
    Info,
    Warn,
    Error,
    Fatal
};

struct LogEntry {
    std::string timestamp;
    std::string node_id;
    std::string mesh_id;
    std::string trace_id;
    std::string span_id;
    std::string session_id;
    std::string component;
    LogLevel    level;
    std::string message;
    std::unordered_map<std::string, std::string> fields;

    std::string level_str() const noexcept;
    std::string to_json() const;
    std::string to_plaintext() const;

    static LogEntry make(std::string component,
                         LogLevel level,
                         std::string message,
                         std::string trace_id = "",
                         std::string span_id = "");
};

class StructuredLogger {
public:
    enum class Format { Plaintext, Json };

    explicit StructuredLogger(Format fmt = Format::Plaintext);
    ~StructuredLogger();

    void set_format(Format fmt);
    void set_node_id(std::string node_id);
    void set_mesh_id(std::string mesh_id);
    void set_component(std::string component);
    void enable_trace_id(bool enable);

    void log(LogLevel level, std::string_view message);
    void log_with_fields(LogLevel level, std::string_view message,
                         std::unordered_map<std::string, std::string> fields);

    void debug(std::string_view msg);
    void info(std::string_view msg);
    void warn(std::string_view msg);
    void error(std::string_view msg);

    std::string node_id() const noexcept;

    struct Impl;

private:
    std::unique_ptr<Impl> impl_;
};

StructuredLogger& global_logger();
void set_global_logger(std::unique_ptr<StructuredLogger> logger);

} // namespace smo::runtime