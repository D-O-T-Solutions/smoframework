#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include "core/types.hpp"
#include "core/errors/error.hpp"

namespace smo::contract::native {

// ===========================================================================
// Transfer Contracts
// ===========================================================================

struct FilePutRequest {
    std::string local_path;
    std::string remote_path;
    bool overwrite = false;
    bool create_dirs = true;
    uint32_t mode = 0644;
    std::string checksum;  // Expected checksum (SHA256 hex)
    std::string algorithm; // sha256, blake3
};

struct FilePutResponse {
    std::string remote_path;
    bool uploaded = false;
    uint64_t bytes_sent = 0;
    std::string checksum;
    std::string algorithm;
    double duration_ms = 0;
};

struct FileGetRequest {
    std::string remote_path;
    std::string local_path;
    bool overwrite = false;
    int64_t offset = 0;
    int64_t length = -1;
};

struct FileGetResponse {
    std::string local_path;
    bool downloaded = false;
    uint64_t bytes_received = 0;
    std::string checksum;
    std::string algorithm;
    double duration_ms = 0;
};

struct SyncRequest {
    std::string local_path;
    std::string remote_path;
    bool bidirectional = false;
    bool delete_extra = false;
    std::vector<std::string> exclude_patterns;
    std::vector<std::string> include_patterns;
    uint32_t max_concurrent = 4;
};

struct SyncResponse {
    bool synced = false;
    uint64_t files_copied = 0;
    uint64_t files_skipped = 0;
    uint64_t files_deleted = 0;
    uint64_t bytes_transferred = 0;
    double duration_ms = 0;
    std::vector<std::string> errors;
};

struct TransferProgress {
    std::string file;
    uint64_t bytes_transferred = 0;
    uint64_t total_size = 0;
    double progress = 0.0;
    double speed_bps = 0;
    double eta_seconds = 0;
    std::string status;  // pending, transferring, completed, failed
    std::string error;
};

// ===========================================================================
// Process Contracts
// ===========================================================================

enum class ProcOpcode : uint8_t {
    EXEC        = 0x01,
    KILL        = 0x02,
    PS          = 0x03,
    TOP         = 0x04,
    SYSTEMDCTL  = 0x05,
    SERVICE     = 0x06,
};

struct ProcExecRequest {
    std::string command;
    std::vector<std::string> args;
    std::string working_dir;
    std::unordered_map<std::string, std::string> env;
    int64_t timeout_ns = 30'000'000'000;  // 30s default
    bool capture_output = true;
    bool shell = false;
    std::string stdin_data;
    uint32_t stdin_fd = 0;
    uint32_t stdout_fd = 1;
    uint32_t stderr_fd = 2;
};

struct ProcExecResponse {
    int exit_code = -1;
    std::string stdout_data;
    std::string stderr_data;
    int64_t duration_ns = 0;
    bool timed_out = false;
    bool signalled = false;
    int signal = 0;
    uint64_t peak_memory_bytes = 0;
    uint64_t peak_cpu_ns = 0;
};

struct ProcKillRequest {
    pid_t pid;
    int signal = SIGTERM;
    bool force = false;
};

struct ProcKillResponse {
    bool killed = false;
    int signal = 0;
};

struct ProcPSRequest {
    bool all = false;
    std::string user;
    std::string command;
    std::string pid;
    bool tree = false;
    std::string sort = "cpu";  // cpu, mem, pid, time
    bool reverse = true;
    int limit = 100;
};

struct ProcPSResponse {
    struct Process {
        pid_t pid;
        pid_t ppid;
        std::string user;
        double cpu_percent = 0;
        double mem_percent = 0;
        uint64_t vsz = 0;
        uint64_t rss = 0;
        std::string tty;
        std::string stat;
        int64_t start_time_ns = 0;
        int64_t cpu_time_ns = 0;
        std::string command;
        std::vector<uint32_t> threads;
    };
    std::vector<Process> processes;
};

struct ProcTopRequest {
    int iterations = 1;
    int delay_ms = 1000;
    std::string sort = "cpu";
};

struct ProcTopResponse {
    struct Snapshot {
        int64_t timestamp_ns;
        double cpu_total = 0;
        uint64_t mem_total = 0;
        uint64_t mem_used = 0;
        uint64_t swap_total = 0;
        uint64_t swap_used = 0;
        double load_1m = 0;
        double load_5m = 0;
        double load_15m = 0;
        std::vector<ProcPSResponse::Process> processes;
    };
    std::vector<Snapshot> snapshots;
};

struct SystemdRequest {
    enum class Action : uint8_t {
        Start = 1,
        Stop = 2,
        Restart = 3,
        Reload = 4,
        Enable = 5,
        Disable = 6,
        Status = 7,
        IsActive = 8,
        IsEnabled = 9,
    } action;
    
    std::string unit;
    bool user = false;
    int64_t timeout_ns = 30'000'000'000;
};

struct SystemdResponse {
    bool success = false;
    std::string status;
    std::string output;
    bool active = false;
    bool enabled = false;
    int64_t since_ns = 0;
    std::string main_pid;
};

struct ServiceRequest {
    enum class Action : uint8_t {
        Start = 1,
        Stop = 2,
        Restart = 3,
        Status = 4,
    } action;
    std::string service;
};

struct ServiceResponse {
    bool success = false;
    std::string status;
    std::string output;
    bool running = false;
};

} // namespace smo::contract::native