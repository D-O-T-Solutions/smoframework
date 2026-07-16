#include "transfer_contracts.hpp"

#include <filesystem>
#include <fstream>
#include <chrono>
#include <thread>
#include <random>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <dirent.h>
#include <sys/sysinfo.h>
#include <unistd.h>

namespace smo::contract::native {

// ===========================================================================
// Process Contract Implementations
// ===========================================================================

namespace {
    std::string read_file(const std::string& path) {
        std::ifstream file(path);
        if (!file) return "";
        std::stringstream ss;
        ss << file.rdbuf();
        return ss.str();
    }
    
    std::vector<std::string> split(const std::string& str, char delim) {
        std::vector<std::string> result;
        std::stringstream ss(str);
        std::string item;
        while (std::getline(ss, item, delim)) {
            if (!item.empty()) result.push_back(item);
        }
        return result;
    }
}

namespace smo::contract::native {

Result<ProcExecResponse> proc_exec(const ProcExecRequest& req) {
    ProcExecResponse resp;
    auto start = std::chrono::steady_clock::now();
    
    // Create pipes for stdout/stderr
    int stdout_pipe[2] = {-1, -1};
    int stderr_pipe[2] = {-1, -1};
    int stdin_pipe[2] = {-1, -1};
    
    if (pipe(stdout_pipe) != 0 || pipe(stderr_pipe) != 0 || 
        (req.stdin_data.size() > 0 && pipe(stdin_pipe) != 0)) {
        return SMO_ERR(Contract, 220, Error, NoRetry, None, "Failed to create pipes");
    }
    
    pid_t pid = fork();
    if (pid == -1) {
        close(stdout_pipe[0]); close(stdout_pipe[1]);
        close(stderr_pipe[0]); close(stderr_pipe[1]);
        if (stdin_pipe[0] != -1) { close(stdin_pipe[0]); close(stdin_pipe[1]); }
        return SMO_ERR(Contract, 221, Error, NoRetry, None, "Fork failed");
    }
    
    if (pid == 0) {  // Child process
        // Set up stdin
        if (req.stdin_data.size() > 0) {
            dup2(stdin_pipe[0], STDIN_FILENO);
            close(stdin_pipe[0]); close(stdin_pipe[1]);
        }
        
        // Redirect stdout
        dup2(stdout_pipe[1], STDOUT_FILENO);
        close(stdout_pipe[0]); close(stdout_pipe[1]);
        
        // Redirect stderr
        dup2(stderr_pipe[1], STDERR_FILENO);
        close(stderr_pipe[0]); close(stderr_pipe[1]);
        
        // Change working directory if specified
        if (!req.working_dir.empty()) {
            chdir(req.working_dir.c_str());
        }
        
        // Set environment variables
        for (const auto& [key, value] : req.env) {
            setenv(key.c_str(), value.c_str(), 1);
        }
        
        // Execute
        if (req.shell) {
            std::vector<char*> args = {"sh", "-c", const_cast<char*>(req.command.c_str()), nullptr};
            execvp("sh", args.data());
        } else {
            std::vector<char*> args;
            args.push_back(const_cast<char*>(req.command.c_str()));
            for (const auto& arg : req.args) {
                args.push_back(const_cast<char*>(arg.c_str()));
            }
            args.push_back(nullptr);
            execvp(req.command.c_str(), args.data());
        }
        
        _exit(127);  // exec failed
    }
    
    // Parent process
    close(stdout_pipe[1]);
    close(stderr_pipe[1]);
    if (stdin_pipe[0] != -1) {
        close(stdin_pipe[0]);
        if (!req.stdin_data.empty()) {
            write(stdin_pipe[1], req.stdin_data.c_str(), req.stdin_data.size());
        }
        close(stdin_pipe[1]);
    }
    
    // Read output
    std::string stdout_data, stderr_data;
    char buffer[4096];
    ssize_t n;
    
    auto read_pipe = [&](int fd, std::string& out) {
        char buf[4096];
        ssize_t n;
        while ((n = read(fd, buf, sizeof(buf))) > 0) {
            out.append(buf, n);
        }
    };
    
    // Use select/poll for non-blocking read
    fd_set fds;
    int max_fd = std::max(stdout_pipe[0], stderr_pipe[0]);
    
    auto deadline = std::chrono::steady_clock::now() + 
                    std::chrono::nanoseconds(req.timeout_ns);
    
    while (true) {
        auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            kill(pid, SIGKILL);
            break;
        }
        
        fd_set read_fds;
        FD_ZERO(&fds);
        FD_SET(stdout_pipe[0], &fds);
        FD_SET(stderr_pipe[0], &fds);
        
        struct timeval tv;
        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() + std::chrono::nanoseconds(req.timeout_ns) - now);
        if (remaining.count() <= 0) {
            kill(pid, SIGKILL);
            break;
        }
        tv.tv_sec = remaining.count() / 1000;
        tv.tv_usec = (remaining.count() % 1000) * 1000;
        
        int ret = select(max_fd + 1, &fds, nullptr, nullptr, &tv);
        if (ret <= 0) break;
        
        if (FD_ISSET(stdout_pipe[0], &fds)) {
            char buf[4096];
            ssize_t n = read(stdout_pipe[0], buf, sizeof(buf));
            if (n > 0) resp.stdout_data.append(buf, n);
        }
        if (FD_ISSET(stderr_pipe[0], &fds)) {
            char buf[4096];
            ssize_t n = read(stderr_pipe[0], buf, sizeof(buf));
            if (n > 0) resp.stderr_data.append(buf, n);
        }
    }
    
    close(stdout_pipe[0]);
    close(stderr_pipe[0]);
    
    int status;
    waitpid(pid, &status, 0);
    
    auto end = std::chrono::steady_clock::now();
    
    resp.exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    resp.timed_out = false;
    resp.signalled = WIFSIGNALED(status);
    resp.signal = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
    resp.duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    
    return resp;
}

Result<ProcKillResponse> proc_kill(const ProcKillRequest& req) {
    ProcKillResponse resp;
    resp.signal = req.signal;
    
    if (kill(req.pid, req.signal) == 0) {
        resp.killed = true;
    } else {
        resp.killed = false;
    }
    
    if (req.force && !resp.killed) {
        if (kill(req.pid, SIGKILL) == 0) {
            resp.killed = true;
            resp.signal = SIGKILL;
        }
    }
    
    return resp;
}

Result<ProcPSResponse> proc_ps(const ProcPSRequest& req) {
    ProcPSResponse resp;
    
    DIR* dir = opendir("/proc");
    if (!dir) {
        return SMO_ERR(Contract, 230, Error, NoRetry, None, "Failed to open /proc");
    }
    
    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type != DT_DIR) continue;
        
        pid_t pid = std::atoi(entry->d_name);
        if (pid <= 0) continue;
        
        // Read /proc/pid/stat
        std::string stat_path = "/proc/" + std::to_string(pid) + "/stat";
        std::string stat_content = read_file(stat_path);
        if (stat_content.empty()) continue;
        
        // Parse stat fields
        // (1) pid  (2) comm  (3) state  (4) ppid  (4) pgrp  (5) session
        // (6) tty_nr  (7) tpgid  (8) flags  (9) minflt  (10) cminflt
        // (11) majflt  (12) cmajflt  (13) utime  (14) stime  (15) cutime
        // (16) cstime  (17) priority  (18) nice  (18) num_threads
        // (19) itrealvalue  (20) starttime  (21) vsize  (22) rss
        // (23) rsslim  (24) startcode  (25) endcode  (26) startstack
        // (27) kstkesp  (28) kstkeip  (29) signal  (30) blocked
        // (31) sigignore  (32) sigcatch  (33) wchan  (34) nswap
        // (35) cnswap  (36) exit_signal  (37) processor  (38) rt_priority
        // (39) policy  (40) delayacct_blkio_ticks
        
        std::vector<std::string> parts = split(stat_content, ' ');
        if (parts.size() < 24) continue;
        
        ProcPSResponse::Process proc;
        proc.pid = std::stoi(parts[0]);
        proc.ppid = std::stoi(parts[3]);
        
        // Get username from /proc/pid/status
        std::string status = read_file("/proc/" + std::to_string(pid) + "/status");
        for (const auto& line : split(status, '\n')) {
            if (line.rfind("Uid:", 0) == 0) {
                std::vector<std::string> parts = split(line, '\t');
                if (parts.size() >= 2) {
                    uid_t uid = std::stoi(parts[1]);
                    struct passwd* pw = getpwuid(uid);
                    if (pw) proc.user = pw->pw_name;
                }
            }
        }
        
        // Parse CPU and memory
        proc.cpu_percent = std::stod(parts[13]) + std::stod(parts[14]); // utime + stime
        proc.vsz = std::stoull(parts[22]) * 4096; // pages to bytes
        proc.rss = std::stoull(parts[23]) * 4096;
        proc.state = parts[2][0];
        
        // Command
        std::string cmdline = read_file("/proc/" + std::to_string(pid) + "/cmdline");
        std::replace(cmdline.begin(), cmdline.end(), '\0', ' ');
        proc.command = cmdline;
        
        // Filter by user if specified
        if (!req.user.empty() && proc.user != req.user) continue;
        
        resp.processes.push_back(std::move(proc));
    }
    
    closedir(dir);
    
    // Sort
    if (req.sort == "cpu") {
        std::sort(resp.processes.begin(), resp.processes.end(),
                  [&](const auto& a, const auto& b) {
                      return a.cpu_percent > b.cpu_percent;
                  });
    } else if (req.sort == "mem") {
        std::sort(resp.processes.begin(), resp.processes.end(),
                  [&](const auto& a, const auto& b) {
                      return a.rss > b.rss;
                  });
    } else if (req.sort == "pid") {
        std::sort(resp.processes.begin(), resp.processes.end(),
                  [&](const auto& a, const auto& b) {
                      return a.pid < b.pid;
                  });
    } else if (req.sort == "time") {
        // sort by start time
    }
    
    if (req.reverse) {
        std::reverse(resp.processes.begin(), resp.processes.end());
    }
    
    if (static_cast<int>(resp.processes.size()) > req.limit) {
        resp.processes.resize(req.limit);
    }
    
    return resp;
}

Result<ProcTopResponse> proc_top(const ProcTopRequest& req) {
    ProcTopResponse resp;
    
    for (int i = 0; i < req.iterations; ++i) {
        auto now = std::chrono::steady_clock::now();
        
        ProcTopResponse::Snapshot snap;
        snap.timestamp_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        
        // Read /proc/stat for CPU
        std::string stat = read_file("/proc/stat");
        std::vector<std::string> lines = split(stat, '\n');
        for (const auto& line : lines) {
            if (line.rfind("cpu ", 0) == 0) {
                std::vector<std::string> parts = split(line, ' ');
                if (parts.size() >= 8) {
                    // Calculate CPU usage
                    snap.cpu_total = std::stod(parts[1]) + std::stod(parts[2]) + 
                                     std::stod(parts[3]) + std::stod(parts[4]) +
                                     std::stod(parts[5]) + std::stod(parts[6]) +
                                     std::stod(parts[7]);
                }
                break;
            }
        }
        
        // Read /proc/meminfo
        std::string meminfo = read_file("/proc/meminfo");
        for (const auto& line : split(meminfo, '\n')) {
            if (line.rfind("MemTotal:", 0) == 0) {
                snap.mem_total = std::stoull(split(line, ' ')[1]) * 1024;
            } else if (line.rfind("MemAvailable:", 0) == 0) {
                snap.mem_used = snap.mem_total - std::stoull(split(line, ' ')[1]) * 1024;
            } else if (line.rfind("SwapTotal:", 0) == 0) {
                snap.swap_total = std::stoull(split(line, ' ')[1]) * 1024;
            } else if (line.rfind("SwapFree:", 0) == 0) {
                snap.swap_used = snap.swap_total - std::stoull(split(line, ' ')[1]) * 1024;
            }
        }
        
        // Read /proc/loadavg
        std::string loadavg = read_file("/proc/loadavg");
        std::vector<std::string> load_parts = split(loadavg, ' ');
        if (load_parts.size() >= 3) {
            snap.load_1m = std::stod(load_parts[0]);
            snap.load_5m = std::stod(load_parts[1]);
            snap.load_15m = std::stod(load_parts[2]);
        }
        
        // Get top processes
        ProcPSRequest ps_req;
        ps_req.all = true;
        ps_req.sort = "cpu";
        ps_req.reverse = true;
        ps_req.limit = 20;
        auto ps_resp = proc_ps(ps_req);
        if (ps_resp) {
            snap.processes = ps_resp.value().processes;
        }
        
        resp.snapshots.push_back(std::move(snap));
        
        if (i < req.iterations - 1) {
            std::this_thread::sleep_for(std::chrono::milliseconds(req.delay_ms));
        }
    }
    
    return resp;
}

Result<SystemdResponse> systemd_control(const SystemdRequest& req) {
    SystemdResponse resp;
    
    std::string cmd = "systemctl ";
    switch (req.action) {
        case SystemdRequest::Action::Start:     cmd += "start "; break;
        case SystemdRequest::Action::Stop:      cmd += "stop "; break;
        case SystemdRequest::Action::Restart:   cmd += "restart "; break;
        case SystemdRequest::Action::Reload:    cmd += "reload "; break;
        case SystemdRequest::Action::Enable:    cmd += "enable "; break;
        case SystemdRequest::Action::Disable:   cmd += "disable "; break;
        case SystemdRequest::Action::Status:    cmd += "status "; break;
        case SystemdRequest::Action::IsActive:  cmd += "is-active "; break;
        case SystemdRequest::Action::IsEnabled: cmd += "is-enabled "; break;
    }
    
    if (req.user) cmd += "--user ";
    cmd += req.unit;
    
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        return SMO_ERR(Contract, 240, Error, NoRetry, None, "Failed to execute systemctl");
    }
    
    char buffer[128];
    std::string output;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output += buffer;
    }
    pclose(pipe);
    
    resp.output = output;
    
    // Parse status
    if (req.action == SystemdRequest::Action::IsActive) {
        resp.active = output.find("active") != std::string::npos;
    } else if (req.action == SystemdRequest::Action::IsEnabled) {
        resp.enabled = output.find("enabled") != std::string::npos;
    }
    
    resp.success = !output.empty();
    resp.status = output;
    
    return resp;
}

Result<ServiceResponse> service_control(const ServiceRequest& req) {
    ServiceResponse resp;
    
    std::string action;
    switch (req.action) {
        case ServiceRequest::Action::Start:   action = "start"; break;
        case ServiceRequest::Action::Stop:    action = "stop"; break;
        case ServiceRequest::Action::Restart: action = "restart"; break;
        case ServiceRequest::Action::Status:  action = "status"; break;
    }
    
    std::string cmd = "service " + req.service + " " + action;
    
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        return SMO_ERR(Contract, 245, Error, NoRetry, None, "Failed to execute service command");
    }
    
    char buffer[128];
    std::string output;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output += buffer;
    }
    pclose(pipe);
    
    resp.output = output;
    resp.success = output.find("OK") != std::string::npos || 
                   output.find("running") != std::string::npos ||
                   output.find("active") != std::string::npos;
    resp.running = output.find("running") != std::string::npos ||
                   output.find("active") != std::string::npos;
    
    return resp;
}

} // namespace smo::contract::native