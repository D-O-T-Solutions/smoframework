#pragma once

#include <core/errors/error.hpp>
#include <core/types.hpp>

#include <atomic>
#include <memory>
#include <string>

namespace smo::runtime {

// ── NodeRuntimeConfig — composition root input ───────────────────────────
struct NodeRuntimeConfig
{
    int port = 7777;
    std::string data_dir;
    std::string mesh_dir;
    std::string node_name;
    std::string seed_addr;
    volatile bool* running_flag = nullptr; // owned by caller (signal handler)
};

// ── NodeRuntime — daemon composition root ────────────────────────────────
//
// Owns every subsystem's lifecycle and exposes a thin, ordered surface:
//   initialize() → start() → run() → shutdown()
//
// No socket/recvfrom/deserialize/dispatch logic lives here — those belong
// to the owned components; run() only ticks/drives them.
class NodeRuntime
{
public:
    explicit NodeRuntime(const NodeRuntimeConfig& config);
    ~NodeRuntime();

    NodeRuntime(const NodeRuntime&) = delete;
    NodeRuntime& operator=(const NodeRuntime&) = delete;
    NodeRuntime(NodeRuntime&&) = delete;
    NodeRuntime& operator=(NodeRuntime&&) = delete;

    Result<void> initialize();
    Result<void> start();
    void shutdown();

    // Blocking. Returns process exit code when running_flag clears.
    int run();

    static NodeRuntime* current() noexcept { return current_; }

    // ── CLI command handlers (thin wrappers, no daemon startup) ──────────
    static int cmd_init(const std::string& name, const std::string& data_dir);
    static int cmd_export(const std::string& output_path, const std::string& data_dir, bool copy_to_clipboard);
    static int cmd_import(const std::string& cert_path_or_empty, const std::string& data_dir);
    static int cmd_pubkey(const std::string& data_dir, bool copy_to_clipboard, bool show_fingerprint);
    static int cmd_join(const std::string& join_token, const std::string& data_dir, const std::string& node_name, int port);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;

    static NodeRuntime* current_;
};

} // namespace smo::runtime