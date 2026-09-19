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

private:
    class Impl;
    std::unique_ptr<Impl> impl_;

    static NodeRuntime* current_;
};

} // namespace smo::runtime