// §XIX — CLI Design
// smo-node: actual node daemon.
//
// Responsibilities:
// - receive intents
// - run FSM
// - manage sessions
// - capability enforcement
// - execute DAG tasks

#include <core/runtime/node_runtime.hpp>
#include <core/mesh/mesh_resolver.hpp>

#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <string>

// Global flag for graceful shutdown
static volatile bool g_running = true;
extern "C" void handle_signal(int)
{
    g_running = false;
}

static void print_usage(const char* prog)
{
    std::fprintf(stderr, R"(SMO Node Daemon

Usage:
  %s --init --name <name> [--data <dir>]
  %s --export [<file> | --copy] [--data <dir>]
  %s --import [<file>] [--data <dir>]
  %s --pubkey [--copy | --fingerprint] [--data <dir>]
  %s --join <token> --data <dir> [--name <name>] [--port <port>]
  %s --daemon --port <port> --data <data-dir> [--name <name>]
                 [--seed <host:port>]

Options:
  --init            Generate identity and save to data directory
  --name <name>     Display name for the node
  --data <dir>      Data directory (default: ~/.smo/node)
  --export <file>   Export CSR to file
  --export --copy   Copy CSR to clipboard
  --import [<file>] Import certificate (auto-detect: stdin->clipboard->file)
  --pubkey          Display public key
  --pubkey --copy   Copy public key to clipboard
  --pubkey --fingerprint  Show short fingerprint
  --join <token>    Join mesh using Join Token (auto-enrollment)
  --daemon          Run as mesh node daemon
  --port <port>     Listen port (default: 7777)
  --seed <host:port>  Bootstrap seed node for discovery
  --help            Show this help
)",
                  prog, prog, prog, prog, prog, prog);
}

int main(int argc, char* argv[])
{
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    // Parse common args
    bool daemon_mode = false;
    bool init_mode = false;
    bool export_mode = false;
    bool import_mode = false;
    bool pubkey_mode = false;
    bool pubkey_copy = false;
    bool pubkey_fingerprint = false;
    bool export_copy = false;
    bool join_mode = false;
    std::string join_token;
    int port = 7777;
    std::string data_dir = smo::mesh::smo_home() + "/node";
    std::string mesh_dir;
    std::string node_name;
    std::string seed_addr;
    std::string export_path;
    std::string import_path;

    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];
        if (arg == "--daemon")
            daemon_mode = true;
        else if (arg == "--init")
            init_mode = true;
        else if (arg == "--port" && i + 1 < argc)
            port = std::atoi(argv[++i]);
        else if (arg == "--data" && i + 1 < argc)
            data_dir = argv[++i];
        else if (arg == "--mesh-dir" && i + 1 < argc)
            mesh_dir = argv[++i];
        else if (arg == "--name" && i + 1 < argc)
            node_name = argv[++i];
        else if (arg == "--seed" && i + 1 < argc)
            seed_addr = argv[++i];
        else if (arg == "--export")
        {
            export_mode = true;
            if (i + 1 < argc && argv[i + 1][0] != '-')
            {
                export_path = argv[++i];
            }
        }
        else if (arg == "--import")
        {
            import_mode = true;
            if (i + 1 < argc && argv[i + 1][0] != '-')
            {
                import_path = argv[++i];
            }
        }
        else if (arg == "--join" && i + 1 < argc)
        {
            join_mode = true;
            join_token = argv[++i];
        }
        else if (arg == "--pubkey")
            pubkey_mode = true;
        else if (arg == "--copy")
        {
            pubkey_copy = true;
            export_copy = true;
        }
        else if (arg == "--fingerprint")
            pubkey_fingerprint = true;
        else if (arg == "--help")
        {
            print_usage(argv[0]);
            return 0;
        }
    }

    // Initialize data directory
    auto create_dir = [](const std::string& dir) {
        if (dir.empty())
            return;
        namespace fs = std::filesystem;
        fs::create_directories(dir);
    };

    // Mode dispatch - CLI commands (no daemon)
    if (pubkey_mode)
    {
        if (!data_dir.empty())
            create_dir(data_dir);
        return smo::runtime::NodeRuntime::cmd_pubkey(data_dir, pubkey_copy, pubkey_fingerprint);
    }

    if (init_mode)
    {
        if (node_name.empty())
        {
            std::fprintf(stderr, "Error: --name <name> is required with --init\n");
            return 1;
        }
        if (!data_dir.empty())
            create_dir(data_dir);
        return smo::runtime::NodeRuntime::cmd_init(node_name, data_dir);
    }

    if (export_mode)
    {
        if (export_copy)
        {
            return smo::runtime::NodeRuntime::cmd_export("", data_dir, true);
        }
        if (export_path.empty())
        {
            std::fprintf(stderr, "Error: --export <file> requires a file path\n");
            return 1;
        }
        return smo::runtime::NodeRuntime::cmd_export(export_path, data_dir, false);
    }

    if (import_mode)
    {
        return smo::runtime::NodeRuntime::cmd_import(import_path, data_dir);
    }

    if (join_mode)
    {
        if (join_token.empty())
        {
            std::fprintf(stderr, "Error: --join requires a token\n");
            return 1;
        }
        return smo::runtime::NodeRuntime::cmd_join(join_token, data_dir, node_name, port);
    }

    // Legacy: show info if no flags
    if (!daemon_mode)
    {
        std::printf("SMO Node\n");
        std::printf("  Data dir: %s\n", data_dir.c_str());
        std::printf("  Port:     %d\n", port);
        if (!node_name.empty())
            std::printf("  Name:     %s\n", node_name.c_str());
        if (!seed_addr.empty())
            std::printf("  Seed:     %s\n", seed_addr.c_str());
        std::printf("  Mode:     standalone (use --daemon to run as service, "
                    "--init to enroll)\n");
        return 0;
    }

    // Daemon mode — delegate to NodeRuntime composition root
    smo::runtime::NodeRuntimeConfig rt_cfg;
    rt_cfg.port = port;
    rt_cfg.data_dir = data_dir;
    rt_cfg.mesh_dir = mesh_dir;
    rt_cfg.node_name = node_name;
    rt_cfg.seed_addr = seed_addr;
    rt_cfg.running_flag = &g_running;

    smo::runtime::NodeRuntime rt(rt_cfg);

    if (auto r = rt.initialize(); !r)
    {
        std::fprintf(stderr, "[smo-node] Error: initialize failed: %s\n", r.error().message.c_str());
        return 1;
    }
    if (auto r = rt.start(); !r)
    {
        std::fprintf(stderr, "[smo-node] Error: start failed: %s\n", r.error().message.c_str());
        return 1;
    }

    int rc = rt.run();
    rt.shutdown();
    return rc;
}