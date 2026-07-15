// §XIX — CLI Design
// smo-cli: user-facing execution tool.
//
// smo exec --opcode ls --name backup-02 --path /var/log
// smo exec --opcode backup --tag Storage
// smo exec --opcode update --role Member
// smo exec --opcode audit --where 'role=="Member" && arch=="arm64"'
// smo exec --opcode sync --nearest
// smo exec --opcode benchmark --random 10
// smo exec --opcode compile --arch arm64
// smo exec --opcode upgrade --version '<3.2'
// smo exec --opcode exec --trust '>0.8'
// smo exec --opcode deploy --cap EXEC
// smo exec --opcode discover --mesh SOC
// smo mesh create --name "SOC-Production" --recovery-group 5 --threshold 3
// smo mesh discover
// smo node init --name soc-hn-01
// smo node join --mesh SOC --token abc123

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static void print_usage(const char* prog) {
    std::fprintf(stderr, R"(SMO CLI — Secure Mesh Operation

Usage:
  %s node init --name <display-name>
  %s node join --mesh <mesh> --token <token>
  %s node leave --mesh <mesh>

  %s exec --opcode <op> [--name <name>] [--id <nodeid>]
          [--role <role>] [--tag <tag>]... [--where <expr>]
          [--os <os>] [--arch <arch>] [--version <ver>]
          [--trust <range>] [--mesh <mesh>]
          [--nearest | --random <n> | --top <n>]
          [--scope single|mesh] [--param <key>=<val>]...

  %s mesh create --name <mesh-name>
  %s mesh discover

  %s --help
)",
        prog, prog, prog, prog, prog, prog, prog);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::vector<std::string> args(argv + 1, argv + argc);

    // --help
    for (auto& a : args) {
        if (a == "--help" || a == "-h") {
            print_usage(argv[0]);
            return 0;
        }
    }

    // Parse subcommand
    auto cmd = args[0];

    if (cmd == "node" && args.size() >= 2) {
        if (args[1] == "init") {
            std::string name;
            for (size_t i = 2; i + 1 < args.size(); ++i) {
                if (args[i] == "--name") name = args[i + 1];
            }
            if (name.empty()) {
                std::fprintf(stderr, "Usage: smo node init --name <display-name>\n");
                return 1;
            }
            std::printf("Node initialized with display name: %s\n", name.c_str());
            std::printf("(Placeholder — keypair generation not yet implemented)\n");
            return 0;
        }
        if (args[1] == "rename") {
            std::string new_name;
            for (size_t i = 2; i + 1 < args.size(); ++i) {
                if (args[i] == "--name") new_name = args[i + 1];
            }
            if (new_name.empty()) {
                std::fprintf(stderr, "Usage: smo node rename --name <new-name>\n");
                return 1;
            }
            std::printf("Rename requested: -> %s\n", new_name.c_str());
            std::printf("(Sends RENAME_REQUEST to Authority — placeholder)\n");
            return 0;
        }
    }

    if (cmd == "exec") {
        std::string opcode, name, node_id, role, where, os, arch, version, trust_range, mesh, cap, scope;
        std::vector<std::string> tags;
        bool nearest = false;
        int random_n = 0, top_n = 0;
        std::vector<std::string> params;

        for (size_t i = 1; i + 1 < args.size(); ++i) {
            auto& a = args[i];
            auto& n = args[i + 1];
            if (a == "--opcode")     { opcode = n; i++; }
            else if (a == "--name")  { name = n; i++; }
            else if (a == "--id")    { node_id = n; i++; }
            else if (a == "--role")  { role = n; i++; }
            else if (a == "--tag")   { tags.push_back(n); i++; }
            else if (a == "--where") { where = n; i++; }
            else if (a == "--os")    { os = n; i++; }
            else if (a == "--arch")  { arch = n; i++; }
            else if (a == "--version") { version = n; i++; }
            else if (a == "--trust") { trust_range = n; i++; }
            else if (a == "--mesh")  { mesh = n; i++; }
            else if (a == "--cap")   { cap = n; i++; }
            else if (a == "--scope") { scope = n; i++; }
            else if (a == "--nearest") { nearest = true; }
            else if (a == "--random") { random_n = std::stoi(n); i++; }
            else if (a == "--top")   { top_n = std::stoi(n); i++; }
            else if (a == "--param") { params.push_back(n); i++; }
        }

        if (opcode.empty()) {
            std::fprintf(stderr, "Error: --opcode is required\n");
            return 1;
        }

        std::printf("Intent: %s\n", opcode.c_str());
        if (!name.empty())      std::printf("  target name: %s\n", name.c_str());
        if (!node_id.empty())   std::printf("  target id:   %s\n", node_id.c_str());
        if (!role.empty())      std::printf("  role:        %s\n", role.c_str());
        if (!tags.empty())      { std::printf("  tags:        "); for (auto& t : tags) std::printf("%s ", t.c_str()); std::printf("\n"); }
        if (!where.empty())     std::printf("  where:       %s\n", where.c_str());
        if (!os.empty())        std::printf("  os:          %s\n", os.c_str());
        if (!arch.empty())      std::printf("  arch:        %s\n", arch.c_str());
        if (!version.empty())   std::printf("  version:     %s\n", version.c_str());
        if (!trust_range.empty()) std::printf("  trust:       %s\n", trust_range.c_str());
        if (!mesh.empty())      std::printf("  mesh:        %s\n", mesh.c_str());
        if (!cap.empty())       std::printf("  cap:         %s\n", cap.c_str());
        if (!scope.empty())     std::printf("  scope:       %s\n", scope.c_str());
        if (nearest)            std::printf("  mode:        nearest\n");
        if (random_n > 0)       std::printf("  mode:        random %d\n", random_n);
        if (top_n > 0)          std::printf("  mode:        top %d\n", top_n);
        std::printf("(Dispatch not yet implemented — placeholder)\n");
        return 0;
    }

    if (cmd == "mesh") {
        if (args.size() >= 2 && args[1] == "create") {
            std::string mesh_name;
            for (size_t i = 2; i + 1 < args.size(); ++i) {
                if (args[i] == "--name") mesh_name = args[i + 1];
            }
            if (mesh_name.empty()) {
                std::fprintf(stderr, "Usage: smo mesh create --name <mesh-name>\n");
                return 1;
            }
            std::printf("Mesh created: %s (placeholder)\n", mesh_name.c_str());
            return 0;
        }
        if (args.size() >= 2 && args[1] == "discover") {
            std::printf("ID        NAME          ROLE         TAGS            STATUS\n");
            std::printf("────────  ────────────  ───────────  ──────────────  ───────\n");
            std::printf("(Discovery table — not yet connected)\n");
            return 0;
        }
    }

    print_usage(argv[0]);
    return 1;
}
