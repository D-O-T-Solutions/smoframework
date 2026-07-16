#include <core/authority/authority.hpp>
#include <core/authority/registry.hpp>
#include <core/certificate/certificate.hpp>
#include <core/crypto/impl.hpp>
#include <core/crypto/registry.hpp>
#include <core/crypto/suite.hpp>
#include <core/enroll/join_token.hpp>
#include <core/errors/error.hpp>
#include <core/types.hpp>

#include <providers/suite1_classical/suite1_classical_provider.hpp>
#include <providers/suite3_purepqc/suite3_purepqc_provider.hpp>

#include <tooling/clipboard.hpp>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using smo::Bytes;
using smo::BytesView;

static void print_usage(const char* prog) {
    std::fprintf(stderr, R"(SMO Admin — Mesh Administration

Usage:
  %s --mesh-dir <dir> sign <csr-file> -o <output-file>
  %s --mesh-dir <dir> create-mesh <name>
  %s --mesh-dir <dir> generate-invite <role> [--expire <dur>] [--endpoint <ep>]
  %s --help

Commands:
  sign            Sign a CSR (.smor) and issue a certificate (.smoc)
  create-mesh     Initialize a new mesh (generate root + authority keys)
  generate-invite Generate a Join Token for automated enrollment
)",
        prog, prog, prog, prog);
}

// ---------------------------------------------------------------------------
// Load a binary file
// ---------------------------------------------------------------------------
static Bytes load_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return {};
    auto size = f.tellg();
    f.seekg(0);
    Bytes data(static_cast<size_t>(size));
    f.read(reinterpret_cast<char*>(data.data()), size);
    return data;
}

// ---------------------------------------------------------------------------
// Write a binary file
// ---------------------------------------------------------------------------
static bool write_file(const std::string& path, BytesView data) {
    std::ofstream f(path, std::ios::binary);
    if (!f) return false;
    f.write(reinterpret_cast<const char*>(data.data()), data.size());
    return f.good();
}

// ---------------------------------------------------------------------------
// Register all available crypto suites once at startup
// ---------------------------------------------------------------------------
static void register_all_suites() {
    smo::providers::register_suite1_classical();
    smo::providers::register_suite3_purepqc();
}

// ---------------------------------------------------------------------------
// Get crypto provider for a given cipher_suite_id from the registry
// ---------------------------------------------------------------------------
static bool get_crypto(smo::CryptoSuiteID suite_id,
                        smo::CryptoProvider const*& provider_out,
                        smo::RngRef& rng_out) {
    auto& reg = smo::CryptoRegistry::instance();
    auto prov_result = reg.get_suite(suite_id);
    if (!prov_result) {
        std::fprintf(stderr, "Error: cipher suite %u not registered\n",
                     (unsigned)suite_id);
        return false;
    }
    provider_out = prov_result.value();
    rng_out = provider_out->default_rng();
    return true;
}

// ---------------------------------------------------------------------------
// Read a string field from JSON (simple parser — no JSON lib needed)
static std::string json_read_string(const std::string& json, const std::string& key) {
    auto pos = json.find("\"" + key + "\"");
    if (pos == std::string::npos) return {};
    auto colon = json.find(':', pos);
    if (colon == std::string::npos) return {};
    auto start = json.find('"', colon + 1);
    if (start == std::string::npos) return {};
    auto end = json.find('"', start + 1);
    if (end == std::string::npos) return {};
    return json.substr(start + 1, end - start - 1);
}

// Read integer field from JSON
static int64_t json_read_int(const std::string& json, const std::string& key, int64_t def) {
    auto pos = json.find("\"" + key + "\"");
    if (pos == std::string::npos) return def;
    auto colon = json.find(':', pos);
    if (colon == std::string::npos) return def;
    auto start = json.find_first_of("0123456789-", colon);
    if (start == std::string::npos) return def;
    auto end = json.find_first_not_of("0123456789", start);
    if (end == std::string::npos) return def;
    try { return std::stoll(json.substr(start, end - start)); } catch (...) { return def; }
}

// Read cipher_suite_id from mesh.json
// ---------------------------------------------------------------------------
static smo::CryptoSuiteID read_suite_from_mesh(const std::string& mesh_dir) {
    std::string path = mesh_dir + "/mesh.json";
    std::ifstream f(path);
    if (!f) {
        std::fprintf(stderr, "Warning: no mesh.json found at %s, using default suite\n",
                     path.c_str());
        return smo::kSuitePurePQC;
    }
    std::string content((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());
    auto pos = content.find("\"cipher_suite_id\"");
    if (pos == std::string::npos) return smo::kSuitePurePQC;
    auto colon = content.find(':', pos);
    if (colon == std::string::npos) return smo::kSuitePurePQC;
    auto val_start = content.find_first_of("0123456789", colon);
    if (val_start == std::string::npos) return smo::kSuitePurePQC;
    auto val_end = content.find_first_not_of("0123456789", val_start);
    std::string num = content.substr(val_start, val_end - val_start);
    return static_cast<smo::CryptoSuiteID>(std::stoul(num));
}

// ---------------------------------------------------------------------------
// cmd_sign: Load CSR, sign via authority, output .smoc
//
// Transports:
//   smo-admin sign <csr-file> -o <cert-file>  (file)
//   smo-admin sign <csr-file> --copy           (clipboard)
//   smo-admin sign --paste -o <cert-file>      (clipboard in)
//   smo-admin sign <csr-file>                  (stdout)
// ---------------------------------------------------------------------------
static int cmd_sign(const std::vector<std::string>& args,
                     const std::string& mesh_dir) {
    std::string input_file;
    std::string output_file;
    bool do_copy = false;
    bool do_paste = false;

    for (size_t i = 1; i < args.size(); ++i) {
        if (args[i] == "-o" && i + 1 < args.size()) {
            output_file = args[++i];
        } else if (args[i] == "--copy") {
            do_copy = true;
        } else if (args[i] == "--paste") {
            do_paste = true;
        } else if (input_file.empty() && !args[i].starts_with("-")) {
            input_file = args[i];
        }
    }

    // Load CSR
    smo::Bytes csr_blob;

    if (do_paste) {
        // Read CSR from clipboard
        auto clip = smo::clipboard_paste();
        if (clip.empty()) {
            std::fprintf(stderr, "Error: clipboard is empty or unavailable\n");
            return 1;
        }
        csr_blob = smo::Bytes(clip.begin(), clip.end());
        std::fprintf(stderr, "[smo-admin] Read CSR from clipboard (%zu bytes)\n", csr_blob.size());
    } else if (!input_file.empty()) {
        if (!fs::exists(input_file)) {
            std::fprintf(stderr, "Error: CSR file not found: %s\n", input_file.c_str());
            return 1;
        }
        csr_blob = load_file(input_file);
        if (csr_blob.empty()) {
            std::fprintf(stderr, "Error: cannot read CSR file: %s\n", input_file.c_str());
            return 1;
        }
    } else {
        std::fprintf(stderr, "Usage:\n"
                             "  smo-admin sign <csr-file> -o <cert-file>\n"
                             "  smo-admin sign <csr-file> --copy\n"
                             "  smo-admin sign --paste [-o <cert-file>]\n");
        return 1;
    }

    // Read cipher suite from mesh config and get crypto provider
    auto suite_id = read_suite_from_mesh(mesh_dir);
    const smo::CryptoProvider* crypto = nullptr;
    smo::RngRef rng;
    if (!get_crypto(suite_id, crypto, rng)) return 1;

    // Open mesh authority
    smo::authority::MeshAuthority authority;
    if (auto r = authority.init(*crypto, rng); !r) {
        std::fprintf(stderr, "Error: authority init failed: %s\n",
                     r.error().message.c_str());
        return 1;
    }

    smo::authority::MeshAuthority::Config cfg;
    cfg.mesh_id = fs::path(mesh_dir).filename().string();
    cfg.data_dir = mesh_dir;
    cfg.registry_path = mesh_dir + "/node_registry.db";

    if (auto r = authority.open(cfg); !r) {
        std::fprintf(stderr, "Error: cannot open mesh authority at %s: %s\n",
                     mesh_dir.c_str(), r.error().message.c_str());
        return 1;
    }

    // Sign CSR
    auto cert_result = authority.sign_csr(csr_blob, cfg.mesh_id);
    if (!cert_result) {
        std::fprintf(stderr, "Error: CSR signing failed: %s\n",
                     cert_result.error().message.c_str());
        return 1;
    }

    // Serialize certificate
    auto cert_serialized = cert_result.value().serialize();
    auto cert_fp = crypto->hash.hash(cert_serialized);
    std::string fp_hex = cert_fp ? smo::bytes_to_hex(cert_fp.value()).substr(0, 16) : "???";

    if (do_copy) {
        // Copy to clipboard
        if (smo::clipboard_copy(std::string(cert_serialized.begin(), cert_serialized.end()))) {
            std::printf("Certificate signed. Fingerprint: %s\n", fp_hex.c_str());
            std::printf("Copied to clipboard.\n");
            return 0;
        }
        std::fprintf(stderr, "Error: clipboard not available\n");
        return 1;
    }

    if (output_file.empty()) {
        // Write to stdout
        fwrite(cert_serialized.data(), 1, cert_serialized.size(), stdout);
        return 0;
    }

    // Write to file
    if (!write_file(output_file, cert_serialized)) {
        std::fprintf(stderr, "Error: cannot write output file: %s\n",
                     output_file.c_str());
        return 1;
    }

    std::printf("Certificate signed: %s (%zu bytes)\n", fp_hex.c_str(), cert_serialized.size());
    return 0;
}

// ---------------------------------------------------------------------------
// cmd_create_mesh: Initialize new mesh with root + authority keys
// ---------------------------------------------------------------------------
static int cmd_create_mesh(const std::string& name,
                            const std::string& output_dir) {
    fs::path mesh_dir = fs::path(output_dir) / name;
    fs::create_directories(mesh_dir);

    // Use default suite for mesh creation (can be overridden via --suite flag later)
    const smo::CryptoProvider* crypto = nullptr;
    smo::RngRef rng;
    if (!get_crypto(smo::kSuitePurePQC, crypto, rng)) return 1;

    smo::authority::MeshAuthority authority;
    if (auto r = authority.init(*crypto, rng); !r) {
        std::fprintf(stderr, "Error: authority init failed: %s\n",
                     r.error().message.c_str());
        return 1;
    }

    smo::authority::MeshAuthority::Config cfg;
    cfg.mesh_id = name;
    cfg.data_dir = mesh_dir.string();
    cfg.registry_path = (mesh_dir / "node_registry.db").string();

    std::string root_pubkey_hex;
    if (auto r = authority.create_mesh_keys(cfg, *crypto, rng, root_pubkey_hex); !r) {
        std::fprintf(stderr, "Error: create mesh keys failed: %s\n",
                     r.error().message.c_str());
        return 1;
    }

    // Also write the root public key hex to a file for reference
    std::ofstream rpk(mesh_dir / "root.pub.hex");
    rpk << root_pubkey_hex;
    rpk.close();

    std::printf("Mesh '%s' created at %s\n", name.c_str(), mesh_dir.string().c_str());
    std::printf("  Root public key: %s\n", root_pubkey_hex.c_str());
    std::printf("  Authority keys:  %s/authority.pub, %s/authority.sec\n",
                mesh_dir.string().c_str(), mesh_dir.string().c_str());
    std::printf("  Root cert:       %s/root.cert\n", mesh_dir.string().c_str());
    std::printf("  Authority cert:  %s/authority.cert\n", mesh_dir.string().c_str());
    std::printf("  Node registry:   %s/node_registry.db\n", mesh_dir.string().c_str());
    return 0;
}

// ---------------------------------------------------------------------------
// cmd_generate_invite: Generate a Join Token
// ---------------------------------------------------------------------------
// Options:
//   <role>               — "Worker", "Validator", "Observer", "Relay"
//   --expire <dur>       — duration like "30m", "1h", "7d" (default: 1h)
//   --endpoint <ep>      — bootstrap endpoint (can be repeated)
//     e.g. authority.company.com:7777
// ---------------------------------------------------------------------------
static int cmd_generate_invite(const std::vector<std::string>& args,
                                const std::string& mesh_dir) {
    std::string role;
    std::string expire_dur = "1h";
    std::vector<std::string> endpoints;

    for (size_t i = 1; i < args.size(); ++i) {
        if (args[i] == "--expire" && i + 1 < args.size()) {
            expire_dur = args[++i];
        } else if (args[i] == "--endpoint" && i + 1 < args.size()) {
            endpoints.push_back(args[++i]);
        } else if (role.empty() && !args[i].starts_with("-")) {
            role = args[i];
        }
    }

    if (role.empty()) {
        std::fprintf(stderr, "Usage: smo-admin --mesh-dir <dir> generate-invite <role> [--expire <dur>] [--endpoint <ep>...]\n");
        return 1;
    }

    // Read mesh.json
    std::string path = mesh_dir + "/mesh.json";
    std::ifstream f(path);
    if (!f) {
        std::fprintf(stderr, "Error: no mesh.json found at %s\n", path.c_str());
        return 1;
    }
    std::string json((std::istreambuf_iterator<char>(f)),
                      std::istreambuf_iterator<char>());

    std::string mesh_id         = json_read_string(json, "mesh_id");
    if (mesh_id.empty()) mesh_id = fs::path(mesh_dir).filename().string();
    std::string hmac_secret_hex = json_read_string(json, "hmac_secret");
    int64_t mesh_epoch          = json_read_int(json, "epoch", 1);
    auto suite_id               = read_suite_from_mesh(mesh_dir);

    if (hmac_secret_hex.empty()) {
        std::fprintf(stderr, "Error: mesh.json has no hmac_secret\n");
        return 1;
    }

    Bytes hmac_secret;
    for (size_t i = 0; i + 1 < hmac_secret_hex.size(); i += 2) {
        char buf[3] = {hmac_secret_hex[i], hmac_secret_hex[i+1], 0};
        hmac_secret.push_back(static_cast<uint8_t>(std::strtoul(buf, nullptr, 16)));
    }

    const smo::CryptoProvider* crypto = nullptr;
    smo::RngRef rng;
    if (!get_crypto(suite_id, crypto, rng)) return 1;

    int64_t expiry = 0;
    if (!expire_dur.empty() && expire_dur != "0") {
        char unit = expire_dur.back();
        int64_t num = 0;
        try { num = std::stoll(expire_dur.substr(0, expire_dur.size() - 1)); } catch (...) {}
        int64_t mult = 3600;
        switch (unit) {
            case 's': mult = 1; break;
            case 'm': mult = 60; break;
            case 'h': mult = 3600; break;
            case 'd': mult = 86400; break;
        }
        auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        expiry = now + num * mult;
    }

    auto token_result = smo::enroll::generate_token(
        mesh_id, mesh_epoch, static_cast<int>(suite_id),
        endpoints, role, expiry, hmac_secret, crypto->hash
    );
    if (!token_result) {
        std::fprintf(stderr, "Error: token generation failed: %s\n",
                     token_result.error().message.c_str());
        return 1;
    }

    auto wire = smo::enroll::encode_token_wire(token_result.value());
    std::printf("%s\n", wire.c_str());
    return 0;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--help") == 0 ||
            std::strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }

    // Parse --mesh-dir
    std::string mesh_dir;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--mesh-dir") == 0 && i + 1 < argc) {
            mesh_dir = argv[++i];
            // Shift remaining args
            for (int j = i - 1; j + 2 < argc; ++j) argv[j] = argv[j + 2];
            argc -= 2;
            break;
        }
    }

    // Register all available crypto suites
    register_all_suites();

    std::vector<std::string> args(argv + 1, argv + argc);
    if (args.empty()) {
        print_usage(argv[0]);
        return 1;
    }

    auto cmd = args[0];

    if (cmd == "create-mesh") {
        std::string name = (args.size() > 1) ? args[1] : "";
        std::string output_dir = mesh_dir.empty()
            ? fs::current_path().string()
            : mesh_dir;
        if (name.empty()) {
            std::fprintf(stderr, "Usage: smo-admin --mesh-dir <dir> create-mesh <name>\n");
            return 1;
        }
        return cmd_create_mesh(name, output_dir);
    }

    if (cmd == "sign") {
        if (mesh_dir.empty()) {
            std::fprintf(stderr, "Error: --mesh-dir is required for sign command\n");
            return 1;
        }
        return cmd_sign(args, mesh_dir);
    }

    if (cmd == "generate-invite") {
        if (mesh_dir.empty()) {
            std::fprintf(stderr, "Error: --mesh-dir is required for generate-invite command\n");
            return 1;
        }
        return cmd_generate_invite(args, mesh_dir);
    }

    std::fprintf(stderr, "Unknown command: %s\n", cmd.c_str());
    print_usage(argv[0]);
    return 1;
}
