// §XIX — CLI Design
// smo-node: actual node daemon.
//
// Responsibilities:
// - receive intents
// - run FSM
// - manage sessions
// - capability enforcement
// - execute DAG tasks

#include <core/crypto/impl.hpp>
#include <core/crypto/registry.hpp>
#include <core/crypto/suite.hpp>
#include <core/discovery/discovery.hpp>
#include <core/errors/error.hpp>
#include <core/identity/identity.hpp>
#include <core/types.hpp>
#include <core/transport/transport.hpp>
#include <core/transport/tcp_transport.hpp>
#include <core/transport/secure_session.hpp>
#include <core/network/udp/udp_transport.hpp>
#include <core/select/selector.hpp>
#include <core/network/udp/heartbeat_service.hpp>
#include <core/discovery/gossip.hpp>
#include <core/network/sync/membership_sync.hpp>
#include <core/network/sync/sync_service.hpp>
#include <core/network/transport/address_resolver.hpp>
#include <core/discovery/peer_store.hpp>
#include <core/certificate/certificate.hpp>
#include <core/enroll/auto_enroll.hpp>
#include <core/mesh/mesh_resolver.hpp>
#include <core/mesh/mesh_manager.hpp>
#include <core/authority/authority.hpp>
#include <core/governance/governance.hpp>
#include <core/recovery/crl.hpp>
#include <core/storage/manifest_store.hpp>
#include <sqlite3.h>
#include <core/network/packet_dispatcher.hpp>
#include <core/fsm/node_lifecycle_fsm.hpp>
#include <core/bootstrap/bootstrap_protocol.hpp>
#include <core/join/join_protocol.hpp>
#include <core/runtime/runtime_bridge.hpp>
#include <core/runtime/middleware_pipeline.hpp>
#include <core/runtime/policy_middleware.hpp>
#include <core/runtime/action_executor.hpp>
#include <core/runtime/dispatcher.hpp>
#include <core/runtime/contracts/echo_contract.hpp>
#include <core/runtime/contracts/bootstrap_contract.hpp>
#include <core/runtime/contracts/join_contract.hpp>
#include <core/runtime/contracts/governance_contract.hpp>
// Recovery/File/Process contracts registered in future sprint
#include <core/runtime/output_manager.hpp>
#include <core/session/session.hpp>
#include <core/trust/trust.hpp>
#include <tooling/clipboard.hpp>
#include <core/recovery/recovery_engine.hpp>
#include <core/recovery/crl.hpp>
#include <core/runtime/contracts/recovery_contract.hpp>
#include <core/runtime/contracts/file_contract.hpp>
#include <core/runtime/contracts/process_contract.hpp>
#include <core/runtime/contracts/deployment_contract.hpp>
#include <core/runtime/contracts/trust_contract.hpp>
#include <core/runtime/service_registry.hpp>
#include <core/runtime/telemetry.hpp>
#include <core/runtime/structured_logger.hpp>
#include <core/network/sync/anti_entropy.hpp>
#include <core/network/sync/sync_backend.hpp>
// ── Vault setup ──────────────────────────────────────────────
#include <storage/policy_store/policy_store.h>

#include <providers/blake3_provider/blake3_provider.hpp>
#include <providers/suite1_classical/suite1_classical_provider.hpp>
#include <providers/suite2_modern/suite2_modern_provider.hpp>
#include <providers/suite3_purepqc/suite3_purepqc_provider.hpp>

#include <core/runtime/node_runtime.hpp>

#include <chrono>
#include <csignal>
#include <cstdlib>
#include <poll.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

// ---------------------------------------------------------------------------
// Local utilities
// ---------------------------------------------------------------------------
namespace {

    std::string bytes_to_base64(smo::BytesView data)
    {
        static const char kEnc[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                   "abcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out;
        for (size_t i = 0; i < data.size(); i += 3)
        {
            uint32_t v = (uint32_t)data[i] << 16;
            if (i + 1 < data.size())
                v |= (uint32_t)data[i + 1] << 8;
            if (i + 2 < data.size())
                v |= (uint32_t)data[i + 2];
            out += kEnc[(v >> 18) & 0x3f];
            out += kEnc[(v >> 12) & 0x3f];
            out += (i + 1 < data.size()) ? kEnc[(v >> 6) & 0x3f] : '=';
            out += (i + 2 < data.size()) ? kEnc[v & 0x3f] : '=';
        }
        return out;
    }

} // anonymous namespace

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

// ===========================================================================
// Helpers
// ===========================================================================

static void node_id_to_hex(const smo::NodeID& id, std::string& out)
{
    std::ostringstream oss;
    for (uint8_t b : id.value)
    {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    }
    out = oss.str();
}

// Load file contents as Bytes
static smo::Bytes load_file_binary(const std::string& path)
{
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f)
        return {};
    auto size = f.tellg();
    f.seekg(0);
    smo::Bytes data(static_cast<size_t>(size));
    f.read(reinterpret_cast<char*>(data.data()), size);
    return data;
}

// Write Bytes to file
static bool write_file_binary(const std::string& path, smo::BytesView data)
{
    std::ofstream f(path, std::ios::binary);
    if (!f)
        return false;
    f.write(reinterpret_cast<const char*>(data.data()), data.size());
    return f.good();
}

// ===========================================================================
// Utils
// ===========================================================================

static std::string read_stdin()
{
    std::string data;
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), stdin)) > 0)
    {
        data.append(buf, n);
    }
    return data;
}

static bool has_stdin_data()
{
    struct pollfd pfd = {STDIN_FILENO, POLLIN, 0};
    return poll(&pfd, 1, 0) > 0 && (pfd.revents & POLLIN);
}

static smo::Bytes load_cert_blob(const std::string& path_or_empty)
{
    // Try stdin first
    if (has_stdin_data())
    {
        auto data = read_stdin();
        if (!data.empty())
        {
            std::fprintf(stderr, "[smo-node] Reading certificate from stdin...\n");
            return smo::Bytes(data.begin(), data.end());
        }
    }
    // Try clipboard
    if (path_or_empty.empty() && smo::clipboard_available())
    {
        auto data = smo::clipboard_paste();
        if (!data.empty())
        {
            std::fprintf(stderr, "[smo-node] Reading certificate from clipboard...\n");
            return smo::Bytes(data.begin(), data.end());
        }
    }
    // Try file
    if (!path_or_empty.empty())
    {
        return load_file_binary(path_or_empty);
    }
    return {};
}

// ===========================================================================
// Register all available crypto suites
// ===========================================================================
static void ensure_crypto()
{
    smo::Blake3Provider::register_as_default();
    smo::providers::register_suite1_classical();
    smo::providers::register_suite2_modern();
#ifdef SMO_WITH_PQC
    smo::providers::register_suite3_purepqc();
#endif
}

// ===========================================================================
// Look up crypto provider by suite ID from registry
// ===========================================================================
static const smo::CryptoProvider* get_crypto(smo::CryptoSuiteID suite_id)
{
    auto& reg = smo::CryptoRegistry::instance();
    auto prov_result = reg.get_suite(suite_id);
    if (!prov_result)
    {
        std::fprintf(stderr, "Error: cipher suite %u not registered\n", (unsigned)suite_id);
        return nullptr;
    }
    return prov_result.value();
}

// ===========================================================================
// Cmd: --init
// ===========================================================================
static int cmd_init(const std::string& name, const std::string& data_dir)
{
    ensure_crypto();

    const auto* crypto = get_crypto(smo::kSuitePurePQC);
    if (!crypto)
        return 1;
    auto rng = crypto->default_rng();

    // Create identity (generates keypair)
    auto id_result = smo::Identity::create(*crypto, rng);
    if (!id_result)
    {
        std::fprintf(stderr, "Error: identity creation failed: %s\n", id_result.error().message.c_str());
        return 1;
    }
    auto identity = std::move(id_result.value());

    // Save identity to file
    std::string id_path = data_dir + "/identity.json";
    if (auto r = identity.save_to_file(id_path); !r)
    {
        std::fprintf(stderr, "Error: cannot save identity: %s\n", r.error().message.c_str());
        return 1;
    }

    // Build CSR
    smo::CertificateSigningRequest csr;
    csr.new_public_key = smo::Bytes(identity.public_key().begin(), identity.public_key().end());
    csr.display_name = name;
    csr.platform = "linux";
    csr.version = "0.1.0";
    csr.timestamp =
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    // For initial CSR, sign with the new key itself
    auto sign_result = csr.sign(crypto->signer, identity.secret_key(), rng);
    if (!sign_result)
    {
        std::fprintf(stderr, "Error: CSR signing failed: %s\n", sign_result.error().message.c_str());
        return 1;
    }

    // Save CSR
    std::string csr_path = data_dir + "/node.csr.smor";
    auto csr_serialized = csr.serialize();
    if (!write_file_binary(csr_path, csr_serialized))
    {
        std::fprintf(stderr, "Error: cannot write CSR file: %s\n", csr_path.c_str());
        return 1;
    }

    std::string nid_hex;
    node_id_to_hex(identity.node_id(), nid_hex);
    std::printf("Identity created:\n");
    std::printf("  NodeID:       %s\n", nid_hex.c_str());
    std::printf("  Display name: %s\n", name.c_str());
    std::printf("  Identity:     %s\n", id_path.c_str());
    std::printf("  CSR:          %s\n", csr_path.c_str());
    std::printf("\n");
    std::printf("Next: Submit %s to the mesh authority for signing.\n", csr_path.c_str());
    std::printf("      Then run: smo-node --import <signed-cert>.smoc --data %s\n", data_dir.c_str());
    return 0;
}

// ===========================================================================
// Cmd: --export
// ===========================================================================
static int cmd_export(const std::string& output_path, const std::string& data_dir)
{
    ensure_crypto();

    const auto* crypto = get_crypto(smo::kSuitePurePQC);
    if (!crypto)
        return 1;

    auto id_result = smo::Identity::load_from_file(data_dir + "/identity.json", *crypto);
    if (!id_result)
    {
        std::fprintf(stderr, "Error: cannot load identity: %s\n", id_result.error().message.c_str());
        return 1;
    }
    auto& identity = id_result.value();
    auto rng = crypto->default_rng();

    // Read existing CSR if present, else build a new one
    std::string csr_path = data_dir + "/node.csr.smor";
    auto existing = load_file_binary(csr_path);
    if (!existing.empty())
    {
        // Copy existing CSR to output
        if (!write_file_binary(output_path, existing))
        {
            std::fprintf(stderr, "Error: cannot write CSR file: %s\n", output_path.c_str());
            return 1;
        }
        std::printf("CSR exported: %s -> %s\n", csr_path.c_str(), output_path.c_str());
        return 0;
    }

    // Build new CSR
    smo::CertificateSigningRequest csr;
    csr.new_public_key = smo::Bytes(identity.public_key().begin(), identity.public_key().end());

    // Try to read display name from existing cert or use "unnamed"
    csr.display_name = "unnamed-node";
    csr.platform = "linux";
    csr.version = "0.1.0";
    csr.timestamp =
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();

    auto sign_result = csr.sign(crypto->signer, identity.secret_key(), rng);
    if (!sign_result)
    {
        std::fprintf(stderr, "Error: CSR signing failed: %s\n", sign_result.error().message.c_str());
        return 1;
    }

    auto csr_serialized = csr.serialize();
    if (!write_file_binary(output_path, csr_serialized))
    {
        std::fprintf(stderr, "Error: cannot write CSR file: %s\n", output_path.c_str());
        return 1;
    }

    // Also save to data dir for convenience
    write_file_binary(csr_path, csr_serialized);

    std::printf("CSR exported: %s (%zu bytes)\n", output_path.c_str(), csr_serialized.size());
    return 0;
}

// ===========================================================================
// Cmd: --import
//
// Auto-detect transport: stdin → clipboard → filename
// ===========================================================================
static int cmd_import(const std::string& cert_path_or_empty, const std::string& data_dir)
{
    ensure_crypto();

    const auto* crypto = get_crypto(smo::kSuitePurePQC);
    if (!crypto)
        return 1;

    // Load identity
    auto id_result = smo::Identity::load_from_file(data_dir + "/identity.json", *crypto);
    if (!id_result)
    {
        std::fprintf(stderr, "Error: cannot load identity: %s\n", id_result.error().message.c_str());
        return 1;
    }
    auto identity = std::move(id_result.value());

    // Auto-detect transport: stdin → clipboard → file
    auto cert_blob = load_cert_blob(cert_path_or_empty);
    if (cert_blob.empty())
    {
        std::fprintf(stderr, "Error: no certificate data found.\n"
                             "  Try: smo node import <file.smoc>\n"
                             "   or: cat cert.smoc | smo node import\n"
                             "   or: smo node import (with certificate in clipboard)\n");
        return 1;
    }

    auto cert_result = smo::Certificate::deserialize(cert_blob);
    if (!cert_result)
    {
        std::fprintf(stderr, "Error: invalid certificate: %s\n", cert_result.error().message.c_str());
        return 1;
    }
    auto& cert = cert_result.value();

    // Verify certificate signature
    auto verify_result = cert.verify(crypto->signer);
    if (!verify_result)
    {
        std::fprintf(stderr, "Error: certificate verification failed: %s\n", verify_result.error().message.c_str());
        return 1;
    }
    if (!verify_result.value())
    {
        std::fprintf(stderr, "Error: certificate signature is invalid\n");
        return 1;
    }

    // Update identity state
    identity.transition_to(smo::IdentityState::Enrolled);

    // Save updated identity
    if (auto r = identity.save_to_file(data_dir + "/identity.json"); !r)
    {
        std::fprintf(stderr, "Error: cannot save identity: %s\n", r.error().message.c_str());
        return 1;
    }

    // Save certificate
    std::string cert_out = data_dir + "/node.cert.smoc";
    if (!write_file_binary(cert_out, cert_blob))
    {
        std::fprintf(stderr, "Error: cannot save certificate: %s\n", cert_out.c_str());
        return 1;
    }

    // ── Post-import summary ────────────────────────────────────
    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    char expiry_buf[32] = {};
    if (cert.not_after > 0)
    {
        std::tm* tm = std::gmtime(&cert.not_after);
        if (tm)
            std::strftime(expiry_buf, sizeof(expiry_buf), "%Y-%m-%d", tm);
    }

    std::printf("\n");
    std::printf("  Enrollment successful.\n");
    std::printf("\n");
    std::printf("  NodeID:          %s\n", identity.node_id().to_string().c_str());
    {
        auto fp_hash = crypto->hash.hash(smo::BytesView(cert_blob));
        std::string fp_hex = fp_hash ? smo::bytes_to_hex(fp_hash.value()).substr(0, 16) : "???";
        std::printf("  Certificate:     %s\n", fp_hex.c_str());
    }
    std::printf("  Cipher Suite:    Suite %d\n", (int)crypto->suite_id);
    std::printf("  Display Name:    %s\n", cert.display_name.c_str());
    std::printf("  Role:            %s\n", smo::to_string(cert.role));
    std::printf("  Epoch:           %llu\n", (unsigned long long)cert.epoch);
    if (expiry_buf[0])
        std::printf("  Valid until:     %s\n", expiry_buf);
    std::printf("\n");
    std::printf("  Node is now enrolled. Run with --daemon to start.\n");
    return 0;
}

// ===========================================================================
// Cmd: --export --copy (send CSR to clipboard)
// ===========================================================================
static int cmd_export_to_clipboard(const std::string& data_dir)
{
    ensure_crypto();

    const auto* crypto = get_crypto(smo::kSuitePurePQC);
    if (!crypto)
        return 1;

    auto id_result = smo::Identity::load_from_file(data_dir + "/identity.json", *crypto);
    if (!id_result)
    {
        std::fprintf(stderr, "Error: cannot load identity.\n"
                             "  Run 'smo-node --init --name <name>' first\n");
        return 1;
    }
    auto& identity = id_result.value();
    auto rng = crypto->default_rng();

    // Build CSR
    std::string csr_path = data_dir + "/node.csr.smor";
    auto existing = load_file_binary(csr_path);
    smo::Bytes csr_serialized;
    if (!existing.empty())
    {
        csr_serialized = existing;
    }
    else
    {
        smo::CertificateSigningRequest csr;
        csr.new_public_key = smo::Bytes(identity.public_key().begin(), identity.public_key().end());
        csr.display_name = "unnamed-node";
        csr.platform = "linux";
        csr.version = "0.1.0";
        csr.timestamp =
            std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
                .count();
        auto sign_result = csr.sign(crypto->signer, identity.secret_key(), rng);
        if (!sign_result)
        {
            std::fprintf(stderr, "Error: CSR signing failed: %s\n", sign_result.error().message.c_str());
            return 1;
        }
        csr_serialized = csr.serialize();
    }

    // Copy to clipboard (base64-encoded for text safety)
    std::string b64 = bytes_to_base64(csr_serialized);
    if (smo::clipboard_copy(b64))
    {
        std::printf("CSR copied to clipboard (%zu bytes).\n", csr_serialized.size());
        std::printf("  On the Authority machine, run:\n");
        std::printf("    smo-admin sign --paste\n");
        return 0;
    }
    std::fprintf(stderr, "Error: clipboard not available\n");
    return 1;
}

// ===========================================================================
// Cmd: --pubkey
// ===========================================================================
static int cmd_pubkey(bool do_copy, bool show_fingerprint, const std::string& data_dir)
{
    ensure_crypto();

    const auto* crypto = get_crypto(smo::kSuitePurePQC);
    if (!crypto)
        return 1;

    auto id_result = smo::Identity::load_from_file(data_dir + "/identity.json", *crypto);
    if (!id_result)
    {
        std::fprintf(stderr, "Error: cannot load identity: %s\n", id_result.error().message.c_str());
        std::fprintf(stderr, "  Run 'smo-node --init --name <name>' first\n");
        return 1;
    }
    auto& identity = id_result.value();

    if (show_fingerprint)
    {
        auto hash = crypto->hash.hash(identity.public_key());
        if (!hash)
        {
            std::fprintf(stderr, "Error: fingerprint computation failed\n");
            return 1;
        }
        std::string hex = smo::bytes_to_hex(hash.value());
        // Format as colon-separated pairs
        for (size_t i = 0; i < hex.size(); i += 2)
        {
            if (i > 0)
                std::putchar(':');
            std::printf("%c%c", hex[i], hex[i + 1]);
            if (i >= 18)
                break; // show first 20 hex chars = 10 bytes
        }
        std::putchar('\n');
        return 0;
    }

    // Base64url-encode public key with SMO-PUBKEY- prefix
    auto pk = identity.public_key();
    std::string b64;
    static const char kEnc[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                               "abcdefghijklmnopqrstuvwxyz0123456789-_";
    for (size_t i = 0; i < pk.size(); i += 3)
    {
        uint32_t v = (uint32_t)pk[i] << 16;
        if (i + 1 < pk.size())
            v |= (uint32_t)pk[i + 1] << 8;
        if (i + 2 < pk.size())
            v |= (uint32_t)pk[i + 2];
        b64 += kEnc[(v >> 18) & 0x3f];
        b64 += kEnc[(v >> 12) & 0x3f];
        if (i + 1 < pk.size())
            b64 += kEnc[(v >> 6) & 0x3f];
        if (i + 2 < pk.size())
            b64 += kEnc[v & 0x3f];
    }
    std::string output = "SMO-PUBKEY-" + b64;

    if (do_copy)
    {
        if (smo::clipboard_copy(output))
        {
            std::printf("Public key copied to clipboard.\n");
            return 0;
        }
        std::fprintf(stderr, "Error: clipboard not available\n");
        return 1;
    }

    std::printf("%s\n", output.c_str());
    return 0;
}

// ── SecureTransportSession — wraps SecureSession as TransportSession ──
struct SecureTransportSession : public smo::TransportSession
{
    smo::SecureSession sec;
    smo::Endpoint remote;
    bool open_ = true;

    SecureTransportSession(smo::SecureSession&& s, smo::Endpoint ep) : sec(std::move(s)), remote(std::move(ep)) {}

    // Legacy AEAD path
    smo::Result<void> send(smo::BytesView data) override { return sec.send(data); }
    smo::Result<smo::Bytes> recv(size_t) override { return sec.recv(); }

    // G3 Packet path: framing only (no AEAD at transport layer)
    smo::Result<void> send_framed(smo::BytesView payload) override { return sec.send_framed(payload); }
    smo::Result<smo::Bytes> recv_framed(size_t) override { return sec.recv_framed(); }

    smo::Result<void> close() override
    {
        open_ = false;
        return {};
    }
    smo::Endpoint remote_endpoint() const override { return remote; }
    bool is_open() const override { return open_; }
};

// ===========================================================================
// Main
// ===========================================================================

int main(int argc, char* argv[])
{
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    // ── Parse common args ──────────────────────────────────────
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
        else if (arg == "--export" && i + 1 < argc)
        {
            export_mode = true;
            export_path = argv[++i];
        }
        else if (arg == "--import" && i + 1 < argc)
        {
            import_mode = true;
            import_path = argv[++i];
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

    // ── Initialize data directory ──────────────────────────────
    auto create_dir = [](const std::string& dir) {
        if (dir.empty())
            return;
        namespace fs = std::filesystem;
        fs::create_directories(dir);
    };

    // ── Mode dispatch ──────────────────────────────────────────

    if (pubkey_mode)
    {
        if (!data_dir.empty())
            create_dir(data_dir);
        return cmd_pubkey(pubkey_copy, pubkey_fingerprint, data_dir);
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
        return cmd_init(node_name, data_dir);
    }

    if (export_mode)
    {
        if (export_copy)
        {
            // --copy flag: send CSR to clipboard instead of file
            return cmd_export_to_clipboard(data_dir);
        }
        if (export_path.empty())
        {
            std::fprintf(stderr, "Error: --export <file> requires a file path\n");
            return 1;
        }
        return cmd_export(export_path, data_dir);
    }

    if (import_mode)
    {
        // import_path may be empty → auto-detect (stdin → clipboard → file)
        return cmd_import(import_path, data_dir);
    }

    if (join_mode)
    {
        if (join_token.empty())
        {
            std::fprintf(stderr, "Error: --join requires a token\n");
            return 1;
        }
        ensure_crypto();
        auto result = smo::enroll::run_join_command(join_token, data_dir, node_name, static_cast<uint16_t>(port), "");
        if (!result)
        {
            std::fprintf(stderr, "Error: %s\n", result.error().message.c_str());
            return 1;
        }
        return 0;
    }

    // ── Legacy: show info if no flags ──────────────────────────
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

    // ====================================================================
    // Daemon mode — delegate to NodeRuntime composition root (P1)
    // ====================================================================

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
}
