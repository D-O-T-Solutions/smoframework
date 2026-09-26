// NodeRuntime - daemon composition root.
//
// Phase 1 (God Object sweep): owns every subsystem's lifecycle and exposes a
// thin, ordered surface: initialize() -> start() -> run() -> shutdown().
//
// Mechanical extraction of the daemon-mode block that previously lived inside
// cmd/smo-node/main.cpp. Semantics (ordering, config paths, ports, crypto
// flow, logging) preserved exactly; no behavior changed.
//
// Remaining network-loop / protocol-dispatch extraction is tracked in the
// ConnectionManager / UdpServer / protocol-service phases (P2/P3/P5).
//
// NOTE: the listen port is NOT hardcoded here - it comes from NodeRuntimeConfig
// supplied by the caller (main.cpp parses --port).

#include <core/runtime/node_runtime.hpp>

#include <core/crypto/impl.hpp>
#include <core/crypto/registry.hpp>
#include <core/crypto/suite.hpp>
#include <core/discovery/discovery.hpp>
#include <core/errors/error.hpp>
#include <core/identity/identity.hpp>
#include <core/transport/transport.hpp>
#include <core/transport/tcp_transport.hpp>
#include <core/transport/secure_session.hpp>
#include <core/network/udp/udp_transport.hpp>
#include <core/select/selector.hpp>
#include <core/network/udp/heartbeat_service.hpp>
#include <core/network/relay/relay_service.hpp>
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
#include <core/runtime/protocol_service.hpp>
#include <core/runtime/sync_delta_service.hpp>
#include <core/network/connection_manager.hpp>
#include <core/network/udp_server.hpp>
#include <core/bootstrap/bootstrap_client.hpp>
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
#include <core/runtime/output_manager.hpp>
#include <core/session/session.hpp>
#include <core/trust/trust.hpp>
#include <core/genesis/recovery_engine.hpp>
#include <core/recovery/crl.hpp>
#include <core/runtime/contracts/recovery_contract.hpp>
#include <core/runtime/contracts/file_contract.hpp>
#include <core/runtime/contracts/process_contract.hpp>
#include <core/runtime/contracts/deployment_contract.hpp>
#include <core/runtime/contracts/trust_contract.hpp>
#include <core/runtime/service_registry.hpp>
#include <core/runtime/telemetry.hpp>
#include <core/runtime/structured_logger.hpp>
#include <core/runtime/event_registry_service.hpp>
#include <core/runtime/authority_mesh_service.hpp>
#include <core/runtime/contract_registry_service.hpp>
#include <core/runtime/telemetry_service.hpp>
#include <core/runtime/session_manager_service.hpp>
#include <core/runtime/recovery_trust_service.hpp>
#include <core/runtime/governance_middleware_service.hpp>
#include <core/runtime/runtime_kernel_service.hpp>
#include <core/acl/policy_engine.hpp>
#include <core/network/sync/anti_entropy.hpp>
#include <core/network/sync/sync_backend.hpp>
#include <core/network/stun/stun_client.hpp>
#include <core/observability/metrics_server.hpp>
#include <core/observability/otlp_exporter.hpp>

#include <storage/policy_store/policy_store.h>

#include <providers/blake3_provider/blake3_provider.hpp>
#include <providers/suite1_classical/suite1_classical_provider.hpp>
#include <providers/suite2_modern/suite2_modern_provider.hpp>
#include <providers/suite3_purepqc/suite3_purepqc_provider.hpp>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <poll.h>
#include <sstream>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

#include <tooling/clipboard.hpp>

namespace smo::runtime {

// ===========================================================================
// Shared helpers (used by Impl and CLI commands)
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

static bool write_file_binary(const std::string& path, smo::BytesView data)
{
    std::ofstream f(path, std::ios::binary);
    if (!f)
        return false;
    f.write(reinterpret_cast<const char*>(data.data()), data.size());
    return f.good();
}

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

static void ensure_crypto()
{
    smo::Blake3Provider::register_as_default();
    smo::providers::register_suite1_classical();
    smo::providers::register_suite2_modern();
#ifdef SMO_WITH_PQC
    smo::providers::register_suite3_purepqc();
#endif
}

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

static int64_t now_ns_since_epoch()
{
    return static_cast<int64_t>(std::chrono::system_clock::now().time_since_epoch().count());
}

static smo::network::udp::HeartbeatService::Config make_hb_config(int port)
{
    smo::network::udp::HeartbeatService::Config hb_config;
    hb_config.ping_interval_ms = 5000;
    hb_config.ping_timeout_ms = 3000;
    hb_config.max_misses = 3;
    hb_config.local_port = port;
    return hb_config;
}

static std::string bytes_to_base64(smo::BytesView data)
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

// Sync backend bridging MembershipTable/CRL to the anti-entropy engine.
struct DaemonSyncBackend : smo::sync::SyncBackend
{
    smo::MembershipTable* memb_ptr;
    smo::recovery::CRL* crl_ptr;

    DaemonSyncBackend(smo::MembershipTable& tbl, smo::recovery::CRL* c) : memb_ptr(&tbl), crl_ptr(c) {}

    smo::sync::Delta get_membership_delta(const smo::sync::VersionVector& vv) override
    {
        (void)vv;
        return {};
    }
    smo::sync::Delta get_crl_delta(const smo::sync::VersionVector& vv) override
    {
        (void)vv;
        return {};
    }
    smo::sync::Delta get_policy_delta(const smo::sync::VersionVector& vv) override
    {
        (void)vv;
        return {};
    }
    smo::sync::Delta get_contract_delta(const smo::sync::VersionVector& vv) override
    {
        (void)vv;
        return {};
    }
    smo::sync::Delta get_full_snapshot(smo::sync::TreeID id) override
    {
        (void)id;
        return {};
    }
    smo::sync::MerkleTree compute_tree(smo::sync::TreeID id) override
    {
        auto tree = smo::sync::MerkleTree(id);
        tree.epoch = 1;
        tree.rebuild();
        return tree;
    }
};

NodeRuntime* NodeRuntime::current_ = nullptr;

NodeRuntime::NodeRuntime(const NodeRuntimeConfig& config) : impl_(std::make_unique<Impl>(config))
{
    current_ = this;
}

NodeRuntime::~NodeRuntime()
{
    if (current_ == this)
        current_ = nullptr;
}

// ===========================================================================
// Impl
// ===========================================================================
//
// Owns every subsystem. Construction order mirrors the daemon-mode block in
// main.cpp (transports -> engines -> runtime -> mesh/trust/recovery -> sync).
// N3: RelayService metrics callback implementation
class RelayMetricsCallback : public smo::network::relay::RelayService::MetricsCallback
{
public:
    void increment_counter(const std::string& name, const std::string& labels, int64_t delta) override
    {
        smo::runtime::global_telemetry().increment_counter(name, labels, delta);
    }
    void set_gauge(const std::string& name, double value, const std::string& labels) override
    {
        smo::runtime::global_telemetry().set_gauge(name, value, labels);
    }
};

class NodeRuntime::Impl
{
public:
    explicit Impl(const NodeRuntimeConfig& cfg);
    ~Impl() = default;

    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;

    Result<void> initialize();
    Result<void> start();
    void shutdown();
    int run();

    // initialize() stage helpers (order-preserving split of the daemon block)
    void print_mesh_bootstrap_summary();
    void connect_to_seed();
    void subscribe_membership_events();
    void wire_runtime();
    void _wire_sync_services();

private:
    RelayMetricsCallback relay_metrics_cb_;
    smo::runtime::EventRegistryService event_registry_service_;
    std::unique_ptr<smo::runtime::AuthorityMeshService> authority_mesh_service_;
    std::unique_ptr<smo::runtime::ContractRegistryService> contract_registry_service_;
    NodeRuntimeConfig config_;
    std::string data_dir_;

    // crypto / identity
    const smo::CryptoProvider* crypto_ = nullptr;
    smo::Identity identity_;
    smo::NodeID local_id_;
    std::string local_id_hex_;

    // PQ handshake material (loaded once, used by accept loop + seed connect)
    smo::Bytes server_cert_blob_;
    smo::Bytes server_signing_key_;
    smo::Bytes root_public_key_;
    std::string mesh_id_str_;
    uint64_t current_epoch_ = 1; // C1.3: Capability Epoch for revocation

    // transports / listeners
    std::unique_ptr<smo::network::udp::UdpTransport> udp_transport_;
    smo::ListenerPtr udp_listener_owner_;
    smo::TransportListener* udp_listener_ = nullptr;
    smo::ListenerPtr tcp_listener_owner_;

    // core engines
    smo::MembershipTable membership_;
    smo::HealthMonitor health_monitor_;
    smo::DiscoveryEngine discovery_;
    smo::GossipEngine gossip_;
    smo::network::sync::MembershipSync membership_sync_;
    smo::PeerStore peer_store_;
    smo::network::transport::AddressResolver address_resolver_;
    smo::network::udp::HeartbeatService heartbeat_;
    smo::network::relay::RelayService relay_service_;
    smo::PeerRecord self_record_;

    // runtime
    smo::runtime::EventBus event_bus_;
    smo::runtime::OutputManager output_mgr_;
    smo::runtime::Dispatcher runtime_dispatcher_;
    smo::runtime::PlanResolver plan_resolver_;
    smo::runtime::RuntimeKernel runtime_kernel_;
    smo::SessionManager session_mgr_;
    smo::MeshManager mesh_manager_;
    smo::authority::MeshAuthority authority_;
    smo::mesh::MeshFsm mesh_fsm_;  // C6.1: MeshFSM for lifecycle transitions
    smo::GovernanceEngine governance_engine_;
    smo::TrustManager trust_mgr_;
    smo::recovery::CRL crl_;
    smo::sync::SyncService sync_service_;
    smo::ManifestStore manifest_store_;
    smo::PolicyStore policy_store_;
    smo::recovery::RecoveryEngine recovery_engine_;
    smo::runtime::MiddlewarePipeline middleware_pipeline_;
    smo::runtime::RuntimeBridge runtime_bridge_;
    smo::network::PacketDispatcher dispatcher_;
    smo::runtime::ProtocolService protocol_service_;
    smo::runtime::SyncDeltaService sync_delta_service_;
    smo::NodeLifecycleFSM node_fsm_;
    smo::acl::PolicyEngine policy_engine_;

    // anti-entropy
    std::shared_ptr<DaemonSyncBackend> sync_backend_;
    std::unique_ptr<smo::sync::AntiEntropyService> anti_entropy_;

    // services (extracted from run() loop)
    std::unique_ptr<smo::runtime::TelemetryService> telemetry_service_;
    std::unique_ptr<smo::runtime::SessionManagerService> session_manager_service_;
    std::unique_ptr<smo::runtime::RecoveryTrustService> recovery_trust_service_;
    std::unique_ptr<smo::runtime::GovernanceMiddlewareService> governance_middleware_service_;
    std::unique_ptr<smo::runtime::RuntimeKernelService> runtime_kernel_service_;
    std::unique_ptr<smo::observability::MetricsServer> metrics_server_;
    std::unique_ptr<smo::observability::OtlpExporter> otlp_exporter_;

    // delta bookkeeping (persisted across initialize/run cycles)
    uint64_t last_crl_epoch_ = 0;
    uint64_t last_policy_version_ = 0;
    uint64_t last_manifest_epoch_ = 0;

    // run() bookkeeping
    int64_t last_tick_ = 0;
    int64_t last_peerstore_sync_ = 0;
    int64_t daemon_start_ns_ = 0;
    bool daemon_ready_logged_ = false;
    bool daemon_degraded_logged_ = false;
};

NodeRuntime::Impl::Impl(const NodeRuntimeConfig& cfg)
    : config_(cfg)
    , data_dir_(cfg.data_dir)
    , udp_transport_(std::make_unique<smo::network::udp::UdpTransport>())
    , discovery_(membership_, health_monitor_, *udp_transport_)
    , gossip_(membership_, smo::GossipEngine::default_config(), &smo::runtime::global_telemetry())
    , membership_sync_(membership_, health_monitor_)
    , heartbeat_(make_hb_config(cfg.port))
    , relay_service_(smo::network::relay::RelayService::default_config())
    , runtime_kernel_(event_bus_, output_mgr_, runtime_dispatcher_, plan_resolver_)
    , mesh_manager_(smo::MeshManager::Config{
          .base_data_dir = cfg.mesh_dir.empty() ? "" : cfg.mesh_dir.substr(0, cfg.mesh_dir.rfind("/meshes/") + 7)})
    , sync_service_(gossip_, &crl_, smo::sync::SyncSchedule{})
    , policy_store_(cfg.data_dir)
    , recovery_engine_(smo::recovery::RecoveryConfig{})
    , runtime_bridge_(runtime_kernel_, runtime_dispatcher_)
    , protocol_service_(smo::runtime::ProtocolService::Config{},
                        discovery_, mesh_manager_, authority_, crl_,
                        local_id_, self_record_)
    , sync_delta_service_(smo::runtime::SyncDeltaService::Config{data_dir_},
                          sync_service_, gossip_, crl_,
                          manifest_store_, policy_store_)
    , policy_engine_(smo::acl::PolicyEngine::Config{.policy_dir = data_dir_})
    , event_registry_service_(smo::runtime::EventRegistryService::Dependencies{
          .event_bus = event_bus_,
          .session_mgr = session_mgr_,
          .peer_store = peer_store_,
          .mesh_manager = mesh_manager_,
          .authority = authority_,
          .crl = crl_,
          .discovery = discovery_,
          .gossip = gossip_,
          .telemetry = smo::runtime::global_telemetry(),
          .output_mgr = output_mgr_,
          .trust_mgr = trust_mgr_,
          .governance_engine = governance_engine_,
          .address_resolver = address_resolver_,
          .heartbeat = heartbeat_,
          .membership = membership_})
    , mesh_fsm_(&authority_)
{
    // Services constructed after all dependencies are available
    telemetry_service_ = std::make_unique<smo::runtime::TelemetryService>(
        smo::runtime::global_telemetry(), smo::runtime::global_logger(), data_dir_);
    session_manager_service_ = std::make_unique<smo::runtime::SessionManagerService>(session_mgr_, data_dir_);
    recovery_trust_service_ = std::make_unique<smo::runtime::RecoveryTrustService>(trust_mgr_, recovery_engine_);
    governance_middleware_service_ = std::make_unique<smo::runtime::GovernanceMiddlewareService>(
        middleware_pipeline_,
        smo::runtime::GovernanceMiddlewareService::Dependencies{
            .governance_engine = &governance_engine_,
            .trust_mgr = &trust_mgr_,
            .policy_engine = &policy_engine_,
            .lifecycle_fsm = &node_fsm_
        });
    runtime_kernel_service_ = std::make_unique<smo::runtime::RuntimeKernelService>(
        smo::runtime::RuntimeKernelService::Dependencies{
            .event_bus = event_bus_,
            .output_mgr = output_mgr_,
            .dispatcher = runtime_dispatcher_,
            .plan_resolver = plan_resolver_});
    metrics_server_ = std::make_unique<smo::observability::MetricsServer>(smo::runtime::global_telemetry());

    // Initialize OTLP exporter with default config (can be overridden via env vars)
    smo::observability::OtlpExporter::Config otlp_config;
    const char* otlp_endpoint = std::getenv("SMO_OTLP_ENDPOINT");
    if (otlp_endpoint)
        otlp_config.endpoint = otlp_endpoint;
    const char* otlp_service_name = std::getenv("SMO_OTLP_SERVICE_NAME");
    if (otlp_service_name)
        otlp_config.service_name = otlp_service_name;
    const char* otlp_protocol = std::getenv("SMO_OTLP_PROTOCOL");
    if (otlp_protocol)
        otlp_config.protocol = otlp_protocol;
    otlp_exporter_ = std::make_unique<smo::observability::OtlpExporter>(otlp_config);
}

// ===========================================================================
// initialize() — identity, transports, engines, bootstrap, runtime wiring
// ===========================================================================

Result<void> NodeRuntime::Impl::initialize()
{
    auto& LOG = smo::runtime::global_logger();

    ensure_crypto();
    crypto_ = get_crypto(smo::kSuitePurePQC);
    if (!crypto_)
    {
        return smo::Error(smo::ErrorCode(smo::ErrorCategory::Crypto, 1, smo::Severity::Error,
                                         smo::RetryClass::NoRetry, smo::Recovery::None),
                          "cipher suite %u not available", __FILE__, __LINE__);
    }

    // Load identity
    std::string id_path = data_dir_ + "/identity.json";
    auto id_result = smo::Identity::load_from_file(id_path, *crypto_);
    if (!id_result)
    {
        std::fprintf(stderr, "[smo-node] Fatal: cannot load identity from %s: %s\n", id_path.c_str(),
                     id_result.error().message.c_str());
        std::fprintf(stderr, "[smo-node] Run 'smo-node --init --name <name>' first\n");
        return id_result.error();
    }
    identity_ = std::move(id_result.value());

    local_id_ = identity_.node_id();
    node_id_to_hex(local_id_, local_id_hex_);
    std::printf("[smo-node] Local NodeID: %s (state: %s)\n", local_id_hex_.c_str(),
                smo::to_string(identity_.state()));

    // Structured Logger (P10)
    {
        auto& slog = smo::runtime::global_logger();
        slog.set_node_id(local_id_hex_);
        slog.set_component("smo-node");
        std::string lf = std::getenv("SMO_LOG_FORMAT") ? std::getenv("SMO_LOG_FORMAT") : "plaintext";
        if (lf == "json")
            slog.set_format(smo::runtime::StructuredLogger::Format::Json);
    }
    LOG.info("starting daemon on port " + std::to_string(config_.port));
    LOG.info("node_id: " + local_id_hex_);

    // Load server certificate for PQ handshake
    std::string cert_path = data_dir_ + "/node.cert.smoc";
    server_cert_blob_ = load_file_binary(cert_path);
    if (server_cert_blob_.empty())
    {
        std::fprintf(stderr, "[smo-node] Warning: no certificate at %s, PQ handshake disabled\n", cert_path.c_str());
    }
    server_signing_key_ = smo::Bytes(identity_.secret_key().begin(), identity_.secret_key().end());

    // Load root public key (mesh authority) for client certificate verification
    std::string root_pub_path = "";
    if (!config_.mesh_dir.empty())
    {
        root_pub_path = config_.mesh_dir + "/authority.pub";
    }
    root_public_key_ = load_file_binary(root_pub_path);
    if (root_public_key_.empty() && !config_.mesh_dir.empty())
    {
        std::fprintf(stderr, "[smo-node] Warning: no root public key at %s, client cert verification may fail\n",
                     root_pub_path.c_str());
    }
    mesh_id_str_ = "";
    if (!config_.mesh_dir.empty())
    {
        // Read canonical mesh_id and epoch from mesh.json (not the directory basename)
        std::string mesh_json_path = config_.mesh_dir + "/mesh.json";
        std::ifstream mfd(mesh_json_path);
        if (mfd)
        {
            std::string mjs((std::istreambuf_iterator<char>(mfd)), std::istreambuf_iterator<char>());
            auto mp = mjs.find("\"mesh_id\"");
            if (mp != std::string::npos)
            {
                auto mc = mjs.find(':', mp);
                auto ms = mc != std::string::npos ? mjs.find('"', mc + 1) : std::string::npos;
                auto me = ms != std::string::npos ? mjs.find('"', ms + 1) : std::string::npos;
                if (ms != std::string::npos && me != std::string::npos)
                    mesh_id_str_ = mjs.substr(ms + 1, me - ms - 1);
            }
            // C1.3: Read epoch for Capability Epoch revocation
            auto ep = mjs.find("\"epoch\"");
            if (ep != std::string::npos)
            {
                auto ec = mjs.find(':', ep);
                if (ec != std::string::npos)
                {
                    auto es = mjs.find_first_of("0123456789", ec);
                    if (es != std::string::npos)
                    {
                        auto ee = mjs.find_first_not_of("0123456789", es);
                        if (ee == std::string::npos)
                            ee = mjs.size();
                        try
                        {
                            current_epoch_ = std::stoull(mjs.substr(es, ee - es));
                        }
                        catch (...)
                        {
                            current_epoch_ = 1;
                        }
                    }
                }
            }
        }
        if (mesh_id_str_.empty())
            mesh_id_str_ = std::filesystem::path(config_.mesh_dir).filename().string();
    }
    smo::Bytes mesh_id_bytes(mesh_id_str_.begin(), mesh_id_str_.end());
    (void)mesh_id_bytes;

    // Register transports BEFORE any references
    smo::TransportRegistry::instance().register_transport(std::make_unique<smo::TcpTransport>(), "tcp");
    smo::TransportRegistry::instance().register_transport(std::make_unique<smo::network::udp::UdpTransport>(), "udp");
    auto* tcp_ptr = smo::TransportRegistry::instance().get("tcp");

    // UDP Transport (5.20: Discovery = UDP)
    smo::Endpoint udp_listen_ep;
    udp_listen_ep.scheme = "udp";
    udp_listen_ep.host = "0.0.0.0";
    udp_listen_ep.port = static_cast<uint16_t>(config_.port);

    auto udp_listener_result = udp_transport_->listen(udp_listen_ep);
    if (!udp_listener_result)
    {
        std::fprintf(stderr, "[smo-node] Failed to listen UDP: %s\n", udp_listener_result.error().message.c_str());
    }
    else
    {
        std::printf("[smo-node] Listening on udp://0.0.0.0:%d\n", config_.port);
        udp_listener_owner_ = std::move(udp_listener_result.value());
        udp_listener_ = udp_listener_owner_.get();
    }

    // DiscoveryEngine uses UDP transport (5.20)
    {
        auto gossip_cfg = smo::GossipEngine::default_config();
        std::printf("[smo-node] Gossip engine initialized (fanout=%u, interval=%llums)\n",
                    (unsigned)gossip_cfg.fanout, (unsigned long long)gossip_cfg.interval_ms);
    }
    gossip_.set_membership_sync(&membership_sync_);

    // PeerStore sync with MembershipTable
    if (auto r = peer_store_.open(data_dir_); !r)
    {
        std::fprintf(stderr, "[smo-node] Failed to open PeerStore: %s\n", r.error().message.c_str());
    }
    else
    {
        peer_store_.sync_to_membership(membership_);
    }

    // HeartbeatService — reuse the daemon's bound UDP socket; do NOT bind again.
    heartbeat_.set_local_node_id(local_id_);
    if (udp_listener_owner_)
    {
        auto* hb_listener = static_cast<smo::network::udp::UdpListener*>(udp_listener_owner_.get());
        auto hb_start = heartbeat_.start(*hb_listener, membership_, health_monitor_, &relay_service_);
        if (!hb_start)
        {
            std::fprintf(stderr, "[smo-node] Failed to start heartbeat: %s\n", hb_start.error().message.c_str());
        }
        else
        {
            auto hb_cfg = make_hb_config(config_.port);
            std::printf("[smo-node] Heartbeat service started (interval=%ums, timeout=%ums, max_misses=%u)\n",
                        hb_cfg.ping_interval_ms, hb_cfg.ping_timeout_ms, hb_cfg.max_misses);
        }

        // N2: Wire UDP listener to GossipEngine for UDP gossip fanout (hole-punched peers)
        gossip_.set_udp_listener(hb_listener);

// N2: Set hole punch callback to update metrics
        heartbeat_.set_hole_punch_callback([&](const NodeID& peer_id, bool success, const std::string& path) {
            // Metrics are recorded inside heartbeat_, but we can add additional logging here
            std::printf("[smo-node] N2: hole punch %s for %s via %s\n",
                        success ? "SUCCESS" : "FAILURE", peer_id.to_string().c_str(), path.c_str());

            // N2: Record hole punch metrics
            auto& telemetry = smo::runtime::global_telemetry();
            if (success)
            {
                telemetry.increment_counter("smo_hole_punch_success_total", "path=" + path);
            }
            else
            {
                telemetry.increment_counter("smo_hole_punch_failure_total", "path=" + path);
            }
        });

        // N5: Set NAT test status callback to update smo_nat_test_status metric
        heartbeat_.set_nat_test_status_callback([&](const NodeID& peer_id, uint8_t status) {
            auto& telemetry = smo::runtime::global_telemetry();
            telemetry.set_gauge("smo_nat_test_status", static_cast<double>(status), "peer=" + peer_id.to_string());
            std::printf("[smo-node] N5: nat_test_status for %s = %u\n", peer_id.to_string().c_str(), status);
        });
    }

    // N3: Start RelayService
    {
        auto relay_start = relay_service_.start(membership_, *udp_transport_, &relay_metrics_cb_);
        if (!relay_start)
        {
            std::fprintf(stderr, "[smo-node] Failed to start relay service: %s\n", relay_start.error().message.c_str());
        }
        else
        {
            auto relay_cfg = relay_service_.default_config();
            std::printf("[smo-node] Relay service started (bandwidth=%llu bps/peer, timeout=%ums)\n",
                        (unsigned long long)relay_cfg.bandwidth_bps_per_peer,
                        relay_cfg.session_timeout_ms);
        }

        // Set self as relay capable if configured (for now, always false unless explicitly set)
        // This would be set via config in the future
        self_record_.relay_capable = false;
    }

    // TCP listening endpoint
    smo::Endpoint listen_ep;
    listen_ep.scheme = "tcp";
    listen_ep.host = "0.0.0.0";
    listen_ep.port = static_cast<uint16_t>(config_.port);

    auto listen_result = tcp_ptr->listen(listen_ep);
    if (!listen_result)
    {
        std::fprintf(stderr, "[smo-node] Failed to listen TCP: %s\n", listen_result.error().message.c_str());
        return listen_result.error();
    }
    tcp_listener_owner_ = std::move(listen_result.value());

    std::printf("[smo-node] Listening on tcp://0.0.0.0:%d\n", config_.port);

    // Self peer record - used when answering HelloMsg so a joining member learns
    // the seed's identity, not its own (ephemeral) record.
    self_record_.node_id = local_id_;
    self_record_.display_name = config_.node_name.empty() ? "smo-node" : config_.node_name;
    self_record_.endpoint.scheme = "tcp";
    self_record_.endpoint.host = "127.0.0.1";
    self_record_.endpoint.port = static_cast<uint16_t>(config_.port);
    self_record_.state = smo::PeerState::Online;
    self_record_.last_seen = now_ns_since_epoch();

    // STUN discovery (N1) — run before joining mesh to learn mapped address
    // Uses default STUN server (stun.l.google.com:19302) with 3 retries, 2s timeout
    {
        auto& LOG = smo::runtime::global_logger();
        LOG.info("starting STUN discovery...");
        smo::network::stun::Config stun_cfg;
        stun_cfg.server_host = "stun.l.google.com";
        stun_cfg.server_port = 19302;
        stun_cfg.max_attempts = 3;
        stun_cfg.timeout = std::chrono::milliseconds(2000);

        auto stun_start = std::chrono::steady_clock::now();
        auto stun_result = smo::network::stun::discover_mapped_address(stun_cfg);
        auto stun_elapsed = std::chrono::steady_clock::now() - stun_start;
        auto stun_latency_sec = std::chrono::duration<double>(stun_elapsed).count();

        // Record STUN latency metric
        smo::runtime::global_telemetry().record_histogram("smo_stun_latency_seconds", stun_latency_sec);

        if (stun_result)
        {
            auto& mapped = stun_result.value();
            self_record_.mapped_address.ip = mapped.ip;
            self_record_.mapped_address.port = mapped.port;
            self_record_.mapped_address.is_ipv6 = mapped.is_ipv6;
            self_record_.mapped_address.discovered_at = now_ns_since_epoch();

            std::printf("[smo-node] STUN discovery: mapped address = %s (latency: %.3fs)\n",
                        self_record_.mapped_address.to_string().c_str(), stun_latency_sec);
            LOG.info("STUN discovery success: " + self_record_.mapped_address.to_string() +
                     " latency=" + std::to_string(stun_latency_sec) + "s");
        }
        else
        {
            std::fprintf(stderr, "[smo-node] STUN discovery failed: %s\n", stun_result.error().message.c_str());
            LOG.warn("STUN discovery failed: " + stun_result.error().message);
            // Not fatal — continue without mapped address
        }
    }

    // Construct services now that crypto_ and identity_ are available
    std::string mesh_base_dir = config_.mesh_dir.empty() ? "" :
        config_.mesh_dir.substr(0, config_.mesh_dir.rfind("/meshes/") + 7);
    authority_mesh_service_ = std::make_unique<smo::runtime::AuthorityMeshService>(
        smo::runtime::AuthorityMeshService::Config{
            .mesh_dir = config_.mesh_dir,
            .data_dir = mesh_base_dir},
        smo::runtime::AuthorityMeshService::Dependencies{
            .crypto = crypto_,
            .mesh_manager = mesh_manager_,
            .authority = authority_});

    contract_registry_service_ = std::make_unique<smo::runtime::ContractRegistryService>(
        smo::runtime::ContractRegistryService::Config{
            .data_dir = config_.data_dir},
        smo::runtime::ContractRegistryService::Dependencies{
            .mesh_manager = mesh_manager_,
            .authority = authority_,
            .governance_engine = governance_engine_,
            .crl = crl_,
            .session_mgr = session_mgr_,
            .trust_mgr = trust_mgr_,
            .recovery_engine = recovery_engine_,
            .runtime_dispatcher = runtime_dispatcher_,
            .runtime_bridge = runtime_bridge_,
            .middleware_pipeline = middleware_pipeline_,
            .packet_dispatcher = dispatcher_,
            .node_fsm = node_fsm_,
            .protocol_service = protocol_service_,
            .event_bus = event_bus_,
            .membership = membership_,
            .crypto = crypto_,
            .identity = identity_});

    print_mesh_bootstrap_summary();
    connect_to_seed();
    subscribe_membership_events();
    wire_runtime();

    // Set telemetry for session manager
    session_mgr_.set_telemetry(&smo::runtime::global_telemetry());
    session_mgr_.set_crl(&crl_);

    // Start metrics server on admin port
    if (metrics_server_)
    {
        auto metrics_result = metrics_server_->start(static_cast<uint16_t>(config_.admin_port));
        if (!metrics_result)
        {
            LOG.warn("Failed to start metrics server on port " + std::to_string(config_.admin_port) +
                     ": " + metrics_result.error().message);
        }
        else
        {
            LOG.info("Metrics server started on port " + std::to_string(config_.admin_port));
            std::printf("[smo-node] Metrics endpoint: http://0.0.0.0:%d/metrics\n", config_.admin_port);
        }
    }

    // Start OTLP exporter for distributed tracing
    if (otlp_exporter_)
    {
        auto otlp_result = otlp_exporter_->start();
        if (!otlp_result)
        {
            LOG.warn("Failed to start OTLP exporter: " + otlp_result.error().message);
        }
        else
        {
            LOG.info("OTLP exporter started: " + otlp_exporter_->get_stats().spans_exported);
            std::printf("[smo-node] OTLP exporter: %s\n", otlp_exporter_->get_stats().spans_exported > 0 ? "running" : "started");
        }
    }

    // Set telemetry for dispatcher (contract execution metrics)
    runtime_dispatcher_.set_telemetry(&smo::runtime::global_telemetry());

    return {};
}

// ===========================================================================
// Bootstrap summary — peer/role/status printout (purely informational)
// ===========================================================================

void NodeRuntime::Impl::print_mesh_bootstrap_summary()
{
    if (config_.mesh_dir.empty())
        return;

    std::string mesh_json = config_.mesh_dir + "/mesh.json";
    std::ifstream f(mesh_json);
    if (!f)
        return;

    std::string json((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    std::string listen_addr = "0.0.0.0:7777";
    std::vector<std::string> advertise;
    std::vector<std::string> bootstrap;
    bool bootstrap_configured = false;

    // Parse listen_address
    auto pos = json.find("\"listen_address\"");
    if (pos != std::string::npos)
    {
        auto colon = json.find(':', pos);
        auto start = json.find('"', colon + 1);
        if (start != std::string::npos)
        {
            auto end = json.find('"', start + 1);
            if (end != std::string::npos)
                listen_addr = json.substr(start + 1, end - start - 1);
        }
    }

    // Parse bootstrap_configured
    pos = json.find("\"bootstrap_configured\"");
    if (pos != std::string::npos)
    {
        auto colon = json.find(':', pos);
        auto start = json.find_first_of("tf", colon);
        if (start != std::string::npos)
            bootstrap_configured = json[start] == 't';
    }

    // Parse advertise_addresses
    pos = json.find("\"advertise_addresses\"");
    if (pos != std::string::npos)
    {
        auto colon = json.find(':', pos);
        auto arr_start = json.find('[', colon);
        if (arr_start != std::string::npos)
        {
            auto arr_end = json.find(']', arr_start);
            if (arr_end != std::string::npos)
            {
                std::string arr = json.substr(arr_start + 1, arr_end - arr_start - 1);
                size_t p = 0;
                while (true)
                {
                    auto q1 = arr.find('"', p);
                    if (q1 == std::string::npos)
                        break;
                    auto q2 = arr.find('"', q1 + 1);
                    if (q2 == std::string::npos)
                        break;
                    advertise.push_back(arr.substr(q1 + 1, q2 - q1 - 1));
                    p = q2 + 1;
                }
            }
        }
    }

    // Parse bootstrap_endpoints
    pos = json.find("\"bootstrap_endpoints\"");
    if (pos != std::string::npos)
    {
        auto colon = json.find(':', pos);
        auto arr_start = json.find('[', colon);
        if (arr_start != std::string::npos)
        {
            auto arr_end = json.find(']', arr_start);
            if (arr_end != std::string::npos)
            {
                std::string arr = json.substr(arr_start + 1, arr_end - arr_start - 1);
                size_t p = 0;
                while (true)
                {
                    auto q1 = arr.find('"', p);
                    if (q1 == std::string::npos)
                        break;
                    auto q2 = arr.find('"', q1 + 1);
                    if (q2 == std::string::npos)
                        break;
                    bootstrap.push_back(arr.substr(q1 + 1, q2 - q1 - 1));
                    p = q2 + 1;
                }
            }
        }
    }

    std::printf("Mesh: %s\n", config_.mesh_dir.c_str());
    std::printf("Status: %s\n", bootstrap_configured ? "ONLINE" : "OFFLINE");
    std::printf("Listen:     %s\n", listen_addr.c_str());
    for (const auto& addr : advertise)
        std::printf("Advertise:  %s\n", addr.c_str());
    if (bootstrap_configured)
        std::printf("Bootstrap:  YES\n");
    std::printf("Peers:      %zu\n", membership_.count());
}

// ===========================================================================
// connect_to_seed() — PQ seed bootstrap (faithful port of main.cpp 1139-1227)
// ===========================================================================

// ===========================================================================
// connect_to_seed() — PQ seed bootstrap via BootstrapClient (Phase 4)
// ===========================================================================

void NodeRuntime::Impl::connect_to_seed()
{
    if (config_.seed_addr.empty())
        return;

    smo::Endpoint seed_ep;
    auto ep_result = smo::Endpoint::from_string(config_.seed_addr);
    if (!ep_result)
    {
        std::fprintf(stderr, "[smo-node] Invalid seed address: %s\n", config_.seed_addr.c_str());
        return;
    }

    seed_ep = ep_result.value();

    // Build self PeerRecord for HELLO
    smo::PeerRecord self_record;
    self_record.node_id = local_id_;
    self_record.endpoint = smo::Endpoint{"tcp", "0.0.0.0", static_cast<uint16_t>(config_.port)};

    auto bs_res = smo::bootstrap::BootstrapClient::bootstrap(
        seed_ep,
        *crypto_,
        identity_,
        self_record,
        discovery_,
        server_cert_blob_,
        server_signing_key_,
        root_public_key_,
        mesh_id_str_,
        current_epoch_ // C1.3: Capability Epoch
    );

    if (!bs_res.success)
    {
        std::printf("[smo-node] Bootstrap failed, continuing as first node in mesh\n");
        return;
    }

    std::printf("[smo-node] Bootstrap complete. Peers: %zu\n", membership_.count());
}

// ===========================================================================
// wire_runtime() — EventBus/session/mesh/authority/sync/contracts/routes/
// handlers/subscriptions/registry/telemetry (port of main.cpp 1229-2138)
// ===========================================================================

void NodeRuntime::Impl::subscribe_membership_events()
{
    membership_sync_.subscribe([&](const smo::network::sync::MembershipEvent& ev) {
        std::printf("[smo-node] Membership event: type=%d\n", static_cast<int>(ev.type));
    });
}

void NodeRuntime::Impl::wire_runtime()
{
    auto& LOG = smo::runtime::global_logger();

    // SessionManager: crash-recover the session store (RFC 0014 6)
    if (session_manager_service_)
    {
        auto res = session_manager_service_->initialize();
        if (!res)
        {
            std::printf("[smo-node] SessionManagerService initialization failed: %s\n",
                        res.error().message.c_str());
        }
    }

    // Initialize Authority and MeshManager via service
    if (authority_mesh_service_)
    {
        auto res = authority_mesh_service_->initialize();
        if (!res)
        {
            std::printf("[smo-node] Warning: AuthorityMeshService initialization failed: %s\n",
                        res.error().message.c_str());
        }
    }

    // Initialize MeshFsm state from mesh config (C6.1: MeshFSM wiring)
    if (!config_.mesh_dir.empty())
    {
        std::string mesh_json_path = config_.mesh_dir + "/mesh.json";
        std::ifstream mfd(mesh_json_path);
        if (mfd)
        {
            std::string mjs((std::istreambuf_iterator<char>(mfd)), std::istreambuf_iterator<char>());
            auto ms_pos = mjs.find("\"mesh_state\"");
            if (ms_pos != std::string::npos)
            {
                auto colon = mjs.find(':', ms_pos);
                auto start = mjs.find('"', colon + 1);
                auto end = start != std::string::npos ? mjs.find('"', start + 1) : std::string::npos;
                if (start != std::string::npos && end != std::string::npos)
                {
                    std::string state_str = mjs.substr(start + 1, end - start - 1);
                    if (state_str == "Genesis")
                        mesh_fsm_.on_event(smo::mesh::MeshEvent::StartGenesis);
                    else if (state_str == "Bootstrap")
                    {
                        mesh_fsm_.on_event(smo::mesh::MeshEvent::StartGenesis);
                        mesh_fsm_.on_event(smo::mesh::MeshEvent::BootstrapReady);
                    }
                    else if (state_str == "Online")
                    {
                        mesh_fsm_.on_event(smo::mesh::MeshEvent::StartGenesis);
                        mesh_fsm_.on_event(smo::mesh::MeshEvent::BootstrapReady);
                        mesh_fsm_.on_event(smo::mesh::MeshEvent::AllSlotsFulfilled);
                    }
                    else if (state_str == "Maintenance")
                    {
                        mesh_fsm_.on_event(smo::mesh::MeshEvent::StartGenesis);
                        mesh_fsm_.on_event(smo::mesh::MeshEvent::BootstrapReady);
                        mesh_fsm_.on_event(smo::mesh::MeshEvent::AllSlotsFulfilled);
                        mesh_fsm_.on_event(smo::mesh::MeshEvent::EnterMaintenance);
                    }
                    else if (state_str == "Recovery")
                    {
                        mesh_fsm_.on_event(smo::mesh::MeshEvent::StartGenesis);
                        mesh_fsm_.on_event(smo::mesh::MeshEvent::BootstrapReady);
                        mesh_fsm_.on_event(smo::mesh::MeshEvent::TriggerRecovery);
                    }
                    else if (state_str == "Archived")
                    {
                        mesh_fsm_.on_event(smo::mesh::MeshEvent::StartGenesis);
                        mesh_fsm_.on_event(smo::mesh::MeshEvent::BootstrapReady);
                        mesh_fsm_.on_event(smo::mesh::MeshEvent::AllSlotsFulfilled);
                        mesh_fsm_.on_event(smo::mesh::MeshEvent::Archive);
                    }
                    std::printf("[smo-node] MeshFsm initialized to state: %s\n",
                                smo::mesh::to_string(mesh_fsm_.current_state()).c_str());
                }
            }
        }
    }

    sync_delta_service_.register_delta_handlers();

    // Register contracts, routes, and packet handlers via service
    if (contract_registry_service_)
    {
        contract_registry_service_->register_all();
    }

    event_registry_service_.register_all();

    // Register bootstrap handler with MeshFsm (C6.1: MeshFSM wiring)
    protocol_service_.register_bootstrap_handler(dispatcher_, &mesh_fsm_, &governance_engine_);

    // Initialize extracted services
    if (telemetry_service_)
        telemetry_service_->initialize();
    if (recovery_trust_service_)
        recovery_trust_service_->initialize();
    if (governance_middleware_service_)
        governance_middleware_service_->initialize();
    if (runtime_kernel_service_)
        runtime_kernel_service_->initialize();
}

// ===========================================================================
// _wire_sync_services() — SyncService delta publishing (main.cpp 1375-1543)
// ===========================================================================

void NodeRuntime::Impl::_wire_sync_services()
{
    // ManifestStore for manifest epochs
    std::string manifest_dir = data_dir_ + "/manifests";
    if (auto r = manifest_store_.open(manifest_dir); !r)
    {
        std::printf("[smo-node] Warning: failed to open ManifestStore at %s: %s\n", manifest_dir.c_str(),
                    r.error().message.c_str());
    }

    // CRL delta: serialize entries since last known epoch
    sync_service_.on_delta("crl", [&](const std::string&) -> smo::Result<void> {
        auto entries = crl_.entries_since(last_crl_epoch_);
        if (entries.empty())
            return {};
        for (const auto& e : entries)
        {
            if (e.epoch > last_crl_epoch_)
                last_crl_epoch_ = e.epoch;
        }
        // Serialize only new entries
        smo::Bytes buf;
        uint32_t count = static_cast<uint32_t>(entries.size());
        for (int i = 3; i >= 0; --i)
            buf.push_back(static_cast<uint8_t>((count >> (i * 8)) & 0xFF));
        for (auto& e : entries)
        {
            auto ser = e.serialize();
            uint32_t len = static_cast<uint32_t>(ser.size());
            for (int i = 3; i >= 0; --i)
                buf.push_back(static_cast<uint8_t>((len >> (i * 8)) & 0xFF));
            buf.insert(buf.end(), ser.begin(), ser.end());
        }
        if (!buf.empty())
        {
            gossip_.queue_delta(smo::DeltaType::CRL, std::move(buf));
        }
        return {};
    });

    // PolicyStore for policy rule persistence
    if (auto ec = policy_store_.open(); ec)
    {
        std::printf("[smo-node] Warning: failed to open PolicyStore: %s\n", ec.message().c_str());
    }

    // Policy delta: send policy records since last known version
    sync_service_.on_delta("policy", [&](const std::string&) -> smo::Result<void> {
        auto current = policy_store_.store_version();
        if (current <= last_policy_version_)
            return {};
        last_policy_version_ = current;
        auto names = policy_store_.list();
        if (names.empty())
            return {};
        // Serialize each record with length prefix
        smo::Bytes buf;
        uint32_t count = static_cast<uint32_t>(names.size());
        for (int i = 3; i >= 0; --i)
            buf.push_back(static_cast<uint8_t>((count >> (i * 8)) & 0xFF));
        for (auto& name : names)
        {
            auto rec = policy_store_.get(name);
            if (!rec)
                continue;
            auto ser = smo::PolicyStore::serialize_record(rec.value());
            uint32_t len = static_cast<uint32_t>(ser.size());
            for (int i = 3; i >= 0; --i)
                buf.push_back(static_cast<uint8_t>((len >> (i * 8)) & 0xFF));
            buf.insert(buf.end(), ser.begin(), ser.end());
        }
        if (!buf.empty())
        {
            gossip_.queue_delta(smo::DeltaType::Policy, std::move(buf));
        }
        return {};
    });

    // Manifest delta: send new epoch list since last sync
    sync_service_.on_delta("manifest", [&](const std::string&) -> smo::Result<void> {
        if (!manifest_store_.is_open())
            return {};
        auto latest = manifest_store_.latest_epoch();
        if (!latest || latest.value() <= last_manifest_epoch_)
            return {};
        auto epochs = manifest_store_.list_epochs();
        if (!epochs)
            return {};
        std::vector<uint64_t> new_epochs;
        for (auto e : epochs.value())
        {
            if (e > last_manifest_epoch_)
                new_epochs.push_back(e);
        }
        if (new_epochs.empty())
            return {};
        last_manifest_epoch_ = latest.value();
        // Serialize epoch list
        smo::Bytes buf;
        uint32_t count = static_cast<uint32_t>(new_epochs.size());
        for (int i = 3; i >= 0; --i)
            buf.push_back(static_cast<uint8_t>((count >> (i * 8)) & 0xFF));
        for (auto e : new_epochs)
        {
            for (int i = 7; i >= 0; --i)
                buf.push_back(static_cast<uint8_t>((e >> (i * 8)) & 0xFF));
        }
        gossip_.queue_delta(smo::DeltaType::Manifest, std::move(buf));
        return {};
    });

    // Routing delta: stub (routing table not yet implemented)
    sync_service_.on_delta("routing", [](const std::string&) -> smo::Result<void> {
        return {};
    });

    // Contracts delta: stub (contracts store not yet implemented)
    sync_service_.on_delta("contracts", [](const std::string&) -> smo::Result<void> {
        return {};
    });

    // Register receive-side delta handlers in GossipEngine
    gossip_.set_delta_handler(smo::DeltaType::Manifest, [&](smo::BytesView payload) -> smo::Result<void> {
        if (payload.size() < 4)
            return {};
        uint32_t count = 0;
        for (int i = 0; i < 4; ++i)
            count = (count << 8) | payload[i];
        std::printf("[smo-node] Gossip: received manifest delta with %u epochs\n", count);
        return {};
    });

    gossip_.set_delta_handler(smo::DeltaType::Policy, [&](smo::BytesView payload) -> smo::Result<void> {
        if (payload.size() < 4)
            return {};
        uint32_t count = 0;
        for (int i = 0; i < 4; ++i)
            count = (count << 8) | payload[i];
        size_t off = 4;
        for (uint32_t j = 0; j < count && off < payload.size(); ++j)
        {
            if (off + 4 > payload.size())
                break;
            uint32_t len = 0;
            for (int i = 0; i < 4; ++i)
                len = (len << 8) | payload[off++];
            if (off + len > payload.size())
                break;
            std::string data(payload.begin() + off, payload.begin() + off + len);
            off += len;
            auto rec = smo::PolicyStore::deserialize_record(data);
            if (rec)
            {
                policy_store_.put(rec.value());
            }
        }
        return {};
    });
}

// ===========================================================================
// start() — anti-entropy + sync service + daemon clock (main.cpp 2143-2198)
// ===========================================================================

Result<void> NodeRuntime::Impl::start()
{
    auto& LOG = smo::runtime::global_logger();
    LOG.info("entering main loop");

    sync_backend_ = std::make_shared<DaemonSyncBackend>(membership_, &crl_);
    event_registry_service_.start_anti_entropy(*sync_backend_);
    anti_entropy_ = std::move(event_registry_service_.anti_entropy());

    last_tick_ = 0;
    last_peerstore_sync_ = 0;
    daemon_start_ns_ = 0;

    sync_service_.start();
    daemon_start_ns_ = now_ns_since_epoch();

    daemon_ready_logged_ = false;
    daemon_degraded_logged_ = false;
    return {};
}

// ===========================================================================
// run() — daemon main loop (main.cpp 2200-2363). Blocking until running_flag
// clears (signal handler in main sets it to false).
// ===========================================================================

int NodeRuntime::Impl::run()
{
    auto& LOG = smo::runtime::global_logger();
    auto& telemetry = smo::runtime::global_telemetry();

    while (config_.running_flag && *config_.running_flag)
    {
        int64_t now_ns = now_ns_since_epoch();

        // SyncService: manages all delta intervals and triggers GossipEngine fanout
        sync_service_.tick(now_ns);

        // Periodic ticks (every 5s)
        if (now_ns - last_tick_ > 5000000000LL)
        {
            discovery_.tick(now_ns);
            heartbeat_.tick(now_ns);
            relay_service_.tick(now_ns);
            anti_entropy_->tick(now_ns); // P1: 30-min Merkle tree exchange

            // Use extracted services for periodic ticks
            if (session_manager_service_)
                session_manager_service_->tick(now_ns);
            if (recovery_trust_service_)
                recovery_trust_service_->tick(now_ns);
            if (governance_middleware_service_)
                governance_middleware_service_->tick(now_ns);
            if (runtime_kernel_service_)
                runtime_kernel_service_->tick(now_ns);
            if (telemetry_service_)
                telemetry_service_->tick(now_ns, membership_.count(), now_ns - daemon_start_ns_, anti_entropy_->repairs_done());

            // Readiness check (P2) - keep inline for now as it involves logging
            int64_t uptime_ns = now_ns - daemon_start_ns_;
            if (!daemon_ready_logged_ && uptime_ns > 30'000'000'000LL)
            {
                bool hb_active = membership_.count() > 0;
                bool gossip_tx = gossip_.gossip_sent_count() > 0;
                bool gossip_rx = gossip_.gossip_received_count() > 0;

                if (hb_active && gossip_tx && gossip_rx)
                {
                    LOG.info("node READY - " + std::to_string(membership_.count()) +
                             " peer(s), gossip tx=" + std::to_string(gossip_.gossip_sent_count()) +
                             " rx=" + std::to_string(gossip_.gossip_received_count()));
                    daemon_ready_logged_ = true;
                }
                else if (!daemon_degraded_logged_)
                {
                    LOG.warn("node DEGRADED - waiting: heartbeat=" + std::string(hb_active ? "yes" : "no") +
                             " gossip_tx=" + std::string(gossip_tx ? "yes" : "no") +
                             " gossip_rx=" + std::string(gossip_rx ? "yes" : "no") +
                             " uptime=" + std::to_string(uptime_ns / 1'000'000'000) + "s");
                    daemon_degraded_logged_ = true;
                }
            }

            last_tick_ = now_ns;
        }

        // UDP Discovery: read and dispatch datagrams (5.20) — delegated to UdpServer (Phase 3).
        // -----------------------------------------------------------------
        // Composition root injects recvfrom() + discovery dispatch hook so
        // DiscoveryEngine stays NodeRuntime-owned; UdpServer only moves bytes /
        // parses the remote Endpoint / closes the session.
        smo::network::UdpServer::Config udp_cfg;
        udp_cfg.default_port     = static_cast<uint16_t>(config_.port);
        udp_cfg.max_datagram_size = 8192;

        smo::network::UdpServer::RecvFn udp_recv = [&]()
        {
            if (!udp_listener_)
                return smo::Result<smo::SessionPtr>{};
            return udp_listener_->accept();
        };

        // Discovery dispatch hook — owns & closes the session. Ping/Pong frames
        // carry the heartbeat path and are routed to HeartbeatService directly;
        // all other frames flow to DiscoveryEngine.
        smo::network::UdpServer::Hook udp_dispatch =
            [&](smo::SessionPtr& session, const smo::Endpoint& remote_ep)
        {
            auto recv_data = session->recv(8192);
            if (recv_data)
            {
                telemetry.increment_counter("udp.datagrams_received", "component=discovery");
                smo::BytesView data = recv_data.value();
                if (smo::is_discovery_msg(data))
                {
                    auto type = smo::discovery_msg_type(data);
                    auto payload = smo::discovery_payload(data);
                    if (type == smo::DiscoveryMsgType::Ping)
                    {
                        auto ping = smo::PingMsg::deserialize(payload);
                        if (ping)
                        {
                            (void)heartbeat_.handle_ping(ping.value(), now_ns, remote_ep);
                        }
                        session->close();
                        return smo::Result<void>{};
                    }
                    if (type == smo::DiscoveryMsgType::Pong)
                    {
                        auto pong = smo::PongMsg::deserialize(payload);
                        if (pong)
                        {
                            (void)heartbeat_.handle_pong(pong.value(), now_ns, remote_ep);
                        }
                        session->close();
                        return smo::Result<void>{};
                    }
                    // N2: Handle UDP gossip messages (custom type 0x08)
                    if (type == static_cast<smo::DiscoveryMsgType>(0x08))
                    {
                        auto res = smo::GossipEngine::handle_gossip_message(payload, gossip_);
                        if (!res)
                        {
                            std::fprintf(stderr, "[smo-node] UDP gossip apply failed: %s\n", res.error().message.c_str());
                        }
                        session->close();
                        return smo::Result<void>{};
                    }
                }
                (void)smo::dispatch_discovery_datagram(data, discovery_, remote_ep, now_ns);
            }
            session->close();
            return smo::Result<void>{};
        };

        smo::network::UdpServer udp_server(udp_cfg, udp_recv, udp_dispatch);
        udp_server.recv_once();

        // Periodic PeerStore sync
        if (now_ns - last_peerstore_sync_ > 30000000000LL)
        {
            peer_store_.sync_from_membership(membership_);
            last_peerstore_sync_ = now_ns;
        }

        // Accept TCP connections — delegated to ConnectionManager (Phase 2).
        // -----------------------------------------------------------------
        // Composition root injects accept() + secure dispatch hooks so
        // crypto/identity/membership stay NodeRuntime-owned; ConnectionManager
        // only moves bytes / parses the remote Endpoint / closes the session.
        // P0-S6: No plain/legacy path - always require SecureSession with cert+sig.
        // C1.3: Capability Epoch for revocation replaces CRL.
        smo::network::ConnectionManager::Config cm_cfg;
        cm_cfg.default_port    = static_cast<uint16_t>(config_.port);
        cm_cfg.server_cert_blob      = server_cert_blob_;
        cm_cfg.server_signing_key    = server_signing_key_;
        cm_cfg.root_public_key       = root_public_key_;
        cm_cfg.mesh_id               = mesh_id_str_;
        cm_cfg.current_epoch         = current_epoch_; // C1.3: Capability Epoch

        smo::network::ConnectionManager::AcceptFn cm_accept = [&]()
        {
            return tcp_listener_owner_->accept();
        };

        // Secure (PQ) dispatch hook — release_fd → SecureSession → PQ handshake
        // → packet dispatch (session_mgr_ owner-closes via dispatch path).
        smo::network::ConnectionManager::Hook cm_secure =
            [&](smo::SessionPtr& session, const smo::Endpoint& remote_ep)
        {
            auto* tcp_ses = static_cast<smo::TcpSession*>(session.get());
            int client_fd = tcp_ses->release_fd();

            smo::SecureSession::Config sec_cfg;
            sec_cfg.role = smo::SecureSession::Role::Server;
            sec_cfg.server_cert        = server_cert_blob_;
            sec_cfg.signing_secret_key = server_signing_key_;
            sec_cfg.root_public_key    = root_public_key_;
            sec_cfg.mesh_id            = mesh_id_str_;
            sec_cfg.current_epoch      = current_epoch_; // C1.3: Capability Epoch

            smo::SecureSession sec(client_fd, sec_cfg, *crypto_);
            auto hs = sec.handshake();
            if (!hs)
            {
                LOG.warn("PQ handshake failed: " + hs.error().message);
                ::close(client_fd);
                return smo::Result<void>{};
            }
            auto dres = dispatcher_.dispatch_packet_session(sec, session_mgr_, remote_ep);
            if (!dres)
            {
                LOG.warn("dispatch failed: " + dres.error().message);
            }
            return smo::Result<void>{};
        };

        smo::network::ConnectionManager conn_mgr(cm_cfg, cm_accept, cm_secure);
        conn_mgr.accept_once();

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    return 0;
}

// ===========================================================================
// shutdown() — ordered teardown (main.cpp 2365-2382)
// ===========================================================================

void NodeRuntime::Impl::shutdown()
{
    auto& LOG = smo::runtime::global_logger();
    LOG.info("shutting down...");

    // Shutdown extracted services
    if (telemetry_service_)
        telemetry_service_->shutdown();
    if (session_manager_service_)
        session_manager_service_->shutdown();
    if (recovery_trust_service_)
        recovery_trust_service_->shutdown();
    if (governance_middleware_service_)
        governance_middleware_service_->shutdown();
    if (runtime_kernel_service_)
        runtime_kernel_service_->shutdown();
    if (metrics_server_)
        metrics_server_->stop();
    if (otlp_exporter_)
        otlp_exporter_->stop();

    gossip_.stop();
    sync_service_.stop();
    if (anti_entropy_)
        anti_entropy_->stop();
    heartbeat_.stop();

    // Drain sessions
    session_mgr_.collect_garbage();

    tcp_listener_owner_->close();

    // Flush peer store last
    peer_store_.sync_from_membership(membership_);
    peer_store_.close();

    LOG.info("shutdown complete");
}

// Public API forwarding methods
Result<void> NodeRuntime::initialize()
{
    return impl_->initialize();
}

Result<void> NodeRuntime::start()
{
    return impl_->start();
}

void NodeRuntime::shutdown()
{
    impl_->shutdown();
}

int NodeRuntime::run()
{
    return impl_->run();
}

} // namespace smo::runtime

// ===========================================================================
// Static CLI command handlers
// ===========================================================================

namespace smo::runtime {

int NodeRuntime::cmd_init(const std::string& name, const std::string& data_dir)
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

int NodeRuntime::cmd_export(const std::string& output_path, const std::string& data_dir, bool copy_to_clipboard)
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

    // Read existing CSR if present
    std::string csr_path = data_dir + "/node.csr.smor";
    auto existing = load_file_binary(csr_path);
    if (!existing.empty() && !copy_to_clipboard)
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

    if (copy_to_clipboard)
    {
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

int NodeRuntime::cmd_import(const std::string& cert_path_or_empty, const std::string& data_dir)
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

    // Post-import summary
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

int NodeRuntime::cmd_pubkey(const std::string& data_dir, bool copy_to_clipboard, bool show_fingerprint)
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

    if (copy_to_clipboard)
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

int NodeRuntime::cmd_join(const std::string& join_token, const std::string& data_dir, const std::string& node_name, int port)
{
    ensure_crypto();
    auto result = smo::enroll::run_join_command(join_token, data_dir, node_name, static_cast<uint16_t>(port), "");
    if (!result)
    {
        std::fprintf(stderr, "Error: %s\n", result.error().message.c_str());
        return 1;
    }
    return 0;
}

} // namespace smo::runtime
