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
#include <core/runtime/event_registry_service.hpp>
#include <core/runtime/authority_mesh_service.hpp>
#include <core/runtime/contract_registry_service.hpp>
#include <core/network/sync/anti_entropy.hpp>
#include <core/network/sync/sync_backend.hpp>

#include <storage/policy_store/policy_store.h>

#include <providers/blake3_provider/blake3_provider.hpp>
#include <providers/suite1_classical/suite1_classical_provider.hpp>
#include <providers/suite2_modern/suite2_modern_provider.hpp>
#include <providers/suite3_purepqc/suite3_purepqc_provider.hpp>

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace smo::runtime {

namespace {

    void node_id_to_hex(const smo::NodeID& id, std::string& out)
    {
        std::ostringstream oss;
        for (uint8_t b : id.value)
        {
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        }
        out = oss.str();
    }

    smo::Bytes load_file_binary(const std::string& path)
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

    void ensure_crypto()
    {
        smo::Blake3Provider::register_as_default();
        smo::providers::register_suite1_classical();
        smo::providers::register_suite2_modern();
#ifdef SMO_WITH_PQC
        smo::providers::register_suite3_purepqc();
#endif
    }

    const smo::CryptoProvider* get_crypto(smo::CryptoSuiteID suite_id)
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

    int64_t now_ns_since_epoch()
    {
        return static_cast<int64_t>(std::chrono::system_clock::now().time_since_epoch().count());
    }

    smo::network::udp::HeartbeatService::Config make_hb_config(int port)
    {
        smo::network::udp::HeartbeatService::Config hb_config;
        hb_config.ping_interval_ms = 5000;
        hb_config.ping_timeout_ms = 3000;
        hb_config.max_misses = 3;
        hb_config.local_port = port;
        return hb_config;
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

} // anonymous namespace

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

    // anti-entropy
    std::shared_ptr<DaemonSyncBackend> sync_backend_;
    std::unique_ptr<smo::sync::AntiEntropyService> anti_entropy_;

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
    , gossip_(membership_, smo::GossipEngine::default_config())
    , membership_sync_(membership_, health_monitor_)
    , heartbeat_(make_hb_config(cfg.port))
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
{
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
        // Read canonical mesh_id from mesh.json (not the directory basename)
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

    // HeartbeatService
    auto hb_start = heartbeat_.start(*udp_transport_, membership_, health_monitor_);
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
        mesh_id_str_
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
    {
        int64_t now_ns = now_ns_since_epoch();
        auto rec_ec = session_mgr_.recover(data_dir_ + "/session_store.bin", now_ns);
        if (!rec_ec)
        {
            std::printf("[smo-node] Session store recover failed: %s\n", rec_ec.error().message.c_str());
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

    sync_delta_service_.register_delta_handlers();

    // Register contracts, routes, and packet handlers via service
    if (contract_registry_service_)
    {
        contract_registry_service_->register_all();
    }

    event_registry_service_.register_all();
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
            session_mgr_.tick(now_ns);
            session_mgr_.collect_garbage();
            anti_entropy_->tick(now_ns); // P1: 30-min Merkle tree exchange

            // Decay trust scores over time (RFC 0017 4) and persist them
            trust_mgr_.tick(now_ns);

            // Persist session store so a crash leaves recoverable state (RFC 0014 6)
            if (auto persist_ec = session_mgr_.persist(data_dir_ + "/session_store.bin"); !persist_ec)
            {
                std::printf("[smo-node] Session store persist failed: %s\n", persist_ec.error().message.c_str());
            }

            // Readiness check (P2)
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

            // Telemetry tick metrics (P10)
            telemetry.set_gauge("smo_connected_peers", static_cast<double>(membership_.count()), "");
            telemetry.set_gauge("smo_membership_epoch", static_cast<double>(now_ns % 1'000'000), "");
            telemetry.set_gauge("smo_anti_entropy_repairs_total",
                                static_cast<double>(anti_entropy_->repairs_done()), "");

            // Export Prometheus metrics to file for scraping
            {
                std::string metrics_path = data_dir_ + "/metrics.prom";
                auto metrics_str = telemetry.export_prometheus();
                if (!metrics_str.empty())
                {
                    if (auto f = std::fopen(metrics_path.c_str(), "w"))
                    {
                        std::fwrite(metrics_str.data(), 1, metrics_str.size(), f);
                        std::fclose(f);
                    }
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

        // Discovery dispatch hook — owns & closes the session.
        smo::network::UdpServer::Hook udp_dispatch =
            [&](smo::SessionPtr& session, const smo::Endpoint& remote_ep)
        {
            auto recv_data = session->recv(8192);
            if (recv_data)
            {
                telemetry.increment_counter("udp.datagrams_received", "component=discovery");
                (void)smo::dispatch_discovery_datagram(recv_data.value(), discovery_, remote_ep, now_ns);
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
        // Composition root injects accept() + plain/secure dispatch hooks so
        // crypto/identity/membership stay NodeRuntime-owned; ConnectionManager
        // only moves bytes / parses the remote Endpoint / closes the session.
        smo::network::ConnectionManager::Config cm_cfg;
        cm_cfg.default_port    = static_cast<uint16_t>(config_.port);
        cm_cfg.server_cert_blob      = server_cert_blob_;
        cm_cfg.server_signing_key    = server_signing_key_;
        cm_cfg.root_public_key       = root_public_key_;
        cm_cfg.mesh_id               = mesh_id_str_;

        smo::network::ConnectionManager::AcceptFn cm_accept = [&]()
        {
            return tcp_listener_owner_->accept();
        };

        // Plain (legacy) dispatch hook — owns & closes the session.
        smo::network::ConnectionManager::Hook cm_plain =
            [&](smo::SessionPtr& session, const smo::Endpoint& remote_ep)
        {
            auto* tcp_ses = static_cast<smo::TcpSession*>(session.get());
            auto dres = dispatcher_.dispatch_session(*tcp_ses, remote_ep);
            if (!dres)
            {
                LOG.warn("dispatch failed: " + dres.error().message);
            }
            session->close();
            return smo::Result<void>{};
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

        smo::network::ConnectionManager conn_mgr(cm_cfg, cm_accept, cm_plain, cm_secure);
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

} // namespace smo::runtime
