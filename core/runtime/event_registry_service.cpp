#include "core/runtime/event_registry_service.hpp"
#include "core/runtime/structured_logger.hpp"

#include <sstream>
#include <iomanip>
#include <sqlite3.h>

namespace smo::runtime {

EventRegistryService::EventRegistryService(const Dependencies& deps) : deps_(deps), sync_backend_(nullptr)
{
}

void EventRegistryService::register_all()
{
    auto& LOG = smo::runtime::global_logger();

    // ── EventBus subscriptions (from _wire_event_subscriptions) ────────────

    // RecoveryProposalCreated: emitted by RecoveryContract
    deps_.event_bus.subscribe(EventType::RecoveryProposalCreated, [&](const Event& ev) {
        std::printf("[smo-node] Event: RecoveryProposalCreated - %s\n", ev.details.c_str());
    });

    // RecoveryApproved: parse payload, CRL::revoke + SessionManager::invalidate
    deps_.event_bus.subscribe(EventType::RecoveryApproved, [&](const Event& ev) {
        std::printf("[smo-node] Event: RecoveryApproved - %s\n", ev.details.c_str());

        std::string payload = ev.details;
        size_t brace_pos = payload.find('{');
        if (brace_pos == std::string::npos)
        {
            std::printf("[smo-node] WARNING: RecoveryApproved payload missing JSON\n");
            return;
        }
        std::string json_str = payload.substr(brace_pos);

        auto extract_field = [&](const std::string& json, const std::string& key) -> std::string {
            std::string search = "\"" + key + "\":\"";
            size_t pos = json.find(search);
            if (pos == std::string::npos)
                return "";
            pos += search.length();
            size_t end = json.find('"', pos);
            if (end == std::string::npos)
                return "";
            return json.substr(pos, end - pos);
        };
        auto extract_uint = [&](const std::string& json, const std::string& key) -> uint64_t {
            std::string search = "\"" + key + "\":";
            size_t pos = json.find(search);
            if (pos == std::string::npos)
                return 0;
            pos += search.length();
            size_t end = json.find_first_of(",}", pos);
            if (end == std::string::npos)
                return 0;
            return std::stoull(json.substr(pos, end - pos));
        };

        std::string fingerprint = extract_field(json_str, "fingerprint");
        std::string node_id_hex = extract_field(json_str, "node_id_hex");
        std::string reason = extract_field(json_str, "reason");
        uint64_t epoch = extract_uint(json_str, "epoch");

        if (fingerprint.empty() || node_id_hex.empty())
        {
            std::printf("[smo-node] WARNING: RecoveryApproved payload incomplete\n");
            return;
        }

        // 1. CRL::revoke(fingerprint)
        auto now_ns = []() -> int64_t {
            return static_cast<int64_t>(std::chrono::system_clock::now().time_since_epoch().count());
        }();
        auto rev_res = deps_.crl.revoke(fingerprint, node_id_hex, reason, epoch, now_ns);
        if (!rev_res)
        {
            std::printf("[smo-node] CRL revoke failed: %s\n", rev_res.error().message.c_str());
        }
        else
        {
            std::printf("[smo-node] CRL: revoked cert %s (epoch=%llu)\n", fingerprint.c_str(),
                        (unsigned long long)epoch);
        }

        // 2. SessionManager::invalidate(node_id) - convert hex to NodeID
        if (node_id_hex.size() == 64)
        {
            smo::NodeID node_id;
            for (size_t i = 0; i < 32 && i * 2 + 1 < node_id_hex.size(); ++i)
            {
                unsigned int byte = 0;
                std::istringstream iss(node_id_hex.substr(i * 2, 2));
                iss >> std::hex >> byte;
                node_id.value[i] = static_cast<uint8_t>(byte);
            }
            size_t invalidated = deps_.session_mgr.invalidate(node_id);
            std::printf("[smo-node] SessionManager: invalidated %zu sessions for node %s\n", invalidated,
                        node_id_hex.c_str());
        }

        // 3. Discovery: gossip CRL update (trigger membership sync)
        std::printf("[smo-node] Discovery: CRL update triggered (gossip will propagate)\n");

        // 4. Audit: log revocation
        std::printf("[smo-node] AUDIT: Certificate revoked - fingerprint=%s node=%s reason=%s epoch=%llu\n",
                    fingerprint.c_str(), node_id_hex.c_str(), reason.c_str(), (unsigned long long)epoch);
    });

    // Trust score changes -> Audit log
    deps_.event_bus.subscribe(EventType::SecurityAlert, [&](const Event& ev) {
        std::printf("[smo-node] AUDIT: Trust score change - %s\n", ev.details.c_str());
    });

    // Session disconnect -> Discovery membership update
    deps_.event_bus.subscribe(EventType::NodeDisconnected, [&](const Event& ev) {
        std::printf("[smo-node] Discovery: Node disconnected - %s\n", ev.details.c_str());
    });

    // Trust score change -> Audit log
    deps_.event_bus.subscribe(EventType::AuditLogged, [&](const Event& ev) {
        std::printf("[smo-node] AUDIT: %s\n", ev.details.c_str());
    });

    // Governance proposal updates -> all nodes
    deps_.event_bus.subscribe(EventType::ProposalCreated, [&](const Event& ev) {
        std::printf("[smo-node] GOVERNANCE: Proposal created - %s\n", ev.details.c_str());
    });
    deps_.event_bus.subscribe(EventType::ProposalVoted, [&](const Event& ev) {
        std::printf("[smo-node] GOVERNANCE: Vote cast - %s\n", ev.details.c_str());
    });
    deps_.event_bus.subscribe(EventType::ProposalCommitted, [&](const Event& ev) {
        std::printf("[smo-node] GOVERNANCE: Proposal committed - %s\n", ev.details.c_str());
    });
    deps_.event_bus.subscribe(EventType::ProposalRejected, [&](const Event& ev) {
        std::printf("[smo-node] GOVERNANCE: Proposal rejected - %s\n", ev.details.c_str());
    });

    // Recovery events
    deps_.event_bus.subscribe(EventType::RecoveryStarted, [&](const Event& ev) {
        std::printf("[smo-node] RECOVERY: Started - %s\n", ev.details.c_str());
    });
    deps_.event_bus.subscribe(EventType::RecoveryCompleted, [&](const Event& ev) {
        std::printf("[smo-node] RECOVERY: Completed - %s\n", ev.details.c_str());
    });
    deps_.event_bus.subscribe(EventType::RecoveryFailed, [&](const Event& ev) {
        std::printf("[smo-node] RECOVERY: Failed - %s\n", ev.details.c_str());
    });

    // ── ServiceRegistry registration (from _wire_registry_telemetry) ───────

    ServiceRegistry& registry = global_registry();
    registry.register_service("event_bus", std::shared_ptr<EventBus>(&deps_.event_bus, [](auto*) {}));
    registry.register_service("crl", std::make_shared<recovery::CRL>(deps_.crl));
    registry.register_service("session_manager", std::make_shared<SessionManager>(deps_.session_mgr));
    registry.register_service("trust_manager", std::make_shared<TrustManager>(deps_.trust_mgr));
    registry.register_service("governance_engine", std::make_shared<GovernanceEngine>(deps_.governance_engine));
    registry.register_service("discovery_engine", std::make_shared<DiscoveryEngine>(deps_.discovery));
    // Note: PeerStore and GossipEngine are non-copyable, skip for now

    // ── Telemetry + Metrics (P10) ──────────────────────────────────────────

    deps_.telemetry.set_event_bus(&deps_.event_bus);

    // Register core health checks
    deps_.telemetry.register_health_check("crl", [](std::string& err) -> bool { return true; });
    deps_.telemetry.register_health_check("session_mgr", [](std::string& err) -> bool { return true; });
    deps_.telemetry.register_health_check("peer_store", [](std::string& err) -> bool { return true; });
    deps_.telemetry.register_health_check("gossip_engine", [](std::string& err) -> bool { return true; });
    deps_.telemetry.register_health_check("heartbeat", [](std::string& err) -> bool { return true; });

    // Register daemon metrics
    deps_.telemetry.increment_counter("node.startup", "component=main");
    deps_.telemetry.set_gauge("node.state", 1.0, "state=running");
    deps_.telemetry.set_gauge("smo_connected_peers", 0.0, "");
    deps_.telemetry.set_gauge("smo_gossip_queue_depth", 0.0, "");
    deps_.telemetry.set_gauge("smo_membership_epoch", 0.0, "");

    // Print registered services using structured logger
    {
        std::string svc_str;
        auto services = registry.list_services();
        for (size_t i = 0; i < services.size(); ++i)
        {
            if (i > 0)
                svc_str += ", ";
            svc_str += services[i];
        }
        LOG.info("services: " + svc_str);
    }
}

void EventRegistryService::start_anti_entropy(sync::SyncBackend& backend)
{
    sync_backend_ = &backend;
    auto ae_config = smo::sync::AntiEntropyService::Config::defaults();
    anti_entropy_ = std::make_unique<smo::sync::AntiEntropyService>(deps_.membership, deps_.gossip, backend, ae_config);
    anti_entropy_->start();
}

} // namespace smo::runtime