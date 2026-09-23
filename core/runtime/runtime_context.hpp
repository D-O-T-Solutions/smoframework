#pragma once

#include "runtime_types.hpp"

#include <string>
#include <cstdint>

namespace smo::acl {
    class PolicyEngine;
}

namespace smo::runtime {

    // ── RuntimeServices (RFC 0037 §2.4) ─────────────────────────────────
    struct RuntimeServices
    {
        // Core services (injected via capability gating)
        class CryptoService* crypto = nullptr;
        class IdentityService* identity = nullptr;
        class VaultService* vault = nullptr;
        class StorageService* storage = nullptr;
        class FileService* fs = nullptr;
        class NetworkService* network = nullptr;
        class TransportService* transport = nullptr;
        class SchedulerService* scheduler = nullptr;
        class acl::PolicyEngine* policy = nullptr;
        class AuditService* audit = nullptr;
        class HistoryService* history = nullptr;
        class MetricsService* metrics = nullptr;
        class LoggerService* logger = nullptr;
        class ClockService* clock = nullptr;
        class RandomService* random = nullptr;

        // Capability gating
        ContractCapabilities granted_caps;

        bool has_capability(ContractCapability cap) const { return granted_caps.test(static_cast<size_t>(cap)); }
    };

    // ── RuntimeContext (RFC 0037 §2.1) ──────────────────────────────────
    struct RuntimeContext
    {
        ExecutionInfo info;            // read-only execution metadata
        Variables vars;                // mutable context key-value store
        RuntimeServices services;      // injected services (may be null per capability)
        EventBus* event_bus = nullptr; // event bus for middleware/audit (not for contracts)
    };

    // ── RuntimeContextBuilder ──────────────────────────────────────────────
    class RuntimeContextBuilder
    {
    public:
        RuntimeContextBuilder() = default;

        RuntimeContextBuilder& with_crypto(CryptoService* svc);
        RuntimeContextBuilder& with_identity(IdentityService* svc);
        RuntimeContextBuilder& with_vault(VaultService* svc);
        RuntimeContextBuilder& with_storage(StorageService* svc);
        RuntimeContextBuilder& with_file(FileService* svc);
        RuntimeContextBuilder& with_network(NetworkService* svc);
        RuntimeContextBuilder& with_transport(TransportService* svc);
        RuntimeContextBuilder& with_scheduler(SchedulerService* svc);
        RuntimeContextBuilder& with_policy(acl::PolicyEngine* svc);
        RuntimeContextBuilder& with_audit(AuditService* svc);
        RuntimeContextBuilder& with_history(HistoryService* svc);
        RuntimeContextBuilder& with_metrics(MetricsService* svc);
        RuntimeContextBuilder& with_logger(LoggerService* svc);
        RuntimeContextBuilder& with_clock(ClockService* svc);
        RuntimeContextBuilder& with_random(RandomService* svc);
        RuntimeContextBuilder& with_capabilities(const ContractCapabilities& caps);
        RuntimeContextBuilder& with_event_bus(EventBus* bus);
        RuntimeContextBuilder& with_execution_info(const ExecutionInfo& info);

        Result<RuntimeContext> build();

    private:
        RuntimeServices services_;
        ExecutionInfo info_;
        Variables vars_;
        EventBus* event_bus_ = nullptr;
    };

    // Factory function for convenient construction
    RuntimeContextBuilder make_runtime_context();

} // namespace smo::runtime
