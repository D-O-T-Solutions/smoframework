#include "runtime_context.hpp"

#include "core/runtime/services/crypto_service.hpp"
#include "core/runtime/services/identity_service.hpp"
#include "core/runtime/services/storage_service.hpp"
#include "core/runtime/services/vault_service.hpp"
#include "core/runtime/services/file_service.hpp"
#include "core/runtime/services/network_service.hpp"
#include "core/runtime/services/transport_service.hpp"
#include "core/runtime/services/scheduler_service.hpp"
#include "core/acl/policy_engine.hpp"
#include "core/runtime/services/audit_service.hpp"
#include "core/runtime/services/history_service.hpp"
#include "core/runtime/services/metrics_service.hpp"
#include "core/runtime/services/logger_service.hpp"
#include "core/runtime/services/clock_service.hpp"
#include "core/runtime/services/random_service.hpp"

#include <memory>

namespace smo::runtime {

// ── RuntimeContextBuilder ──────────────────────────────────────────────────

RuntimeContextBuilder& RuntimeContextBuilder::with_crypto(CryptoService* svc)
{
    services_.crypto = svc;
    return *this;
}

RuntimeContextBuilder& RuntimeContextBuilder::with_identity(IdentityService* svc)
{
    services_.identity = svc;
    return *this;
}

RuntimeContextBuilder& RuntimeContextBuilder::with_vault(VaultService* svc)
{
    services_.vault = svc;
    return *this;
}

RuntimeContextBuilder& RuntimeContextBuilder::with_storage(StorageService* svc)
{
    services_.storage = svc;
    return *this;
}

RuntimeContextBuilder& RuntimeContextBuilder::with_file(FileService* svc)
{
    services_.fs = svc;
    return *this;
}

RuntimeContextBuilder& RuntimeContextBuilder::with_network(NetworkService* svc)
{
    services_.network = svc;
    return *this;
}

RuntimeContextBuilder& RuntimeContextBuilder::with_transport(TransportService* svc)
{
    services_.transport = svc;
    return *this;
}

RuntimeContextBuilder& RuntimeContextBuilder::with_scheduler(SchedulerService* svc)
{
    services_.scheduler = svc;
    return *this;
}

RuntimeContextBuilder& RuntimeContextBuilder::with_policy(acl::PolicyEngine* svc)
{
    services_.policy = svc;
    return *this;
}

RuntimeContextBuilder& RuntimeContextBuilder::with_audit(AuditService* svc)
{
    services_.audit = svc;
    return *this;
}

RuntimeContextBuilder& RuntimeContextBuilder::with_history(HistoryService* svc)
{
    services_.history = svc;
    return *this;
}

RuntimeContextBuilder& RuntimeContextBuilder::with_metrics(MetricsService* svc)
{
    services_.metrics = svc;
    return *this;
}

RuntimeContextBuilder& RuntimeContextBuilder::with_logger(LoggerService* svc)
{
    services_.logger = svc;
    return *this;
}

RuntimeContextBuilder& RuntimeContextBuilder::with_clock(ClockService* svc)
{
    services_.clock = svc;
    return *this;
}

RuntimeContextBuilder& RuntimeContextBuilder::with_random(RandomService* svc)
{
    services_.random = svc;
    return *this;
}

RuntimeContextBuilder& RuntimeContextBuilder::with_capabilities(const ContractCapabilities& caps)
{
    services_.granted_caps = caps;
    return *this;
}

RuntimeContextBuilder& RuntimeContextBuilder::with_event_bus(EventBus* bus)
{
    event_bus_ = bus;
    return *this;
}

RuntimeContextBuilder& RuntimeContextBuilder::with_execution_info(const ExecutionInfo& info)
{
    info_ = info;
    return *this;
}

Result<RuntimeContext> RuntimeContextBuilder::build()
{
    if (info_.execution_id != 0 && info_.contract_id.empty())
    {
        return SMO_ERR_RUNTIME(1001, Error, NoRetry, None,
                               "contract_id is required when execution_id is set");
    }

    RuntimeContext ctx;
    ctx.info = info_;
    ctx.services = services_;
    ctx.event_bus = event_bus_;
    return ctx;
}

RuntimeContextBuilder make_runtime_context()
{
    return RuntimeContextBuilder();
}

} // namespace smo::runtime