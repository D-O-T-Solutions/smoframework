// SPDX-License-Identifier: Apache-2.0
//
// RuntimeContext — unit tests

#include <runtime/runtime_context.hpp>
#include <runtime/services/crypto_service.hpp>
#include <runtime/services/identity_service.hpp>
#include <runtime/services/storage_service.hpp>
#include <runtime/services/vault_service.hpp>
#include <runtime/services/file_service.hpp>
#include <runtime/services/network_service.hpp>
#include <runtime/services/transport_service.hpp>
#include <runtime/services/scheduler_service.hpp>
#include <runtime/services/audit_service.hpp>
#include <runtime/services/history_service.hpp>
#include <runtime/services/metrics_service.hpp>
#include <runtime/services/logger_service.hpp>
#include <runtime/services/clock_service.hpp>
#include <runtime/services/random_service.hpp>
#include <acl/policy_engine.hpp>

#include <cstdio>
#include <cstring>
#include <memory>

// Mock implementations for testing
namespace smo::runtime {

class MockCryptoService : public CryptoService
{
public:
    Result<Signature> sign(const std::vector<uint8_t>&, const KeyID&) override { return Signature{}; }
    Result<bool> verify(const std::vector<uint8_t>&, const Signature&, const PublicKey&) override { return true; }
    Result<std::vector<uint8_t>> encrypt(const std::vector<uint8_t>&, const PublicKey&) override { return std::vector<uint8_t>{}; }
    Result<std::vector<uint8_t>> decrypt(const std::vector<uint8_t>&, const KeyID&) override { return std::vector<uint8_t>{}; }
    Result<KeyID> generate_key(KeyType) override { return KeyID{"mock_key"}; }
};

class MockIdentityService : public IdentityService
{
public:
    Result<std::string> node_id() const override { return std::string{"test_node"}; }
    Result<std::string> mesh_id() const override { return std::string{"test_mesh"}; }
    Result<PublicKey> public_key() const override { return PublicKey{}; }
    Result<std::string> fingerprint() const override { return std::string{"test_fp"}; }
};

class MockStorageService : public StorageService
{
public:
    Result<void> put(const std::string&, const Bytes&) override { return {}; }
    Result<Bytes> get(const std::string&) override { return Bytes{}; }
    Result<void> erase(const std::string&) override { return {}; }
    Result<bool> exists(const std::string&) override { return false; }
    Result<std::vector<std::string>> list(const std::string&) override { return {}; }
};

class MockVaultService : public VaultService
{
public:
    Result<void> store(const std::string&, const Bytes&) override { return {}; }
    Result<Bytes> retrieve(const std::string&) override { return Bytes{}; }
    Result<void> delete_key(const std::string&) override { return {}; }
    Result<bool> exists(const std::string&) override { return false; }
};

class MockFileService : public FileService
{
public:
    Result<std::string> read_text(const std::string&) override { return std::string{}; }
    Result<Bytes> read_binary(const std::string&) override { return Bytes{}; }
    Result<void> write_text(const std::string&, const std::string&) override { return {}; }
    Result<void> write_binary(const std::string&, const Bytes&) override { return {}; }
    Result<bool> exists(const std::string&) override { return false; }
};

class MockNetworkService : public NetworkService
{
public:
    Result<void> send(const std::string&, const std::vector<uint8_t>&) override { return {}; }
    Result<std::vector<uint8_t>> request(const std::string&, const std::vector<uint8_t>&, uint64_t) override { return std::vector<uint8_t>{}; }
};

class MockTransportService : public TransportService
{
public:
    Result<void> send_message(const std::string&, const std::string&, const std::vector<uint8_t>&) override { return {}; }
    Result<std::vector<uint8_t>> send_request(const std::string&, const std::string&, const std::vector<uint8_t>&, uint64_t) override { return std::vector<uint8_t>{}; }
    Result<void> broadcast(const std::string&, const std::vector<uint8_t>&) override { return {}; }
};

class MockSchedulerService : public SchedulerService
{
public:
    Result<void> schedule_retry(const std::string&, const std::string&, uint64_t) override { return {}; }
    Result<void> cancel_scheduled(const std::string&) override { return {}; }
};

class MockAuditService : public AuditService
{
public:
    void emit(const AuditEvent&) override {}
};

class MockHistoryService : public HistoryService
{
public:
    Result<void> record_execution(const std::string&, const std::string&, bool, const std::string&) override { return {}; }
    Result<std::vector<std::string>> get_history(const std::string&, size_t) override { return std::vector<std::string>{}; }
};

class MockMetricsService : public MetricsService
{
public:
    void increment(const std::string&, int64_t) override {}
    void gauge(const std::string&, double) override {}
    void histogram(const std::string&, double) override {}
    void timing(const std::string&, uint64_t) override {}
};

class MockLoggerService : public LoggerService
{
public:
    void debug(const std::string&) override {}
    void info(const std::string&) override {}
    void warn(const std::string&) override {}
    void error(const std::string&) override {}
};

class MockClockService : public ClockService
{
public:
    uint64_t now_ns() override { return 1000; }
    uint64_t wall_clock_ns() override { return 1000; }
    void advance(uint64_t) override {}
};

class MockRandomService : public RandomService
{
public:
    Bytes random_bytes(size_t) override { return Bytes{}; }
    uint64_t random_u64() override { return 42; }
    void seed(const Bytes&) override {}
};

} // namespace smo::runtime

// ---------------------------------------------------------------------------
// Minimal test runner
// ---------------------------------------------------------------------------
static int failures = 0;

#define TEST(name)                                                                                                     \
    do                                                                                                                 \
    {                                                                                                                  \
        printf("  TEST %-50s ... ", name);                                                                             \
        fflush(stdout);

#define END_TEST(result)                                                                                               \
    if (result)                                                                                                        \
    {                                                                                                                  \
        printf("PASS\n");                                                                                              \
    }                                                                                                                  \
    else                                                                                                               \
    {                                                                                                                  \
        printf("FAIL\n");                                                                                              \
        ++failures;                                                                                                    \
    }                                                                                                                  \
    }                                                                                                                  \
    while (false)

#define ASSERT(cond)                                                                                                   \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(cond))                                                                                                   \
        {                                                                                                              \
            printf("\n    ASSERTION FAILED at %s:%d: %s\n", __FILE__, __LINE__, #cond);                                \
            return false;                                                                                              \
        }                                                                                                              \
    } while (false)

#define ASSERT_EQ(a, b)                                                                                                \
    do                                                                                                                 \
    {                                                                                                                  \
        if ((a) != (b))                                                                                                \
        {                                                                                                              \
            printf("\n    ASSERTION FAILED at %s:%d: %s != %s\n", __FILE__, __LINE__, #a, #b);                        \
            return false;                                                                                              \
        }                                                                                                              \
    } while (false)

#define ASSERT_STREQ(a, b)                                                                                             \
    do                                                                                                                 \
    {                                                                                                                  \
        if (std::strcmp((a), (b)) != 0)                                                                                \
        {                                                                                                              \
            printf("\n    ASSERTION FAILED at %s:%d: %s == %s\n"                                                       \
                   "      LHS=%s  RHS=%s\n",                                                                           \
                   __FILE__, __LINE__, #a, #b, (a), (b));                                                              \
            return false;                                                                                              \
        }                                                                                                              \
    } while (false)

// ==========================================================================
// Tests
// ==========================================================================

static bool test_builder_basic()
{
    using namespace smo::runtime;

    // Use heap allocation to keep services alive during test
    auto crypto = std::make_unique<MockCryptoService>();
    auto identity = std::make_unique<MockIdentityService>();
    auto storage = std::make_unique<MockStorageService>();
    auto vault = std::make_unique<MockVaultService>();
    auto fs = std::make_unique<MockFileService>();
    auto network = std::make_unique<MockNetworkService>();
    auto transport = std::make_unique<MockTransportService>();
    auto scheduler = std::make_unique<MockSchedulerService>();
    auto policy = std::make_unique<smo::acl::PolicyEngine>();
    auto audit = std::make_unique<MockAuditService>();
    auto history = std::make_unique<MockHistoryService>();
    auto metrics = std::make_unique<MockMetricsService>();
    auto logger = std::make_unique<MockLoggerService>();
    auto clock = std::make_unique<MockClockService>();
    auto random = std::make_unique<MockRandomService>();

    auto ctx_result = make_runtime_context()
                          .with_crypto(crypto.get())
                          .with_identity(identity.get())
                          .with_vault(vault.get())
                          .with_storage(storage.get())
                          .with_file(fs.get())
                          .with_network(network.get())
                          .with_transport(transport.get())
                          .with_scheduler(scheduler.get())
                          .with_policy(policy.get())
                          .with_audit(audit.get())
                          .with_history(history.get())
                          .with_metrics(metrics.get())
                          .with_logger(logger.get())
                          .with_clock(clock.get())
                          .with_random(random.get())
                          .build();

    ASSERT(ctx_result);
    auto ctx = ctx_result.value();
    ASSERT(ctx.services.crypto == crypto.get());
    ASSERT(ctx.services.identity == identity.get());
    ASSERT(ctx.services.storage == storage.get());
    ASSERT(ctx.services.policy == policy.get());
    ASSERT(ctx.services.audit == audit.get());
    ASSERT(ctx.services.clock == clock.get());
    ASSERT(ctx.services.random == random.get());
    return true;
}

static bool test_builder_with_execution_info()
{
    using namespace smo::runtime;

    auto crypto = std::make_unique<MockCryptoService>();
    auto policy = std::make_unique<smo::acl::PolicyEngine>();

    ExecutionInfo info;
    info.execution_id = 12345;
    info.contract_id = "test_contract";

    auto ctx_result = make_runtime_context()
                          .with_crypto(crypto.get())
                          .with_policy(policy.get())
                          .with_execution_info(info)
                          .build();

    ASSERT(ctx_result);
    auto ctx = ctx_result.value();
    ASSERT_EQ(ctx.info.execution_id, 12345);
    ASSERT_EQ(ctx.info.contract_id, "test_contract");
    return true;
}

static bool test_builder_without_contract_id_fails()
{
    using namespace smo::runtime;

    auto crypto = std::make_unique<MockCryptoService>();
    auto policy = std::make_unique<smo::acl::PolicyEngine>();

    ExecutionInfo info;
    info.execution_id = 12345;
    // contract_id intentionally not set

    auto ctx_result = make_runtime_context()
                          .with_crypto(crypto.get())
                          .with_policy(policy.get())
                          .with_execution_info(info)
                          .build();

    ASSERT(!ctx_result);
    ASSERT_EQ(ctx_result.error().code.code, 1001);
    return true;
}

static bool test_builder_with_zero_execution_id_works()
{
    using namespace smo::runtime;

    auto crypto = std::make_unique<MockCryptoService>();
    auto policy = std::make_unique<smo::acl::PolicyEngine>();

    ExecutionInfo info;
    info.execution_id = 0;  // No execution_id
    info.contract_id = "";  // No contract_id either

    auto ctx_result = make_runtime_context()
                          .with_crypto(crypto.get())
                          .with_policy(policy.get())
                          .with_execution_info(info)
                          .build();

    ASSERT(ctx_result);  // Should work when execution_id is 0
    return true;
}

static bool test_has_capability()
{
    using namespace smo::runtime;

    auto crypto = std::make_unique<MockCryptoService>();
    auto policy = std::make_unique<smo::acl::PolicyEngine>();

    ContractCapabilities caps;
    caps.set(static_cast<size_t>(ContractCapability::Crypto));
    caps.set(static_cast<size_t>(ContractCapability::Storage));

    auto ctx_result = make_runtime_context()
                          .with_crypto(crypto.get())
                          .with_policy(policy.get())
                          .with_capabilities(caps)
                          .build();

    ASSERT(ctx_result);
    auto ctx = ctx_result.value();
    ASSERT(ctx.services.has_capability(ContractCapability::Crypto));
    ASSERT(ctx.services.has_capability(ContractCapability::Storage));
    ASSERT(!ctx.services.has_capability(ContractCapability::Network));
    return true;
}

static bool test_event_bus_injection()
{
    using namespace smo::runtime;

    auto crypto = std::make_unique<MockCryptoService>();
    auto policy = std::make_unique<smo::acl::PolicyEngine>();
    auto event_bus = std::make_unique<EventBus>();

    auto ctx_result = make_runtime_context()
                          .with_crypto(crypto.get())
                          .with_policy(policy.get())
                          .with_event_bus(event_bus.get())
                          .build();

    ASSERT(ctx_result);
    auto ctx = ctx_result.value();
    ASSERT(ctx.event_bus == event_bus.get());
    return true;
}

// ==========================================================================
// Main
// ==========================================================================

int main(int, char*[])
{
    printf("SMO RuntimeContext — Unit Tests\n");
    printf("================================\n\n");

    TEST("BuilderBasic") END_TEST(test_builder_basic());
    TEST("BuilderWithExecutionInfo") END_TEST(test_builder_with_execution_info());
    TEST("BuilderWithoutContractIdFails") END_TEST(test_builder_without_contract_id_fails());
    TEST("BuilderWithZeroExecutionIdWorks") END_TEST(test_builder_with_zero_execution_id_works());
    TEST("HasCapability") END_TEST(test_has_capability());
    TEST("EventBusInjection") END_TEST(test_event_bus_injection());

    printf("\n");
    if (failures == 0)
    {
        printf("ALL TESTS PASSED\n");
        return 0;
    }
    else
    {
        printf("%d TEST(S) FAILED\n", failures);
        return 1;
    }
}