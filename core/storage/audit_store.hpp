#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <chrono>
#include "core/types.hpp"
#include "core/errors/error.hpp"
#include "core/crypto/impl.hpp"

namespace smo {

// ===========================================================================
// Audit Store
// ===========================================================================

enum class AuditEventType : uint8_t {
    ContractDeployed    = 1,
    ContractUpdated     = 2,
    ContractRevoked     = 3,
    ExecutionStarted    = 4,
    ExecutionCompleted  = 5,
    ExecutionFailed     = 6,
    ExecutionCancelled  = 7,
    PolicyEvaluated     = 6,
    WitnessAttested     = 7,
    PolicyChanged       = 8,
    MeshJoined          = 9,
    MeshLeft            = 10,
    CertificateIssued   = 11,
    CertificateRevoked  = 11,
    EpochIncremented    = 12,
};

struct AuditRecord {
    uint64_t sequence = 0;
    AuditEventType type;
    int64_t timestamp_ns = 0;
    std::string actor_id;
    std::string target_id;
    std::string contract_id;
    std::string execution_id;
    std::string trace_id;
    std::string details;       // JSON payload
    std::string prev_hash;
    std::string record_hash;
    std::string signature;
};

struct AuditQuery {
    std::optional<std::string> actor_id;
    std::optional<std::string> target_id;
    std::optional<std::string> contract_id;
    std::optional<std::string> execution_id;
    std::optional<AuditEventType> type;
    std::optional<int64_t> from_ns;
    std::optional<int64_t> to_ns;
    uint64_t limit = 1000;
    uint64_t offset = 0;
};

struct AuditQueryResult {
    std::vector<std::string> records;  // JSON-encoded
    uint64_t total_count = 0;
    bool has_more = false;
};

class AuditStore {
public:
    struct Config {
        std::string db_path;
        size_t max_records = 10000000;
        bool enable_wal = true;
    };

    explicit AuditStore(const Config& config = {});
    ~AuditStore();

    AuditStore(const AuditStore&) = delete;
    AuditStore& operator=(const AuditStore&) = delete;
    AuditStore(AuditStore&&) = default;
    AuditStore& operator=(AuditStore&&) = default;

    Result<void> open();
    void close();

    Result<uint64_t> record(const AuditRecord& record);
    Result<AuditQueryResult> query(const AuditQuery& query) const;
    Result<std::vector<std::string>> get_contract_history(const std::string& contract_id, uint64_t limit = 1000) const;
    Result<std::vector<std::string>> get_execution_history(const std::string& execution_id) const;
    Result<std::vector<std::string>> get_actor_history(const std::string& actor_id, uint64_t limit = 1000) const;
    Result<std::vector<std::string>> get_timeline(int64_t from_ns, int64_t to_ns, uint64_t limit = 1000) const;

    Result<void> vacuum();
    Result<size_t> count() const;
    Result<size_t> db_size_bytes() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace smo