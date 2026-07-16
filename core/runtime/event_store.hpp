#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <chrono>
#include <cbor/cbor.h>
#include "core/types.hpp"
#include "core/errors/error.hpp"
#include "core/contract/contract.hpp"

namespace smo {

// Event types for full lifecycle tracing
enum class EventType : uint8_t {
    Created          = 1,   // Contract/Execution created
    Validated        = 2,   // Validation passed
    Queued           = 3,   // Queued for execution
    Scheduled        = 4,   // Scheduled on nodes
    Selected         = 5,   // Nodes selected
    Dispatched       = 6,   // Dispatched to nodes
    Accepted         = 7,   // Accepted by responder
    Started          = 8,   // Execution started
    Progress         = 9,   // Progress update
    Completed        = 10,  // Completed successfully
    Failed           = 11,  // Failed
    Cancelled        = 12,  // Cancelled by user
    QueuedRetry      = 13,  // Queued for retry
    PolicyChecked    = 14,  // Policy validation
    Witnessed        = 15,  // Witness attestation
    Dispatched       = 16,  // Dispatched to node
    AcceptedByNode   = 17,  // Accepted by target node
    ProgressUpdate   = 18,  // Progress percentage
    PartialResult    = 19,  // Partial result available
};

struct EventRecord {
    uint64_t sequence = 0;
    EventType type = EventType::Created;
    int64_t timestamp_ns = 0;
    std::string contract_id;
    std::string execution_id;
    std::string trace_id;
    std::string node_id;
    std::string actor_id;
    std::string payload;       // CBOR-encoded payload
    std::string prev_hash;     // Hash of previous event
    std::string event_hash;    // Blake3 hash of this event
    std::string signature;     // Signature of event_hash
};

struct ExecutionRecord {
    std::string execution_id;
    std::string contract_id;
    std::string trace_id;
    std::string requester_id;
    std::string responder_id;
    std::vector<std::string> witness_ids;
    std::vector<std::string> selected_nodes;
    std::string intent_hash;
    std::string policy_name;
    uint32_t control_level = 0;  // 0=safe, 1=normal, 2=force, 3=emergency
    uint32_t scope = 0;          // 0=single, 1=mesh, 2=quorum, 3=witness
    int64_t created_ns = 0;
    int64_t started_ns = 0;
    int64_t completed_ns = 0;
    int64_t timeout_ns = 0;
    int32_t retry_count = 0;
    int32_t max_retries = 0;
    int32_t priority = 0;
    std::string status;           // created/running/completed/failed/cancelled
    std::string result_hash;
    std::string error_message;
};

class EventStore {
public:
    struct Config {
        std::string db_path;
        size_t max_events = 1000000;
        bool enable_wal = true;
        bool memory_map = true;
    };

    explicit EventStore(const Config& config);
    ~EventStore();

    EventStore(const EventStore&) = delete;
    EventStore& operator=(const EventStore&) = delete;
    EventStore(EventStore&&) = default;
    EventStore& operator=(EventStore&&) = default;

    Result<void> open();
    void close();

    // Event operations
    Result<uint64_t> append(const EventRecord& event);
    Result<std::vector<EventRecord>> query_by_execution(const std::string& execution_id) const;
    Result<std::vector<EventRecord>> query_by_trace(const std::string& trace_id) const;
    Result<std::vector<EventRecord>> query_by_contract(const std::string& contract_id) const;
    Result<std::vector<EventRecord>> query_by_node(const std::string& node_id, uint64_t limit = 1000) const;
    Result<std::vector<EventRecord>> query_range(int64_t from_ns, int64_t to_ns, uint64_t limit = 1000) const;
    Result<std::vector<EventRecord>> query_latest(uint64_t count) const;

    // Execution record operations
    Result<void> upsert_execution(const ExecutionRecord& record);
    Result<ExecutionRecord> get_execution(const std::string& execution_id) const;
    Result<std::vector<ExecutionRecord>> query_executions_by_contract(const std::string& contract_id) const;
    Result<std::vector<ExecutionRecord>> query_executions_by_trace(const std::string& trace_id) const;
    Result<std::vector<ExecutionRecord>> query_recent_executions(uint64_t limit) const;

    // CBOR serialization
    static Bytes serialize_event(const EventRecord& event);
    static Result<EventRecord> deserialize_event(BytesView data);
    static Bytes serialize_execution(const ExecutionRecord& record);
    static Result<ExecutionRecord> deserialize_execution(BytesView data);

    // Maintenance
    Result<void> vacuum();
    Result<size_t> count_events() const;
    Result<size_t> count_executions() const;
    Result<size_t> db_size_bytes() const;

    // Iterators for streaming
    class Iterator {
    public:
        virtual ~Iterator() = default;
        virtual bool next(EventRecord& out) = 0;
    };
    std::unique_ptr<Iterator> iterate_all();
    std::unique_ptr<Iterator> iterate_execution(const std::string& execution_id);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace smo