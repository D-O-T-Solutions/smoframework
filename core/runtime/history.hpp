#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <chrono>
#include "core/types.hpp"
#include "core/errors/error.hpp"

namespace smo {

// ===========================================================================
// History API
// ===========================================================================

struct ContractHistoryEntry {
    std::string contract_id;
    std::string name;
    std::string version;
    std::string publisher;
    std::string abi_hash;
    std::string semantic_hash;
    int64_t published_at;
    std::string publisher_id;
};

struct ExecutionHistoryEntry {
    std::string execution_id;
    std::string contract_id;
    std::string trace_id;
    std::string requester_id;
    std::string responder_id;
    std::vector<std::string> witness_ids;
    std::vector<std::string> selected_nodes;
    int64_t created_ns;
    int64_t started_ns;
    int64_t completed_ns;
    int64_t timeout_ns;
    int32_t retry_count;
    int32_t max_retries;
    std::string status;
    std::string result_hash;
    std::string error_message;
};

struct ExecutionEventEntry {
    uint64_t sequence;
    std::string event_type;
    int64_t timestamp_ns;
    std::string execution_id;
    std::string trace_id;
    std::string contract_id;
    std::string actor_id;
    std::string node_id;
    std::string payload;
    std::string prev_hash;
    std::string event_hash;
};

struct NodeHistoryEntry {
    std::string node_id;
    std::string display_name;
    std::string mesh_name;
    std::string role;
    std::vector<std::string> tags;
    std::string platform;
    std::string arch;
    std::string version;
    int64_t last_seen;
    int ping_misses;
    double rtt_ms;
};

struct PolicyHistoryEntry {
    uint64_t sequence;
    std::string policy_name;
    std::string actor_id;
    std::string target_id;
    std::string details;
    int64_t timestamp_ns;
};

struct MeshHistoryEntry {
    std::string mesh_id;
    std::string mesh_name;
    int64_t epoch;
    std::string authority;
    std::string action;
    int64_t timestamp_ns;
};

struct HistoryQuery {
    std::optional<std::string> contract_id;
    std::optional<std::string> execution_id;
    std::optional<std::string> trace_id;
    std::optional<std::string> node_id;
    std::optional<std::string> actor_id;
    std::optional<int64_t> from_ns;
    std::optional<int64_t> to_ns;
    uint64_t limit = 1000;
    uint64_t offset = 0;
};

class HistoryService {
public:
    struct Config {
        std::string audit_db_path;
    };

    explicit HistoryService(const Config& config = {});
    ~HistoryService();

    HistoryService(const HistoryService&) = delete;
    HistoryService& operator=(const HistoryService&) = delete;
    HistoryService(HistoryService&&) = default;
    HistoryService& operator=(HistoryService&&) = default;

    Result<void> open();
    void close();

    // Contract history
    Result<std::vector<ContractHistoryEntry>> get_contract_history(
        const std::string& contract_id, uint64_t limit = 1000, uint64_t offset = 0) const;
    Result<ContractHistoryEntry> get_contract(const std::string& contract_id) const;

    // Execution history
    Result<std::vector<ExecutionHistoryEntry>> get_execution_history(
        const std::string& execution_id) const;
    Result<std::vector<ExecutionHistoryEntry>> get_contract_executions(
        const std::string& contract_id, uint64_t limit = 1000, uint64_t offset = 0) const;
    Result<std::vector<ExecutionHistoryEntry>> get_node_executions(
        const std::string& node_id, uint64_t limit = 1000, uint64_t offset = 0) const;
    Result<std::vector<ExecutionHistoryEntry>> get_failed_executions(
        int64_t from_ns, int64_t to_ns, uint64_t limit = 1000) const;

    // Event history
    Result<std::vector<ExecutionEventEntry>> get_execution_events(
        const std::string& execution_id) const;
    Result<std::vector<ExecutionEventEntry>> get_trace_events(
        const std::string& trace_id) const;

    // Node history
    Result<std::vector<NodeHistoryEntry>> get_node_history(
        const std::string& node_id, uint64_t limit = 1000) const;
    Result<std::vector<NodeHistoryEntry>> get_mesh_nodes(
        const std::string& mesh_id, uint64_t limit = 1000) const;

    // Policy history
    Result<std::vector<PolicyHistoryEntry>> get_policy_history(
        const std::string& policy_name, uint64_t limit = 1000) const;

    // Mesh history
    Result<std::vector<MeshHistoryEntry>> get_mesh_history(
        const std::string& mesh_id, uint64_t limit = 1000) const;

    // Advanced queries
    Result<std::vector<ExecutionHistoryEntry>> query_executions(
        const std::optional<std::string>& contract_id,
        const std::optional<std::string>& node_id,
        const std::optional<std::string>& status,
        const std::optional<int64_t>& from_ns,
        const std::optional<int64_t>& to_ns,
        uint64_t limit = 1000, uint64_t offset = 0) const;

    Result<std::vector<ExecutionEventEntry>> query_events(
        const std::optional<std::string>& execution_id,
        const std::optional<std::string>& trace_id,
        const std::optional<std::string>& event_type,
        const std::optional<int64_t>& from_ns,
        const std::optional<int64_t>& to_ns,
        uint64_t limit = 1000, uint64_t offset = 0) const;

    // Trace API
    Result<std::vector<ExecutionHistoryEntry>> get_trace_executions(
        const std::string& trace_id) const;
    Result<std::vector<ExecutionEventEntry>> get_trace_events(
        const std::string& trace_id) const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace smo