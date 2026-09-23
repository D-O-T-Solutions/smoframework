#include "history.hpp"

#include <sqlite3.h>
#include <chrono>
#include <filesystem>
#include <memory>
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>
#include <functional>

namespace smo {

// Static helper functions
static std::vector<std::string> parse_string_list(const std::string& csv)
{
    std::vector<std::string> result;
    if (csv.empty())
        return result;
    std::stringstream ss(csv);
    std::string item;
    while (std::getline(ss, item, ','))
    {
        if (!item.empty())
            result.push_back(item);
    }
    return result;
}

static std::string join_string_list(const std::vector<std::string>& list)
{
    if (list.empty())
        return "";
    std::string result;
    for (size_t i = 0; i < list.size(); ++i)
    {
        if (i > 0)
            result += ",";
        result += list[i];
    }
    return result;
}

struct HistoryService::Impl
{
    sqlite3* db = nullptr;
    Config config;
    uint64_t sequence_counter = 0;

    Impl(const Config& cfg) : config(cfg) {}

    ~Impl() { close(); }

    Result<void> open()
    {
        namespace fs = std::filesystem;
        fs::path dir(config.audit_db_path);
        fs::path dir_path = dir.parent_path();
        if (!dir_path.empty())
        {
            std::error_code ec;
            fs::create_directories(dir_path, ec);
        }

        int rc = sqlite3_open(config.audit_db_path.c_str(), &db);
        if (rc != SQLITE_OK)
        {
            return SMO_ERR_STORAGE(900, Critical, NoRetry, RebootNode,
                                   "Failed to open history DB: " + std::string(sqlite3_errmsg(db)));
        }

        char* err = nullptr;
        rc = sqlite3_exec(db, "PRAGMA journal_mode = WAL;", nullptr, nullptr, &err);
        if (rc != SQLITE_OK)
        {
            std::string msg = err ? err : "unknown";
            sqlite3_free(err);
            sqlite3_close(db);
            return SMO_ERR_STORAGE(900, Critical, NoRetry, RebootNode, msg);
        }

        sqlite3_busy_timeout(db, 5000);

        const char* schema = R"(
        CREATE TABLE IF NOT EXISTS contract_history (
            contract_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            version TEXT NOT NULL,
            publisher TEXT NOT NULL,
            abi_hash TEXT NOT NULL,
            semantic_hash TEXT NOT NULL,
            published_at INTEGER NOT NULL,
            publisher_id TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS execution_history (
            execution_id TEXT PRIMARY KEY,
            contract_id TEXT NOT NULL,
            trace_id TEXT NOT NULL,
            requester_id TEXT NOT NULL,
            responder_id TEXT NOT NULL,
            witness_ids TEXT NOT NULL,
            selected_nodes TEXT NOT NULL,
            created_ns INTEGER NOT NULL,
            started_ns INTEGER NOT NULL,
            completed_ns INTEGER NOT NULL,
            timeout_ns INTEGER NOT NULL,
            retry_count INTEGER NOT NULL,
            max_retries INTEGER NOT NULL,
            status TEXT NOT NULL,
            result_hash TEXT NOT NULL,
            error_message TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_execution_contract ON execution_history(contract_id);
        CREATE INDEX IF NOT EXISTS idx_execution_trace ON execution_history(trace_id);
        CREATE INDEX IF NOT EXISTS idx_execution_node ON execution_history(responder_id);
        CREATE INDEX IF NOT EXISTS idx_execution_status ON execution_history(status);
        CREATE INDEX IF NOT EXISTS idx_execution_created ON execution_history(created_ns);

        CREATE TABLE IF NOT EXISTS execution_events (
            sequence INTEGER PRIMARY KEY,
            event_type TEXT NOT NULL,
            timestamp_ns INTEGER NOT NULL,
            execution_id TEXT NOT NULL,
            trace_id TEXT NOT NULL,
            contract_id TEXT NOT NULL,
            actor_id TEXT NOT NULL,
            node_id TEXT NOT NULL,
            payload TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_events_execution ON execution_events(execution_id);
        CREATE INDEX IF NOT EXISTS idx_events_trace ON execution_events(trace_id);
        CREATE INDEX IF NOT EXISTS idx_events_type ON execution_events(event_type);
        CREATE INDEX IF NOT EXISTS idx_events_timestamp ON execution_events(timestamp_ns);

        CREATE TABLE IF NOT EXISTS node_history (
            node_id TEXT PRIMARY KEY,
            display_name TEXT NOT NULL,
            mesh_name TEXT NOT NULL,
            role TEXT NOT NULL,
            tags TEXT NOT NULL,
            platform TEXT NOT NULL,
            arch TEXT NOT NULL,
            version TEXT NOT NULL,
            last_seen INTEGER NOT NULL,
            ping_misses INTEGER NOT NULL,
            rtt_ms REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_node_mesh ON node_history(mesh_name);

        CREATE TABLE IF NOT EXISTS policy_history (
            sequence INTEGER PRIMARY KEY,
            policy_name TEXT NOT NULL,
            actor_id TEXT NOT NULL,
            target_id TEXT NOT NULL,
            details TEXT NOT NULL,
            timestamp_ns INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_policy_name ON policy_history(policy_name);
        CREATE INDEX IF NOT EXISTS idx_policy_timestamp ON policy_history(timestamp_ns);

        CREATE TABLE IF NOT EXISTS mesh_history (
            mesh_id TEXT NOT NULL,
            mesh_name TEXT NOT NULL,
            epoch INTEGER NOT NULL,
            authority TEXT NOT NULL,
            action TEXT NOT NULL,
            timestamp_ns INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_mesh_id ON mesh_history(mesh_id);
        CREATE INDEX IF NOT EXISTS idx_mesh_timestamp ON mesh_history(timestamp_ns);
        )";

        rc = sqlite3_exec(db, schema, nullptr, nullptr, &err);
        if (rc != SQLITE_OK)
        {
            std::string msg = err ? err : "unknown";
            sqlite3_free(err);
            return SMO_ERR_STORAGE(900, Critical, NoRetry, RebootNode, msg);
        }

        sqlite3_stmt* stmt;
        rc = sqlite3_prepare_v2(db, "SELECT MAX(sequence) FROM policy_history", -1, &stmt, nullptr);
        if (rc == SQLITE_OK)
        {
            if (sqlite3_step(stmt) == SQLITE_ROW)
            {
                sequence_counter = sqlite3_column_int64(stmt, 0);
            }
            sqlite3_finalize(stmt);
        }

        return {};
    }

    void close()
    {
        if (db)
        {
            sqlite3_close(db);
            db = nullptr;
        }
    }

    template <typename T, typename Mapper>
    Result<std::vector<T>> exec_query(const std::string& base_sql,
                                       const std::vector<std::pair<int, std::string>>& bindings,
                                       uint64_t limit,
                                       Mapper&& row_mapper) const
    {
        std::string sql = base_sql + " LIMIT ? OFFSET ?";
        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
        if (rc != SQLITE_OK)
        {
            return SMO_ERR_STORAGE(904, Error, RetrySafe, RetryOperation,
                                   "Failed to prepare query: " + std::string(sqlite3_errmsg(db)));
        }

        int idx = 1;
        for (const auto& [bind_idx, value] : bindings)
        {
            sqlite3_bind_text(stmt, idx++, value.c_str(), -1, SQLITE_TRANSIENT);
        }
        sqlite3_bind_int64(stmt, idx++, static_cast<int64_t>(limit));
        sqlite3_bind_int64(stmt, idx++, static_cast<int64_t>(0)); // offset - simplified

        std::vector<T> results;
        while ((rc = sqlite3_step(stmt)) == SQLITE_ROW)
        {
            results.push_back(row_mapper(stmt));
        }
        sqlite3_finalize(stmt);

        if (rc != SQLITE_DONE)
        {
            return SMO_ERR_STORAGE(904, Error, RetrySafe, RetryOperation,
                                   "Query failed: " + std::string(sqlite3_errmsg(db)));
        }

        return results;
    }
};

HistoryService::HistoryService(const Config& config) : impl_(std::make_unique<Impl>(config)) {}
HistoryService::~HistoryService() = default;

HistoryService::HistoryService(HistoryService&&) noexcept = default;
HistoryService& HistoryService::operator=(HistoryService&&) noexcept = default;

Result<void> HistoryService::open() { return impl_->open(); }
void HistoryService::close() { impl_->close(); }

Result<std::vector<ContractHistoryEntry>> HistoryService::get_contract_history(const std::string& contract_id, uint64_t limit, uint64_t offset) const
{
    return impl_->exec_query<ContractHistoryEntry>(
        "SELECT contract_id, name, version, publisher, abi_hash, semantic_hash, published_at, publisher_id "
        "FROM contract_history WHERE contract_id = ?",
        {{1, contract_id}}, limit,
        [](sqlite3_stmt* stmt) -> ContractHistoryEntry {
            ContractHistoryEntry entry;
            auto ctext = [](sqlite3_stmt* s, int c) -> std::string {
                auto p = sqlite3_column_text(s, c);
                return p ? reinterpret_cast<const char*>(p) : "";
            };
            entry.contract_id = ctext(stmt, 0);
            entry.name = ctext(stmt, 1);
            entry.version = ctext(stmt, 2);
            entry.publisher = ctext(stmt, 3);
            entry.abi_hash = ctext(stmt, 4);
            entry.semantic_hash = ctext(stmt, 5);
            entry.published_at = sqlite3_column_int64(stmt, 6);
            entry.publisher_id = ctext(stmt, 7);
            return entry;
        });
}

Result<ContractHistoryEntry> HistoryService::get_contract(const std::string& contract_id) const
{
    auto result = get_contract_history(contract_id, 1, 0);
    if (!result)
        return result.error();
    if (result.value().empty())
        return SMO_ERR_STORAGE(902, Info, RetrySafe, None, "Contract not found: " + contract_id);
    return result.value()[0];
}

Result<std::vector<ExecutionHistoryEntry>> HistoryService::get_execution_history(const std::string& execution_id) const
{
    return impl_->exec_query<ExecutionHistoryEntry>(
        "SELECT execution_id, contract_id, trace_id, requester_id, responder_id, "
        "witness_ids, selected_nodes, created_ns, started_ns, completed_ns, timeout_ns, "
        "retry_count, max_retries, status, result_hash, error_message "
        "FROM execution_history WHERE execution_id = ?",
        {{1, execution_id}}, 1,
        [](sqlite3_stmt* stmt) -> ExecutionHistoryEntry {
            ExecutionHistoryEntry entry;
            auto ctext = [](sqlite3_stmt* s, int c) -> std::string {
                auto p = sqlite3_column_text(s, c);
                return p ? reinterpret_cast<const char*>(p) : "";
            };
            entry.execution_id = ctext(stmt, 0);
            entry.contract_id = ctext(stmt, 1);
            entry.trace_id = ctext(stmt, 2);
            entry.requester_id = ctext(stmt, 3);
            entry.responder_id = ctext(stmt, 4);
            entry.witness_ids = parse_string_list(ctext(stmt, 5));
            entry.selected_nodes = parse_string_list(ctext(stmt, 6));
            entry.created_ns = sqlite3_column_int64(stmt, 7);
            entry.started_ns = sqlite3_column_int64(stmt, 8);
            entry.completed_ns = sqlite3_column_int64(stmt, 9);
            entry.timeout_ns = sqlite3_column_int64(stmt, 10);
            entry.retry_count = sqlite3_column_int(stmt, 11);
            entry.max_retries = sqlite3_column_int(stmt, 12);
            entry.status = ctext(stmt, 13);
            entry.result_hash = ctext(stmt, 14);
            entry.error_message = ctext(stmt, 15);
            return entry;
        });
}

Result<std::vector<ExecutionHistoryEntry>> HistoryService::get_contract_executions(const std::string& contract_id, uint64_t limit, uint64_t offset) const
{
    return impl_->exec_query<ExecutionHistoryEntry>(
        "SELECT execution_id, contract_id, trace_id, requester_id, responder_id, "
        "witness_ids, selected_nodes, created_ns, started_ns, completed_ns, timeout_ns, "
        "retry_count, max_retries, status, result_hash, error_message "
        "FROM execution_history WHERE contract_id = ? ORDER BY created_ns DESC",
        {{1, contract_id}}, limit,
        [](sqlite3_stmt* stmt) -> ExecutionHistoryEntry {
            ExecutionHistoryEntry entry;
            auto ctext = [](sqlite3_stmt* s, int c) -> std::string {
                auto p = sqlite3_column_text(s, c);
                return p ? reinterpret_cast<const char*>(p) : "";
            };
            entry.execution_id = ctext(stmt, 0);
            entry.contract_id = ctext(stmt, 1);
            entry.trace_id = ctext(stmt, 2);
            entry.requester_id = ctext(stmt, 3);
            entry.responder_id = ctext(stmt, 4);
            entry.witness_ids = parse_string_list(ctext(stmt, 5));
            entry.selected_nodes = parse_string_list(ctext(stmt, 6));
            entry.created_ns = sqlite3_column_int64(stmt, 7);
            entry.started_ns = sqlite3_column_int64(stmt, 8);
            entry.completed_ns = sqlite3_column_int64(stmt, 9);
            entry.timeout_ns = sqlite3_column_int64(stmt, 10);
            entry.retry_count = sqlite3_column_int(stmt, 11);
            entry.max_retries = sqlite3_column_int(stmt, 12);
            entry.status = ctext(stmt, 13);
            entry.result_hash = ctext(stmt, 14);
            entry.error_message = ctext(stmt, 15);
            return entry;
        });
}

Result<std::vector<ExecutionHistoryEntry>> HistoryService::get_node_executions(const std::string& node_id, uint64_t limit, uint64_t offset) const
{
    return impl_->exec_query<ExecutionHistoryEntry>(
        "SELECT execution_id, contract_id, trace_id, requester_id, responder_id, "
        "witness_ids, selected_nodes, created_ns, started_ns, completed_ns, timeout_ns, "
        "retry_count, max_retries, status, result_hash, error_message "
        "FROM execution_history WHERE responder_id = ? ORDER BY created_ns DESC",
        {{1, node_id}}, limit,
        [](sqlite3_stmt* stmt) -> ExecutionHistoryEntry {
            ExecutionHistoryEntry entry;
            auto ctext = [](sqlite3_stmt* s, int c) -> std::string {
                auto p = sqlite3_column_text(s, c);
                return p ? reinterpret_cast<const char*>(p) : "";
            };
            entry.execution_id = ctext(stmt, 0);
            entry.contract_id = ctext(stmt, 1);
            entry.trace_id = ctext(stmt, 2);
            entry.requester_id = ctext(stmt, 3);
            entry.responder_id = ctext(stmt, 4);
            entry.witness_ids = parse_string_list(ctext(stmt, 5));
            entry.selected_nodes = parse_string_list(ctext(stmt, 6));
            entry.created_ns = sqlite3_column_int64(stmt, 7);
            entry.started_ns = sqlite3_column_int64(stmt, 8);
            entry.completed_ns = sqlite3_column_int64(stmt, 9);
            entry.timeout_ns = sqlite3_column_int64(stmt, 10);
            entry.retry_count = sqlite3_column_int(stmt, 11);
            entry.max_retries = sqlite3_column_int(stmt, 12);
            entry.status = ctext(stmt, 13);
            entry.result_hash = ctext(stmt, 14);
            entry.error_message = ctext(stmt, 15);
            return entry;
        });
}

Result<std::vector<ExecutionHistoryEntry>> HistoryService::get_failed_executions(int64_t from_ns, int64_t to_ns, uint64_t limit) const
{
    return impl_->exec_query<ExecutionHistoryEntry>(
        "SELECT execution_id, contract_id, trace_id, requester_id, responder_id, "
        "witness_ids, selected_nodes, created_ns, started_ns, completed_ns, timeout_ns, "
        "retry_count, max_retries, status, result_hash, error_message "
        "FROM execution_history WHERE status = 'failed' AND created_ns >= ? AND created_ns <= ? ORDER BY created_ns DESC",
        {{1, std::to_string(from_ns)}, {2, std::to_string(to_ns)}}, limit,
        [](sqlite3_stmt* stmt) -> ExecutionHistoryEntry {
            ExecutionHistoryEntry entry;
            auto ctext = [](sqlite3_stmt* s, int c) -> std::string {
                auto p = sqlite3_column_text(s, c);
                return p ? reinterpret_cast<const char*>(p) : "";
            };
            entry.execution_id = ctext(stmt, 0);
            entry.contract_id = ctext(stmt, 1);
            entry.trace_id = ctext(stmt, 2);
            entry.requester_id = ctext(stmt, 3);
            entry.responder_id = ctext(stmt, 4);
            entry.witness_ids = parse_string_list(ctext(stmt, 5));
            entry.selected_nodes = parse_string_list(ctext(stmt, 6));
            entry.created_ns = sqlite3_column_int64(stmt, 7);
            entry.started_ns = sqlite3_column_int64(stmt, 8);
            entry.completed_ns = sqlite3_column_int64(stmt, 9);
            entry.timeout_ns = sqlite3_column_int64(stmt, 10);
            entry.retry_count = sqlite3_column_int(stmt, 11);
            entry.max_retries = sqlite3_column_int(stmt, 12);
            entry.status = ctext(stmt, 13);
            entry.result_hash = ctext(stmt, 14);
            entry.error_message = ctext(stmt, 15);
            return entry;
        });
}

Result<std::vector<ExecutionEventEntry>> HistoryService::get_execution_events(const std::string& execution_id) const
{
    return impl_->exec_query<ExecutionEventEntry>(
        "SELECT sequence, event_type, timestamp_ns, execution_id, trace_id, contract_id, "
        "actor_id, node_id, payload, prev_hash, event_hash "
        "FROM execution_events WHERE execution_id = ? ORDER BY sequence ASC",
        {{1, execution_id}}, 1000,
        [](sqlite3_stmt* stmt) -> ExecutionEventEntry {
            ExecutionEventEntry entry;
            auto ctext = [](sqlite3_stmt* s, int c) -> std::string {
                auto p = sqlite3_column_text(s, c);
                return p ? reinterpret_cast<const char*>(p) : "";
            };
            entry.sequence = sqlite3_column_int64(stmt, 0);
            entry.event_type = ctext(stmt, 1);
            entry.timestamp_ns = sqlite3_column_int64(stmt, 2);
            entry.execution_id = ctext(stmt, 3);
            entry.trace_id = ctext(stmt, 4);
            entry.contract_id = ctext(stmt, 5);
            entry.actor_id = ctext(stmt, 6);
            entry.node_id = ctext(stmt, 7);
            entry.payload = ctext(stmt, 8);
            entry.prev_hash = ctext(stmt, 9);
            entry.event_hash = ctext(stmt, 10);
            return entry;
        });
}

Result<std::vector<ExecutionEventEntry>> HistoryService::get_trace_events(const std::string& trace_id) const
{
    return impl_->exec_query<ExecutionEventEntry>(
        "SELECT sequence, event_type, timestamp_ns, execution_id, trace_id, contract_id, "
        "actor_id, node_id, payload, prev_hash, event_hash "
        "FROM execution_events WHERE trace_id = ? ORDER BY sequence ASC",
        {{1, trace_id}}, 1000,
        [](sqlite3_stmt* stmt) -> ExecutionEventEntry {
            ExecutionEventEntry entry;
            auto ctext = [](sqlite3_stmt* s, int c) -> std::string {
                auto p = sqlite3_column_text(s, c);
                return p ? reinterpret_cast<const char*>(p) : "";
            };
            entry.sequence = sqlite3_column_int64(stmt, 0);
            entry.event_type = ctext(stmt, 1);
            entry.timestamp_ns = sqlite3_column_int64(stmt, 2);
            entry.execution_id = ctext(stmt, 3);
            entry.trace_id = ctext(stmt, 4);
            entry.contract_id = ctext(stmt, 5);
            entry.actor_id = ctext(stmt, 6);
            entry.node_id = ctext(stmt, 7);
            entry.payload = ctext(stmt, 8);
            entry.prev_hash = ctext(stmt, 9);
            entry.event_hash = ctext(stmt, 10);
            return entry;
        });
}

Result<std::vector<NodeHistoryEntry>> HistoryService::get_node_history(const std::string& node_id, uint64_t limit) const
{
    return impl_->exec_query<NodeHistoryEntry>(
        "SELECT node_id, display_name, mesh_name, role, tags, platform, arch, version, last_seen, ping_misses, rtt_ms "
        "FROM node_history WHERE node_id = ? ORDER BY last_seen DESC",
        {{1, node_id}}, limit,
        [](sqlite3_stmt* stmt) -> NodeHistoryEntry {
            NodeHistoryEntry entry;
            auto ctext = [](sqlite3_stmt* s, int c) -> std::string {
                auto p = sqlite3_column_text(s, c);
                return p ? reinterpret_cast<const char*>(p) : "";
            };
            entry.node_id = ctext(stmt, 0);
            entry.display_name = ctext(stmt, 1);
            entry.mesh_name = ctext(stmt, 2);
            entry.role = ctext(stmt, 3);
            entry.tags = parse_string_list(ctext(stmt, 4));
            entry.platform = ctext(stmt, 5);
            entry.arch = ctext(stmt, 6);
            entry.version = ctext(stmt, 7);
            entry.last_seen = sqlite3_column_int64(stmt, 8);
            entry.ping_misses = sqlite3_column_int(stmt, 9);
            entry.rtt_ms = sqlite3_column_double(stmt, 10);
            return entry;
        });
}

Result<std::vector<NodeHistoryEntry>> HistoryService::get_mesh_nodes(const std::string& mesh_id, uint64_t limit) const
{
    return impl_->exec_query<NodeHistoryEntry>(
        "SELECT node_id, display_name, mesh_name, role, tags, platform, arch, version, last_seen, ping_misses, rtt_ms "
        "FROM node_history WHERE mesh_name = ? ORDER BY last_seen DESC",
        {{1, mesh_id}}, limit,
        [](sqlite3_stmt* stmt) -> NodeHistoryEntry {
            NodeHistoryEntry entry;
            auto ctext = [](sqlite3_stmt* s, int c) -> std::string {
                auto p = sqlite3_column_text(s, c);
                return p ? reinterpret_cast<const char*>(p) : "";
            };
            entry.node_id = ctext(stmt, 0);
            entry.display_name = ctext(stmt, 1);
            entry.mesh_name = ctext(stmt, 2);
            entry.role = ctext(stmt, 3);
            entry.tags = parse_string_list(ctext(stmt, 4));
            entry.platform = ctext(stmt, 5);
            entry.arch = ctext(stmt, 6);
            entry.version = ctext(stmt, 7);
            entry.last_seen = sqlite3_column_int64(stmt, 8);
            entry.ping_misses = sqlite3_column_int(stmt, 9);
            entry.rtt_ms = sqlite3_column_double(stmt, 10);
            return entry;
        });
}

Result<std::vector<PolicyHistoryEntry>> HistoryService::get_policy_history(const std::string& policy_name, uint64_t limit) const
{
    return impl_->exec_query<PolicyHistoryEntry>(
        "SELECT sequence, policy_name, actor_id, target_id, details, timestamp_ns "
        "FROM policy_history WHERE policy_name = ? ORDER BY timestamp_ns DESC",
        {{1, policy_name}}, limit,
        [](sqlite3_stmt* stmt) -> PolicyHistoryEntry {
            PolicyHistoryEntry entry;
            auto ctext = [](sqlite3_stmt* s, int c) -> std::string {
                auto p = sqlite3_column_text(s, c);
                return p ? reinterpret_cast<const char*>(p) : "";
            };
            entry.sequence = sqlite3_column_int64(stmt, 0);
            entry.policy_name = ctext(stmt, 1);
            entry.actor_id = ctext(stmt, 2);
            entry.target_id = ctext(stmt, 3);
            entry.details = ctext(stmt, 4);
            entry.timestamp_ns = sqlite3_column_int64(stmt, 5);
            return entry;
        });
}

Result<std::vector<MeshHistoryEntry>> HistoryService::get_mesh_history(const std::string& mesh_id, uint64_t limit) const
{
    return impl_->exec_query<MeshHistoryEntry>(
        "SELECT mesh_id, mesh_name, epoch, authority, action, timestamp_ns "
        "FROM mesh_history WHERE mesh_id = ? ORDER BY timestamp_ns DESC",
        {{1, mesh_id}}, limit,
        [](sqlite3_stmt* stmt) -> MeshHistoryEntry {
            MeshHistoryEntry entry;
            auto ctext = [](sqlite3_stmt* s, int c) -> std::string {
                auto p = sqlite3_column_text(s, c);
                return p ? reinterpret_cast<const char*>(p) : "";
            };
            entry.mesh_id = ctext(stmt, 0);
            entry.mesh_name = ctext(stmt, 1);
            entry.epoch = sqlite3_column_int64(stmt, 2);
            entry.authority = ctext(stmt, 3);
            entry.action = ctext(stmt, 4);
            entry.timestamp_ns = sqlite3_column_int64(stmt, 5);
            return entry;
        });
}

Result<std::vector<ExecutionHistoryEntry>> HistoryService::query_executions(
    const std::optional<std::string>& contract_id, const std::optional<std::string>& node_id,
    const std::optional<std::string>& status, const std::optional<int64_t>& from_ns,
    const std::optional<int64_t>& to_ns, uint64_t limit, uint64_t offset) const
{
    std::string sql = "SELECT execution_id, contract_id, trace_id, requester_id, responder_id, "
                      "witness_ids, selected_nodes, created_ns, started_ns, completed_ns, timeout_ns, "
                      "retry_count, max_retries, status, result_hash, error_message "
                      "FROM execution_history WHERE 1=1";
    std::vector<std::pair<int, std::string>> bindings;
    int bind_idx = 1;

    if (contract_id)
    {
        sql += " AND contract_id = ?";
        bindings.emplace_back(bind_idx++, *contract_id);
    }
    if (node_id)
    {
        sql += " AND responder_id = ?";
        bindings.emplace_back(bind_idx++, *node_id);
    }
    if (status)
    {
        sql += " AND status = ?";
        bindings.emplace_back(bind_idx++, *status);
    }
    if (from_ns)
    {
        sql += " AND created_ns >= ?";
        bindings.emplace_back(bind_idx++, std::to_string(*from_ns));
    }
    if (to_ns)
    {
        sql += " AND created_ns <= ?";
        bindings.emplace_back(bind_idx++, std::to_string(*to_ns));
    }
    sql += " ORDER BY created_ns DESC";

    return impl_->exec_query<ExecutionHistoryEntry>(sql, bindings, limit,
        [](sqlite3_stmt* stmt) -> ExecutionHistoryEntry {
            ExecutionHistoryEntry entry;
            auto ctext = [](sqlite3_stmt* s, int c) -> std::string {
                auto p = sqlite3_column_text(s, c);
                return p ? reinterpret_cast<const char*>(p) : "";
            };
            entry.execution_id = ctext(stmt, 0);
            entry.contract_id = ctext(stmt, 1);
            entry.trace_id = ctext(stmt, 2);
            entry.requester_id = ctext(stmt, 3);
            entry.responder_id = ctext(stmt, 4);
            entry.witness_ids = parse_string_list(ctext(stmt, 5));
            entry.selected_nodes = parse_string_list(ctext(stmt, 6));
            entry.created_ns = sqlite3_column_int64(stmt, 7);
            entry.started_ns = sqlite3_column_int64(stmt, 8);
            entry.completed_ns = sqlite3_column_int64(stmt, 9);
            entry.timeout_ns = sqlite3_column_int64(stmt, 10);
            entry.retry_count = sqlite3_column_int(stmt, 11);
            entry.max_retries = sqlite3_column_int(stmt, 12);
            entry.status = ctext(stmt, 13);
            entry.result_hash = ctext(stmt, 14);
            entry.error_message = ctext(stmt, 15);
            return entry;
        });
}

Result<std::vector<ExecutionEventEntry>> HistoryService::query_events(
    const std::optional<std::string>& execution_id, const std::optional<std::string>& trace_id,
    const std::optional<std::string>& event_type, const std::optional<int64_t>& from_ns,
    const std::optional<int64_t>& to_ns, uint64_t limit, uint64_t offset) const
{
    std::string sql = "SELECT sequence, event_type, timestamp_ns, execution_id, trace_id, contract_id, "
                      "actor_id, node_id, payload, prev_hash, event_hash "
                      "FROM execution_events WHERE 1=1";
    std::vector<std::pair<int, std::string>> bindings;
    int bind_idx = 1;

    if (execution_id)
    {
        sql += " AND execution_id = ?";
        bindings.emplace_back(bind_idx++, *execution_id);
    }
    if (trace_id)
    {
        sql += " AND trace_id = ?";
        bindings.emplace_back(bind_idx++, *trace_id);
    }
    if (event_type)
    {
        sql += " AND event_type = ?";
        bindings.emplace_back(bind_idx++, *event_type);
    }
    if (from_ns)
    {
        sql += " AND timestamp_ns >= ?";
        bindings.emplace_back(bind_idx++, std::to_string(*from_ns));
    }
    if (to_ns)
    {
        sql += " AND timestamp_ns <= ?";
        bindings.emplace_back(bind_idx++, std::to_string(*to_ns));
    }
    sql += " ORDER BY sequence ASC";

    return impl_->exec_query<ExecutionEventEntry>(sql, bindings, limit,
        [](sqlite3_stmt* stmt) -> ExecutionEventEntry {
            ExecutionEventEntry entry;
            auto ctext = [](sqlite3_stmt* s, int c) -> std::string {
                auto p = sqlite3_column_text(s, c);
                return p ? reinterpret_cast<const char*>(p) : "";
            };
            entry.sequence = sqlite3_column_int64(stmt, 0);
            entry.event_type = ctext(stmt, 1);
            entry.timestamp_ns = sqlite3_column_int64(stmt, 2);
            entry.execution_id = ctext(stmt, 3);
            entry.trace_id = ctext(stmt, 4);
            entry.contract_id = ctext(stmt, 5);
            entry.actor_id = ctext(stmt, 6);
            entry.node_id = ctext(stmt, 7);
            entry.payload = ctext(stmt, 8);
            entry.prev_hash = ctext(stmt, 9);
            entry.event_hash = ctext(stmt, 10);
            return entry;
        });
}

Result<std::vector<ExecutionHistoryEntry>> HistoryService::get_trace_executions(const std::string& trace_id) const
{
    return impl_->exec_query<ExecutionHistoryEntry>(
        "SELECT execution_id, contract_id, trace_id, requester_id, responder_id, "
        "witness_ids, selected_nodes, created_ns, started_ns, completed_ns, timeout_ns, "
        "retry_count, max_retries, status, result_hash, error_message "
        "FROM execution_history WHERE trace_id = ? ORDER BY created_ns ASC",
        {{1, trace_id}}, 1000,
        [](sqlite3_stmt* stmt) -> ExecutionHistoryEntry {
            ExecutionHistoryEntry entry;
            auto ctext = [](sqlite3_stmt* s, int c) -> std::string {
                auto p = sqlite3_column_text(s, c);
                return p ? reinterpret_cast<const char*>(p) : "";
            };
            entry.execution_id = ctext(stmt, 0);
            entry.contract_id = ctext(stmt, 1);
            entry.trace_id = ctext(stmt, 2);
            entry.requester_id = ctext(stmt, 3);
            entry.responder_id = ctext(stmt, 4);
            entry.witness_ids = parse_string_list(ctext(stmt, 5));
            entry.selected_nodes = parse_string_list(ctext(stmt, 6));
            entry.created_ns = sqlite3_column_int64(stmt, 7);
            entry.started_ns = sqlite3_column_int64(stmt, 8);
            entry.completed_ns = sqlite3_column_int64(stmt, 9);
            entry.timeout_ns = sqlite3_column_int64(stmt, 10);
            entry.retry_count = sqlite3_column_int(stmt, 11);
            entry.max_retries = sqlite3_column_int(stmt, 12);
            entry.status = ctext(stmt, 13);
            entry.result_hash = ctext(stmt, 14);
            entry.error_message = ctext(stmt, 15);
            return entry;
        });
}

} // namespace smo