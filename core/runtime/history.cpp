#include "history.hpp"

#include <sqlite3.h>
#include <chrono>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>

namespace smo {

struct HistoryService::Impl {
    sqlite3* db = nullptr;
    Config config;

    Impl(const Config& config) : config(config) {}

    ~Impl() { close(); }

    ~Impl() { close(); }

    Result<void> open() {
        namespace fs = std::filesystem;
        fs::path dir(config.audit_db_path);
        fs::path dir_path = dir.parent_path();
        if (!dir_path.empty()) {
            std::error_code ec;
            fs::create_directories(dir_path, ec);
        }

        int rc = sqlite3_open(config.audit_db_path.c_str(), &db);
        if (rc != SQLITE_OK) {
            return SMO_ERR_STORAGE(900, Critical, NoRetry, RebootNode,
                                   "Failed to open audit DB: " + std::string(sqlite3_errmsg(db)));
        }

        // WAL mode
        char* err = nullptr;
        int rc = sqlite3_exec(db, "PRAGMA journal_mode = WAL;", nullptr, nullptr, &err);
        if (rc != SQLITE_OK) {
            std::string msg = err ? err : "unknown";
            sqlite3_free(err);
            sqlite3_close(db);
            return SMO_ERR_STORAGE(900, Critical, NoRetry, RebootNode, msg);
        }

        sqlite3_busy_timeout(db, 5000);

        // Schema for history tables
        const char* schema = R"(
            CREATE TABLE IF NOT EXISTS contract_history (
                contract_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                version TEXT NOT NULL,
                publisher TEXT NOT NULL,
                abi_hash TEXT NOT NULL,
                semantic_hash TEXT NOT NULL,
                published_at INTEGER NOT NULL,
                publisher_id TEXT NOT NULL,
                definition_json TEXT NOT NULL
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
                started_ns INTEGER,
                completed_ns INTEGER,
                timeout_ns INTEGER NOT NULL,
                retry_count INTEGER NOT NULL DEFAULT 0,
                max_retries INTEGER NOT NULL DEFAULT 0,
                priority INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL,
                result_hash TEXT,
                error_message TEXT,
                created_ns INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_exec_contract ON execution_history(contract_id);
            CREATE INDEX IF NOT EXISTS idx_exec_trace ON execution_history(trace_id);
            CREATE INDEX IF NOT EXISTS idx_exec_status ON execution_history(status);
            CREATE INDEX IF NOT EXISTS idx_exec_created ON execution_history(created_ns);

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

            CREATE INDEX IF NOT EXISTS idx_events_exec ON execution_events(execution_id);
            CREATE INDEX IF NOT EXISTS idx_events_trace ON execution_events(trace_id);
            CREATE INDEX IF NOT EXISTS idx_events_contract ON execution_events(contract_id);
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON execution_events(timestamp_ns);

            CREATE TABLE IF NOT EXISTS node_history (
                node_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                display_name TEXT,
                mesh_name TEXT,
                role TEXT,
                tags TEXT,
                platform TEXT,
                arch TEXT,
                version TEXT,
                last_seen INTEGER,
                ping_misses INTEGER,
                rtt_ms REAL,
                PRIMARY KEY (node_id, sequence)
            );

            CREATE TABLE IF NOT EXISTS policy_history (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                policy_name TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                details TEXT,
                timestamp_ns INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_policy_name ON policy_history(policy_name);
            CREATE INDEX IF NOT EXISTS idx_policy_actor ON policy_history(actor_id);
            CREATE INDEX IF NOT EXISTS idx_policy_timestamp ON policy_history(timestamp_ns);

            CREATE TABLE IF NOT EXISTS mesh_history (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
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

        char* err = nullptr;
        int rc = sqlite3_exec(db, schema, nullptr, nullptr, &err);
        if (rc != SQLITE_OK) {
            std::string msg = err ? err : "unknown";
            sqlite3_free(err);
            return SMO_ERR_STORAGE(900, Critical, NoRetry, RebootNode, msg);
        }

        return {};
    }

    void close() {
        if (db) {
            sqlite3_close(db);
            db = nullptr;
        }
    }

    // Helper to execute prepared statements
    template<typename Func>
    Result<void> execute_query(const std::string& sql, Func&& func) {
        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            return SMO_ERR_STORAGE(905, Error, RetrySafe, RetryOperation, sqlite3_errmsg(db));
        }

        while (true) {
            int rc = sqlite3_step(stmt);
            if (rc == SQLITE_DONE) break;
            if (rc != SQLITE_ROW) {
                sqlite3_finalize(stmt);
                return SMO_ERR_STORAGE(905, Error, RetrySafe, RetryOperation, sqlite3_errmsg(db));
            }
            func(stmt);
        }
        sqlite3_finalize(stmt);
        return {};
    }
};

HistoryService::HistoryService(const Config& config) : impl_(std::make_unique<Impl>(config)) {}

HistoryService::~HistoryService() = default;

HistoryService::HistoryService(HistoryService&&) noexcept = default;
HistoryService& HistoryService::operator=(HistoryService&&) noexcept = default;

Result<void> HistoryService::open() {
    return impl_->open();
}

void HistoryService::close() {
    impl_->close();
}

Result<std::vector<ContractHistoryEntry>> HistoryService::get_contract_history(
    const std::string& contract_id, uint64_t limit, uint64_t offset) const {
    return std::vector<ContractHistoryEntry>{};
}

Result<ContractHistoryEntry> HistoryService::get_contract(const std::string& contract_id) const {
    return ContractHistoryEntry{};
}

Result<std::vector<ExecutionHistoryEntry>> HistoryService::get_execution_history(
    const std::string& execution_id) const {
    return std::vector<ExecutionHistoryEntry>{};
}

Result<std::vector<ExecutionHistoryEntry>> HistoryService::get_contract_executions(
    const std::string& contract_id, uint64_t limit, uint64_t offset) const {
    return std::vector<ExecutionHistoryEntry>{};
}

Result<std::vector<ExecutionHistoryEntry>> HistoryService::get_node_executions(
    const std::string& node_id, uint64_t limit, uint64_t offset) const {
    return std::vector<ExecutionHistoryEntry>{};
}

Result<std::vector<ExecutionHistoryEntry>> HistoryService::get_failed_executions(
    int64_t from_ns, int64_t to_ns, uint64_t limit) const {
    return std::vector<ExecutionHistoryEntry>{};
}

Result<std::vector<ExecutionEventEntry>> HistoryService::get_execution_events(
    const std::string& execution_id) const {
    return std::vector<ExecutionEventEntry>{};
}

Result<std::vector<ExecutionEventEntry>> HistoryService::get_trace_events(
    const std::string& trace_id) const {
    return std::vector<ExecutionEventEntry>{};
}

Result<std::vector<NodeHistoryEntry>> HistoryService::get_node_history(
    const std::string& node_id, uint64_t limit) const {
    return std::vector<NodeHistoryEntry>{};
}

Result<std::vector<NodeHistoryEntry>> HistoryService::get_mesh_nodes(
    const std::string& mesh_id, uint64_t limit) const {
    return std::vector<NodeHistoryEntry>{};
}

Result<std::vector<PolicyHistoryEntry>> HistoryService::get_policy_history(
    const std::string& policy_name, uint64_t limit) const {
    return std::vector<PolicyHistoryEntry>{};
}

Result<std::vector<MeshHistoryEntry>> HistoryService::get_mesh_history(
    const std::string& mesh_id, uint64_t limit) const {
    return std::vector<MeshHistoryEntry>{};
}

Result<std::vector<ExecutionHistoryEntry>> HistoryService::query_executions(
    const std::optional<std::string>& contract_id,
    const std::optional<std::string>& node_id,
    const std::optional<std::string>& status,
    const std::optional<int64_t>& from_ns,
    const std::optional<int64_t>& to_ns,
    uint64_t limit, uint64_t offset) const {
    return std::vector<ExecutionHistoryEntry>{};
}

Result<std::vector<ExecutionEventEntry>> HistoryService::query_events(
    const std::optional<std::string>& execution_id,
    const std::optional<std::string>& trace_id,
    const std::optional<std::string>& event_type,
    const std::optional<int64_t>& from_ns,
    const std::optional<int64_t>& to_ns,
    uint64_t limit, uint64_t offset) const {
    return std::vector<ExecutionEventEntry>{};
}

Result<std::vector<ExecutionHistoryEntry>> HistoryService::get_trace_executions(
    const std::string& trace_id) const {
    return std::vector<ExecutionHistoryEntry>{};
}

Result<std::vector<ExecutionEventEntry>> HistoryService::get_trace_events(
    const std::string& trace_id) const {
    return std::vector<ExecutionEventEntry>{};
}

} // namespace smo