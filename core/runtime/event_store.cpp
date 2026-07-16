#include "event_store.hpp"

#include <sqlite3.h>
#include <chrono>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <vector>
#include <string>
#include <cstring>
#include <iomanip>
#include <sstream>

namespace smo {

// ===========================================================================
// EventStore Implementation
// ===========================================================================

struct EventStore::Impl {
    sqlite3* db = nullptr;
    std::string db_path;
    Config config;
    std::string last_prev_hash;
    uint64_t sequence_counter = 0;
    
    Impl(const Config& cfg) : config(cfg) {}
    
    ~Impl() {
        close();
    }
    
    Result<void> open() {
        std::filesystem::path dir = std::filesystem::path(config.db_path).parent_path();
        if (!std::filesystem::exists(dir)) {
            std::filesystem::create_directories(dir);
        }
        
        int rc = sqlite3_open_v2(config.db_path.c_str(), &db,
                                 SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                                 nullptr);
        if (rc != SQLITE_OK) {
            return SMO_ERR_STORAGE(900, Error, NoRetry, RebootNode,
                                  "Failed to open database: " + std::string(sqlite3_errmsg(db)));
        }
        
        // Enable WAL mode
        if (config.enable_wal) {
            char* err = nullptr;
            int rc = sqlite3_exec(db, "PRAGMA journal_mode = WAL;", nullptr, nullptr, nullptr);
            if (rc != SQLITE_OK) {
                std::string msg = sqlite3_errmsg(db);
                sqlite3_close(db);
                return SMO_ERR_STORAGE(900, Critical, NoRetry, RebootNode, msg);
            }
        }
        
        // Busy timeout
        sqlite3_busy_timeout(db, 5000);
        
        // Create schema
        const char* schema = R"(
            CREATE TABLE IF NOT EXISTS events (
                sequence INTEGER PRIMARY KEY,
                type INTEGER NOT NULL,
                timestamp_ns INTEGER NOT NULL,
                contract_id TEXT NOT NULL,
                execution_id TEXT NOT NULL,
                trace_id TEXT NOT NULL,
                node_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                payload TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL,
                signature TEXT NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000000000)
            );
            
            CREATE INDEX IF NOT EXISTS idx_events_execution ON events(execution_id);
            CREATE INDEX IF NOT EXISTS idx_events_trace ON events(trace_id);
            CREATE INDEX IF NOT EXISTS idx_events_contract ON events(contract_id);
            CREATE INDEX IF NOT EXISTS idx_events_node ON events(node_id);
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp_ns);
            
            CREATE TABLE IF NOT EXISTS executions (
                execution_id TEXT PRIMARY KEY,
                contract_id TEXT NOT NULL,
                trace_id TEXT NOT NULL,
                requester_id TEXT NOT NULL,
                responder_id TEXT NOT NULL,
                witness_ids TEXT NOT NULL,       -- JSON array
                selected_nodes TEXT NOT NULL,     -- JSON array
                intent_hash TEXT NOT NULL,
                policy_name TEXT NOT NULL,
                control_level INTEGER NOT NULL DEFAULT 0,
                scope INTEGER NOT NULL DEFAULT 0,
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
                created_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000000000)
            );
            
            CREATE INDEX IF NOT EXISTS idx_executions_contract ON executions(contract_id);
            CREATE INDEX IF NOT EXISTS idx_executions_trace ON executions(trace_id);
            CREATE INDEX IF NOT EXISTS idx_executions_status ON executions(status);
            CREATE INDEX IF NOT EXISTS idx_executions_created ON executions(created_ns);
            
            CREATE TABLE IF NOT EXISTS traces (
                trace_id TEXT PRIMARY KEY,
                workflow_id TEXT,
                created_ns INTEGER NOT NULL,
                completed_ns INTEGER,
                status TEXT NOT NULL,
                execution_count INTEGER NOT NULL DEFAULT 0
            );
        )";
        
        char* err = nullptr;
        int rc = sqlite3_exec(db, schema, nullptr, nullptr, nullptr);
        if (rc != SQLITE_OK) {
            std::string msg = sqlite3_errmsg(db);
            sqlite3_close(db);
            return SMO_ERR_STORAGE(900, Critical, NoRetry, RebootNode, msg);
        }
        
        // Get last sequence number
        sqlite3_stmt* stmt;
        int rc2 = sqlite3_prepare_v2(db, "SELECT MAX(sequence) FROM events", -1, &stmt, nullptr);
        if (rc2 == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                sequence_counter = sqlite3_column_int64(stmt, 0);
            }
            sqlite3_finalize(stmt);
        }
        
        // Get last event hash for chaining
        int rc3 = sqlite3_prepare_v2(db, "SELECT event_hash FROM events ORDER BY sequence DESC LIMIT 1", -1, &stmt, nullptr);
        if (rc3 == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                const unsigned char* hash = sqlite3_column_text(stmt, 0);
                if (hash) last_prev_hash = reinterpret_cast<const char*>(hash);
            }
            sqlite3_finalize(stmt);
        }
        
        return {};
    }
    
    void close() {
        if (db) {
            sqlite3_close(db);
            db = nullptr;
        }
    }
    
    std::string compute_event_hash(const EventRecord& event) {
        std::stringstream ss;
        ss << event.sequence << event.type << event.timestamp_ns
           << event.contract_id << event.execution_id << event.trace_id
           << event.node_id << event.actor_id << event.payload
           << event.prev_hash;
        std::string data = ss.str();
        
        std::array<uint8_t, 32> hash;
        blake3_hasher hasher;
        blake3_hasher_init(&hasher);
        blake3_hasher_update(&hasher, data.c_str(), data.size());
        blake3_hasher_finalize(&hasher, hash.data(), 32);
        
        std::stringstream ss;
        for (uint8_t b : hash) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        }
        return ss.str();
    }
    
    Result<void> execute(const char* sql) {
        char* err = nullptr;
        int rc = sqlite3_exec(db, sql, nullptr, nullptr, nullptr);
        if (rc != SQLITE_OK) {
            std::string msg = sqlite3_errmsg(db);
            sqlite3_free(err);
            return SMO_ERR_STORAGE(904, Error, RetrySafe, RetryOperation, msg);
        }
        return {};
    }
    
    Result<sqlite3_stmt*> prepare(const char* sql) {
        sqlite3_stmt* stmt = nullptr;
        int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            return SMO_ERR_STORAGE(905, Error, RetrySafe, RetryOperation,
                                   sqlite3_errmsg(db));
        }
        return Statement(db, stmt);
    }
};

// ===========================================================================
// EventStore Implementation
// ===========================================================================

EventStore::EventStore(const Config& config) : impl_(std::make_unique<Impl>(config)) {}

EventStore::~EventStore() = default;

EventStore::EventStore(EventStore&& other) noexcept = default;
EventStore& EventStore::operator=(EventStore&& other) noexcept = default;

Result<void> EventStore::open() {
    return impl_->open();
}

void EventStore::close() {
    impl_->close();
}

Result<uint64_t> EventStore::append(const EventRecord& event) {
    EventRecord e = event;
    e.sequence = ++impl_->sequence_counter;
    e.timestamp_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    e.prev_hash = impl_->last_prev_hash;
    e.event_hash = impl_->compute_event_hash(e);
    
    // Sign the event hash (placeholder - would use actual signing)
    e.signature = "sig_placeholder";
    
    auto stmt = impl_->prepare(
        "INSERT INTO events (sequence, type, timestamp_ns, contract_id, execution_id, "
        "trace_id, node_id, actor_id, payload, prev_hash, event_hash, signature) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    );
    if (!stmt) return stmt.error();
    
    int idx = 1;
    sqlite3_bind_int64(stmt.value().handle(), 1, e.sequence);
    sqlite3_bind_int(stmt.value().handle(), 2, static_cast<int>(e.type));
    sqlite3_bind_int64(stmt.value().handle(), 3, e.timestamp_ns);
    sqlite3_bind_text(stmt.value().handle(), 4, e.contract_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.value().handle(), 4, e.execution_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.value().handle(), 5, e.trace_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.value().handle(), 6, e.node_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.value().handle(), 7, e.actor_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.value().handle(), 8, e.payload.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.value().handle(), 9, e.prev_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.value().handle(), 10, e.event_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.value().handle(), 11, e.signature.c_str(), -1, SQLITE_TRANSIENT);
    
    int rc = sqlite3_step(stmt.value().handle());
    if (rc != SQLITE_DONE) {
        return SMO_ERR_STORAGE(904, Error, RetrySafe, RetryOperation,
                              "Failed to insert event");
    }
    
    impl_->last_prev_hash = e.event_hash;
    return e.sequence;
}

Result<std::vector<EventRecord>> EventStore::query_by_execution(const std::string& execution_id) const {
    auto stmt = impl_->prepare(
        "SELECT sequence, type, timestamp_ns, contract_id, execution_id, trace_id, "
        "node_id, actor_id, payload, prev_hash, event_hash, signature "
        "FROM events WHERE execution_id = ? ORDER BY sequence"
    );
    if (!stmt) return stmt.error();
    
    sqlite3_bind_text(stmt.value().handle(), 1, execution_id.c_str(), -1, SQLITE_TRANSIENT);
    
    std::vector<EventRecord> results;
    while (true) {
        int rc = sqlite3_step(stmt.value().handle());
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            return SMO_ERR_STORAGE(904, Error, RetrySafe, RetryOperation, "Query failed");
        }
        
        EventRecord rec;
        rec.sequence = sqlite3_column_int64(stmt.value().handle(), 0);
        rec.type = static_cast<EventType>(sqlite3_column_int(stmt.value().handle(), 1));
        rec.timestamp_ns = sqlite3_column_int64(stmt.value().handle(), 2);
        rec.contract_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt.value().handle(), 3));
        rec.execution_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt.value().handle(), 4));
        rec.trace_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt.value().handle(), 5));
        rec.node_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt.value().handle(), 6));
        rec.actor_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt.value().handle(), 7));
        rec.payload = reinterpret_cast<const char*>(sqlite3_column_text(stmt.value().handle(), 8));
        rec.prev_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt.value().handle(), 8));
        rec.event_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt.value().handle(), 9));
        rec.signature = reinterpret_cast<const char*>(sqlite3_column_text(stmt.value().handle(), 10));
        
        results.push_back(std::move(rec));
    }
    
    return results;
}

// Additional query methods would be implemented similarly...

Result<void> EventStore::upsert_execution(const ExecutionRecord& record) {
    auto stmt = impl_->prepare(
        "INSERT OR REPLACE INTO executions "
        "(execution_id, contract_id, trace_id, requester_id, responder_id, "
        "witness_ids, selected_nodes, intent_hash, policy_name, control_level, "
        "scope, created_ns, started_ns, completed_ns, timeout_ns, "
        "retry_count, max_retries, priority, status, result_hash, error_message) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    );
    if (!stmt) return stmt.error();
    
    int idx = 1;
    sqlite3_bind_text(stmt.value().handle(), 1, record.execution_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.value().handle(), 2, record.contract_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.value().handle(), 3, record.trace_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.value().handle(), 4, record.requester_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.value().handle(), 5, record.responder_id.c_str(), -1, SQLITE_TRANSIENT);
    
    // Serialize witness_ids and selected_nodes as JSON
    // Simplified for now
    sqlite3_bind_text(stmt.value().handle(), 6, "[]", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.value().handle(), 7, "[]", -1, SQLITE_TRANSIENT);
    
    sqlite3_bind_text(stmt.value().handle(), 8, record.intent_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.value().handle(), 9, record.policy_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt.value().handle(), 10, record.control_level);
    sqlite3_bind_int(stmt.value().handle(), 11, record.scope);
    sqlite3_bind_int64(stmt.value().handle(), 12, record.created_ns);
    sqlite3_bind_int64(stmt.value().handle(), 13, record.started_ns);
    sqlite3_bind_int64(stmt.value().handle(), 14, record.completed_ns);
    sqlite3_bind_int64(stmt.value().handle(), 15, record.timeout_ns);
    sqlite3_bind_int(stmt.value().handle(), 16, record.retry_count);
    sqlite3_bind_int(stmt.value().handle(), 17, record.max_retries);
    sqlite3_bind_int(stmt.value().handle(), 18, record.priority);
    sqlite3_bind_text(stmt.value().handle(), 19, record.status.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.value().handle(), 20, record.result_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.value().handle(), 20, record.error_message.c_str(), -1, SQLITE_TRANSIENT);
    
    int rc = sqlite3_step(stmt.value().handle());
    if (rc != SQLITE_DONE) {
        return SMO_ERR_STORAGE(904, Error, RetrySafe, RetryOperation, "Failed to upsert execution");
    }
    return {};
}

Result<ExecutionRecord> EventStore::get_execution(const std::string& execution_id) const {
    auto stmt = impl_->prepare(
        "SELECT execution_id, contract_id, trace_id, requester_id, responder_id, "
        "witness_ids, selected_nodes, intent_hash, policy_name, control_level, "
        "scope, created_ns, started_ns, completed_ns, timeout_ns, "
        "retry_count, max_retries, priority, status, result_hash, error_message "
        "FROM executions WHERE execution_id = ?"
    );
    if (!stmt) return stmt.error();
    
    sqlite3_bind_text(stmt.value().handle(), 1, execution_id.c_str(), -1, SQLITE_TRANSIENT);
    
    int rc = sqlite3_step(stmt.value().handle());
    if (rc != SQLITE_ROW) {
        return SMO_ERR_STORAGE(902, Info, RetrySafe, None, "Execution not found");
    }
    
    ExecutionRecord record;
    record.execution_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt.value().handle(), 0));
    record.contract_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt.value().handle(), 1));
    record.trace_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt.value().handle(), 2));
    record.requester_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt.value().handle(), 3));
    record.responder_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt.value().handle(), 4));
    // Simplified - would need JSON parsing for arrays
    record.intent_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt.value().handle(), 7));
    record.policy_name = reinterpret_cast<const char*>(sqlite3_column_text(stmt.value().handle(), 8));
    record.control_level = sqlite3_column_int(stmt.value().handle(), 9);
    record.scope = sqlite3_column_int(stmt.value().handle(), 10);
    record.created_ns = sqlite3_column_int64(stmt.value().handle(), 11);
    record.started_ns = sqlite3_column_int64(stmt.value().handle(), 12);
    record.completed_ns = sqlite3_column_int64(stmt.value().handle(), 13);
    record.timeout_ns = sqlite3_column_int64(stmt.value().handle(), 14);
    record.retry_count = sqlite3_column_int(stmt.value().handle(), 15);
    record.max_retries = sqlite3_column_int(stmt.value().handle(), 16);
    record.priority = sqlite3_column_int(stmt.value().handle(), 17);
    record.status = reinterpret_cast<const char*>(sqlite3_column_text(stmt.value().handle(), 18));
    record.result_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt.value().handle(), 19));
    record.error_message = reinterpret_cast<const char*>(sqlite3_column_text(stmt.value().handle(), 20));
    
    return record;
}

// ... Additional methods would be implemented similarly ...

Result<void> EventStore::vacuum() {
    return impl_->execute("VACUUM;");
}

Result<size_t> EventStore::count_events() const {
    auto stmt = impl_->prepare("SELECT COUNT(*) FROM events");
    if (!stmt) return stmt.error();
    
    int rc = sqlite3_step(stmt.value().handle());
    if (rc == SQLITE_ROW) {
        return static_cast<size_t>(sqlite3_column_int64(stmt.value().handle(), 0));
    }
    return 0;
}

Result<size_t> EventStore::count_executions() const {
    auto stmt = impl_->prepare("SELECT COUNT(*) FROM executions");
    if (!stmt) return stmt.error();
    
    int rc = sqlite3_step(stmt.value().handle());
    if (rc == SQLITE_ROW) {
        return static_cast<size_t>(sqlite3_column_int64(stmt.value().handle(), 0));
    }
    return 0;
}

Result<size_t> EventStore::db_size_bytes() const {
    auto stmt = impl_->prepare("SELECT page_count * page_size FROM pragma_page_count, pragma_page_size");
    if (!stmt) return stmt.error();
    
    int rc = sqlite3_step(stmt.value().handle());
    if (rc == SQLITE_ROW) {
        return static_cast<size_t>(sqlite3_column_int64(stmt.value().handle(), 0));
    }
    return 0;
}

} // namespace smo