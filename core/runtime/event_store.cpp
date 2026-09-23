#include "event_store.hpp"

#include <sqlite3.h>
#include <blake3.h>
#include <chrono>
#include <filesystem>
#include <memory>
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>

namespace smo {

struct EventStore::Impl
{
    sqlite3* db = nullptr;
    Config config;
    std::string last_hash;
    uint64_t sequence_counter = 0;
    uint64_t execution_sequence_counter = 0;

    Impl(const Config& cfg) : config(cfg) {}

    ~Impl() { close(); }

    Result<void> open()
    {
        namespace fs = std::filesystem;
        fs::path dir(config.db_path);
        fs::path dir_path = dir.parent_path();
        if (!dir_path.empty())
        {
            std::error_code ec;
            fs::create_directories(dir_path, ec);
        }

        int rc = sqlite3_open(config.db_path.c_str(), &db);
        if (rc != SQLITE_OK)
        {
            return SMO_ERR_STORAGE(900, Critical, NoRetry, RebootNode,
                                   "Failed to open event store DB: " + std::string(sqlite3_errmsg(db)));
        }

        if (config.enable_wal)
        {
            char* err = nullptr;
            rc = sqlite3_exec(db, "PRAGMA journal_mode = WAL;", nullptr, nullptr, &err);
            if (rc != SQLITE_OK)
            {
                std::string msg = err ? err : "unknown";
                sqlite3_free(err);
                sqlite3_close(db);
                return SMO_ERR_STORAGE(900, Critical, NoRetry, RebootNode, msg);
            }
        }

        sqlite3_busy_timeout(db, 5000);

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
            witness_ids TEXT NOT NULL,
            selected_nodes TEXT NOT NULL,
            intent_hash TEXT NOT NULL,
            policy_name TEXT NOT NULL,
            control_level INTEGER NOT NULL,
            scope INTEGER NOT NULL,
            created_ns INTEGER NOT NULL,
            started_ns INTEGER NOT NULL,
            completed_ns INTEGER NOT NULL,
            timeout_ns INTEGER NOT NULL,
            retry_count INTEGER NOT NULL,
            max_retries INTEGER NOT NULL,
            priority INTEGER NOT NULL,
            status TEXT NOT NULL,
            result_hash TEXT NOT NULL,
            error_message TEXT NOT NULL,
            updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000000000)
        );
        CREATE INDEX IF NOT EXISTS idx_executions_contract ON executions(contract_id);
        CREATE INDEX IF NOT EXISTS idx_executions_trace ON executions(trace_id);
        CREATE INDEX IF NOT EXISTS idx_executions_status ON executions(status);
        CREATE INDEX IF NOT EXISTS idx_executions_created ON executions(created_ns);
        )";

        char* err = nullptr;
        rc = sqlite3_exec(db, schema, nullptr, nullptr, &err);
        if (rc != SQLITE_OK)
        {
            std::string msg = err ? err : "unknown";
            sqlite3_free(err);
            return SMO_ERR_STORAGE(900, Critical, NoRetry, RebootNode, msg);
        }

        sqlite3_stmt* stmt;
        rc = sqlite3_prepare_v2(db, "SELECT MAX(sequence) FROM events", -1, &stmt, nullptr);
        if (rc == SQLITE_OK)
        {
            if (sqlite3_step(stmt) == SQLITE_ROW)
            {
                sequence_counter = sqlite3_column_int64(stmt, 0);
            }
            sqlite3_finalize(stmt);
        }

        rc = sqlite3_prepare_v2(db, "SELECT event_hash FROM events ORDER BY sequence DESC LIMIT 1", -1,
                                &stmt, nullptr);
        if (rc == SQLITE_OK)
        {
            if (sqlite3_step(stmt) == SQLITE_ROW)
            {
                const unsigned char* hash = sqlite3_column_text(stmt, 0);
                if (hash)
                    last_hash = reinterpret_cast<const char*>(hash);
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

    std::string compute_event_hash(const EventRecord& event)
    {
        std::stringstream ss;
        ss << event.sequence << static_cast<int>(event.type) << event.timestamp_ns
           << event.contract_id << event.execution_id << event.trace_id
           << event.node_id << event.actor_id << event.payload << event.prev_hash;
        std::string data = ss.str();

        std::array<uint8_t, 32> hash;
        blake3_hasher hasher;
        blake3_hasher_init(&hasher);
        blake3_hasher_update(&hasher, data.c_str(), data.size());
        blake3_hasher_finalize(&hasher, hash.data(), 32);

        std::stringstream hs;
        for (uint8_t b : hash)
        {
            hs << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        }
        return hs.str();
    }

    Result<std::vector<EventRecord>> exec_event_query(const std::string& base_sql,
                                                       const std::vector<std::pair<int, std::string>>& bindings,
                                                       uint64_t limit) const
    {
        std::string sql = base_sql + " ORDER BY sequence DESC LIMIT ?";
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
        sqlite3_bind_int64(stmt, idx, static_cast<int64_t>(limit));

        std::vector<EventRecord> results;
        while ((rc = sqlite3_step(stmt)) == SQLITE_ROW)
        {
            EventRecord record;
            record.sequence = sqlite3_column_int64(stmt, 0);
            record.type = static_cast<EventType>(sqlite3_column_int(stmt, 1));
            record.timestamp_ns = sqlite3_column_int64(stmt, 2);
            auto ctext = [](sqlite3_stmt* s, int c) -> std::string {
                auto p = sqlite3_column_text(s, c);
                return p ? reinterpret_cast<const char*>(p) : "";
            };
            record.contract_id = ctext(stmt, 3);
            record.execution_id = ctext(stmt, 4);
            record.trace_id = ctext(stmt, 5);
            record.node_id = ctext(stmt, 6);
            record.actor_id = ctext(stmt, 7);
            record.payload = ctext(stmt, 8);
            record.prev_hash = ctext(stmt, 9);
            record.event_hash = ctext(stmt, 10);
            record.signature = ctext(stmt, 11);
            results.push_back(std::move(record));
        }
        sqlite3_finalize(stmt);

        if (rc != SQLITE_DONE)
        {
            return SMO_ERR_STORAGE(904, Error, RetrySafe, RetryOperation,
                                   "Query failed: " + std::string(sqlite3_errmsg(db)));
        }

        std::reverse(results.begin(), results.end());
        return results;
    }

    Result<std::vector<ExecutionRecord>> exec_execution_query(const std::string& base_sql,
                                                              const std::vector<std::pair<int, std::string>>& bindings,
                                                              uint64_t limit) const
    {
        std::string sql = base_sql + " ORDER BY created_ns DESC LIMIT ?";
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
        sqlite3_bind_int64(stmt, idx, static_cast<int64_t>(limit));

        std::vector<ExecutionRecord> results;
        while ((rc = sqlite3_step(stmt)) == SQLITE_ROW)
        {
            ExecutionRecord record;
            auto ctext = [](sqlite3_stmt* s, int c) -> std::string {
                auto p = sqlite3_column_text(s, c);
                return p ? reinterpret_cast<const char*>(p) : "";
            };
            record.execution_id = ctext(stmt, 0);
            record.contract_id = ctext(stmt, 1);
            record.trace_id = ctext(stmt, 2);
            record.requester_id = ctext(stmt, 3);
            record.responder_id = ctext(stmt, 4);
            record.witness_ids = parse_string_list(ctext(stmt, 5));
            record.selected_nodes = parse_string_list(ctext(stmt, 6));
            record.intent_hash = ctext(stmt, 7);
            record.policy_name = ctext(stmt, 8);
            record.control_level = sqlite3_column_int(stmt, 9);
            record.scope = sqlite3_column_int(stmt, 10);
            record.created_ns = sqlite3_column_int64(stmt, 11);
            record.started_ns = sqlite3_column_int64(stmt, 12);
            record.completed_ns = sqlite3_column_int64(stmt, 13);
            record.timeout_ns = sqlite3_column_int64(stmt, 14);
            record.retry_count = sqlite3_column_int(stmt, 15);
            record.max_retries = sqlite3_column_int(stmt, 16);
            record.priority = sqlite3_column_int(stmt, 17);
            record.status = ctext(stmt, 18);
            record.result_hash = ctext(stmt, 19);
            record.error_message = ctext(stmt, 20);
            results.push_back(std::move(record));
        }
        sqlite3_finalize(stmt);

        if (rc != SQLITE_DONE)
        {
            return SMO_ERR_STORAGE(904, Error, RetrySafe, RetryOperation,
                                   "Query failed: " + std::string(sqlite3_errmsg(db)));
        }

        std::reverse(results.begin(), results.end());
        return results;
    }

    std::vector<std::string> parse_string_list(const std::string& csv) const
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

    std::string join_string_list(const std::vector<std::string>& list) const
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
};

EventStore::EventStore(const Config& config) : impl_(std::make_unique<Impl>(config)) {}
EventStore::~EventStore() = default;

Result<void> EventStore::open() { return impl_->open(); }
void EventStore::close() { impl_->close(); }

Result<uint64_t> EventStore::append(const EventRecord& event)
{
    EventRecord e = event;
    e.sequence = ++impl_->sequence_counter;
    e.timestamp_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    e.prev_hash = impl_->last_hash;
    e.event_hash = impl_->compute_event_hash(e);
    e.signature = "sig_placeholder";

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(impl_->db,
                                "INSERT INTO events "
                                "(sequence, type, timestamp_ns, contract_id, execution_id, trace_id, "
                                "node_id, actor_id, payload, prev_hash, event_hash, signature) "
                                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                -1, &stmt, nullptr);
    if (rc != SQLITE_OK)
    {
        return SMO_ERR_STORAGE(904, Error, RetrySafe, RetryOperation,
                               "Failed to prepare insert: " + std::string(sqlite3_errmsg(impl_->db)));
    }

    sqlite3_bind_int64(stmt, 1, e.sequence);
    sqlite3_bind_int(stmt, 2, static_cast<int>(e.type));
    sqlite3_bind_int64(stmt, 3, e.timestamp_ns);
    sqlite3_bind_text(stmt, 4, e.contract_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, e.execution_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, e.trace_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, e.node_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 8, e.actor_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 9, e.payload.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 10, e.prev_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 11, e.event_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 12, e.signature.c_str(), -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE)
    {
        return SMO_ERR_STORAGE(904, Error, RetrySafe, RetryOperation,
                               "Failed to insert event: " + std::string(sqlite3_errmsg(impl_->db)));
    }

    impl_->last_hash = e.event_hash;
    return e.sequence;
}

Result<std::vector<EventRecord>> EventStore::query_by_execution(const std::string& execution_id) const
{
    return impl_->exec_event_query("SELECT sequence, type, timestamp_ns, contract_id, execution_id, trace_id, "
                                   "node_id, actor_id, payload, prev_hash, event_hash, signature "
                                   "FROM events WHERE execution_id = ?",
                                   {{1, execution_id}}, 1000);
}

Result<std::vector<EventRecord>> EventStore::query_by_trace(const std::string& trace_id) const
{
    return impl_->exec_event_query("SELECT sequence, type, timestamp_ns, contract_id, execution_id, trace_id, "
                                   "node_id, actor_id, payload, prev_hash, event_hash, signature "
                                   "FROM events WHERE trace_id = ?",
                                   {{1, trace_id}}, 1000);
}

Result<std::vector<EventRecord>> EventStore::query_by_contract(const std::string& contract_id) const
{
    return impl_->exec_event_query("SELECT sequence, type, timestamp_ns, contract_id, execution_id, trace_id, "
                                   "node_id, actor_id, payload, prev_hash, event_hash, signature "
                                   "FROM events WHERE contract_id = ?",
                                   {{1, contract_id}}, 1000);
}

Result<std::vector<EventRecord>> EventStore::query_by_node(const std::string& node_id, uint64_t limit) const
{
    return impl_->exec_event_query("SELECT sequence, type, timestamp_ns, contract_id, execution_id, trace_id, "
                                   "node_id, actor_id, payload, prev_hash, event_hash, signature "
                                   "FROM events WHERE node_id = ?",
                                   {{1, node_id}}, limit);
}

Result<std::vector<EventRecord>> EventStore::query_range(int64_t from_ns, int64_t to_ns, uint64_t limit) const
{
    std::string sql = "SELECT sequence, type, timestamp_ns, contract_id, execution_id, trace_id, "
                      "node_id, actor_id, payload, prev_hash, event_hash, signature "
                      "FROM events WHERE timestamp_ns >= ? AND timestamp_ns <= ?";
    std::vector<std::pair<int, std::string>> bindings = {{1, std::to_string(from_ns)}, {2, std::to_string(to_ns)}};
    return impl_->exec_event_query(sql, bindings, limit);
}

Result<std::vector<EventRecord>> EventStore::query_latest(uint64_t count) const
{
    return impl_->exec_event_query("SELECT sequence, type, timestamp_ns, contract_id, execution_id, trace_id, "
                                   "node_id, actor_id, payload, prev_hash, event_hash, signature "
                                   "FROM events",
                                   {}, count);
}

Result<void> EventStore::upsert_execution(const ExecutionRecord& record)
{
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(impl_->db,
                                "INSERT OR REPLACE INTO executions "
                                "(execution_id, contract_id, trace_id, requester_id, responder_id, "
                                "witness_ids, selected_nodes, intent_hash, policy_name, control_level, scope, "
                                "created_ns, started_ns, completed_ns, timeout_ns, retry_count, max_retries, "
                                "priority, status, result_hash, error_message) "
                                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                -1, &stmt, nullptr);
    if (rc != SQLITE_OK)
    {
        return SMO_ERR_STORAGE(904, Error, RetrySafe, RetryOperation,
                               "Failed to prepare upsert: " + std::string(sqlite3_errmsg(impl_->db)));
    }

    sqlite3_bind_text(stmt, 1, record.execution_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, record.contract_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, record.trace_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, record.requester_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, record.responder_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, impl_->join_string_list(record.witness_ids).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, impl_->join_string_list(record.selected_nodes).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 8, record.intent_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 9, record.policy_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 10, record.control_level);
    sqlite3_bind_int(stmt, 11, record.scope);
    sqlite3_bind_int64(stmt, 12, record.created_ns);
    sqlite3_bind_int64(stmt, 13, record.started_ns);
    sqlite3_bind_int64(stmt, 14, record.completed_ns);
    sqlite3_bind_int64(stmt, 15, record.timeout_ns);
    sqlite3_bind_int(stmt, 16, record.retry_count);
    sqlite3_bind_int(stmt, 17, record.max_retries);
    sqlite3_bind_int(stmt, 18, record.priority);
    sqlite3_bind_text(stmt, 19, record.status.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 20, record.result_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 21, record.error_message.c_str(), -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE)
    {
        return SMO_ERR_STORAGE(904, Error, RetrySafe, RetryOperation,
                               "Failed to upsert execution: " + std::string(sqlite3_errmsg(impl_->db)));
    }

    return {};
}

Result<ExecutionRecord> EventStore::get_execution(const std::string& execution_id) const
{
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(impl_->db,
                                "SELECT execution_id, contract_id, trace_id, requester_id, responder_id, "
                                "witness_ids, selected_nodes, intent_hash, policy_name, control_level, scope, "
                                "created_ns, started_ns, completed_ns, timeout_ns, retry_count, max_retries, "
                                "priority, status, result_hash, error_message "
                                "FROM executions WHERE execution_id = ?",
                                -1, &stmt, nullptr);
    if (rc != SQLITE_OK)
    {
        return SMO_ERR_STORAGE(904, Error, RetrySafe, RetryOperation,
                               "Failed to prepare query: " + std::string(sqlite3_errmsg(impl_->db)));
    }

    sqlite3_bind_text(stmt, 1, execution_id.c_str(), -1, SQLITE_TRANSIENT);

    ExecutionRecord record;
    auto ctext = [](sqlite3_stmt* s, int c) -> std::string {
        auto p = sqlite3_column_text(s, c);
        return p ? reinterpret_cast<const char*>(p) : "";
    };

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW)
    {
        record.execution_id = ctext(stmt, 0);
        record.contract_id = ctext(stmt, 1);
        record.trace_id = ctext(stmt, 2);
        record.requester_id = ctext(stmt, 3);
        record.responder_id = ctext(stmt, 4);
        record.witness_ids = impl_->parse_string_list(ctext(stmt, 5));
        record.selected_nodes = impl_->parse_string_list(ctext(stmt, 6));
        record.intent_hash = ctext(stmt, 7);
        record.policy_name = ctext(stmt, 8);
        record.control_level = sqlite3_column_int(stmt, 9);
        record.scope = sqlite3_column_int(stmt, 10);
        record.created_ns = sqlite3_column_int64(stmt, 11);
        record.started_ns = sqlite3_column_int64(stmt, 12);
        record.completed_ns = sqlite3_column_int64(stmt, 13);
        record.timeout_ns = sqlite3_column_int64(stmt, 14);
        record.retry_count = sqlite3_column_int(stmt, 15);
        record.max_retries = sqlite3_column_int(stmt, 16);
        record.priority = sqlite3_column_int(stmt, 17);
        record.status = ctext(stmt, 18);
        record.result_hash = ctext(stmt, 19);
        record.error_message = ctext(stmt, 20);
    }
    else
    {
        sqlite3_finalize(stmt);
        return SMO_ERR_STORAGE(902, Info, RetrySafe, None, "Execution not found: " + execution_id);
    }
    sqlite3_finalize(stmt);

    return record;
}

Result<std::vector<ExecutionRecord>> EventStore::query_executions_by_contract(const std::string& contract_id) const
{
    return impl_->exec_execution_query(
        "SELECT execution_id, contract_id, trace_id, requester_id, responder_id, "
        "witness_ids, selected_nodes, intent_hash, policy_name, control_level, scope, "
        "created_ns, started_ns, completed_ns, timeout_ns, retry_count, max_retries, "
        "priority, status, result_hash, error_message "
        "FROM executions WHERE contract_id = ?",
        {{1, contract_id}}, 1000);
}

Result<std::vector<ExecutionRecord>> EventStore::query_executions_by_trace(const std::string& trace_id) const
{
    return impl_->exec_execution_query(
        "SELECT execution_id, contract_id, trace_id, requester_id, responder_id, "
        "witness_ids, selected_nodes, intent_hash, policy_name, control_level, scope, "
        "created_ns, started_ns, completed_ns, timeout_ns, retry_count, max_retries, "
        "priority, status, result_hash, error_message "
        "FROM executions WHERE trace_id = ?",
        {{1, trace_id}}, 1000);
}

Result<std::vector<ExecutionRecord>> EventStore::query_recent_executions(uint64_t limit) const
{
    return impl_->exec_execution_query(
        "SELECT execution_id, contract_id, trace_id, requester_id, responder_id, "
        "witness_ids, selected_nodes, intent_hash, policy_name, control_level, scope, "
        "created_ns, started_ns, completed_ns, timeout_ns, retry_count, max_retries, "
        "priority, status, result_hash, error_message "
        "FROM executions",
        {}, limit);
}

Bytes EventStore::serialize_event(const EventRecord& event)
{
    cbor::Encoder enc;
    enc.encode_map(12);
    cbor::encode_uint_key(enc, 1);
    enc.encode_uint(event.sequence);
    cbor::encode_uint_key(enc, 2);
    enc.encode_uint(static_cast<uint64_t>(event.type));
    cbor::encode_uint_key(enc, 3);
    enc.encode_uint(event.timestamp_ns);
    cbor::encode_uint_key(enc, 4);
    enc.encode_string(event.contract_id);
    cbor::encode_uint_key(enc, 5);
    enc.encode_string(event.execution_id);
    cbor::encode_uint_key(enc, 6);
    enc.encode_string(event.trace_id);
    cbor::encode_uint_key(enc, 7);
    enc.encode_string(event.node_id);
    cbor::encode_uint_key(enc, 8);
    enc.encode_string(event.actor_id);
    cbor::encode_uint_key(enc, 9);
    enc.encode_string(event.payload);
    cbor::encode_uint_key(enc, 10);
    enc.encode_string(event.prev_hash);
    cbor::encode_uint_key(enc, 11);
    enc.encode_string(event.event_hash);
    cbor::encode_uint_key(enc, 12);
    enc.encode_string(event.signature);
    return enc.take();
}

Result<EventRecord> EventStore::deserialize_event(BytesView data)
{
    cbor::Decoder dec(data);
    auto map_size = dec.decode_map_size();
    if (!map_size)
        return map_size.error();

    EventRecord event;
    for (size_t i = 0; i < map_size.value(); ++i)
    {
        auto key = dec.decode_uint();
        if (!key)
            return key.error();

        switch (key.value())
        {
            case 1:
                event.sequence = dec.decode_uint().value();
                break;
            case 2:
                event.type = static_cast<EventType>(dec.decode_uint().value());
                break;
            case 3:
                event.timestamp_ns = dec.decode_uint().value();
                break;
            case 4:
                event.contract_id = dec.decode_string().value();
                break;
            case 5:
                event.execution_id = dec.decode_string().value();
                break;
            case 6:
                event.trace_id = dec.decode_string().value();
                break;
            case 7:
                event.node_id = dec.decode_string().value();
                break;
            case 8:
                event.actor_id = dec.decode_string().value();
                break;
            case 9:
                event.payload = dec.decode_string().value();
                break;
            case 10:
                event.prev_hash = dec.decode_string().value();
                break;
            case 11:
                event.event_hash = dec.decode_string().value();
                break;
            case 12:
                event.signature = dec.decode_string().value();
                break;
            default:
                dec.skip();
                break;
        }
    }
    return event;
}

Bytes EventStore::serialize_execution(const ExecutionRecord& record)
{
    cbor::Encoder enc;
    enc.encode_map(20);
    cbor::encode_uint_key(enc, 1);
    enc.encode_string(record.execution_id);
    cbor::encode_uint_key(enc, 2);
    enc.encode_string(record.contract_id);
    cbor::encode_uint_key(enc, 3);
    enc.encode_string(record.trace_id);
    cbor::encode_uint_key(enc, 4);
    enc.encode_string(record.requester_id);
    cbor::encode_uint_key(enc, 5);
    enc.encode_string(record.responder_id);
    cbor::encode_uint_key(enc, 6);
    // witness_ids as array
    enc.encode_array(record.witness_ids.size());
    for (const auto& id : record.witness_ids)
        enc.encode_string(id);
    cbor::encode_uint_key(enc, 7);
    // selected_nodes as array
    enc.encode_array(record.selected_nodes.size());
    for (const auto& id : record.selected_nodes)
        enc.encode_string(id);
    cbor::encode_uint_key(enc, 8);
    enc.encode_string(record.intent_hash);
    cbor::encode_uint_key(enc, 9);
    enc.encode_string(record.policy_name);
    cbor::encode_uint_key(enc, 10);
    enc.encode_uint(record.control_level);
    cbor::encode_uint_key(enc, 11);
    enc.encode_uint(record.scope);
    cbor::encode_uint_key(enc, 12);
    enc.encode_uint(record.created_ns);
    cbor::encode_uint_key(enc, 13);
    enc.encode_uint(record.started_ns);
    cbor::encode_uint_key(enc, 14);
    enc.encode_uint(record.completed_ns);
    cbor::encode_uint_key(enc, 15);
    enc.encode_uint(record.timeout_ns);
    cbor::encode_uint_key(enc, 16);
    enc.encode_uint(record.retry_count);
    cbor::encode_uint_key(enc, 17);
    enc.encode_uint(record.max_retries);
    cbor::encode_uint_key(enc, 18);
    enc.encode_uint(record.priority);
    cbor::encode_uint_key(enc, 19);
    enc.encode_string(record.status);
    cbor::encode_uint_key(enc, 20);
    enc.encode_string(record.result_hash);
    cbor::encode_uint_key(enc, 21);
    enc.encode_string(record.error_message);
    return enc.take();
}

Result<ExecutionRecord> EventStore::deserialize_execution(BytesView data)
{
    cbor::Decoder dec(data);
    auto map_size = dec.decode_map_size();
    if (!map_size)
        return map_size.error();

    ExecutionRecord record;
    for (size_t i = 0; i < map_size.value(); ++i)
    {
        auto key = dec.decode_uint();
        if (!key)
            return key.error();

        switch (key.value())
        {
            case 1:
                record.execution_id = dec.decode_string().value();
                break;
            case 2:
                record.contract_id = dec.decode_string().value();
                break;
            case 3:
                record.trace_id = dec.decode_string().value();
                break;
            case 4:
                record.requester_id = dec.decode_string().value();
                break;
            case 5:
                record.responder_id = dec.decode_string().value();
                break;
            case 6: {
                auto arr_size = dec.decode_array_size();
                if (arr_size)
                {
                    for (size_t j = 0; j < arr_size.value(); ++j)
                        record.witness_ids.push_back(dec.decode_string().value());
                }
                break;
            }
            case 7: {
                auto arr_size = dec.decode_array_size();
                if (arr_size)
                {
                    for (size_t j = 0; j < arr_size.value(); ++j)
                        record.selected_nodes.push_back(dec.decode_string().value());
                }
                break;
            }
            case 8:
                record.intent_hash = dec.decode_string().value();
                break;
            case 9:
                record.policy_name = dec.decode_string().value();
                break;
            case 10:
                record.control_level = dec.decode_uint().value();
                break;
            case 11:
                record.scope = dec.decode_uint().value();
                break;
            case 12:
                record.created_ns = dec.decode_uint().value();
                break;
            case 13:
                record.started_ns = dec.decode_uint().value();
                break;
            case 14:
                record.completed_ns = dec.decode_uint().value();
                break;
            case 15:
                record.timeout_ns = dec.decode_uint().value();
                break;
            case 16:
                record.retry_count = dec.decode_uint().value();
                break;
            case 17:
                record.max_retries = dec.decode_uint().value();
                break;
            case 18:
                record.priority = dec.decode_uint().value();
                break;
            case 19:
                record.status = dec.decode_string().value();
                break;
            case 20:
                record.result_hash = dec.decode_string().value();
                break;
            case 21:
                record.error_message = dec.decode_string().value();
                break;
            default:
                dec.skip();
                break;
        }
    }
    return record;
}

Result<void> EventStore::vacuum()
{
    char* err = nullptr;
    int rc = sqlite3_exec(impl_->db, "VACUUM;", nullptr, nullptr, &err);
    if (rc != SQLITE_OK)
    {
        std::string msg = err ? err : "unknown";
        sqlite3_free(err);
        return SMO_ERR_STORAGE(904, Error, RetrySafe, RetryOperation, msg);
    }
    return {};
}

Result<size_t> EventStore::count_events() const
{
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(impl_->db, "SELECT COUNT(*) FROM events", -1, &stmt, nullptr);
    if (rc != SQLITE_OK)
        return size_t(0);
    size_t n = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        n = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    return n;
}

Result<size_t> EventStore::count_executions() const
{
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(impl_->db, "SELECT COUNT(*) FROM executions", -1, &stmt, nullptr);
    if (rc != SQLITE_OK)
        return size_t(0);
    size_t n = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        n = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    return n;
}

Result<size_t> EventStore::db_size_bytes() const
{
    namespace fs = std::filesystem;
    std::error_code ec;
    auto sz = fs::file_size(impl_->config.db_path, ec);
    if (ec)
        return size_t(0);
    return static_cast<size_t>(sz);
}

struct EventIterator : public EventStore::Iterator
{
    sqlite3_stmt* stmt_ = nullptr;

    explicit EventIterator(sqlite3_stmt* stmt) : stmt_(stmt) {}
    ~EventIterator() override { if (stmt_) sqlite3_finalize(stmt_); }

    bool next(EventRecord& out) override
    {
        if (!stmt_) return false;
        int rc = sqlite3_step(stmt_);
        if (rc != SQLITE_ROW) return false;

        out.sequence = sqlite3_column_int64(stmt_, 0);
        out.type = static_cast<EventType>(sqlite3_column_int(stmt_, 1));
        out.timestamp_ns = sqlite3_column_int64(stmt_, 2);
        auto ctext = [](sqlite3_stmt* s, int c) -> std::string {
            auto p = sqlite3_column_text(s, c);
            return p ? reinterpret_cast<const char*>(p) : "";
        };
        out.contract_id = ctext(stmt_, 3);
        out.execution_id = ctext(stmt_, 4);
        out.trace_id = ctext(stmt_, 5);
        out.node_id = ctext(stmt_, 6);
        out.actor_id = ctext(stmt_, 7);
        out.payload = ctext(stmt_, 8);
        out.prev_hash = ctext(stmt_, 9);
        out.event_hash = ctext(stmt_, 10);
        out.signature = ctext(stmt_, 11);
        return true;
    }
};

std::unique_ptr<EventStore::Iterator> EventStore::iterate_all()
{
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(impl_->db,
                                "SELECT sequence, type, timestamp_ns, contract_id, execution_id, trace_id, "
                                "node_id, actor_id, payload, prev_hash, event_hash, signature "
                                "FROM events ORDER BY sequence ASC",
                                -1, &stmt, nullptr);
    if (rc != SQLITE_OK)
        return nullptr;
    return std::make_unique<EventIterator>(stmt);
}

std::unique_ptr<EventStore::Iterator> EventStore::iterate_execution(const std::string& execution_id)
{
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(impl_->db,
                                "SELECT sequence, type, timestamp_ns, contract_id, execution_id, trace_id, "
                                "node_id, actor_id, payload, prev_hash, event_hash, signature "
                                "FROM events WHERE execution_id = ? ORDER BY sequence ASC",
                                -1, &stmt, nullptr);
    if (rc != SQLITE_OK)
        return nullptr;
    sqlite3_bind_text(stmt, 1, execution_id.c_str(), -1, SQLITE_TRANSIENT);
    return std::make_unique<EventIterator>(stmt);
}

} // namespace smo