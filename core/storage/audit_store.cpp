#include "audit_store.hpp"

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

    struct AuditStore::Impl
    {
        sqlite3* db = nullptr;
        Config config;
        std::string last_hash;
        uint64_t sequence_counter = 0;

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
                                       "Failed to open audit DB: " + std::string(sqlite3_errmsg(db)));
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
            CREATE TABLE IF NOT EXISTS audit_records (
                sequence INTEGER PRIMARY KEY,
                type INTEGER NOT NULL,
                timestamp_ns INTEGER NOT NULL,
                actor_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                contract_id TEXT,
                execution_id TEXT,
                trace_id TEXT,
                details TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                record_hash TEXT NOT NULL,
                signature TEXT NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000000000)
            );
            CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_records(actor_id);
            CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_records(target_id);
            CREATE INDEX IF NOT EXISTS idx_audit_contract ON audit_records(contract_id);
            CREATE INDEX IF NOT EXISTS idx_audit_execution ON audit_records(execution_id);
            CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_records(type);
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_records(timestamp_ns);
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
            rc = sqlite3_prepare_v2(db, "SELECT MAX(sequence) FROM audit_records", -1, &stmt, nullptr);
            if (rc == SQLITE_OK)
            {
                if (sqlite3_step(stmt) == SQLITE_ROW)
                {
                    sequence_counter = sqlite3_column_int64(stmt, 0);
                }
                sqlite3_finalize(stmt);
            }

            rc = sqlite3_prepare_v2(db, "SELECT record_hash FROM audit_records ORDER BY sequence DESC LIMIT 1", -1,
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

        std::string compute_hash(const AuditRecord& record)
        {
            std::stringstream ss;
            ss << record.sequence << static_cast<int>(record.type) << record.timestamp_ns << record.actor_id
               << record.target_id << record.contract_id << record.execution_id << record.trace_id << record.details
               << record.prev_hash;
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

        Result<AuditQueryResult> exec_query(const AuditQuery& q) const
        {
            std::string sql = "SELECT sequence, type, timestamp_ns, actor_id, target_id, "
                              "contract_id, execution_id, trace_id, details, prev_hash, "
                              "record_hash, signature FROM audit_records WHERE 1=1";
            if (q.actor_id)
                sql += " AND actor_id = ?";
            if (q.target_id)
                sql += " AND target_id = ?";
            if (q.contract_id)
                sql += " AND contract_id = ?";
            if (q.execution_id)
                sql += " AND execution_id = ?";
            if (q.type)
                sql += " AND type = ?";
            if (q.from_ns)
                sql += " AND timestamp_ns >= ?";
            if (q.to_ns)
                sql += " AND timestamp_ns <= ?";
            sql += " ORDER BY sequence DESC LIMIT ? OFFSET ?";

            sqlite3_stmt* stmt;
            int rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
            if (rc != SQLITE_OK)
            {
                return SMO_ERR_STORAGE(904, Error, RetrySafe, RetryOperation,
                                       "Failed to prepare query: " + std::string(sqlite3_errmsg(db)));
            }

            int idx = 1;
            if (q.actor_id)
                sqlite3_bind_text(stmt, idx++, q.actor_id->c_str(), -1, SQLITE_TRANSIENT);
            if (q.target_id)
                sqlite3_bind_text(stmt, idx++, q.target_id->c_str(), -1, SQLITE_TRANSIENT);
            if (q.contract_id)
                sqlite3_bind_text(stmt, idx++, q.contract_id->c_str(), -1, SQLITE_TRANSIENT);
            if (q.execution_id)
                sqlite3_bind_text(stmt, idx++, q.execution_id->c_str(), -1, SQLITE_TRANSIENT);
            if (q.type)
                sqlite3_bind_int(stmt, idx++, static_cast<int>(*q.type));
            if (q.from_ns)
                sqlite3_bind_int64(stmt, idx++, *q.from_ns);
            if (q.to_ns)
                sqlite3_bind_int64(stmt, idx++, *q.to_ns);
            sqlite3_bind_int64(stmt, idx++, static_cast<int64_t>(q.limit));
            sqlite3_bind_int64(stmt, idx++, static_cast<int64_t>(q.offset));

            AuditQueryResult result;
            while ((rc = sqlite3_step(stmt)) == SQLITE_ROW)
            {
                int64_t seq = sqlite3_column_int64(stmt, 0);
                int typ = sqlite3_column_int(stmt, 1);
                int64_t ts = sqlite3_column_int64(stmt, 2);
                auto ctext = [](sqlite3_stmt* s, int c) -> std::string {
                    auto p = sqlite3_column_text(s, c);
                    return p ? reinterpret_cast<const char*>(p) : "";
                };
                std::string act = ctext(stmt, 3);
                std::string tgt = ctext(stmt, 4);
                std::string cid = ctext(stmt, 5);
                std::string eid = ctext(stmt, 6);
                std::string tid = ctext(stmt, 7);
                std::string det = ctext(stmt, 8);
                std::string phs = ctext(stmt, 9);
                std::string rhs = ctext(stmt, 10);
                std::string sig = ctext(stmt, 11);

                auto escape = [](const std::string& s) -> std::string {
                    std::string o;
                    o.reserve(s.size() + 4);
                    for (char c : s)
                    {
                        if (c == '"' || c == '\\')
                        {
                            o += '\\';
                            o += c;
                        }
                        else if (c == '\n')
                            o += "\\n";
                        else
                            o += c;
                    }
                    return o;
                };

                std::string js = R"({"sequence":)" + std::to_string(seq) + R"(,"type":)" + std::to_string(typ) +
                                 R"(,"timestamp_ns":)" + std::to_string(ts) + R"(,"actor_id":")" + escape(act) + '"' +
                                 R"(,"target_id":")" + escape(tgt) + '"' + R"(,"contract_id":")" + escape(cid) + '"' +
                                 R"(,"execution_id":")" + escape(eid) + '"' + R"(,"trace_id":")" + escape(tid) + '"' +
                                 R"(,"details":")" + escape(det) + '"' + R"(,"prev_hash":")" + escape(phs) + '"' +
                                 R"(,"record_hash":")" + escape(rhs) + '"' + R"(,"signature":")" + escape(sig) + "\"}";
                result.records.push_back(std::move(js));
            }
            sqlite3_finalize(stmt);

            if (rc != SQLITE_DONE)
            {
                return SMO_ERR_STORAGE(904, Error, RetrySafe, RetryOperation,
                                       "Query failed: " + std::string(sqlite3_errmsg(db)));
            }

            result.total_count = result.records.size();
            result.has_more = result.records.size() >= q.limit;
            return result;
        }
    };

    AuditStore::AuditStore() : AuditStore(Config{}) {}
    AuditStore::AuditStore(const Config& config) : impl_(std::make_unique<Impl>(config)) {}
    AuditStore::~AuditStore() = default;

    Result<void> AuditStore::open()
    {
        return impl_->open();
    }
    void AuditStore::close()
    {
        impl_->close();
    }

    Result<uint64_t> AuditStore::record(const AuditRecord& record)
    {
        AuditRecord r = record;
        r.sequence = ++impl_->sequence_counter;
        r.timestamp_ns =
            std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch())
                .count();
        r.prev_hash = impl_->last_hash;
        r.record_hash = impl_->compute_hash(r);
        r.signature = "sig_placeholder";

        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(impl_->db,
                                    "INSERT INTO audit_records "
                                    "(sequence, type, timestamp_ns, actor_id, target_id, contract_id, "
                                    "execution_id, trace_id, details, prev_hash, record_hash, signature) "
                                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                    -1, &stmt, nullptr);
        if (rc != SQLITE_OK)
        {
            return SMO_ERR_STORAGE(904, Error, RetrySafe, RetryOperation,
                                   "Failed to prepare insert: " + std::string(sqlite3_errmsg(impl_->db)));
        }

        sqlite3_bind_int64(stmt, 1, r.sequence);
        sqlite3_bind_int(stmt, 2, static_cast<int>(r.type));
        sqlite3_bind_int64(stmt, 3, r.timestamp_ns);
        sqlite3_bind_text(stmt, 4, r.actor_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, r.target_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 6, r.contract_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 7, r.execution_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 8, r.trace_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 9, r.details.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 10, r.prev_hash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 11, r.record_hash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 12, r.signature.c_str(), -1, SQLITE_TRANSIENT);

        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        if (rc != SQLITE_DONE)
        {
            return SMO_ERR_STORAGE(904, Error, RetrySafe, RetryOperation,
                                   "Failed to insert: " + std::string(sqlite3_errmsg(impl_->db)));
        }

        impl_->last_hash = r.record_hash;
        return r.sequence;
    }

    Result<AuditQueryResult> AuditStore::query(const AuditQuery& query) const
    {
        return impl_->exec_query(query);
    }

    Result<std::vector<std::string>> AuditStore::get_contract_history(const std::string& contract_id,
                                                                      uint64_t limit) const
    {
        AuditQuery q;
        q.contract_id = contract_id;
        q.limit = limit;
        auto r = impl_->exec_query(q);
        if (!r)
            return r.error();
        return std::move(r.value().records);
    }

    Result<std::vector<std::string>> AuditStore::get_execution_history(const std::string& execution_id) const
    {
        AuditQuery q;
        q.execution_id = execution_id;
        auto r = impl_->exec_query(q);
        if (!r)
            return r.error();
        return std::move(r.value().records);
    }

    Result<std::vector<std::string>> AuditStore::get_actor_history(const std::string& actor_id, uint64_t limit) const
    {
        AuditQuery q;
        q.actor_id = actor_id;
        q.limit = limit;
        auto r = impl_->exec_query(q);
        if (!r)
            return r.error();
        return std::move(r.value().records);
    }

    Result<std::vector<std::string>> AuditStore::get_timeline(int64_t from_ns, int64_t to_ns, uint64_t limit) const
    {
        AuditQuery q;
        q.from_ns = from_ns;
        q.to_ns = to_ns;
        q.limit = limit;
        auto r = impl_->exec_query(q);
        if (!r)
            return r.error();
        return std::move(r.value().records);
    }

    Result<void> AuditStore::vacuum()
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

    Result<size_t> AuditStore::count() const
    {
        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(impl_->db, "SELECT COUNT(*) FROM audit_records", -1, &stmt, nullptr);
        if (rc != SQLITE_OK)
            return size_t(0);
        size_t n = 0;
        if (sqlite3_step(stmt) == SQLITE_ROW)
            n = sqlite3_column_int64(stmt, 0);
        sqlite3_finalize(stmt);
        return n;
    }

    Result<size_t> AuditStore::db_size_bytes() const
    {
        namespace fs = std::filesystem;
        std::error_code ec;
        auto sz = fs::file_size(impl_->config.db_path, ec);
        if (ec)
            return size_t(0);
        return static_cast<size_t>(sz);
    }

    void AuditStore::on_recovery_approved(const runtime::Event& ev)
    {
        std::string payload = ev.details;
        size_t brace_pos = payload.find('{');
        if (brace_pos == std::string::npos)
            return;

        std::string json_str = payload.substr(brace_pos);

        auto extract_field = [&](const std::string& json, const std::string& key) -> std::string {
            std::string search = "\"" + key + "\":\"";
            size_t pos = json.find(search);
            if (pos == std::string::npos)
                return "";
            pos += search.length();
            size_t end = json.find('"', pos);
            if (end == std::string::npos)
                return "";
            return json.substr(pos, end - pos);
        };
        auto extract_uint = [&](const std::string& json, const std::string& key) -> uint64_t {
            std::string search = "\"" + key + "\":";
            size_t pos = json.find(search);
            if (pos == std::string::npos)
                return 0;
            pos += search.length();
            size_t end = json.find_first_of(",}", pos);
            if (end == std::string::npos)
                return 0;
            return std::stoull(json.substr(pos, end - pos));
        };

        std::string fingerprint = extract_field(json_str, "fingerprint");
        std::string node_id_hex = extract_field(json_str, "node_id_hex");
        std::string reason = extract_field(json_str, "reason");
        uint64_t epoch = extract_uint(json_str, "epoch");

        if (fingerprint.empty() || node_id_hex.empty())
            return;

        AuditRecord r;
        r.type = AuditEventType::CertificateRevoked;
        r.timestamp_ns =
            std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch())
                .count();
        r.actor_id = "governance";
        r.target_id = node_id_hex;
        r.contract_id = "system.recovery";
        r.details = "Certificate revoked: " + reason + " (fingerprint=" + fingerprint +
                    ", epoch=" + std::to_string(epoch) + ")";
        r.sequence = ++impl_->sequence_counter;
        r.prev_hash = impl_->last_hash;
        r.record_hash = impl_->compute_hash(r);
        r.signature = "sig_governance";

        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(impl_->db,
                                    "INSERT INTO audit_records "
                                    "(sequence, type, timestamp_ns, actor_id, target_id, contract_id, "
                                    "execution_id, trace_id, details, prev_hash, record_hash, signature) "
                                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                    -1, &stmt, nullptr);
        if (rc != SQLITE_OK)
        {
            std::printf("[smo-node] AUDIT: failed to record revocation: %s\n", sqlite3_errmsg(impl_->db));
            return;
        }

        sqlite3_bind_int64(stmt, 1, r.sequence);
        sqlite3_bind_int(stmt, 2, static_cast<int>(r.type));
        sqlite3_bind_int64(stmt, 3, r.timestamp_ns);
        sqlite3_bind_text(stmt, 4, r.actor_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, r.target_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 6, r.contract_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 7, "" /* execution_id */, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 8, "" /* trace_id */, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 9, r.details.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 10, r.prev_hash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 11, r.record_hash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 12, r.signature.c_str(), -1, SQLITE_TRANSIENT);

        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        if (rc == SQLITE_DONE)
        {
            impl_->last_hash = r.record_hash;
            std::printf("[smo-node] AUDIT: Certificate revoked recorded seq=%llu fingerprint=%s\n",
                        (unsigned long long)r.sequence, fingerprint.c_str());
        }
    }

} // namespace smo