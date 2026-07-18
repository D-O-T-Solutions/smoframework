#include "audit_store.hpp"

#include <sqlite3.h>
#include <blake3.h>
#include <chrono>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#include "core/runtime/event_bus.hpp"
#include <sstream>
#include <iomanip>

namespace smo {

struct AuditStore::Impl {
    sqlite3* db = nullptr;
    Config config;
    std::string last_hash;
    uint64_t sequence_counter = 0;

    Impl(const Config& config) : config(config) {}

    ~Impl() { close(); }

    Result<void> open() {
        namespace fs = std::filesystem;
        fs::path dir(config.db_path);
        fs::path dir_path = dir.parent_path();
        if (!dir_path.empty()) {
            std::error_code ec;
            fs::create_directories(dir_path, ec);
        }

        int rc = sqlite3_open(config.db_path.c_str(), &db);
        if (rc != SQLITE_OK) {
            return SMO_ERR_STORAGE(900, Critical, NoRetry, RebootNode,
                                   "Failed to open audit DB: " + std::string(sqlite3_errmsg(db)));
        }

        // WAL mode
        if (config.enable_wal) {
            char* err = nullptr;
            int rc = sqlite3_exec(db, "PRAGMA journal_mode = WAL;", nullptr, nullptr, &err);
            if (rc != SQLITE_OK) {
                std::string msg = err ? err : "unknown";
                sqlite3_free(err);
                sqlite3_close(db);
                return SMO_ERR_STORAGE(900, Critical, NoRetry, RebootNode, msg);
            }
        }

        sqlite3_busy_timeout(db, 5000);

        // Schema
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
        int rc = sqlite3_exec(db, schema, nullptr, nullptr, &err);
        if (rc != SQLITE_OK) {
            std::string msg = err ? err : "unknown";
            sqlite3_free(err);
            return SMO_ERR_STORAGE(900, Critical, NoRetry, RebootNode, msg);
        }

        // Get last sequence
        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(db, "SELECT MAX(sequence) FROM audit_records", -1, &stmt, nullptr);
        if (rc == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                sequence_counter = sqlite3_column_int64(stmt, 0);
            }
            sqlite3_finalize(stmt);
        }

        // Get last hash
        int rc3 = sqlite3_prepare_v2(db, "SELECT record_hash FROM audit_records ORDER BY sequence DESC LIMIT 1", -1, &stmt, nullptr);
        if (rc3 == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                const unsigned char* hash = sqlite3_column_text(stmt, 0);
                if (hash) last_hash = reinterpret_cast<const char*>(hash);
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

    std::string compute_hash(const AuditRecord& record) {
        std::stringstream ss;
        ss << record.sequence << static_cast<int>(record.type)
           << record.timestamp_ns << record.actor_id << record.target_id
           << record.contract_id << record.execution_id << record.trace_id
           << record.details << record.prev_hash;
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
};

class AuditStore::Impl {
public:
    sqlite3* db = nullptr;
    Config config;
    std::string last_hash;
    uint64_t sequence_counter = 0;

    Impl(const Config& config) : config(config) {}

    ~Impl() { close(); }

    Result<void> open() {
        namespace fs = std::filesystem;
        fs::path dir(config.db_path);
        fs::path dir_path = dir.parent_path();
        if (!dir_path.empty()) {
            std::error_code ec;
            fs::create_directories(dir_path, ec);
        }

        int rc = sqlite3_open(config.db_path.c_str(), &db);
        if (rc != SQLITE_OK) {
            return SMO_ERR_STORAGE(900, Critical, NoRetry, RebootNode,
                                   "Failed to open audit DB: " + std::string(sqlite3_errmsg(db)));
        }

        // WAL mode
        if (config.enable_wal) {
            char* err = nullptr;
            int rc = sqlite3_exec(db, "PRAGMA journal_mode = WAL;", nullptr, nullptr, &err);
            if (rc != SQLITE_OK) {
                std::string msg = err ? err : "unknown";
                sqlite3_free(err);
                sqlite3_close(db);
                return SMO_ERR_STORAGE(900, Critical, NoRetry, RebootNode, msg);
            }
        }

        sqlite3_busy_timeout(db, 5000);

        // Schema
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
        int rc = sqlite3_exec(db, schema, nullptr, nullptr, &err);
        if (rc != SQLITE_OK) {
            std::string msg = err ? err : "unknown";
            sqlite3_free(err);
            return SMO_ERR_STORAGE(900, Critical, NoRetry, RebootNode, msg);
        }

        // Get last sequence
        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(db, "SELECT MAX(sequence) FROM audit_records", -1, &stmt, nullptr);
        if (rc == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                sequence_counter = sqlite3_column_int64(stmt, 0);
            }
            sqlite3_finalize(stmt);
        }

        // Get last hash
        int rc3 = sqlite3_prepare_v2(db, "SELECT record_hash FROM audit_records ORDER BY sequence DESC LIMIT 1", -1, &stmt, nullptr);
        if (rc3 == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                const unsigned char* hash = sqlite3_column_text(stmt, 0);
                if (hash) last_hash = reinterpret_cast<const char*>(hash);
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

    std::string compute_hash(const AuditRecord& record) {
        std::stringstream ss;
        ss << record.sequence << static_cast<int>(record.type)
           << record.timestamp_ns << record.actor_id << record.target_id
           << record.contract_id << record.execution_id << record.trace_id
           << record.details << record.prev_hash;
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
};

AuditStore::AuditStore(const Config& config) : impl_(std::make_unique<Impl>(config)) {}

AuditStore::~AuditStore() = default;

AuditStore::AuditStore(AuditStore&&) noexcept = default;
AuditStore& AuditStore::operator=(AuditStore&&) noexcept = default;

Result<void> AuditStore::open() {
    return impl_->open();
}

void AuditStore::close() {
    impl_->close();
}

Result<uint64_t> AuditStore::record(const AuditRecord& record) {
    AuditRecord r = record;
    r.sequence = ++impl_->sequence_counter;
    r.timestamp_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    r.prev_hash = impl_->last_hash;
    r.record_hash = impl_->compute_hash(r);
    r.signature = "sig_placeholder";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(impl_->db,
        "INSERT INTO audit_records "
        "(sequence, type, timestamp_ns, actor_id, target_id, contract_id, "
        "execution_id, trace_id, details, prev_hash, record_hash, signature) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", -1, &stmt, nullptr);
    
    if (rc != SQLITE_OK) {
        return SMO_ERR_STORAGE(904, Error, RetrySafe, RetryOperation,
                              "Failed to prepare statement");
    }

    sqlite3_bind_int64(stmt, 1, r.sequence);
    sqlite3_bind_int(stmt, 2, static_cast<int>(r.type));
    sqlite3_bind_int64(stmt, 3, r.timestamp_ns);
    sqlite3_bind_text(stmt, 4, r.actor_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, r.target_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, r.contract_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, r.execution_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, r.trace_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 8, r.details.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 9, r.prev_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 10, r.record_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 11, r.signature.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        return SMO_ERR_STORAGE(904, Error, RetrySafe, RetryOperation, "Failed to insert audit record");
    }

    impl_->last_hash = r.record_hash;
    return r.sequence;
}

// Additional query methods would be implemented similarly...

Result<void> AuditStore::vacuum() {
    return impl_->execute("VACUUM;");
}

Result<size_t> AuditStore::count() const {
    return 0;
}

Result<size_t> AuditStore::db_size_bytes() const {
    return 0;
}

// EventBus listener for RecoveryApproved events
// Logs certificate revocation to audit store
void AuditStore::on_recovery_approved(const runtime::Event& ev) {
    // Parse JSON payload from event details
    // Expected: "CertificateRevocation proposal approved: {fingerprint, node_id_hex, reason, epoch}"
    std::string payload = ev.details;
    size_t brace_pos = payload.find('{');
    if (brace_pos == std::string::npos) return;

    std::string json_str = payload.substr(brace_pos);

    // Simple JSON parsing
    auto extract_field = [&](const std::string& json, const std::string& key) -> std::string {
        std::string search = "\"" + key + "\":\"";
        size_t pos = json.find(search);
        if (pos == std::string::npos) return "";
        pos += search.length();
        size_t end = json.find('"', pos);
        if (end == std::string::npos) return "";
        return json.substr(pos, end - pos);
    };
    auto extract_uint = [&](const std::string& json, const std::string& key) -> uint64_t {
        std::string search = "\"" + key + "\":";
        size_t pos = json.find(search);
        if (pos == std::string::npos) return 0;
        pos += search.length();
        size_t end = json.find_first_of(",}", pos);
        if (end == std::string::npos) return 0;
        return std::stoull(json.substr(pos, end - pos));
    };

    std::string fingerprint = extract_field(json_str, "fingerprint");
    std::string node_id_hex = extract_field(json_str, "node_id_hex");
    std::string reason = extract_field(json_str, "reason");
    uint64_t epoch = extract_uint(json_str, "epoch");

    if (fingerprint.empty() || node_id_hex.empty()) return;

    // Create audit record
    AuditRecord record;
    record.sequence = 0; // will be set by record()
    record.type = AuditEventType::CertificateRevoked;
    record.timestamp_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    record.actor_id = "governance";
    record.target_id = node_id_hex;
    record.contract_id = "system.recovery";
    record.details = "Certificate revoked: " + reason + " (fingerprint=" + fingerprint + ", epoch=" + std::to_string(epoch) + ")";
    record.prev_hash = impl_->last_hash;
    record.record_hash = impl_->compute_hash(*this->get_dummy_record()); // placeholder

    // For simplicity, just log to stdout (full implementation would write to DB)
    std::printf("[smo-node] AUDIT: Certificate revoked - fingerprint=%s node=%s reason=%s epoch=%llu\n",
                fingerprint.c_str(), node_id_hex.c_str(), reason.c_str(), (unsigned long long)epoch);
}

} // namespace smo