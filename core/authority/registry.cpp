#include "registry.hpp"

#include <sqlite3.h>
#include <chrono>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <sstream>
#include <type_traits>

namespace smo::authority {

// ---------------------------------------------------------------------------
// Display Name Validation & Normalization
// ---------------------------------------------------------------------------

Result<void> validate_display_name(const std::string& name) noexcept {
    if (name.empty()) {
        return SMO_ERR_CERT(221, Warn, NoRetry, None,
                            "display name cannot be empty");
    }
    if (name.size() > 128) {
        return SMO_ERR_CERT(222, Warn, NoRetry, None,
                            "display name too long (max 128 chars)");
    }
    // Must start with alphanumeric
    if (!std::isalnum(static_cast<unsigned char>(name[0]))) {
        return SMO_ERR_CERT(221, Warn, NoRetry, None,
                            "display name must start with alphanumeric character");
    }
    // Allow alphanumeric, hyphen, underscore, dot
    for (char c : name) {
        if (!std::isalnum(static_cast<unsigned char>(c)) &&
            c != '-' && c != '_' && c != '.') {
            return SMO_ERR_CERT(221, Warn, NoRetry, None,
                                "display name contains invalid character: " + std::string(1, c));
        }
    }
    return {};
}

std::string normalize_display_name(const std::string& name) noexcept {
    std::string out;
    out.reserve(name.size());
    // Trim leading
    size_t start = 0;
    while (start < name.size() && std::isspace(static_cast<unsigned char>(name[start])))
        ++start;
    // Trim trailing
    size_t end = name.size();
    while (end > start && std::isspace(static_cast<unsigned char>(name[end - 1])))
        --end;
    // Lowercase
    for (size_t i = start; i < end; ++i) {
        out.push_back(static_cast<char>(
            std::tolower(static_cast<unsigned char>(name[i]))));
    }
    return out;
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

static const char kRegistrySchema[] = R"(
    CREATE TABLE IF NOT EXISTS nodes (
        node_id_hex TEXT PRIMARY KEY,
        display_name TEXT NOT NULL UNIQUE,
        mesh_id TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'Reader',
        cert_fingerprint TEXT DEFAULT '',
        status TEXT NOT NULL DEFAULT 'active',
        epoch INTEGER NOT NULL DEFAULT 0,
        enrolled_at INTEGER NOT NULL,
        last_seen INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS node_aliases (
        alias TEXT PRIMARY KEY,
        node_id_hex TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        FOREIGN KEY (node_id_hex) REFERENCES nodes(node_id_hex)
    );
    CREATE TABLE IF NOT EXISTS certificates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        node_id_hex TEXT NOT NULL,
        serial_number TEXT NOT NULL,
        cert_fingerprint TEXT UNIQUE NOT NULL,
        issuer_pubkey_hex TEXT NOT NULL,
        subject_pubkey_hex TEXT NOT NULL,
        role TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'active',
        epoch INTEGER NOT NULL DEFAULT 0,
        issued_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        revoked_at INTEGER NOT NULL DEFAULT 0,
        revocation_reason TEXT DEFAULT '',
        FOREIGN KEY (node_id_hex) REFERENCES nodes(node_id_hex)
    );
    CREATE TABLE IF NOT EXISTS enrollments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        node_id_hex TEXT NOT NULL,
        display_name TEXT NOT NULL,
        mesh_id TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'Reader',
        platform TEXT DEFAULT '',
        version TEXT DEFAULT '',
        timestamp INTEGER NOT NULL,
        csr_blob TEXT NOT NULL,
        submitted_at INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending'
    );
    CREATE TABLE IF NOT EXISTS revocations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        node_id_hex TEXT NOT NULL,
        reason TEXT NOT NULL,
        epoch INTEGER NOT NULL,
        timestamp INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_aliases_node ON node_aliases(node_id_hex);
    CREATE INDEX IF NOT EXISTS idx_certs_node ON certificates(node_id_hex);
    CREATE INDEX IF NOT EXISTS idx_certs_status ON certificates(status);
    CREATE INDEX IF NOT EXISTS idx_enrollments_status ON enrollments(status);
    CREATE INDEX IF NOT EXISTS idx_revocations_epoch ON revocations(epoch);
)";

// ---------------------------------------------------------------------------
// SQLite error → SMO error mapping
// ---------------------------------------------------------------------------

// Map SQLite error code. The template allows use with both Result<void> and Result<T>.
template <typename T = void>
static Result<T> map_sqlite_error(int rc, sqlite3* db, const char* context) {
    if (rc == SQLITE_OK || rc == SQLITE_DONE || rc == SQLITE_ROW) {
        if constexpr (std::is_void_v<T>) {
            return {};
        } else {
            return T{};
        }
    }

    if (rc == SQLITE_CONSTRAINT) {
        int ext = sqlite3_extended_errcode(db);
        if (ext == SQLITE_CONSTRAINT_UNIQUE) {
            return SMO_ERR_CERT(220, Warn, RetrySafe, None,
                                std::string("display name or alias already exists (") + context + ")");
        }
        return SMO_ERR_CERT(220, Warn, RetrySafe, None,
                            std::string("constraint violation (") + context + ")");
    }

    return SMO_ERR_STORAGE(904, Error, RetrySafe, RetryOperation,
                           std::string(context) + ": " + sqlite3_errmsg(db));
}

// ---------------------------------------------------------------------------
// NodeRegistry
// ---------------------------------------------------------------------------

NodeRegistry::~NodeRegistry() { close(); }

Result<void> NodeRegistry::open(const std::string& db_path) {
    int rc = sqlite3_open_v2(db_path.c_str(), &db_,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                             nullptr);
    if (rc != SQLITE_OK) {
        std::string msg = sqlite3_errmsg(db_);
        sqlite3_close(db_); db_ = nullptr;
        return SMO_ERR_STORAGE(900, Critical, NoRetry, RebootNode, msg);
    }
    // WAL mode + foreign keys
    char* err = nullptr;
    sqlite3_exec(db_, "PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;",
                 nullptr, nullptr, &err);
    if (err) { sqlite3_free(err); }
    return ensure_schema();
}

void NodeRegistry::close() {
    if (db_) { sqlite3_close(db_); db_ = nullptr; }
}

Result<void> NodeRegistry::ensure_schema() {
    char* err = nullptr;
    if (sqlite3_exec(db_, kRegistrySchema, nullptr, nullptr, &err) != SQLITE_OK) {
        std::string msg = err ? err : "schema creation failed";
        sqlite3_free(err);
        return SMO_ERR_STORAGE(900, Critical, NoRetry, RebootNode, msg);
    }
    return {};
}

// ── Transaction support ──────────────────────────────────────────────────

Result<void> NodeRegistry::begin_transaction() {
    char* err = nullptr;
    if (sqlite3_exec(db_, "BEGIN IMMEDIATE;", nullptr, nullptr, &err) != SQLITE_OK) {
        std::string msg = err ? err : "begin failed";
        sqlite3_free(err);
        return SMO_ERR_STORAGE(904, Error, RetrySafe, RetryOperation, msg);
    }
    return {};
}

Result<void> NodeRegistry::commit() {
    char* err = nullptr;
    if (sqlite3_exec(db_, "COMMIT;", nullptr, nullptr, &err) != SQLITE_OK) {
        std::string msg = err ? err : "commit failed";
        sqlite3_free(err);
        return SMO_ERR_STORAGE(904, Error, RetrySafe, RetryOperation, msg);
    }
    return {};
}

Result<void> NodeRegistry::rollback() {
    sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, nullptr);
    return {};
}

// ── Atomic enrollment ────────────────────────────────────────────────────

Result<EnrollResult> NodeRegistry::enroll_node(
    const std::string& node_id_hex,
    const std::string& display_name,
    const std::string& mesh_id,
    const std::string& role,
    const std::string& cert_fingerprint,
    const std::string& cert_issuer_pubkey_hex,
    const std::string& cert_subject_pubkey_hex,
    uint64_t epoch,
    int64_t  cert_issued_at,
    int64_t  cert_expires_at)
{
    if (!db_) {
        return SMO_ERR_STORAGE(900, Critical, NoRetry, RebootNode, "database not open");
    }

    std::string normalized = normalize_display_name(display_name);

    auto tx = begin_transaction();
    if (!tx) return tx.error();

    // 1. Insert node (UNIQUE on display_name → catches duplicates)
    {
        const char* sql = "INSERT INTO nodes "
                          "(node_id_hex, display_name, mesh_id, role, "
                          " cert_fingerprint, status, epoch, enrolled_at) "
                          "VALUES (?, ?, ?, ?, ?, 'active', ?, ?)";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            rollback();
            return map_sqlite_error<EnrollResult>(SQLITE_ERROR, db_, "prepare enroll_node");
        }
        sqlite3_bind_text(stmt, 1, node_id_hex.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, normalized.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, mesh_id.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 4, role.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 5, cert_fingerprint.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 6, static_cast<int64_t>(epoch));
        sqlite3_bind_int64(stmt, 7, std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) {
            rollback();
            return map_sqlite_error<EnrollResult>(rc, db_, "insert node");
        }
    }

    // 2. Insert certificate
    {
        const char* sql = "INSERT INTO certificates "
                          "(node_id_hex, serial_number, cert_fingerprint, issuer_pubkey_hex, "
                          " subject_pubkey_hex, role, status, epoch, issued_at, expires_at) "
                          "VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            rollback();
            return map_sqlite_error<EnrollResult>(SQLITE_ERROR, db_, "prepare enroll_cert");
        }
        sqlite3_bind_text(stmt, 1, node_id_hex.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, cert_fingerprint.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, cert_fingerprint.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 4, cert_issuer_pubkey_hex.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 5, cert_subject_pubkey_hex.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 6, role.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 7, static_cast<int64_t>(epoch));
        sqlite3_bind_int64(stmt, 8, cert_issued_at);
        sqlite3_bind_int64(stmt, 9, cert_expires_at);
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) {
            rollback();
            return map_sqlite_error<EnrollResult>(rc, db_, "insert certificate");
        }
    }

    // 3. Insert alias (so display_name is also claimed as an alias)
    {
        const char* sql = "INSERT INTO node_aliases (alias, node_id_hex, created_at) "
                          "VALUES (?, ?, ?)";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            rollback();
            return map_sqlite_error<EnrollResult>(SQLITE_ERROR, db_, "prepare enroll_alias");
        }
        sqlite3_bind_text(stmt, 1, normalized.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, node_id_hex.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 3, std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) {
            rollback();
            // If alias insert fails (e.g. the name exists as an alias already),
            // map to DisplayNameAlreadyExists
            if (rc == SQLITE_CONSTRAINT) {
                return SMO_ERR_CERT(220, Warn, RetrySafe, None,
                                    "display name already taken: " + normalized);
            }
            return map_sqlite_error<EnrollResult>(rc, db_, "insert alias");
        }
    }

    // Commit
    auto c = commit();
    if (!c) {
        rollback();
        return c.error();
    }

    // Build result
    EnrollResult result;
    result.node.node_id_hex = node_id_hex;
    result.node.display_name = normalized;
    result.node.mesh_id = mesh_id;
    result.node.role = role;
    result.node.cert_fingerprint = cert_fingerprint;
    result.node.status = "active";
    result.node.epoch = epoch;
    result.cert_fingerprint = cert_fingerprint;
    result.certificate.node_id_hex = node_id_hex;
    result.certificate.cert_fingerprint = cert_fingerprint;
    result.certificate.issuer_pubkey_hex = cert_issuer_pubkey_hex;
    result.certificate.subject_pubkey_hex = cert_subject_pubkey_hex;
    result.certificate.role = role;
    result.certificate.status = "active";
    result.certificate.epoch = epoch;

    return result;
}

// ── Node management ──────────────────────────────────────────────────────

Result<void> NodeRegistry::register_node(const NodeRecord& node) {
    const char* sql = "INSERT OR REPLACE INTO nodes "
                      "(node_id_hex, display_name, mesh_id, role, "
                      " cert_fingerprint, status, epoch, enrolled_at, last_seen) "
                      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return map_sqlite_error(SQLITE_ERROR, db_, "prepare register_node");
    }
    sqlite3_bind_text(stmt, 1, node.node_id_hex.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, normalize_display_name(node.display_name).c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, node.mesh_id.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, node.role.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, node.cert_fingerprint.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, node.status.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 7, static_cast<int64_t>(node.epoch));
    sqlite3_bind_int64(stmt, 8, node.enrolled_at);
    sqlite3_bind_int64(stmt, 9, node.last_seen);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return map_sqlite_error(rc, db_, "register_node");
}

Result<std::optional<NodeRecord>> NodeRegistry::get_node(const std::string& node_id_hex) const {
    const char* sql = "SELECT node_id_hex, display_name, mesh_id, role, "
                      "cert_fingerprint, status, epoch, enrolled_at, last_seen "
                      "FROM nodes WHERE node_id_hex = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return map_sqlite_error<std::optional<NodeRecord>>(SQLITE_ERROR, db_, "prepare get_node");
    }
    sqlite3_bind_text(stmt, 1, node_id_hex.c_str(), -1, SQLITE_STATIC);
    std::optional<NodeRecord> result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        NodeRecord rec;
        rec.node_id_hex = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        rec.display_name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        rec.mesh_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        rec.role = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        rec.cert_fingerprint = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        rec.status = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        rec.epoch = static_cast<uint64_t>(sqlite3_column_int64(stmt, 6));
        rec.enrolled_at = sqlite3_column_int64(stmt, 7);
        rec.last_seen = sqlite3_column_int64(stmt, 8);
        result = std::move(rec);
    }
    sqlite3_finalize(stmt);
    return result;
}

Result<std::vector<NodeRecord>> NodeRegistry::list_nodes(const std::string& mesh_id) const {
    std::vector<NodeRecord> nodes;
    const char* sql = mesh_id.empty()
        ? "SELECT node_id_hex, display_name, mesh_id, role, "
          "cert_fingerprint, status, epoch, enrolled_at, last_seen FROM nodes ORDER BY display_name"
        : "SELECT node_id_hex, display_name, mesh_id, role, "
          "cert_fingerprint, status, epoch, enrolled_at, last_seen FROM nodes WHERE mesh_id = ? ORDER BY display_name";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return map_sqlite_error<std::vector<NodeRecord>>(SQLITE_ERROR, db_, "prepare list_nodes");
    }
    if (!mesh_id.empty()) {
        sqlite3_bind_text(stmt, 1, mesh_id.c_str(), -1, SQLITE_STATIC);
    }
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        NodeRecord rec;
        rec.node_id_hex = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        rec.display_name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        rec.mesh_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        rec.role = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        rec.cert_fingerprint = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        rec.status = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        rec.epoch = static_cast<uint64_t>(sqlite3_column_int64(stmt, 6));
        rec.enrolled_at = sqlite3_column_int64(stmt, 7);
        rec.last_seen = sqlite3_column_int64(stmt, 8);
        nodes.push_back(std::move(rec));
    }
    sqlite3_finalize(stmt);
    return nodes;
}

Result<void> NodeRegistry::update_node_status(const std::string& node_id_hex, const std::string& status) {
    const char* sql = "UPDATE nodes SET status = ? WHERE node_id_hex = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return map_sqlite_error(SQLITE_ERROR, db_, "prepare update_node_status");
    }
    sqlite3_bind_text(stmt, 1, status.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, node_id_hex.c_str(), -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return map_sqlite_error(rc, db_, "update_node_status");
}

Result<void> NodeRegistry::update_last_seen(const std::string& node_id_hex, int64_t timestamp) {
    const char* sql = "UPDATE nodes SET last_seen = ? WHERE node_id_hex = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return map_sqlite_error(SQLITE_ERROR, db_, "prepare update_last_seen");
    }
    sqlite3_bind_int64(stmt, 1, timestamp);
    sqlite3_bind_text(stmt, 2, node_id_hex.c_str(), -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return map_sqlite_error(rc, db_, "update_last_seen");
}

Result<bool> NodeRegistry::node_exists(const std::string& node_id_hex) const {
    const char* sql = "SELECT 1 FROM nodes WHERE node_id_hex = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return map_sqlite_error<bool>(SQLITE_ERROR, db_, "prepare node_exists");
    }
    sqlite3_bind_text(stmt, 1, node_id_hex.c_str(), -1, SQLITE_STATIC);
    bool exists = sqlite3_step(stmt) == SQLITE_ROW;
    sqlite3_finalize(stmt);
    return exists;
}

// ── Alias management ────────────────────────────────────────────────────

Result<void> NodeRegistry::register_alias(const std::string& alias, const std::string& node_id_hex) {
    std::string normalized = normalize_display_name(alias);
    // Check node exists first
    auto exists = node_exists(node_id_hex);
    if (!exists) return exists.error();
    if (!exists.value()) {
        return SMO_ERR_STORAGE(404, Error, NoRetry, None, "node not found: " + node_id_hex);
    }

    const char* sql = "INSERT INTO node_aliases (alias, node_id_hex, created_at) VALUES (?, ?, ?)";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return map_sqlite_error(SQLITE_ERROR, db_, "prepare register_alias");
    }
    sqlite3_bind_text(stmt, 1, normalized.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, node_id_hex.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc == SQLITE_CONSTRAINT) {
        return SMO_ERR_CERT(220, Warn, RetrySafe, None,
                            "alias already exists: " + normalized);
    }
    return map_sqlite_error(rc, db_, "register_alias");
}

Result<void> NodeRegistry::release_alias(const std::string& alias) {
    const char* sql = "DELETE FROM node_aliases WHERE alias = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return map_sqlite_error(SQLITE_ERROR, db_, "prepare release_alias");
    }
    sqlite3_bind_text(stmt, 1, normalize_display_name(alias).c_str(), -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return {};
}

Result<std::optional<AliasRecord>> NodeRegistry::get_alias(const std::string& alias) const {
    const char* sql = "SELECT alias, node_id_hex, created_at FROM node_aliases WHERE alias = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return map_sqlite_error<std::optional<AliasRecord>>(SQLITE_ERROR, db_, "prepare get_alias");
    }
    sqlite3_bind_text(stmt, 1, normalize_display_name(alias).c_str(), -1, SQLITE_STATIC);
    std::optional<AliasRecord> result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        AliasRecord rec;
        rec.alias = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        rec.node_id_hex = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        rec.created_at = sqlite3_column_int64(stmt, 2);
        result = std::move(rec);
    }
    sqlite3_finalize(stmt);
    return result;
}

Result<std::vector<AliasRecord>> NodeRegistry::list_aliases_for_node(const std::string& node_id_hex) const {
    std::vector<AliasRecord> aliases;
    const char* sql = "SELECT alias, node_id_hex, created_at FROM node_aliases WHERE node_id_hex = ? ORDER BY alias";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return map_sqlite_error<std::vector<AliasRecord>>(SQLITE_ERROR, db_, "prepare list_aliases_for_node");
    }
    sqlite3_bind_text(stmt, 1, node_id_hex.c_str(), -1, SQLITE_STATIC);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        AliasRecord rec;
        rec.alias = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        rec.node_id_hex = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        rec.created_at = sqlite3_column_int64(stmt, 2);
        aliases.push_back(std::move(rec));
    }
    sqlite3_finalize(stmt);
    return aliases;
}

// ── Certificate management ───────────────────────────────────────────────

Result<void> NodeRegistry::register_certificate(const CertificateRecord& cert) {
    const char* sql = "INSERT INTO certificates "
                      "(node_id_hex, serial_number, cert_fingerprint, issuer_pubkey_hex, "
                      " subject_pubkey_hex, role, status, epoch, issued_at, expires_at) "
                      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return map_sqlite_error(SQLITE_ERROR, db_, "prepare register_certificate");
    }
    sqlite3_bind_text(stmt, 1, cert.node_id_hex.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, cert.serial_number.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, cert.cert_fingerprint.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, cert.issuer_pubkey_hex.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, cert.subject_pubkey_hex.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, cert.role.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 7, cert.status.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 8, static_cast<int64_t>(cert.epoch));
    sqlite3_bind_int64(stmt, 9, cert.issued_at);
    sqlite3_bind_int64(stmt, 10, cert.expires_at);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return map_sqlite_error(rc, db_, "register_certificate");
}

Result<std::optional<CertificateRecord>> NodeRegistry::get_certificate(const std::string& cert_fingerprint) const {
    const char* sql = "SELECT id, node_id_hex, serial_number, cert_fingerprint, "
                      "issuer_pubkey_hex, subject_pubkey_hex, role, status, epoch, "
                      "issued_at, expires_at, revoked_at, revocation_reason "
                      "FROM certificates WHERE cert_fingerprint = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return map_sqlite_error<std::optional<CertificateRecord>>(SQLITE_ERROR, db_, "prepare get_certificate");
    }
    sqlite3_bind_text(stmt, 1, cert_fingerprint.c_str(), -1, SQLITE_STATIC);
    std::optional<CertificateRecord> result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        CertificateRecord rec;
        rec.id = sqlite3_column_int64(stmt, 0);
        rec.node_id_hex = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        rec.serial_number = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        rec.cert_fingerprint = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        rec.issuer_pubkey_hex = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        rec.subject_pubkey_hex = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        rec.role = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        rec.status = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        rec.epoch = static_cast<uint64_t>(sqlite3_column_int64(stmt, 8));
        rec.issued_at = sqlite3_column_int64(stmt, 9);
        rec.expires_at = sqlite3_column_int64(stmt, 10);
        rec.revoked_at = sqlite3_column_int64(stmt, 11);
        rec.revocation_reason = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 12));
        result = std::move(rec);
    }
    sqlite3_finalize(stmt);
    return result;
}

Result<std::vector<CertificateRecord>> NodeRegistry::list_certificates(const std::string& node_id_hex) const {
    std::vector<CertificateRecord> certs;
    std::string sql = "SELECT id, node_id_hex, serial_number, cert_fingerprint, "
                      "issuer_pubkey_hex, subject_pubkey_hex, role, status, epoch, "
                      "issued_at, expires_at, revoked_at, revocation_reason "
                      "FROM certificates";
    if (!node_id_hex.empty()) sql += " WHERE node_id_hex = ?";
    sql += " ORDER BY issued_at DESC";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        return map_sqlite_error<std::vector<CertificateRecord>>(SQLITE_ERROR, db_, "prepare list_certificates");
    }
    if (!node_id_hex.empty()) {
        sqlite3_bind_text(stmt, 1, node_id_hex.c_str(), -1, SQLITE_STATIC);
    }
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        CertificateRecord rec;
        rec.id = sqlite3_column_int64(stmt, 0);
        rec.node_id_hex = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        rec.serial_number = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        rec.cert_fingerprint = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        rec.issuer_pubkey_hex = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        rec.subject_pubkey_hex = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        rec.role = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        rec.status = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        rec.epoch = static_cast<uint64_t>(sqlite3_column_int64(stmt, 8));
        rec.issued_at = sqlite3_column_int64(stmt, 9);
        rec.expires_at = sqlite3_column_int64(stmt, 10);
        rec.revoked_at = sqlite3_column_int64(stmt, 11);
        rec.revocation_reason = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 12));
        certs.push_back(std::move(rec));
    }
    sqlite3_finalize(stmt);
    return certs;
}

Result<void> NodeRegistry::revoke_certificate(const std::string& cert_fingerprint, const std::string& reason) {
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    const char* sql = "UPDATE certificates SET status = 'revoked', revoked_at = ?, "
                      "revocation_reason = ? WHERE cert_fingerprint = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return map_sqlite_error(SQLITE_ERROR, db_, "prepare revoke_certificate");
    }
    sqlite3_bind_int64(stmt, 1, now);
    sqlite3_bind_text(stmt, 2, reason.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, cert_fingerprint.c_str(), -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return map_sqlite_error(rc, db_, "revoke_certificate");
}

Result<std::vector<CertificateRecord>> NodeRegistry::find_certificates_by_node(const std::string& node_id_hex) const {
    return list_certificates(node_id_hex);
}

// ── Enrollment ────────────────────────────────────────────────────────────

Result<void> NodeRegistry::submit_enrollment(const EnrollmentRecord& enrollment) {
    const char* sql = "INSERT INTO enrollments "
                      "(node_id_hex, display_name, mesh_id, role, "
                      " platform, version, timestamp, csr_blob, submitted_at, status) "
                      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return map_sqlite_error(SQLITE_ERROR, db_, "prepare submit_enrollment");
    }
    sqlite3_bind_text(stmt, 1, enrollment.node_id_hex.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, enrollment.display_name.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, enrollment.mesh_id.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, enrollment.role.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, enrollment.platform.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, enrollment.version.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 7, enrollment.timestamp);
    sqlite3_bind_text(stmt, 8, enrollment.csr_blob.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 9, enrollment.submitted_at);
    sqlite3_bind_text(stmt, 10, enrollment.status.c_str(), -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return map_sqlite_error(rc, db_, "submit_enrollment");
}

Result<std::vector<EnrollmentRecord>> NodeRegistry::list_pending_enrollments() const {
    std::vector<EnrollmentRecord> enrollments;
    const char* sql = "SELECT id, node_id_hex, display_name, mesh_id, role, "
                      "platform, version, timestamp, csr_blob, submitted_at, status "
                      "FROM enrollments WHERE status = 'pending' ORDER BY submitted_at ASC";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return map_sqlite_error<std::vector<EnrollmentRecord>>(SQLITE_ERROR, db_, "prepare list_pending_enrollments");
    }
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        EnrollmentRecord rec;
        rec.id = sqlite3_column_int64(stmt, 0);
        rec.node_id_hex = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        rec.display_name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        rec.mesh_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        rec.role = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        rec.platform = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        rec.version = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        rec.timestamp = sqlite3_column_int64(stmt, 7);
        rec.csr_blob = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
        rec.submitted_at = sqlite3_column_int64(stmt, 9);
        rec.status = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 10));
        enrollments.push_back(std::move(rec));
    }
    sqlite3_finalize(stmt);
    return enrollments;
}

Result<void> NodeRegistry::update_enrollment_status(int64_t enrollment_id, const std::string& status) {
    const char* sql = "UPDATE enrollments SET status = ? WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return map_sqlite_error(SQLITE_ERROR, db_, "prepare update_enrollment_status");
    }
    sqlite3_bind_text(stmt, 1, status.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, enrollment_id);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return map_sqlite_error(rc, db_, "update_enrollment_status");
}

// ── Revocation ────────────────────────────────────────────────────────────

Result<std::vector<RevocationRecord>> NodeRegistry::get_revocation_list(uint64_t since_epoch) const {
    std::vector<RevocationRecord> revs;
    const char* sql = "SELECT id, node_id_hex, reason, epoch, timestamp "
                      "FROM revocations WHERE epoch >= ? ORDER BY epoch ASC";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return map_sqlite_error<std::vector<RevocationRecord>>(SQLITE_ERROR, db_, "prepare get_revocation_list");
    }
    sqlite3_bind_int64(stmt, 1, static_cast<int64_t>(since_epoch));
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        RevocationRecord rec;
        rec.id = sqlite3_column_int64(stmt, 0);
        rec.node_id_hex = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        rec.reason = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        rec.epoch = static_cast<uint64_t>(sqlite3_column_int64(stmt, 3));
        rec.timestamp = sqlite3_column_int64(stmt, 4);
        revs.push_back(std::move(rec));
    }
    sqlite3_finalize(stmt);
    return revs;
}

Result<void> NodeRegistry::add_revocation(const RevocationRecord& rec) {
    const char* sql = "INSERT INTO revocations (node_id_hex, reason, epoch, timestamp) VALUES (?, ?, ?, ?)";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return map_sqlite_error(SQLITE_ERROR, db_, "prepare add_revocation");
    }
    sqlite3_bind_text(stmt, 1, rec.node_id_hex.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, rec.reason.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, static_cast<int64_t>(rec.epoch));
    sqlite3_bind_int64(stmt, 4, rec.timestamp);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return map_sqlite_error(rc, db_, "add_revocation");
}

} // namespace smo::authority
