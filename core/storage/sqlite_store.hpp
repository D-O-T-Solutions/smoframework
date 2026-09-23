#pragma once

#include "../errors/error.hpp"
#include "../types.hpp"
#include "database.hpp"
#include "migration.hpp"
#include "store_id.hpp"

#include <string>
#include <vector>

namespace smo {

    // ---------------------------------------------------------------------------
    // SqliteStore — key-value store on top of a single SQLite database
    //
    // Uses a simple schema:
    //   CREATE TABLE kv (key BLOB PRIMARY KEY, value BLOB) WITHOUT ROWID;
    // ---------------------------------------------------------------------------
    class SqliteStore
    {
    public:
        SqliteStore(StoreID id, std::string base_path);

        SqliteStore(SqliteStore&&) = default;
        SqliteStore& operator=(SqliteStore&&) = default;
        ~SqliteStore() = default;

        SqliteStore(const SqliteStore&) = delete;
        SqliteStore& operator=(const SqliteStore&) = delete;

        // Open the database file at <base_path>/<store_filename>.
        // Creates the file if it doesn't exist.
        // Runs WAL pragmas and ensures schema.
        Result<void> open();

        // Close the database.
        void close() { db_.close(); }

        bool is_open() const { return db_.is_open(); }
        StoreID store_id() const { return id_; }
        const std::string& db_path() const { return db_.path(); }

        // ── KV operations ────────────────────────────────────────────────

        // Insert or replace a key-value pair.
        Result<void> put(BytesView key, BytesView value);

        // Retrieve a value by key. Returns KEY_NOT_FOUND if missing.
        Result<Bytes> get(BytesView key);

        // Delete a key. Succeeds even if the key doesn't exist.
        Result<void> del(BytesView key);

        // List all keys with the given prefix.
        Result<std::vector<Bytes>> list(BytesView prefix);

        // ── Transaction helpers ──────────────────────────────────────────

        Result<void> begin_transaction();
        Result<void> commit();
        Result<void> rollback();

        // ── Direct SQL access (for advanced queries) ─────────────────────

        DatabaseHandle& database() { return db_; }

// ── Backup / restore ─────────────────────────────────────────────
 
        // Back up the current database to `dest_path`.
        Result<void> backup(const std::string& dest_path);
 
        // Restore from a backup file. Closes current DB, copies file, reopens.
        Result<void> restore(const std::string& src_path);
 
        // ── Schema migration ──────────────────────────────────────────────
 
        // Migrate database to target schema version (using frozen schema).
        Result<void> migrate(int target_version);
 
        // Get current schema version from PRAGMA user_version.
        int current_schema_version() const;
 
    private:
        StoreID id_;
        std::string base_path_;
        DatabaseHandle db_;
    };

} // namespace smo
