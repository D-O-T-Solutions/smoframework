#include "seed_store.hpp"

#include "../storage/database.hpp"

#include <ctime>

namespace smo {

Result<void> SeedStore::open(std::string_view base_path) {
    if (opened_) return {};
    db_path_ = std::string(base_path) + "/seed_store.sqlite";
    SMO_TRY(db_.open(db_path_));
    SMO_TRY(db_.exec(
        "CREATE TABLE IF NOT EXISTS seeds ("
        "  endpoint    TEXT PRIMARY KEY,"
        "  weight      INTEGER NOT NULL DEFAULT 100,"
        "  mesh_id     TEXT NOT NULL DEFAULT '',"
        "  added_at    INTEGER NOT NULL DEFAULT (strftime('%s','now'))"
        ")"));
    opened_ = true;
    return {};
}

void SeedStore::close() {
    if (opened_) db_.close();
    opened_ = false;
}

Result<void> SeedStore::put(const SeedEntry& entry) {
    if (!opened_)
        return SMO_ERR_STORAGE(905, Error, RetrySafe, None, "SeedStore not open");

    auto st = db_.prepare(
        "INSERT OR REPLACE INTO seeds (endpoint, weight, mesh_id, added_at) "
        "VALUES (?1, ?2, ?3, ?4)");
    if (!st) return st.error();

    int idx = 1;
    st.value().bind_text(idx++, entry.endpoint);
    st.value().bind_int64(idx++, static_cast<int64_t>(entry.weight));
    st.value().bind_text(idx++, entry.mesh_id);
    st.value().bind_int64(idx++, entry.added_at > 0 ? entry.added_at : static_cast<int64_t>(std::time(nullptr)));

    auto step_res = st.value().step();
    if (!step_res) return step_res.error();
    return {};
}

Result<std::vector<SeedEntry>> SeedStore::list(const std::string& mesh_id) const {
    if (!opened_)
        return SMO_ERR_STORAGE(905, Error, RetrySafe, None, "SeedStore not open");

    std::string sql = "SELECT endpoint, weight, mesh_id, added_at FROM seeds";
    if (!mesh_id.empty()) sql += " WHERE mesh_id = ?1";
    sql += " ORDER BY weight DESC";

    auto st = db_.prepare(sql.c_str());
    if (!st) return st.error();

    if (!mesh_id.empty()) st.value().bind_text(1, mesh_id);

    std::vector<SeedEntry> entries;
    while (true) {
        auto step_res = st.value().step();
        if (!step_res) return step_res.error();
        if (step_res.value() != SQLITE_ROW) break;

        SeedEntry e;
        e.endpoint = st.value().column_text(0);
        e.weight = static_cast<uint32_t>(st.value().column_int64(1));
        e.mesh_id = st.value().column_text(2);
        e.added_at = st.value().column_int64(3);
        entries.push_back(std::move(e));
    }
    return entries;
}

Result<void> SeedStore::remove(const std::string& endpoint) {
    if (!opened_)
        return SMO_ERR_STORAGE(905, Error, RetrySafe, None, "SeedStore not open");

    auto st = db_.prepare("DELETE FROM seeds WHERE endpoint = ?1");
    if (!st) return st.error();
    st.value().bind_text(1, endpoint);
    auto step_res = st.value().step();
    if (!step_res) return step_res.error();
    return {};
}

Result<SeedEntry> SeedStore::select_best(const std::string& mesh_id) const {
    auto entries = list(mesh_id);
    if (!entries) return entries.error();
    auto& vec = entries.value();
    if (vec.empty())
        return SMO_ERR_STORAGE(404, Info, NoRetry, None, "No seeds available");
    // Weighted random: higher weight = more likely
    uint64_t total = 0;
    for (auto& e : vec) total += e.weight;
    if (total == 0) return vec.front();
    uint64_t pick = static_cast<uint64_t>(rand()) % total;
    uint64_t accum = 0;
    for (auto& e : vec) {
        accum += e.weight;
        if (pick < accum) return e;
    }
    return vec.back();
}

Result<size_t> SeedStore::count() const {
    if (!opened_)
        return SMO_ERR_STORAGE(905, Error, RetrySafe, None, "SeedStore not open");

    auto st = db_.prepare("SELECT COUNT(*) FROM seeds");
    if (!st) return st.error();

    auto step_res = st.value().step();
    if (!step_res) return step_res.error();
    if (step_res.value() != SQLITE_ROW) return size_t{0};
    return static_cast<size_t>(st.value().column_int64(0));
}

} // namespace smo
