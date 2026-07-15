#pragma once

#include <optional>
#include "storage/storage.h"

namespace smo {

// Compiled execution DAG records.
// DAG is immutable after compile (Invariant I-03).
class DagStore : public Store {
public:
    struct DagRecord {
        std::string graph_id;
        std::string intent_id;
        std::string dag_json;       // serialized DAG
        std::string dag_hash;       // Blake3 of the DAG
        int64_t     compiled_at{0};
    };

    std::error_code put(const DagRecord& dag);
    std::optional<DagRecord> get(const std::string& graph_id);
};

} // namespace smo
