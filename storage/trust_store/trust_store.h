#pragma once

#include <optional>
#include "storage/storage.h"

namespace smo {

// Trust score records.
// Per-node isolated trust data.
class TrustStore : public Store {
public:
    struct Record {
        std::string node_id;
        double      citizen_score{0.0};
        double      execution_score{0.0};
        double      witness_score{0.0};
        double      consistency_score{0.0};
        double      composite{0.0};
        int64_t     updated_at{0};
    };

    std::error_code put(const Record& rec);
    std::optional<Record> get(const std::string& node_id);
    std::error_code remove(const std::string& node_id);
};

} // namespace smo
