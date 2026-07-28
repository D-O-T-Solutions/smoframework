#include "sync_backend.hpp"
#include "sync_errors.hpp"
#include <cstring>

namespace smo::sync {

Bytes Delta::serialize() const {
    Bytes out;
    out.push_back(static_cast<uint8_t>(tree_id));
    out.insert(out.end(), reinterpret_cast<const uint8_t*>(&base_epoch),
               reinterpret_cast<const uint8_t*>(&base_epoch) + 8);
    uint32_t count = entry_count;
    out.insert(out.end(), reinterpret_cast<const uint8_t*>(&count),
               reinterpret_cast<const uint8_t*>(&count) + 4);
    out.push_back(is_snapshot ? 1 : 0);
    uint32_t dlen = static_cast<uint32_t>(data.size());
    out.insert(out.end(), reinterpret_cast<const uint8_t*>(&dlen),
               reinterpret_cast<const uint8_t*>(&dlen) + 4);
    out.insert(out.end(), data.begin(), data.end());
    return out;
}

Result<Delta> Delta::deserialize(BytesView data) {
    if (data.size() < 1 + 8 + 4 + 1 + 4) {
        return Error(SyncErrc::Truncated, "Delta: truncated");
    }
    size_t pos = 0;
    Delta d;
    d.tree_id = static_cast<TreeID>(data[pos]); pos += 1;
    std::memcpy(&d.base_epoch, data.data() + pos, 8); pos += 8;
    std::memcpy(&d.entry_count, data.data() + pos, 4); pos += 4;
    d.is_snapshot = data[pos] != 0; pos += 1;
    uint32_t dlen;
    std::memcpy(&dlen, data.data() + pos, 4); pos += 4;
    if (pos + dlen > data.size()) {
        return Error(SyncErrc::Truncated, "Delta: data truncated");
    }
    d.data.assign(data.data() + pos, data.data() + pos + dlen);
    return d;
}

} // namespace smo::sync