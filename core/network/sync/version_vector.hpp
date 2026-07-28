#pragma once

#include <core/errors/error.hpp>
#include <core/types.hpp>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace smo::sync {

struct VersionVector {
    std::unordered_map<std::string, uint64_t> dots;

    bool operator==(const VersionVector& o) const { return dots == o.dots; }
    bool operator!=(const VersionVector& o) const { return dots != o.dots; }

    bool empty() const { return dots.empty(); }
    size_t size() const { return dots.size(); }
    void clear() { dots.clear(); }

    uint64_t get(const std::string& node_id) const {
        auto it = dots.find(node_id);
        return it != dots.end() ? it->second : 0;
    }

    void set(const std::string& node_id, uint64_t epoch) {
        dots[node_id] = epoch;
    }

    void merge(const VersionVector& other) {
        for (const auto& [nid, ep] : other.dots) {
            auto it = dots.find(nid);
            if (it == dots.end() || ep > it->second) {
                dots[nid] = ep;
            }
        }
    }

    bool dominates(const VersionVector& other) const {
        bool any_less = false;
        for (const auto& [nid, ep] : other.dots) {
            auto it = dots.find(nid);
            if (it == dots.end() || it->second < ep) {
                any_less = true;
            }
        }
        return !any_less;
    }

    Bytes serialize() const;
    static Result<VersionVector> deserialize(BytesView data);
};

} // namespace smo::sync