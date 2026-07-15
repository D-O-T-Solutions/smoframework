#pragma once

#include <optional>
#include "storage/storage.h"
#include "protocol/signing/signing.h"

namespace smo {

// Node identity, keys, configuration, route table.
class NodeStore : public Store {
public:
    struct Identity {
        std::string node_id;
        PublicKey   public_key;
        SecretKey   secret_key;     // stored encrypted at rest
        std::string domain;         // mesh domain name
    };

    struct RouteEntry {
        std::string node_id;
        std::string address;
        uint16_t    port{0};
        int64_t     last_seen{0};
        double      trust_score{0.0};
    };

    std::error_code put_identity(const Identity& id);
    std::optional<Identity> get_identity();

    std::error_code put_route(const RouteEntry& entry);
    std::optional<RouteEntry> get_route(const std::string& node_id);
    std::vector<RouteEntry> all_routes();
};

} // namespace smo
