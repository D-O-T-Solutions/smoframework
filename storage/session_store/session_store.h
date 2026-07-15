#pragma once

#include <optional>
#include "storage/storage.h"
#include "core/session/session.h"

namespace smo {

// Active session state: capabilities, keys, expiration.
class SessionStore : public Store {
public:
    std::error_code put(const Session& session);
    std::optional<Session> get(const SessionId& id);
    std::error_code remove(const SessionId& id);
    std::error_code expire_before(int64_t timestamp);
};

} // namespace smo
