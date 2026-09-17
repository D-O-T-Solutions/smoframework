#include "session_id.hpp"

#include "../crypto/impl.hpp"

#include <cstring>

namespace smo {

    bool SessionId::is_zero() const noexcept
    {
        for (uint8_t b : bytes)
        {
            if (b != 0)
                return false;
        }
        return true;
    }

    Result<SessionId> SessionId::derive(BytesView seed, const HashImpl& hash)
    {
        if (!hash.hash)
        {
            return SMO_ERR_SESSION(500, Error, NoRetry, Reconnect, "null hash implementation");
        }
        auto h = hash.hash(seed);
        if (!h)
            return std::move(h.error());

        SessionId id;
        const size_t copy = h.value().size() < kSize ? h.value().size() : kSize;
        std::memcpy(id.bytes.data(), h.value().data(), copy);
        return id;
    }

    Bytes SessionId::to_bytes() const
    {
        return Bytes(bytes.begin(), bytes.end());
    }

    std::string SessionId::to_hex() const
    {
        static const char* hex = "0123456789abcdef";
        std::string out;
        out.reserve(32);
        for (uint8_t b : bytes)
        {
            out.push_back(hex[b >> 4]);
            out.push_back(hex[b & 0xF]);
        }
        return out;
    }

    Result<SessionId> SessionId::from_bytes(BytesView data)
    {
        if (data.size() < kSize)
        {
            return SMO_ERR_SESSION(500, Error, NoRetry, Reconnect, "truncated SessionId");
        }
        SessionId id;
        std::memcpy(id.bytes.data(), data.data(), kSize);
        return id;
    }

} // namespace smo
