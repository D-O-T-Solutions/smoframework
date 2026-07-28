#include "version_vector.hpp"
#include "sync_errors.hpp"
#include <cstring>

namespace smo::sync {

    Bytes VersionVector::serialize() const
    {
        Bytes out;
        uint32_t count = static_cast<uint32_t>(dots.size());
        out.insert(out.end(), reinterpret_cast<const uint8_t*>(&count), reinterpret_cast<const uint8_t*>(&count) + 4);
        for (const auto& [nid, ep] : dots)
        {
            uint32_t len = static_cast<uint32_t>(nid.size());
            out.insert(out.end(), reinterpret_cast<const uint8_t*>(&len), reinterpret_cast<const uint8_t*>(&len) + 4);
            out.insert(out.end(), nid.begin(), nid.end());
            out.insert(out.end(), reinterpret_cast<const uint8_t*>(&ep), reinterpret_cast<const uint8_t*>(&ep) + 8);
        }
        return out;
    }

    Result<VersionVector> VersionVector::deserialize(BytesView data)
    {
        size_t pos = 0;
        if (pos + 4 > data.size())
        {
            return Error(SyncErrc::Truncated, "VersionVector: truncated header");
        }
        uint32_t count;
        std::memcpy(&count, data.data() + pos, 4);
        pos += 4;

        VersionVector vv;
        for (uint32_t i = 0; i < count; ++i)
        {
            if (pos + 4 > data.size())
            {
                return Error(SyncErrc::Truncated, "VersionVector: truncated node_id length");
            }
            uint32_t nlen;
            std::memcpy(&nlen, data.data() + pos, 4);
            pos += 4;
            if (pos + nlen + 8 > data.size())
            {
                return Error(SyncErrc::Truncated, "VersionVector: truncated node_id or epoch");
            }
            std::string nid(reinterpret_cast<const char*>(data.data() + pos), nlen);
            pos += nlen;
            uint64_t ep;
            std::memcpy(&ep, data.data() + pos, 8);
            pos += 8;
            vv.dots[nid] = ep;
        }
        return vv;
    }

} // namespace smo::sync