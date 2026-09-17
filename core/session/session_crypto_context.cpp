#include "session_crypto_context.hpp"

#include "../crypto/secure/secure_compare.hpp"

namespace smo {

    bool PacketTxKey::matches(const PacketRxKey& other) const noexcept
    {
        if (material_.empty() || material_.size() != other.material_.size())
            return false;
        return secure::constant_time_compare(material_.data(), other.material_.data(), material_.size());
    }

    bool PacketRxKey::matches(const PacketTxKey& other) const noexcept
    {
        return other.matches(*this);
    }

    SessionCryptoContext SessionCryptoContext::create(SessionId id, BytesView tx_key, BytesView rx_key)
    {
        SessionCryptoContext ctx;
        ctx.session_id_ = id;
        ctx.tx_key_ = PacketTxKey(Bytes(tx_key.begin(), tx_key.end()));
        ctx.rx_key_ = PacketRxKey(Bytes(rx_key.begin(), rx_key.end()));
        return ctx;
    }

} // namespace smo
