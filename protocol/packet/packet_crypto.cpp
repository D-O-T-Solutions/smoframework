#include "packet_crypto.hpp"

#include "../../core/crypto/aead/xchacha20_provider.hpp"

#include <blake3.h>

#include <array>
#include <exception>

namespace smo {

    namespace {

        constexpr size_t kAeadTagLen = aead::XChaCha20Provider::kMacSize;   // 16
        constexpr size_t kAeadKeyLen = aead::XChaCha20Provider::kKeySize;   // 32
        constexpr size_t kAeadNonceLen = aead::XChaCha20Provider::kNonceSize; // 24

        bool is_zero_session(const std::array<uint8_t, 16>& sid) noexcept
        {
            for (const auto b : sid)
                if (b != 0)
                    return false;
            return true;
        }

    } // anonymous namespace

    Bytes derive_aead_nonce(BytesView session_id, uint64_t wire_nonce)
    {
        uint8_t seq_be[8];
        for (int i = 0; i < 8; ++i)
            seq_be[i] = static_cast<uint8_t>(wire_nonce >> ((7 - i) * 8));

        uint8_t digest[32];
        blake3_hasher hasher;
        blake3_hasher_init(&hasher);
        blake3_hasher_update(&hasher, session_id.data(), session_id.size());
        blake3_hasher_update(&hasher, seq_be, sizeof(seq_be));
        blake3_hasher_finalize(&hasher, digest, sizeof(digest));

        return Bytes(digest, digest + kAeadNonceLen);
    }

    Result<void> packet_seal_data(Packet& packet, const PacketTxKey& key, uint64_t sequence)
    {
        if (key.material_.size() != kAeadKeyLen)
            return SMO_ERR_PROTOCOL(610, Error, NoRetry, None, "packet seal: invalid key size");
        if (sequence == 0)
            return SMO_ERR_PROTOCOL(611, Error, NoRetry, None, "packet seal: zero sequence rejected");
        if (is_zero_session(packet.header.session_id))
            return SMO_ERR_PROTOCOL(612, Error, NoRetry, None, "packet seal: zero session_id rejected");
        if (packet.payload.size() > 65535)
            return SMO_ERR_PROTOCOL(613, Error, NoRetry, None, "packet seal: payload too large");

        packet.header.protocol_version = kPacketProtocolVersion;
        packet.header.nonce = sequence;
        packet.header.payload_length = static_cast<uint16_t>(packet.payload.size());

        const Bytes nonce =
            derive_aead_nonce(BytesView(packet.header.session_id.data(), packet.header.session_id.size()), sequence);
        const auto aad = serialize_packet_header(packet.header);

        Bytes combined;
        try
        {
            combined = aead::XChaCha20Provider::encrypt(BytesView(packet.payload), BytesView(aad),
                                                        BytesView(key.material_), BytesView(nonce));
        }
        catch (const std::exception&)
        {
            return SMO_ERR_PROTOCOL(614, Error, NoRetry, None, "packet seal: AEAD encrypt failed");
        }

        if (combined.size() != packet.payload.size() + kAeadTagLen)
            return SMO_ERR_PROTOCOL(614, Error, NoRetry, None, "packet seal: unexpected AEAD output size");

        const size_t ct_len = combined.size() - kAeadTagLen;
        packet.auth.assign(combined.begin() + static_cast<ptrdiff_t>(ct_len), combined.end());
        packet.payload.assign(combined.begin(), combined.begin() + static_cast<ptrdiff_t>(ct_len));
        return {};
    }

    Result<void> packet_open_data(Packet& packet, const PacketRxKey& key)
    {
        if (key.material_.size() != kAeadKeyLen)
            return SMO_ERR_PROTOCOL(610, Error, NoRetry, None, "packet open: invalid key size");
        if (packet.header.nonce == 0)
            return SMO_ERR_PROTOCOL(611, Error, NoRetry, None, "packet open: zero nonce rejected");
        if (packet.auth.size() != kAeadTagLen)
            return SMO_ERR_PROTOCOL(615, Error, NoRetry, None, "packet open: invalid auth tag length");
        if (packet.header.payload_length != packet.payload.size())
            return SMO_ERR_PROTOCOL(616, Error, NoRetry, None, "packet open: payload_length mismatch");

        const uint64_t sequence = packet.header.nonce;
        const Bytes nonce =
            derive_aead_nonce(BytesView(packet.header.session_id.data(), packet.header.session_id.size()), sequence);
        const auto aad = serialize_packet_header(packet.header);

        Bytes combined;
        combined.reserve(packet.payload.size() + packet.auth.size());
        combined.insert(combined.end(), packet.payload.begin(), packet.payload.end());
        combined.insert(combined.end(), packet.auth.begin(), packet.auth.end());

        Bytes plaintext;
        try
        {
            plaintext = aead::XChaCha20Provider::decrypt(BytesView(combined), BytesView(aad), BytesView(key.material_),
                                                         BytesView(nonce));
        }
        catch (const std::exception&)
        {
            return SMO_ERR_PROTOCOL(617, Error, NoRetry, None, "packet open: AEAD authentication failed");
        }

        packet.payload = std::move(plaintext);
        packet.auth.clear();
        return {};
    }

} // namespace smo
